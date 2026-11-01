// The faucet page: GET /faucet, a form over the chain's EXISTING claim rule.
//
// Design decision 3 makes this page a READ of the puzzle, never a participant
// in it. It shows what one claim pays, what the faucet holds, whether one
// address is eligible in the epoch the next block will execute, and the exact
// command that claims. It performs no Argon2id evaluation and produces no
// signature: the node holds no key for the visitor, and solving for anonymous
// requests would turn a courtesy faucet into a free-claim oracle paid for with
// the node's CPU. It also submits nothing: the command it prints is the one the
// claimant runs locally, which is where the key and the signature belong.
//
// TestTheFaucetPageCannotSolveSignOrSubmit enforces that structurally instead
// of by observation: this package's production sources may not import the
// solver, the signer or the keystore, and this file may not call the mempool or
// make an outbound HTTP request.
//
// Every page here is server-rendered HTML with no script and no external asset
// (design decision 4), and carries a fixed "what this page cannot do" list
// (design decision 5).
package rpc

import (
	"bytes"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"unicode/utf8"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

// The pages are COMPILED IN, not read from the data directory: operator data
// is not a place to load executable presentation from, and a template file
// there would be one more thing an operator had to install and could edit into
// something that submits.
//
//go:embed templates/*.html
var templateFS embed.FS

// pageFuncs are the only functions a template in this package may call. `b10`
// is genesis.FormatB10, so an amount on a page is rendered by the same integer
// arithmetic the CLI and /history use; a template that divided by 10^8 itself
// would be a second, floating-point source of truth for money.
var pageFuncs = template.FuncMap{
	"b10": genesis.FormatB10,
}

// pageTemplates is parsed once. A broken template panics at startup rather than
// on the first unauthenticated request; the rendered pages are covered by tests.
var pageTemplates = template.Must(template.New("pages").Funcs(pageFuncs).ParseFS(templateFS, "templates/*.html"))

const (
	faucetTemplateName   = "faucet.html"
	explorerTemplateName = "explorer.html"
)

// defaultNodeURL is cmd/b10coin's --node default. It is only the fallback for a
// Host that cannot safely be printed into a command line.
const defaultNodeURL = "http://127.0.0.1:8645"

// pageHeader sets what every page in this package shares: the content type,
// nosniff (a body we render must never be sniffed into another type) and a
// policy that forbids scripts and every external asset. An inline stylesheet is
// the one allowance, hence style-src 'unsafe-inline'; a page that needed a CDN
// would have to change this header, which is the point of stating it here.
func pageHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	// The page reports the CURRENT epoch's eligibility. A cached copy would
	// tell a visitor they can claim when they cannot - or the reverse.
	w.Header().Set("Cache-Control", "no-store")
}

// faucetView is everything the page renders. Every number in it is a copy made
// under one read lock, so rendering never touches the chain again and a commit
// cannot interleave a half-updated page.
type faucetView struct {
	ChainID        string
	Height         uint64
	EpochBlocks    uint64
	Epoch          uint64 // (height+1)/EpochBlocks + 1: the 1-BASED epoch of the block that will apply the claim
	ClaimAmount    uint64 // sparks, from state.Params().ClaimAmount
	ClaimAmountB10 string // genesis.FormatB10
	FaucetAddress  string
	FaucetBalance  uint64 // state.Get(params.FaucetAddress).Balance
	FaucetBalB10   string
	NodeURL        string // from the request's Host, so the command is copy-pasteable

	Queried      string // the canonical address, "" unless the query validated
	QueriedAddr  string // canonical form, "" when absent
	QueriedErr   string // why the query was refused
	CanClaim     bool
	ClaimedEpoch uint64
	Reason       string // the sentence rendered next to CanClaim
	Command      string // "b10coin claim --node <NodeURL> --key <path>"
}

// handleFaucet serves the page. GET only: a GET form is deliberate, because a
// POST would need a body bound, a CSRF story and a reason to exist, and this
// page has no state to change.
func (s *Server) handleFaucet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	v, err := s.faucetView(faucetNodeURL(r), r.URL.Query().Get("address"))
	if err != nil {
		http.Error(w, "the faucet page is unavailable on this node", http.StatusInternalServerError)
		return
	}
	// Render into a buffer, then write once. A template error must not leave a
	// half-written page, and a reader must see either the whole document or a
	// clean error - never a truncated one (TestFaucetPageIsSafeDuringAppends).
	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, faucetTemplateName, v); err != nil {
		http.Error(w, "the faucet page could not be rendered", http.StatusInternalServerError)
		return
	}
	pageHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// faucetView reads everything the page shows. It is a pure read of committed
// state: no lock is held across rendering, no chain scan happens, and the only
// per-request work is two account-map lookups (the faucet and, when given, the
// queried address), so its cost is independent of the chain's length.
func (s *Server) faucetView(nodeURL, rawAddr string) (faucetView, error) {
	// AdmissionHead is ONE read-locked snapshot of the state and the head
	// height. Reading State() and Height() separately can pair the new height
	// with the previous state during an append, and the eligibility answer
	// would then be derived from a height that state does not belong to.
	st, height := s.chain.AdmissionHead()
	params := st.Params()
	if params.EpochBlocks == 0 {
		// Unreachable through chain.Open (genesis.Validate refuses a zero
		// epoch), but refused rather than divided by: this handler is
		// unauthenticated, so a request-triggered panic is not acceptable.
		return faucetView{}, errors.New("the node reports epoch_blocks 0")
	}
	v := faucetView{
		ChainID:        s.chain.Genesis().ChainID,
		Height:         height,
		EpochBlocks:    params.EpochBlocks,
		Epoch:          (height+1)/params.EpochBlocks + 1,
		ClaimAmount:    params.ClaimAmount,
		ClaimAmountB10: genesis.FormatB10(params.ClaimAmount),
		FaucetAddress:  params.FaucetAddress.String(),
		FaucetBalance:  st.Get(params.FaucetAddress).Balance,
		NodeURL:        nodeURL,
		Reason:         "Enter a b10 address to see whether it can claim now.",
		Command:        fmt.Sprintf("b10coin claim --node %s --key <path>", nodeURL),
	}
	v.FaucetBalB10 = genesis.FormatB10(v.FaucetBalance)

	if rawAddr == "" {
		return v, nil
	}
	// A key pasted into a form is refused BY NAME and never echoed: this page
	// is served over plain HTTP, and the refusal must not put a secret into the
	// page, a browser history entry or anything that copies the body.
	if what := keyShape(rawAddr); what != "" {
		v.QueriedErr = fmt.Sprintf("That input is %s, not a b10 address. It cannot hold your key: never paste a key into a page - this page is served over plain HTTP, it has no use for a key, and a key pasted here would be a key exposed. Claim with `b10coin claim --key <path>` on your own machine instead.", what)
		return v, nil
	}
	addr, err := types.ParseAddress(rawAddr)
	if err != nil {
		v.QueriedErr = fmt.Sprintf("%s is not a canonical b10 address. A b10 address starts with %q and is the address a key controls; paste the address, never the key.", queryEcho(rawAddr), types.AddressPrefix)
		return v, nil
	}

	acc := st.Get(addr)
	v.Queried = addr.String()
	v.QueriedAddr = addr.String()
	v.ClaimedEpoch = acc.ClaimedEpoch
	if acc.ClaimedEpoch >= v.Epoch {
		// The same comparison state.applyFaucetClaim makes (>=, not >): a
		// claim is refused when the account's marker has already reached the
		// epoch that will execute it. Epochs are 1-based, so a never-claimed
		// account holds 0 and is eligible at epoch 1.
		v.Reason = fmt.Sprintf("This address already claimed in epoch %d. It can claim again when epoch %d opens.", acc.ClaimedEpoch, acc.ClaimedEpoch+1)
		return v, nil
	}
	v.CanClaim = true
	v.Reason = fmt.Sprintf("This address can claim in epoch %d: it has not claimed in this epoch. One claim per key per epoch is the rule, and one claim pays %s b10 (%d sparks).", v.Epoch, v.ClaimAmountB10, v.ClaimAmount)
	return v, nil
}

// keyShape names the key material a hex string has the shape of, or "" if it
// has none. An Ed25519 public key is 32 bytes (64 hex) and a private key is 64
// bytes (128 hex); neither is an address, and 128 hex digits in a form are
// far more likely to be a pasted secret than a typo.
func keyShape(s string) string {
	if len(s) != 64 && len(s) != 128 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return ""
		}
	}
	if len(s) == 128 {
		return "a 128-hex-character private key"
	}
	return "a 64-hex-character public key"
}

// maxQueryEcho bounds how much of a refused query the refusal sentence quotes.
// The query is attacker-chosen and the page is unauthenticated, so the reply
// must not be a function of its length.
const maxQueryEcho = 64

// queryEcho quotes at most maxQueryEcho bytes of a refused query, cutting at a
// rune boundary so the page stays valid UTF-8. It returns plain text; the
// template escapes it, and that is the ONLY place a query is rendered.
func queryEcho(raw string) string {
	if len(raw) <= maxQueryEcho {
		return strconv.Quote(raw)
	}
	cut := maxQueryEcho
	for cut > 0 && !utf8.RuneStart(raw[cut]) {
		cut--
	}
	return strconv.Quote(raw[:cut]) + "..."
}

// faucetNodeURL builds the --node value the page's command line shows. It comes
// from the Host the visitor actually reached, so the command names the node
// they are looking at - but it is VALIDATED and re-formatted rather than
// copied, because that line is pasted into a shell and the Host header is
// attacker-controlled. Only an http URL whose host is an IP literal or a plain
// DNS name, with a numeric port, survives; anything else falls back to the
// node's documented default: a command naming the wrong node is annoying, a
// command an attacker chose is not acceptable.
func faucetNodeURL(r *http.Request) string {
	u, err := url.Parse("http://" + r.Host)
	if err != nil || u.Host == "" {
		return defaultNodeURL
	}
	host, port := u.Hostname(), u.Port()
	if host == "" || port == "" {
		return defaultNodeURL
	}
	if p, perr := strconv.ParseUint(port, 10, 16); perr != nil || p == 0 {
		return defaultNodeURL
	}
	if net.ParseIP(host) == nil && !dnsName(host) {
		return defaultNodeURL
	}
	return "http://" + u.Host
}

// dnsName reports whether h is made only of characters a DNS name may contain.
// It is a shell-safety check, not a resolver: letters, digits, dots and
// hyphens cannot begin a shell word, separate a command, expand a variable or
// quote anything.
func dnsName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// ---- the explorer (Task 3) -------------------------------------------------

// The page's two bounds. They are constants, not query parameters: GET /explorer
// is unauthenticated and outside the /tx limiter, and ST-10 is the precedent for
// what an unbounded read on such a route costs (an /account read capped once).
// A request may therefore never widen the scan, whatever it puts in the query.
const (
	// explorerBlocks bounds BOTH loops: the blocks table reads at most this
	// many blocks, and the transaction scan covers at most this many heights.
	// 20 disk reads for the table plus 20 for the scan is a constant cost,
	// well inside the HTTP server's 10 s write timeout, and independent of the
	// chain's length.
	explorerBlocks = 20
	// explorerTxs bounds the transaction TABLE independently of the window: a
	// window of 20 blocks can hold far more transactions than one page should
	// render, so the view carries `truncated` when the cap dropped some, the
	// way /history does.
	explorerTxs = 20
)

// explorerBlock is one row of the blocks table. Time is the header's own unix
// seconds: the page does not convert it, so there is no timezone to be wrong
// about (and no date library to add).
type explorerBlock struct {
	Height uint64
	Hash   string // hex
	Time   int64  // unix seconds, as the header carries it
	Txs    int
	Root   string // hex, the block's state root
}

// explorerView is everything the page renders, copied out of the chain before
// any rendering happens: the template touches no chain method, so nothing can
// be re-read halfway through a page.
//
// The five window fields are NOT decoration. design decision 5 says every page
// states what it cannot do, and the first thing this page cannot do is see the
// whole chain: /history reports `from`/`to`/`blocks`/`truncated` for exactly
// that reason, and this page reports the same four numbers from the same scan.
type explorerView struct {
	ChainID   string
	Height    uint64
	HeadHash  string
	StateRoot string
	Blocks    []explorerBlock // newest first
	Txs       []historyEntry  // newest first; the Task 0 entry type, reused
	CannotDo  []string        // the fixed limit list, rendered as a <ul>

	BlocksShown int    // len(Blocks): how many the table actually holds
	TxFrom      uint64 // lowest height the transaction scan covered
	TxTo        uint64 // == Height
	TxBlocks    int    // heights actually scanned for transactions; 0 on a genesis-only chain
	TxTruncated bool   // the entry cap dropped transactions from that window
}

// explorerCannotDo is the page's fixed limit list (design decision 5). The
// wording is a deliverable rather than decoration: TestExplorerStatesWhatItCannotDo
// asserts these sentences, and every one of them is a property of this code - no
// search box exists, no index exists, the window is bounded, times are not
// converted - so a page that dropped one would be lying by omission.
var explorerCannotDo = []string{
	"It has no search. There is no box to type into and no query to send: the page shows this node's head and the recent window below it, and nothing else.",
	"It has no address lookup. To see one address's balance and transactions, run \"b10coin balance\" or \"b10coin history\" against this node; this page cannot be asked about an address.",
	"It has no transaction index, so it cannot answer \"where is transaction X?\". There is no /tx/{id} route, and this page lists only transactions a block in the scanned window actually included.",
	// The two caps are interpolated rather than written out, so the sentence
	// cannot drift from the bound the handler applies: changing explorerBlocks
	// changes the page's claim about it in the same commit.
	fmt.Sprintf("It has no pagination and no next page. It shows at most %d blocks and at most %d transactions per request; older blocks are reachable through the JSON API at /block/{height}, one height at a time.", explorerBlocks, explorerTxs),
	"The transaction list covers only the block window stated above it, never the whole chain. \"truncated: yes\" there means more transactions matched in that window than the page shows; it never means nothing else happened.",
	"Times are unix seconds exactly as the block header carries them. The page does not convert them, so there is no timezone to be wrong about and no calendar to disagree with the chain.",
	"A transaction appears here only once a block has included it. A transaction still in the mempool, or one that never lands, is not shown and is not promised.",
	"It is one node's view of one chain at one moment, not a network view. Another node may be at a different height; this page does not reconcile the difference and cannot tell you the network's head.",
	"It cannot verify anything for you. It reads blocks this node already accepted; it does not re-validate them and it is not a light client.",
}

// handleExplorer serves the page. GET only: the page has no state to change, so
// any other method is refused by name rather than treated as a read.
func (s *Server) handleExplorer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	v, err := s.explorerView()
	if err != nil {
		// Never the error text: a store failure names the data directory, the
		// segment file and an offset (audit O-8's rule, applied to the page).
		http.Error(w, "the explorer page is unavailable on this node", http.StatusInternalServerError)
		return
	}
	// Render into a buffer, then write once: a reader must see either the whole
	// document or a clean error, never a truncated page.
	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, explorerTemplateName, v); err != nil {
		http.Error(w, "the explorer page could not be rendered", http.StatusInternalServerError)
		return
	}
	pageHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
}

// explorerView reads everything the page shows.
//
// The head, its ID and the state root of that head come from HeadSnapshot,
// which takes them in ONE read-locked critical section. Reading Height() and
// then Head() (or State()) is two acquisitions, and a block committed between
// them pairs the new height with the old hash and root - exactly the torn pair
// Task 2 replaced with AdmissionHead on the faucet page. This page displays all
// three, so it needs the one accessor that returns all three together.
//
// The head is then passed DOWN: recentBlocks and scanHistory both take it as a
// parameter and never call Height() themselves, so every number on the page
// describes the one snapshot the header names.
func (s *Server) explorerView() (explorerView, error) {
	head, id, root := s.chain.HeadSnapshot()
	blocks, err := s.recentBlocks(head, explorerBlocks)
	if err != nil {
		return explorerView{}, err
	}
	// The transaction list is the ONE scan /history uses, with no address
	// filter, given the same window as the block table and its own entry cap.
	// Reusing it is what keeps the page's `from`/`to`/`truncated` semantics
	// identical to the wallet's instead of a second, drifting copy.
	scan, err := s.scanHistory(head, types.Address{}, false, explorerBlocks, explorerTxs)
	if err != nil {
		return explorerView{}, err
	}
	return explorerView{
		ChainID:     s.chain.Genesis().ChainID,
		Height:      head,
		HeadHash:    hex.EncodeToString(id[:]),
		StateRoot:   hex.EncodeToString(root[:]),
		Blocks:      blocks,
		Txs:         scan.Txs,
		CannotDo:    explorerCannotDo,
		BlocksShown: len(blocks),
		TxFrom:      scan.From,
		TxTo:        scan.To,
		TxBlocks:    scan.Blocks,
		TxTruncated: scan.Truncated,
	}, nil
}

// recentBlocks renders the newest n blocks at or below head, newest first.
//
// head is a parameter for the reason given on explorerView. The loop counts
// DOWN from head+1 with the bound fixed first, so height 0 is rendered exactly
// once and no uint64 underflow is possible: `for h := head; h >= 0; h--` would
// never terminate (uint64 has no negative), which is why the bound is computed
// before the loop rather than tested inside it.
func (s *Server) recentBlocks(head uint64, n int) ([]explorerBlock, error) {
	if n <= 0 {
		return nil, nil
	}
	lo := uint64(0)
	if head >= uint64(n) {
		lo = head - uint64(n) + 1
	}
	out := make([]explorerBlock, 0, n)
	for h := head + 1; h > lo; {
		h--
		b, err := s.chain.BlockAt(h)
		if err != nil {
			// Refused, not skipped. A short table with a silent gap would
			// read as "the chain has fewer blocks", which is a lie about the
			// chain rather than an admission that this node cannot serve it.
			return nil, err
		}
		id := b.ID()
		out = append(out, explorerBlock{
			Height: b.Header.Height,
			Hash:   hex.EncodeToString(id[:]),
			Time:   b.Header.Timestamp,
			Txs:    len(b.Txs),
			Root:   hex.EncodeToString(b.Header.StateRoot[:]),
		})
	}
	return out, nil
}
