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

// pageTemplates is parsed once. A broken template panics at startup rather than
// on the first unauthenticated request; the rendered pages are covered by tests.
var pageTemplates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

const faucetTemplateName = "faucet.html"

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
