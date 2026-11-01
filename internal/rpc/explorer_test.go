// The explorer page's tests. Three of them are structural rather than
// observational: TestTheExplorerPageCannotSearchSubmitOrLoadAnything reads the
// production sources and the template, so a search box, a form, a script or a
// filesystem template fails the suite even if no test exercises it;
// TestExplorerTransactionsAreTheSameScanAsHistory pins the page to Task 0's one
// scan instead of a second copy; and TestExplorerCannotWidenItsScanFromTheQuery
// pins the bound to a constant rather than a request parameter.
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

// The page markers the assertions read. They are deliberately narrow: a row is
// identified by a height or a transaction id, never by "the page contains the
// string", because presence survives a reversed table.
var (
	explorerBlockRowRE = regexp.MustCompile(`(?s)<tr data-height="(\d+)">\s*<td>(\d+)</td>\s*<td><code>([0-9a-f]{64})</code></td>\s*<td>(\d+)</td>\s*<td>(-?\d+)</td>\s*<td><code>([0-9a-f]{64})</code></td>`)
	explorerHeadHgtRE  = regexp.MustCompile(`<th>Head height</th><td>(\d+)</td>`)
	explorerHeadHashRE = regexp.MustCompile(`<th>Head hash</th><td><code>([0-9a-f]{64})</code></td>`)
	explorerHeadRootRE = regexp.MustCompile(`<th>Head state root</th><td><code>([0-9a-f]{64})</code></td>`)
	explorerTxRowRE    = regexp.MustCompile(`<tr data-txid="([0-9a-f]{64})">`)
)

// explorerBlockHeights returns the heights of the block rows, in document order.
func explorerBlockHeights(t *testing.T, body string) []uint64 {
	t.Helper()
	var out []uint64
	for _, m := range explorerBlockRowRE.FindAllStringSubmatch(body, -1) {
		h, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			t.Fatalf("block row height %q: %v", m[1], err)
		}
		out = append(out, h)
	}
	return out
}

// explorerTxIDs returns the transaction ids the page lists, in document order.
func explorerTxIDs(body string) []string {
	var out []string
	for _, m := range explorerTxRowRE.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func explorerPage(t *testing.T, url string) string {
	t.Helper()
	body, resp := getPage(t, url)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body:\n%s", url, resp.StatusCode, body)
	}
	return body
}

// TestExplorerListsRecentBlocksNewestFirst is decision 4's one-page listing,
// with the ORDER as the property: a table that lists 0,1,2 contains exactly the
// same strings as 2,1,0, so presence alone proves nothing.
func TestExplorerListsRecentBlocksNewestFirst(t *testing.T) {
	c, ts := pageServer(t, genesis.Devnet())
	_, priv := genesis.DevValidatorKey()
	for h := 1; h <= 2; h++ {
		b, err := c.Build(priv, nil, c.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	if c.Height() != 2 {
		t.Fatalf("height = %d, want 2", c.Height())
	}
	body := explorerPage(t, ts.URL+"/explorer")

	got := explorerBlockHeights(t, body)
	want := []uint64{2, 1, 0}
	if len(got) != len(want) {
		t.Fatalf("the page listed %d blocks %v, want %v; body:\n%s", len(got), got, want, body)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("block row %d = height %d, want %d (rows %v): newest must come first", i, got[i], want[i], got)
		}
	}
	// The literals, by index, so a change of marker cannot quietly pass.
	i2 := strings.Index(body, `data-height="2"`)
	i1 := strings.Index(body, `data-height="1"`)
	i0 := strings.Index(body, `data-height="0"`)
	if !(i2 >= 0 && i2 < i1 && i1 < i0) {
		t.Fatalf("the block rows are not in newest-first document order: heights at %d,%d,%d", i2, i1, i0)
	}
}

// TestExplorerShowsATransferFromARecentBlock is the page's half of the M6
// acceptance sentence: the transfer a wallet sent is visible in HTML.
//
// The amount is 29,000,000 sparks = 0.29 b10 on purpose: 0.1 round-trips
// exactly through float64 and proves nothing, while 0.29 does not, so a page
// that rendered the amount through a float would disagree with the chain.
func TestExplorerShowsATransferFromARecentBlock(t *testing.T) {
	c, ts := pageServer(t, genesis.Devnet())
	g := c.Genesis()
	alicePub, alicePriv := genesis.DevAccountKey(0)
	bobPub, _ := genesis.DevAccountKey(1)
	const amount = 29_000_000

	tx := &types.Tx{
		Type: types.TxTransfer, From: types.AddressFromPub(alicePub), PubKey: alicePub,
		Nonce: 0, Fee: g.Params.MinFeeSparks, To: types.AddressFromPub(bobPub), Amount: amount,
	}
	signTx(t, c, tx, alicePriv)
	appendBlock(t, c, []types.Tx{*tx}, g.Time+1)

	id := tx.ID()
	txid := hex.EncodeToString(id[:])
	body := explorerPage(t, ts.URL+"/explorer")

	if got := explorerTxIDs(body); len(got) != 1 || got[0] != txid {
		t.Fatalf("the page listed transactions %v, want [%s]", got, txid)
	}
	for _, want := range []string{
		txid[:16],  // the brief's first-16 pin
		"transfer", // the type label
		strconv.FormatUint(amount, 10) + " sparks", // the integer
		"0.29 b10",       // the same amount, via genesis.FormatB10
		"0.00000001 b10", // MinFeeSparks = 1 spark, same function
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not contain %q; body:\n%s", want, body)
		}
	}
	// The float trap, explicitly: no rendering of this amount may be the
	// float64 approximation.
	for _, wrong := range []string{"0.28999999", "0.29000000", "2.9e-01"} {
		if strings.Contains(body, wrong) {
			t.Errorf("the page rendered the amount as %q: money is integer sparks through genesis.FormatB10", wrong)
		}
	}
}

// TestExplorerOnAGenesisOnlyChain pins the loop's lower bound: height 0 is
// rendered once, no height -1 is requested (uint64 has none) and the page is a
// 200 rather than a 404.
func TestExplorerOnAGenesisOnlyChain(t *testing.T) {
	c, ts := pageServer(t, genesis.Devnet())
	if c.Height() != 0 {
		t.Fatalf("the fresh chain reports height %d, want 0", c.Height())
	}
	body := explorerPage(t, ts.URL+"/explorer")

	got := explorerBlockHeights(t, body)
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("a genesis-only chain rendered blocks %v, want exactly [0]", got)
	}
	if strings.Contains(body, `data-height="1"`) {
		t.Error("the page rendered a block above the head")
	}
	if ids := explorerTxIDs(body); len(ids) != 0 {
		t.Errorf("a genesis-only chain listed transactions %v", ids)
	}
	if !strings.Contains(body, "This chain holds only its genesis block") {
		t.Error("the page does not say a genesis-only chain has no transaction window")
	}
	if !strings.Contains(body, "Truncated:") && !strings.Contains(body, "no transactions") {
		t.Error("the page does not state what its empty transaction table means")
	}
}

// TestExplorerIsSafeDuringAppends is the torn-read test, made concrete: during
// a commit storm the header's height, hash and state root must describe the
// same block as the table's first row, and every body must be whole.
//
// It is the test that kills "call Height() again inside the loop": a page whose
// header says 37 while its first row says 36 disagrees with itself.
func TestExplorerIsSafeDuringAppends(t *testing.T) {
	c, ts := pageServer(t, genesis.Devnet())
	_, priv := genesis.DevValidatorKey()

	const rounds = 40
	done := make(chan struct{})
	fail := make(chan string, 1)
	go func() {
		defer close(done)
		for i := 0; i < rounds; i++ {
			resp, err := http.Get(ts.URL + "/explorer")
			if err != nil {
				fail <- fmt.Sprintf("GET /explorer during an append: %v", err)
				return
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				fail <- fmt.Sprintf("read /explorer during an append: %v", err)
				return
			}
			if resp.StatusCode != http.StatusOK {
				fail <- fmt.Sprintf("GET /explorer during an append = %d, want 200", resp.StatusCode)
				return
			}
			s := string(body)
			if !strings.HasSuffix(strings.TrimSpace(s), "</html>") {
				fail <- "the page was written partially: the body does not end with </html>"
				return
			}
			hm := explorerHeadHgtRE.FindStringSubmatch(s)
			hh := explorerHeadHashRE.FindStringSubmatch(s)
			hr := explorerHeadRootRE.FindStringSubmatch(s)
			rows := explorerBlockRowRE.FindAllStringSubmatch(s, -1)
			if hm == nil || hh == nil || hr == nil || len(rows) == 0 {
				fail <- "the page is missing its header or its first block row"
				return
			}
			// rows[0]: [full, data-height, height, hash, txs, time, root]
			if hm[1] != rows[0][2] {
				fail <- fmt.Sprintf("header height %s disagrees with the newest block row %s", hm[1], rows[0][2])
				return
			}
			if hh[1] != rows[0][3] {
				fail <- fmt.Sprintf("header hash %s disagrees with the newest block row %s", hh[1], rows[0][3])
				return
			}
			if hr[1] != rows[0][6] {
				fail <- fmt.Sprintf("header state root %s disagrees with the newest block row %s", hr[1], rows[0][6])
				return
			}
		}
	}()
	for i := 0; i < rounds; i++ {
		// Strictly after the parent, as chain.Append requires; the test is
		// about concurrent READS during appends, not about timestamps.
		b, err := c.Build(priv, nil, c.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	select {
	case msg := <-fail:
		t.Fatal(msg)
	default:
	}
}

// TestExplorerStatesWhatItCannotDo is design decision 5 as a contract: the page
// names its own limits, and each sentence states something true of this code.
func TestExplorerStatesWhatItCannotDo(t *testing.T) {
	_, ts := pageServer(t, genesis.Devnet())
	body := explorerPage(t, ts.URL+"/explorer")
	for _, want := range []string{
		"no search",                            // decision 4/5
		"no address lookup",                    // use b10coin history
		"b10coin history",                      // ...and it says which verb
		"no transaction index",                 // Task 0's finding
		"no pagination",                        // bounded, not paged
		"at most 20 blocks",                    // the block bound, from the const
		"at most 20 transactions",              // the entry bound, from the const
		"unix seconds",                         // no timezone conversion
		"only once a block has included it",    // no mempool view
		"one node's view of one chain",         // not a network view
		"It cannot verify anything for you",    // not a light client
		"no JavaScript, no external asset",     // decision 4, restated on the page
		"There is no /tx/{id} route",           // the missing index, by name
		"the JSON API at /block/{height}",      // where the older blocks are
		"it never means nothing else happened", // the truncated honesty
		"read together, in one lock",           // the torn-read note, see below
	} {
		// html/template escapes the apostrophe in "node's"; the sentence is
		// asserted as the ESCAPED bytes that actually reach a reader.
		if want := html.EscapeString(want); !strings.Contains(body, want) {
			t.Errorf("the page does not state %q", want)
		}
	}
}

// TestExplorerStatesTheBoundItScanned pins the page's window to Task 0's, from
// Task 0's own numbers: the page and /history?blocks=20 must report the same
// from, to and block count for the same head, because they are the same scan.
func TestExplorerStatesTheBoundItScanned(t *testing.T) {
	c, ts := pageServer(t, genesis.Devnet())
	g := c.Genesis()
	alicePub, alicePriv := genesis.DevAccountKey(0)
	bobPub, _ := genesis.DevAccountKey(1)
	for nonce := uint64(0); nonce < 3; nonce++ {
		tx := &types.Tx{
			Type: types.TxTransfer, From: types.AddressFromPub(alicePub), PubKey: alicePub,
			Nonce: nonce, Fee: g.Params.MinFeeSparks, To: types.AddressFromPub(bobPub), Amount: 1_000,
		}
		signTx(t, c, tx, alicePriv)
		appendBlock(t, c, []types.Tx{*tx}, c.Head().Header.Timestamp+1)
	}
	if c.Height() != 3 {
		t.Fatalf("height = %d, want 3", c.Height())
	}

	resp, err := http.Get(ts.URL + "/history?blocks=20")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var hist historyResponse
	if err := json.NewDecoder(resp.Body).Decode(&hist); err != nil {
		t.Fatal(err)
	}
	if hist.Blocks != 3 || hist.From != 1 || hist.To != 3 {
		t.Fatalf("/history window = %d..%d (%d blocks), want 1..3 (3 blocks)", hist.From, hist.To, hist.Blocks)
	}

	body := explorerPage(t, ts.URL+"/explorer")
	for _, want := range []string{
		fmt.Sprintf("blocks %d to %d inclusive, %d block(s)", hist.From, hist.To, hist.Blocks),
		"At most 20 transactions are shown",
		"Truncated: no",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not state its scanned window %q; body:\n%s", want, body)
		}
	}
	// And the transaction table is exactly that window's transactions.
	if got := explorerTxIDs(body); len(got) != len(hist.Txs) {
		t.Errorf("the page lists %d transactions, the window holds %d", len(got), len(hist.Txs))
	}
}

// TestExplorerTransactionsAreTheSameScanAsHistory is the "one scan path" pin,
// end to end: the page's transaction list must be the prefix of /history's for
// the same window. A second, divergent scan fails here even though each side
// passes its own tests - which is exactly how a duplicated source of truth
// hides.
func TestExplorerTransactionsAreTheSameScanAsHistory(t *testing.T) {
	c, ts := pageServer(t, genesis.Devnet())
	g := c.Genesis()
	alicePub, alicePriv := genesis.DevAccountKey(0)
	bobPub, _ := genesis.DevAccountKey(1)
	for nonce := uint64(0); nonce < 5; nonce++ {
		tx := &types.Tx{
			Type: types.TxTransfer, From: types.AddressFromPub(alicePub), PubKey: alicePub,
			Nonce: nonce, Fee: g.Params.MinFeeSparks, To: types.AddressFromPub(bobPub), Amount: 500 + nonce,
		}
		signTx(t, c, tx, alicePriv)
		appendBlock(t, c, []types.Tx{*tx}, c.Head().Header.Timestamp+1)
	}

	resp, err := http.Get(ts.URL + "/history?blocks=20")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var hist historyResponse
	if err := json.NewDecoder(resp.Body).Decode(&hist); err != nil {
		t.Fatal(err)
	}
	body := explorerPage(t, ts.URL+"/explorer")
	got := explorerTxIDs(body)
	if len(got) != 5 {
		t.Fatalf("the page lists %d transactions, want 5", len(got))
	}
	for i, want := range hist.Txs {
		if i >= len(got) {
			break
		}
		if got[i] != want.TxID {
			t.Fatalf("transaction %d: page %s, /history %s (they must be one scan)", i, got[i], want.TxID)
		}
	}
}

// TestExplorerCannotWidenItsScanFromTheQuery is the ST-10 guard on this route:
// it is unauthenticated and outside the /tx limiter, so no query string may
// make it read more blocks. A `?blocks=100000` is ignored, not clamped silently
// into something that still costs a variable amount of work.
//
// The chain is deliberately LONGER than explorerBlocks: on a chain shorter than
// the bound, a query-driven window is invisible because every window already
// covers the whole chain, and this test would pass while the route was wide
// open. That is measured, not assumed: the first version of this test used a
// 3-block chain and survived exactly that mutant.
func TestExplorerCannotWidenItsScanFromTheQuery(t *testing.T) {
	c, ts := pageServer(t, genesis.Devnet())
	_, priv := genesis.DevValidatorKey()
	for h := 1; h <= explorerBlocks+5; h++ {
		b, err := c.Build(priv, nil, c.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	plain := explorerPage(t, ts.URL+"/explorer")
	if rows := explorerBlockHeights(t, plain); len(rows) != explorerBlocks {
		t.Fatalf("the page listed %d blocks on a chain of %d, want exactly explorerBlocks = %d", len(rows), c.Height(), explorerBlocks)
	}
	for _, q := range []string{
		"?blocks=100000",
		"?blocks=100000&address=" + strings.Repeat("0", 40),
		"?from=0&to=0&txs=100000&search=1",
	} {
		got := explorerPage(t, ts.URL+"/explorer"+q)
		if got != plain {
			t.Errorf("GET /explorer%s changed the page: the scan is bounded by a constant, not by the query", q)
		}
	}
}

// TestExplorerIsGetOnly refuses a write verb by name rather than treating it as
// a read. The page changes no state, so there is no POST to accept.
func TestExplorerIsGetOnly(t *testing.T) {
	_, ts := pageServer(t, genesis.Devnet())
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req, err := http.NewRequest(method, ts.URL+"/explorer", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s /explorer = %d, want 405", method, resp.StatusCode)
		}
		if got := resp.Header.Get("Allow"); got != http.MethodGet {
			t.Errorf("%s /explorer Allow = %q, want %q", method, got, http.MethodGet)
		}
		if strings.Contains(string(body), "data-height=") {
			t.Errorf("%s /explorer rendered the page; it must be refused", method)
		}
	}
}

// TestExplorerReportsAnUnreadableBlockAsAPageError constructs the failure the
// way TestBlockEndpointDoesNotLeakFilesystemPaths does - by deleting the
// segment an historical read needs, not by racing a writer. A short table would
// read as "the chain is shorter"; the page must fail instead, without naming a
// path (audit O-8).
func TestExplorerReportsAnUnreadableBlockAsAPageError(t *testing.T) {
	dir := t.TempDir()
	c, err := chain.Open(genesis.Devnet(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_, priv := genesis.DevValidatorKey()
	for h := 1; h <= 2; h++ {
		b, err := c.Build(priv, nil, c.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	seg := filepath.Join(dir, "00000000.seg")
	if err := os.Remove(seg); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(c, mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)).Handler())
	t.Cleanup(srv.Close)

	// Both loops read heights 1..2, so a page-level 500 alone would be
	// satisfied by the transaction scan failing even if the block table
	// silently dropped the unreadable block. The table is asked directly:
	// "a gap is not a shorter chain" is its own contract, and this is the
	// assertion that mutant M5 (swallow the error and continue) survives
	// without.
	direct := NewServer(c, mempool.New(100, c.Genesis().Hash(), c.AdmissionHead))
	if rows, err := direct.recentBlocks(c.Height(), explorerBlocks); err == nil {
		t.Fatalf("recentBlocks skipped an unreadable block instead of reporting it: %d rows, no error", len(rows))
	}

	resp, err := http.Get(srv.URL + "/explorer")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET /explorer with its segment removed = %d, want 500; body:\n%s", resp.StatusCode, body)
	}
	for _, leak := range []string{dir, "00000000.seg", "no such file", "read "} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("the 500 body leaked %q: %s", leak, body)
		}
	}
	if strings.Contains(string(body), "data-height=") {
		t.Fatal("the failed page rendered a block table: a gap must not look like a short chain")
	}
}

// TestTheExplorerPageHasNoScriptAndNoExternalResource is decision 4's header and
// body contract, asserted on the bytes because there is no browser here.
func TestTheExplorerPageHasNoScriptAndNoExternalResource(t *testing.T) {
	_, ts := pageServer(t, genesis.Devnet())
	body, resp := getPage(t, ts.URL+"/explorer")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /explorer = %d, want 200", resp.StatusCode)
	}
	for header, want := range map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
		"Cache-Control":           "no-store",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	lower := strings.ToLower(body)
	for _, banned := range []string{"<script", "<link", "src=", "href=", "@import", "http://", "https://", "javascript:"} {
		if strings.Contains(lower, banned) {
			t.Errorf("the page contains %q: it is one document with no script and no external asset", banned)
		}
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(body) {
		t.Error("the page contains an inline event handler; CSP forbids scripts and the page must not need one")
	}
	if !strings.HasSuffix(strings.TrimSpace(body), "</html>") {
		t.Error("the page is not one complete document")
	}
}

// TestTheExplorerPageCannotSearchSubmitOrLoadAnything is the structural pin,
// and it is where the explorer is held to Task 2's bar and above it:
//
//   - the template has no form, no input, no button and no link, so there is
//     nothing to search with and nothing to submit to - decision 4's "no
//     JavaScript" and decision 5's "no search", enforced together;
//   - no production file in this package parses a template from disk or reads a
//     file at request time: the pages are embedded at build time, so operator
//     data cannot become presentation;
//   - the templates are parsed EXACTLY ONCE, at startup.
//
// The package-wide "no solver, no signer, no keystore, no second listener"
// assertions live in TestTheFaucetPageCannotSolveSignOrSubmit and, because they
// glob every production file in this package, they cover the explorer too.
func TestTheExplorerPageCannotSearchSubmitOrLoadAnything(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("templates", "explorer.html"))
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, banned := range []string{
		"<script", "<form", "<input", "<button", "<link", "<a ",
		"src=", "href=", "@import", "http://", "https://",
		`method="post"`, `name="q"`, "placeholder=",
	} {
		if strings.Contains(lower, banned) {
			t.Errorf("templates/explorer.html contains %q: the page has no search, no input and no external asset", banned)
		}
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(string(raw)) {
		t.Error("templates/explorer.html contains an inline event handler")
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		checked++
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			switch name {
			case "ParseFiles", "ParseGlob", "ReadFile", "ReadDir", "OpenFile":
				t.Errorf("%s calls %s: the pages are embedded at build time and must never be read from a data directory", fset.Position(call.Pos()), name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no production source files were checked - the glob found only tests")
	}

	src, err := os.ReadFile("web.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "//go:embed templates/*.html") {
		t.Error("web.go no longer embeds templates/*.html: the pages must be compiled in")
	}
	if n := strings.Count(string(src), "ParseFS("); n != 1 {
		t.Errorf("web.go parses templates %d times, want exactly 1 at startup", n)
	}
}

// TestTheExplorerPageSharesTheNodesOneServer: the page added a route, not a
// server. One listener serves the JSON API, the faucet and the explorer.
func TestTheExplorerPageSharesTheNodesOneServer(t *testing.T) {
	devPub, _ := genesis.DevAccountKey(0)
	_, ts := pageServer(t, genesis.Devnet())
	for _, path := range []string{
		"/status", "/block/0", "/history", "/faucet", "/explorer",
		"/account/" + types.AddressFromPub(devPub).String(),
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200: the page must not have displaced the JSON API", path, resp.StatusCode)
		}
	}
}

// The page's bounds must stay inside the bounds /history was audited with: one
// source of truth for "how much work may an unauthenticated read do".
func TestExplorerBoundsStayInsideTheHistoryBounds(t *testing.T) {
	if explorerBlocks > maxHistoryBlocks {
		t.Errorf("explorerBlocks = %d exceeds maxHistoryBlocks = %d", explorerBlocks, maxHistoryBlocks)
	}
	if explorerTxs > maxHistoryEntries {
		t.Errorf("explorerTxs = %d exceeds maxHistoryEntries = %d", explorerTxs, maxHistoryEntries)
	}
	if explorerBlocks <= 0 || explorerTxs <= 0 {
		t.Errorf("the page's bounds must be positive: explorerBlocks = %d, explorerTxs = %d", explorerBlocks, explorerTxs)
	}
	// And the page's own sentence about its bound is derived, not retyped.
	if got, want := len(explorerCannotDo), 9; got != want {
		t.Errorf("the limit list has %d entries, want %d: every limit the page has is stated on it", got, want)
	}
}

// TestTheExplorerPageMoneyIsFormatB10NotADivision pins the money renderer
// STRUCTURALLY, and the reason is a measured fact rather than caution.
//
// The obvious test would be a value: render some amount and compare its b10
// string with an independent FormatB10. That test cannot catch the defect it is
// for. Over the whole b10 supply (0..21e14 sparks) a float64 quotient printed
// with strconv.FormatFloat(v, 'f', -1, 64) is BYTE-IDENTICAL to FormatB10 for
// every value sampled - the supply never exceeds 2^53 sparks, so no amount in
// this chain has a shortest-round-trip decimal that the division gets wrong.
// A "0.1 round-trips, so use 0.29" case therefore proves nothing here either:
// 0.29 round-trips just as exactly, and so does every other reachable amount.
//
// What does catch it is identity and absence: the template's `b10` function must
// BE genesis.FormatB10, and the page's own source must contain no float type at
// all, so no amount on the page can come from a division.
func TestTheExplorerPageMoneyIsFormatB10NotADivision(t *testing.T) {
	fn, ok := pageFuncs["b10"]
	if !ok {
		t.Fatal("no b10 function is registered: the page could not render an amount at all")
	}
	if reflect.ValueOf(fn).Pointer() != reflect.ValueOf(genesis.FormatB10).Pointer() {
		t.Fatal("the page's b10 renderer is not genesis.FormatB10: money is integer sparks, never a division")
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "web.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && (id.Name == "float64" || id.Name == "float32") {
			t.Errorf("%s uses %s: no amount on a page may pass through a float", fset.Position(id.Pos()), id.Name)
		}
		return true
	})
}

// TestExplorerTakesTheHeadInOneRead is the torn-read pin, and it is STRUCTURAL
// because the observational version is FLAKY: TestExplorerIsSafeDuringAppends
// kills "Height() then Head()" only when a commit lands in the gap between the
// two calls, which on a fast machine is most of the time, not always. Measured:
// that mutant survived one of two runs. A pin with a 50% kill rate is not a pin.
//
// So this one reads the production sources and states the rule the code must
// obey: the page's read path takes the head EXACTLY ONCE, through HeadSnapshot,
// and no function on that path may call Height(), Head(), State() or
// AdmissionHead - each of which is a separate acquisition that a commit can
// split from the others. Task 2's finding was State()+Height(); this is the
// same defect with a different pair.
func TestExplorerTakesTheHeadInOneRead(t *testing.T) {
	// expected HeadSnapshot calls in the function's body.
	wanted := map[string]int{
		"explorerView":   1, // the one read that produces height, hash and root together
		"recentBlocks":   0, // the head is a parameter
		"scanHistory":    0, // the head is a parameter
		"handleExplorer": 0, // the handler renders, it does not read the chain
	}
	separateReads := map[string]bool{"Height": true, "Head": true, "State": true, "AdmissionHead": true}
	seen := make(map[string]bool, len(wanted))
	for _, path := range []string{"web.go", "wallet.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			want, ok := wanted[fn.Name.Name]
			if !ok {
				continue
			}
			seen[fn.Name.Name] = true
			snapshots := 0
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "HeadSnapshot":
					snapshots++
				case "Height", "Head", "State", "AdmissionHead":
					if separateReads[sel.Sel.Name] {
						t.Errorf("%s: %s calls %s: the page's read path takes height, hash and state root in ONE HeadSnapshot, never in two acquisitions",
							fset.Position(call.Pos()), fn.Name.Name, sel.Sel.Name)
					}
				}
				return true
			})
			if snapshots != want {
				t.Errorf("%s: %s calls HeadSnapshot %d time(s), want %d", fset.Position(fn.Pos()), fn.Name.Name, snapshots, want)
			}
		}
	}
	for name := range wanted {
		if !seen[name] {
			t.Errorf("the function %s was not found: this property was not verified", name)
		}
	}
}
