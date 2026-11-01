// The faucet page's tests. Two properties here are structural rather than
// observational: TestTheFaucetPageCannotSolveSignOrSubmit reads the production
// sources, so adding a solver, a signer or a submit path to this package fails
// the suite even if no test happens to exercise it; and the template assertions
// cover the rendered page's shape, which is what design decision 4 is about.
package rpc

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

// pageServer opens a chain on g - which a caller may have modified before the
// call - and serves its RPC handler on one test listener. Every assertion below
// goes through the REAL routing table and the real middleware (there is none),
// so a page that only works when called directly is not proven here.
func pageServer(t *testing.T, g *genesis.Genesis) (*chain.Chain, *httptest.Server) {
	t.Helper()
	c, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatalf("open chain: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	ts := httptest.NewServer(NewServer(c, mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)).Handler())
	t.Cleanup(ts.Close)
	return c, ts
}

// getPage fetches url and returns its body. The response is returned with its
// body already closed, so only its headers may be read afterwards.
func getPage(t *testing.T, url string) (string, *http.Response) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(body), resp
}

// claimIntoBlock commits one REAL faucet claim in the next block and returns the
// claimant's address. That is a constructed state - a solved puzzle in a
// committed block - not a race with a running producer.
func claimIntoBlock(t *testing.T, c *chain.Chain) types.Address {
	t.Helper()
	g := c.Genesis()
	height := c.Height() + 1
	epoch := height/g.Params.EpochBlocks + 1 // the epoch of the block that executes the claim
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pow, ok := faucet.Solve(pub, epoch, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, 1_000_000)
	if !ok {
		t.Fatalf("could not solve the devnet puzzle for epoch %d", epoch)
	}
	tx := &types.Tx{
		Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: 0, Epoch: epoch, PowNonce: pow,
	}
	signTx(t, c, tx, priv)
	appendBlock(t, c, []types.Tx{*tx}, c.Head().Header.Timestamp+1)
	return types.AddressFromPub(pub)
}

// Decision 5 is a deliverable, not decoration: the page must state the claim
// amount in both units, the epoch bound, the one-claim-per-key rule, and what
// it cannot do. It must also be a single server-rendered document.
func TestFaucetPageStatesItsLimitsAndTheClaimAmount(t *testing.T) {
	_, ts := pageServer(t, genesis.Devnet())
	body, resp := getPage(t, ts.URL+"/faucet")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /faucet = %d, want 200; body: %s", resp.StatusCode, body)
	}
	if got, want := resp.Header.Get("Content-Type"), "text/html; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got, want := resp.Header.Get("Content-Security-Policy"), "default-src 'none'; style-src 'unsafe-inline'"; got != want {
		t.Errorf("Content-Security-Policy = %q, want %q", got, want)
	}

	amount := genesis.Devnet().Params.ClaimAmountSparks
	for _, want := range []string{
		"1 b10", // b10
		strconv.FormatUint(amount, 10) + " sparks", // and sparks, from the same integer
		"epoch 1",                     // the epoch a claim would execute in at head 0
		"1000 blocks",                 // the epoch length
		"one claim per key per epoch", // the rule
		"rate-limited",                // decision 5
		"cannot sign",                 // ...
		"cannot hold your key",        // ...
		"cannot pay you",              // ...
		"queued",                      // a claim queues; it does not credit instantly
		`method="get"`,                // the one form is a GET form
		"b10coin claim --node",        // the command it exists to hand over
		"--key",                       // ... and it names the key, not an ephemeral claim
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the faucet page does not contain %q; body:\n%s", want, body)
		}
	}
	// Design decision 4: no script, no POST, no submit path, no external asset.
	for _, banned := range []string{`<script`, `method="post"`, "/tx", `src="http`, "@import"} {
		if strings.Contains(strings.ToLower(body), banned) {
			t.Errorf("the faucet page contains %q: the page is one server-rendered document with no submit path and no external asset", banned)
		}
	}
}

// Eligibility comes from committed state: who has claimed in the epoch the next
// block will execute. The >= comparison is the state machine's own (>=, not >),
// so the claimant is refused and the fresh address is handed the command.
func TestFaucetPageReportsEligibility(t *testing.T) {
	g := *genesis.Devnet()
	g.Params.ClaimAmountSparks = 100 // payable from the genesis faucet; the numbers are not this test's subject
	c, ts := pageServer(t, &g)
	alice := claimIntoBlock(t, c)
	if c.Height() != 1 {
		t.Fatalf("height = %d, want 1", c.Height())
	}
	bobPub, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	bob := types.AddressFromPub(bobPub)

	body, resp := getPage(t, ts.URL+"/faucet?address="+alice.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /faucet?address=alice = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "already claimed in epoch 1") {
		t.Errorf("the claimed address is not told it already claimed in epoch 1; body:\n%s", body)
	}
	if strings.Contains(body, "can claim in epoch") {
		t.Errorf("the claimed address is told it can claim in the same epoch (the >= vs > mutant); body:\n%s", body)
	}

	body, resp = getPage(t, ts.URL+"/faucet?address="+bob.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /faucet?address=bob = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "can claim in epoch 1") {
		t.Errorf("the fresh address is not told it can claim in epoch 1; body:\n%s", body)
	}
	if !strings.Contains(body, "b10coin claim --node "+ts.URL+" --key") {
		t.Errorf("the fresh address is not handed the command that claims; body:\n%s", body)
	}
	if strings.Contains(body, "already claimed") {
		t.Errorf("the fresh address is told it already claimed; body:\n%s", body)
	}
}

// The page must derive the epoch of the block that will APPLY a claim, not the
// head's epoch: claimWithKey does (height+1)/EpochBlocks+1, and the state
// machine compares against that block's epoch. At head 1 with two-block epochs,
// the head sits in epoch 1 but block 2 - the block a submitted claim would
// execute in - is epoch 2, so a key that claimed in epoch 1 is eligible again.
// A page using height/EpochBlocks+1 would refuse it.
func TestFaucetPageDerivesTheEpochOfTheApplyingBlock(t *testing.T) {
	g := *genesis.Devnet()
	g.Params.EpochBlocks = 2
	g.Params.ClaimAmountSparks = 1_000 // the faucet's emission covers it
	c, ts := pageServer(t, &g)
	alice := claimIntoBlock(t, c) // block 1 executes epoch 1
	if c.Height() != 1 {
		t.Fatalf("height = %d, want 1", c.Height())
	}
	body, resp := getPage(t, ts.URL+"/faucet?address="+alice.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /faucet = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "can claim in epoch 2") {
		t.Errorf("the page did not derive epoch 2 for the block that will apply the claim; body:\n%s", body)
	}
	if strings.Contains(body, "already claimed") {
		t.Errorf("a key eligible in epoch 2 is refused because the page used the head's epoch; body:\n%s", body)
	}
}

// A secret pasted into the address field is refused BY NAME and never echoed.
// The refusal is a 200 with a sentence, because a form error is still a usable
// page; what it must not be is a page that repeats the secret back.
func TestFaucetPageRefusesAPrivateKeyInTheAddressField(t *testing.T) {
	_, ts := pageServer(t, genesis.Devnet())
	for _, tc := range []struct {
		name  string
		query string
		shape string
	}{
		{"private key", strings.Repeat("ab", 64), "128-hex-character private key"},
		{"public key", strings.Repeat("cd", 32), "64-hex-character public key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, resp := getPage(t, ts.URL+"/faucet?address="+tc.query)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET /faucet = %d, want 200", resp.StatusCode)
			}
			if !strings.Contains(body, "never paste a key") {
				t.Errorf("the refusal does not say never to paste a key; body:\n%s", body)
			}
			if !strings.Contains(body, tc.shape) {
				t.Errorf("the refusal does not name %q; body:\n%s", tc.shape, body)
			}
			if strings.Contains(body, tc.query) || strings.Contains(body, tc.query[:16]) {
				t.Errorf("the page echoed the pasted secret: the refusal must never render it; body:\n%s", body)
			}
		})
	}
}

// The page is read-only: it is not a submit path, and its body has no POST form
// and no reference to the transaction endpoint at all.
func TestFaucetPageIsReadOnly(t *testing.T) {
	_, ts := pageServer(t, genesis.Devnet())
	resp, err := http.Post(ts.URL+"/faucet", "application/x-www-form-urlencoded", strings.NewReader("address=b10"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /faucet = %d, want 405", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); !strings.Contains(allow, http.MethodGet) {
		t.Errorf("POST /faucet Allow = %q, want it to name GET", allow)
	}

	body, _ := getPage(t, ts.URL+"/faucet")
	lower := strings.ToLower(body)
	for _, banned := range []string{`method="post"`, `method='post'`, "/tx", `action="http`} {
		if strings.Contains(lower, banned) {
			t.Errorf("the page contains %q: it must have no path to submit a transaction", banned)
		}
	}
}

// Every value the page renders comes from the template; this feeds a value that
// would break out of an unescaped context and asserts it arrives escaped.
func TestThePagesEscapeEveryValueTheyRender(t *testing.T) {
	_, ts := pageServer(t, genesis.Devnet())
	raw := `"><script>alert(1)</script>`
	body, resp := getPage(t, ts.URL+"/faucet?address="+url.QueryEscape(raw))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /faucet = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "not a canonical b10 address") {
		t.Errorf("the hostile query was not refused as an address; body:\n%s", body)
	}
	if strings.Contains(body, "<script") {
		t.Errorf("the page rendered an unescaped script tag; body:\n%s", body)
	}
	if strings.Contains(body, raw) {
		t.Errorf("the page echoed the query unescaped; body:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script") {
		t.Errorf("the query was not rendered escaped (it should appear as &lt;script...); body:\n%s", body)
	}
}

// Rendering during appends must never produce a partial document: the view is a
// snapshot taken under one lock and the template is executed into a buffer.
func TestFaucetPageIsSafeDuringAppends(t *testing.T) {
	c, ts := pageServer(t, genesis.Devnet())
	_, priv := genesis.DevValidatorKey()
	done := make(chan struct{})
	fail := make(chan string, 1)
	go func() {
		defer close(done)
		for i := 0; i < 40; i++ {
			resp, err := http.Get(ts.URL + "/faucet")
			if err != nil {
				fail <- fmt.Sprintf("GET /faucet during an append: %v", err)
				return
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				fail <- fmt.Sprintf("read /faucet during an append: %v", err)
				return
			}
			if resp.StatusCode != http.StatusOK {
				fail <- fmt.Sprintf("GET /faucet during an append = %d, want 200", resp.StatusCode)
				return
			}
			if !strings.HasSuffix(strings.TrimSpace(string(body)), "</html>") {
				fail <- "the page was written partially: the body does not end with </html>"
				return
			}
			if !strings.Contains(string(body), "100000000 sparks") {
				fail <- "the page lost the claim amount during an append"
				return
			}
		}
	}()
	for i := 0; i < 40; i++ {
		// Strictly after the parent, as chain.Append requires; the test is
		// about concurrent reads during appends, not about timestamps.
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

// The claim amount is NOT a constant: it is the chain parameter /status reports
// as claim_amount_sparks, and changing it changes both in step. This is the
// page's half of the one-source-of-truth rule Task 0 established.
func TestFaucetPageClaimAmountComesFromStatusNotAConstant(t *testing.T) {
	g := *genesis.Devnet()
	g.Params.ClaimAmountSparks = 7*genesis.SparksPerB10 + 3 // 700000003 sparks
	_, ts := pageServer(t, &g)

	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.ClaimAmountSparks != g.Params.ClaimAmountSparks {
		t.Fatalf("/status claim_amount_sparks = %d, want %d", st.ClaimAmountSparks, g.Params.ClaimAmountSparks)
	}

	body, _ := getPage(t, ts.URL+"/faucet")
	if want := strconv.FormatUint(st.ClaimAmountSparks, 10) + " sparks"; !strings.Contains(body, want) {
		t.Errorf("the page does not show the /status claim amount %q; body:\n%s", want, body)
	}
	if !strings.Contains(body, "7.00000003 b10") {
		t.Errorf("the page does not show the same amount in b10; body:\n%s", body)
	}
	if devnet := strconv.FormatUint(genesis.Devnet().Params.ClaimAmountSparks, 10) + " sparks"; strings.Contains(body, devnet) {
		t.Errorf("the page still shows the devnet default %q: the amount is hardcoded", devnet)
	}
}

// The page is a handler on the node's EXISTING server. Every read route is
// reached through one listener and one mux; the page added a pattern, not a
// server.
func TestTheFaucetPageSharesTheNodesOneServer(t *testing.T) {
	devPub, _ := genesis.DevAccountKey(0)
	_, ts := pageServer(t, genesis.Devnet())
	for _, path := range []string{"/status", "/block/0", "/account/" + types.AddressFromPub(devPub).String(), "/faucet"} {
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

// This is the "no solve, no sign" pin, made structural: the package that
// renders the page cannot import the solver, the signer or the keystore, and
// the page's own file cannot call the mempool, make an outbound request or
// start a listener. Adding "just a small helper" that solves a puzzle for a
// visitor fails here rather than shipping a free-claim oracle.
func TestTheFaucetPageCannotSolveSignOrSubmit(t *testing.T) {
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
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			for _, banned := range []string{"internal/faucet", "internal/crypto", "internal/keystore"} {
				if strings.Contains(p, banned) {
					t.Errorf("%s imports %s: the RPC read surface must not be able to solve, sign or hold a key", path, p)
				}
			}
		}
		// Calls no file in this package may make: a solver, a signer, a key
		// loader, or a second listener.
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
			case "Solve", "SolveClaim", "Sign", "IDKey", "ParsePrivateKey",
				"Listen", "ListenAndServe", "ListenAndServeTLS":
				t.Errorf("%s calls %s: the page is a read surface, not a solver, signer or listener", fset.Position(call.Pos()), name)
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "template" {
					switch sel.Sel.Name {
					case "HTML", "HTMLAttr", "JS", "URL", "CSS", "Srcset":
						t.Errorf("%s uses template.%s: every value is escaped by construction", fset.Position(call.Pos()), sel.Sel.Name)
					}
				}
			}
			return true
		})
		// The page's own file: no submission and no outbound request.
		if path == "web.go" {
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
				case "Add", "Post", "PostForm", "NewRequest", "Do":
					t.Errorf("%s calls %s: the faucet page must not submit anything", fset.Position(call.Pos()), name)
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("no production source files were checked - the glob found only tests, so this property was not verified")
	}

	// And the template itself: no script, no POST, no submit target, no inline
	// handler, no external asset.
	raw, err := os.ReadFile(filepath.Join("templates", "faucet.html"))
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, banned := range []string{"<script", `method="post"`, `method='post'`, "/tx", `src=`, "@import"} {
		if strings.Contains(lower, banned) {
			t.Errorf("templates/faucet.html contains %q: the page is one document with no script, no submit and no external asset", banned)
		}
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(string(raw)) {
		t.Error("templates/faucet.html contains an inline event handler; CSP forbids scripts and the page must not need one")
	}
}
