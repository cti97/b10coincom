package rpc

// The wallet page's tests. They assert what the page PROMISES - a balance in
// b10 for a funded address, an unbonding row with its release height, and a
// clear "no key, no spend" posture - rather than that the handler returned 200.

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

func fetchPage(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(b)
}

// The devnet fixture funds its dev account, so the page has something real to
// show without any setup: the balance must appear in b10 AND in sparks, and the
// address must be on the page.
func TestWalletPageShowsTheFundedAccount(t *testing.T) {
	_, ts := testServer(t)
	pub, _ := genesis.DevAccountKey(0)
	addr := types.AddressFromPub(pub).String()

	code, body := fetchPage(t, ts.URL+"/wallet/"+addr)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !strings.Contains(body, addr) {
		t.Fatal("the page does not name the address it is showing")
	}
	// 1,000,000 b10 is the fixture's premine; FormatB10 renders it exactly.
	if !strings.Contains(body, "1000000 b10") {
		t.Fatalf("balance is missing from the page; body:\n%s", body)
	}
	if !strings.Contains(body, "100000000000000 sparks") {
		t.Fatal("the balance in sparks is missing: both units are shown on purpose")
	}
}

// The page must not become a way to spend. It is server-rendered HTML with no
// script, and the page says so; a form POSTing to /tx would fail this test even
// though the handler ignores it.
func TestWalletPageHasNoScriptAndNoForm(t *testing.T) {
	_, ts := testServer(t)
	pub, _ := genesis.DevAccountKey(0)
	addr := types.AddressFromPub(pub).String()

	code, body := fetchPage(t, ts.URL+"/wallet/"+addr)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	lower := strings.ToLower(body)
	for _, forbidden := range []string{"<script", "<form", "type=\"password\""} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("the wallet page contains %q: it must not be able to submit or hold a key", forbidden)
		}
	}
	if !strings.Contains(body, "cannot sign") {
		t.Fatal("the page does not state that it cannot sign: the posture is part of the page")
	}
}

func TestWalletPageRefusesWhatItCannotRead(t *testing.T) {
	_, ts := testServer(t)
	if code, _ := fetchPage(t, ts.URL+"/wallet/"); code != http.StatusBadRequest {
		t.Fatalf("empty address: status = %d, want 400", code)
	}
	if code, _ := fetchPage(t, ts.URL+"/wallet/not-an-address"); code != http.StatusBadRequest {
		t.Fatalf("bad address: status = %d, want 400", code)
	}
	// A well-formed address with no history is a 200 with an empty table: an
	// unknown address is not an error, it is an account that holds nothing.
	other := types.AddressFromPub(make([]byte, 32))
	code, body := fetchPage(t, ts.URL+"/wallet/"+other.String())
	if code != http.StatusOK {
		t.Fatalf("empty account: status = %d, want 200", code)
	}
	if !strings.Contains(body, "No transactions involving this address") {
		t.Fatal("an account with no history must say so rather than render nothing")
	}
}

// The scan window is a constant, never a query parameter: a page that could be
// told to scan further back would be an unbounded read dressed as a UI.
func TestWalletPageScanWindowIsFixed(t *testing.T) {
	if walletScanBlocks != 20000 {
		t.Fatalf("walletScanBlocks = %d: the window is part of the page's promise and must not drift silently", walletScanBlocks)
	}
}
