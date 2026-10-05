package rpc

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s := NewServer(c, mempool.New(100, c.Genesis().Hash(), c.AdmissionHead))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func TestStatusEndpoint(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ChainID != "b10coin-devnet-1" {
		t.Fatalf("chain ID = %q", body.ChainID)
	}
	if body.Height != 0 {
		t.Fatalf("height = %d, want 0", body.Height)
	}
}

func TestBlockEndpointReturnsGenesis(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/block/0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var b blockResponse
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	if b.Height != 0 {
		t.Fatalf("height = %d, want 0", b.Height)
	}
}

func TestBlockEndpointRejectsMissingHeight(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/block/99")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestTxEndpointRejectsGarbage(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Post(ts.URL+"/tx", "text/plain", strings.NewReader("not-hex"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// buildSignedTx returns a valid transfer signed by a fresh key. The RPC
// endpoint only decodes a transaction and verifies its signature - it never
// checks balances - so an unfunded key is sufficient here.
func buildSignedTx(t *testing.T) *types.Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, otherPub, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   types.AddressFromPub(pub),
		PubKey: pub,
		Nonce:  0,
		Fee:    1,
		To:     types.AddressFromPub(otherPub),
		Amount: 1,
	}
	sigHash := tx.SigningHash(genesis.Devnet().Hash())
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return tx
}

func TestTxEndpointAcceptsValidTx(t *testing.T) {
	_, ts := testServer(t)
	enc := hex.EncodeToString(buildSignedTx(t).Encode())
	resp, err := http.Post(ts.URL+"/tx", "text/plain", strings.NewReader(enc))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := make([]byte, 256)
		n, _ := resp.Body.Read(buf)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, buf[:n])
	}
	// A 200 must mean the transaction was actually stored, not merely decoded.
	// A handler that returned 200 without mempool.Add would pass the status
	// check alone.
	status, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer status.Body.Close()
	var body statusResponse
	if err := json.NewDecoder(status.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Mempool != 1 {
		t.Fatalf("mempool holds %d transactions after a 200 POST, want 1", body.Mempool)
	}
}

// The RPC server reads the chain while the node loop appends to it. Run the
// suite with -race and this fails loudly if the guards are ever removed.
func TestRPCReadsAreSafeDuringAppends(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ts := httptest.NewServer(NewServer(c, mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)).Handler())
	defer ts.Close()
	_, priv := genesis.DevValidatorKey()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 80; i++ {
			resp, err := http.Get(ts.URL + "/status")
			if err == nil {
				resp.Body.Close()
			}
		}
	}()
	for i := 0; i < 80; i++ {
		b, err := c.Build(priv, nil, int64(1_700_000_000+i))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}

// Per-source /tx limiting (audit R-1). The clock is injected, so the test is a
// constructed state: no sleep, no kernel buffer, no timing race.
func TestTxEndpointRateLimitsOneSource(t *testing.T) {
	s, ts := testServer(t)
	fixed := time.Unix(1_700_000_000, 0)
	s.txLimiter.now = func() time.Time { return fixed }
	s.txLimiter.burst = 1
	s.txLimiter.rate = 0

	post := func() int {
		enc := hex.EncodeToString(buildSignedTx(t).Encode())
		resp, err := http.Post(ts.URL+"/tx", "text/plain", strings.NewReader(enc))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("first POST /tx = %d, want 200", code)
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("second POST /tx from one source with its burst spent = %d, want 429", code)
	}
	// Other endpoints are not rate limited by the /tx bucket.
	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /status after a rate-limited POST = %d, want 200", resp.StatusCode)
	}
}

func TestSourceLimiterIsPerSource(t *testing.T) {
	l := newSourceLimiter(1, 0, 8)
	l.now = func() time.Time { return time.Unix(0, 0) }
	if !l.allow("1.1.1.1") {
		t.Fatal("the first request from a source must be allowed")
	}
	if l.allow("1.1.1.1") {
		t.Fatal("a source with an empty bucket must be refused")
	}
	if !l.allow("2.2.2.2") {
		t.Fatal("a different source must have its own bucket")
	}
}

func TestSourceLimiterRefills(t *testing.T) {
	l := newSourceLimiter(1, 1, 8) // one token, refilled at one per second
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	if !l.allow("a") {
		t.Fatal("the first request must be allowed")
	}
	if l.allow("a") {
		t.Fatal("a source with an empty bucket must be refused")
	}
	now = now.Add(time.Second)
	if !l.allow("a") {
		t.Fatal("a token should have refilled after one second")
	}
}

func TestSourceLimiterBoundsItsMap(t *testing.T) {
	l := newSourceLimiter(10, 0, 3)
	l.now = func() time.Time { return time.Unix(0, 0) }
	for _, s := range []string{"a", "b", "c", "d", "e"} {
		l.allow(s)
	}
	if len(l.buckets) != 3 {
		t.Fatalf("limiter tracks %d sources, want the bound 3: an address-cycling attacker must not grow the map", len(l.buckets))
	}
}
