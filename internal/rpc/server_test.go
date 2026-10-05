package rpc

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	s := NewServer(c, mempool.New(100, c.Genesis().Hash()))
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
	ts := httptest.NewServer(NewServer(c, mempool.New(100, c.Genesis().Hash())).Handler())
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
