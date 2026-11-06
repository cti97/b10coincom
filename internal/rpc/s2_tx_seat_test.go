package rpc

import (
	"encoding/hex"
	"encoding/json"
	"io"
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

// Testrun S-2: transactions are not gossiped. A proposal is built from the
// LOCAL mempool (consensus.Driver.build), so a transaction reaches a block only
// through the node it was posted to, and only in a round where that node is the
// proposer. On a node whose key holds no seat the pool never feeds a block, so
// POST /tx must say so rather than answering a bare txid that reads as a
// promise.
//
// These tests CONSTRUCT that state: a chain, a mempool, and a server whose
// signing key is not in the committee. No timing, no network, no rotation.

// txServerWithSigningKey builds a one-seat devnet chain and a server that signs
// with seatKey, so a test can choose a key that holds a seat and one that does
// not.
func txServerWithSigningKey(t *testing.T, g *genesis.Genesis, seatKey []byte) (srv *Server, ts *httptest.Server) {
	t.Helper()
	c, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s := NewServerWithSigningKey(c, mempool.New(100, c.Genesis().Hash(), c.AdmissionHead), seatKey)
	ts = httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

// signedTransfer signs a transfer over g's genesis hash. The endpoint verifies
// the signature against the chain's own hash, so the transaction is valid for
// the chain it is posted to and for no other.
func signedTransfer(t *testing.T, g *genesis.Genesis) *types.Tx {
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
	sigHash := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return tx
}

// postTx posts a signed transaction and decodes the reply body verbatim, so a
// test sees the wire shape a client sees (including a field being absent). The
// raw body is returned as well so a test can log exactly what the node said.
func postTx(t *testing.T, url string, tx *types.Tx) (code int, fields map[string]any, raw string) {
	t.Helper()
	resp, err := http.Post(url+"/tx", "text/plain", strings.NewReader(hex.EncodeToString(tx.Encode())))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatalf("the reply is not a JSON object: %s", body)
	}
	return resp.StatusCode, fields, strings.TrimSpace(string(body))
}

func TestPostTxOnAnUnseatedNodeSaysTheTransactionWillNotBeIncluded(t *testing.T) {
	// A key that is nothing to do with the devnet committee: this node signs
	// blocks with it, and it holds no seat.
	foreign, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, ts := txServerWithSigningKey(t, genesis.Devnet(), foreign)

	code, body, raw := postTx(t, ts.URL, signedTransfer(t, genesis.Devnet()))
	t.Logf("an unseated node's POST /tx reply: %s", raw)
	// 200, not a refusal: the transaction WAS admitted, and the reply must not
	// tell the client its bytes were wrong (S-2's decision record).
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the transaction was admitted; only its prospects are nil)", code)
	}
	if !validHexTxID(body["txid"]) {
		t.Fatalf("txid = %v, want 64 lowercase hex characters", body["txid"])
	}
	seated, ok := body["seated"]
	if !ok {
		t.Fatal("the reply carries no seated field: a client cannot tell that this node holds no seat")
	}
	if seated != false {
		t.Fatalf("seated = %v, want false (the signing key is not in the committee)", seated)
	}
	warning, _ := body["warning"].(string)
	// The height is the one a transaction posted now would be carried at:
	// head is 0, so the next block is height 1.
	for _, want := range []string{
		"no committee seat at height 1",
		"will not propose a block",
		"parked in this node's mempool",
		"post the same bytes to a node that holds a seat",
	} {
		if !strings.Contains(warning, want) {
			t.Errorf("the warning does not contain %q:\n%s", want, warning)
		}
	}
}

func TestPostTxOnASeatedNodeCarriesNoWarning(t *testing.T) {
	// The devnet genesis seats exactly this key, so a transaction posted here
	// can be proposed by this node. This is the case that must NOT regress into
	// a warning: every honest single-node run is this case.
	pub, _ := genesis.DevValidatorKey()
	_, ts := txServerWithSigningKey(t, genesis.Devnet(), pub)

	code, body, raw := postTx(t, ts.URL, signedTransfer(t, genesis.Devnet()))
	t.Logf("a seated node's POST /tx reply: %s", raw)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body["seated"] != true {
		t.Fatalf("seated = %v, want true for the genesis seat", body["seated"])
	}
	if w, ok := body["warning"]; ok {
		t.Fatalf("a seated node's reply carries a warning %q: the operator would be told to repost a transaction this node will include", w)
	}
}

func TestPostTxOnAChainThatSeatsNoCommitteeNamesThatAndNotTheKey(t *testing.T) {
	// The testnet genesis lists no validators, so no committee can be derived
	// at any height. That is a different fact from "your key is not seated",
	// and the reply must not blame the key: IsSeatedAt answers false for both,
	// and CommitteeAt is what tells them apart.
	anyKey, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	g := genesis.Testnet()
	_, ts := txServerWithSigningKey(t, g, anyKey)

	code, body, _ := postTx(t, ts.URL, signedTransfer(t, g))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	warning, _ := body["warning"].(string)
	if !strings.Contains(warning, "cannot derive the committee") {
		t.Errorf("the warning does not say the chain seats no committee at all:\n%s", warning)
	}
	if strings.Contains(warning, "holds no committee seat") {
		t.Errorf("the warning blames this node's key for a chain that has no committee:\n%s", warning)
	}
}

func TestPostTxWithoutASigningKeySaysNothingAboutSeats(t *testing.T) {
	// A server built by NewServer (a test, an embedded reader) has no signing
	// key, so it must answer the M5 shape exactly: no seat claim it cannot
	// support either way.
	_, ts := testServer(t)

	code, body, _ := postTx(t, ts.URL, signedTransfer(t, genesis.Devnet()))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if _, ok := body["seated"]; ok {
		t.Fatalf("a server with no signing key reported seated = %v", body["seated"])
	}
	if _, ok := body["warning"]; ok {
		t.Fatalf("a server with no signing key reported a warning %q", body["warning"])
	}
}

func validHexTxID(v any) bool {
	s, ok := v.(string)
	if !ok || len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
