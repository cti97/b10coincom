package mempool

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

func mkTx(t *testing.T, nonce uint64) types.Tx {
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
		Nonce:  nonce,
		To:     types.AddressFromPub(otherPub),
		Amount: 1,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return *tx
}

// mkClaim builds a faucet claim with a real signature but a garbage proof-of-work
// nonce. The mempool checks only signatures, so this is exactly what a spammer can
// produce for the cost of one Ed25519 signature - which is the asymmetry the bound
// in this task exists to neutralise.
func mkClaim(t *testing.T, nonce uint64) types.Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Tx{
		Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: nonce, Epoch: 1, PowNonce: 0,
	}
	h := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, h[:])
	return *tx
}

func TestMempoolAddAndTake(t *testing.T) {
	m := New(10)
	errs := m.Add([]types.Tx{mkTx(t, 0), mkTx(t, 1)})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
	}
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
	got := m.Take(10)
	if len(got) != 2 {
		t.Fatalf("Take returned %d txs, want 2", len(got))
	}
	if m.Len() != 0 {
		t.Fatalf("Take must drain; Len = %d", m.Len())
	}
}

func TestMempoolDeduplicates(t *testing.T) {
	m := New(10)
	tx := mkTx(t, 0)
	if err := m.Add([]types.Tx{tx})[0]; err != nil {
		t.Fatal(err)
	}
	if err := m.Add([]types.Tx{tx})[0]; err == nil {
		t.Fatal("expected a duplicate to be rejected")
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d, want 1", m.Len())
	}
}

func TestMempoolRejectsBadSignature(t *testing.T) {
	m := New(10)
	tx := mkTx(t, 0)
	tx.Sig[0] ^= 0xFF
	if err := m.Add([]types.Tx{tx})[0]; err == nil {
		t.Fatal("expected a bad signature to be rejected")
	}
}

func TestMempoolRespectsCapacity(t *testing.T) {
	m := New(2)
	_ = m.Add([]types.Tx{mkTx(t, 0), mkTx(t, 1), mkTx(t, 2)})
	if m.Len() > 2 {
		t.Fatalf("Len = %d exceeds capacity 2", m.Len())
	}
}

func TestMempoolRemove(t *testing.T) {
	m := New(10)
	tx := mkTx(t, 0)
	_ = m.Add([]types.Tx{tx})
	m.Remove(tx.ID())
	if m.Len() != 0 {
		t.Fatalf("Len = %d after Remove, want 0", m.Len())
	}
}

// A mempool full of signature-valid faucet claims must not force the node to
// evaluate an unbounded number of Argon2id puzzles per block. At the testnet
// tuning one claim costs ~3 s of CPU, so ten thousand of them would stall block
// production for hours; the pool must bound how many claims it will hand over.
func TestTakeBoundsFaucetClaimsPerBlock(t *testing.T) {
	m := New(1000)

	// Fill the pool with claims, which are validly signed but carry no evidence
	// that their puzzle was actually solved.
	var claims []types.Tx
	for i := 0; i < 50; i++ {
		claims = append(claims, mkClaim(t, uint64(i)))
	}
	for i, err := range m.Add(claims) {
		if err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
	}
	// Plus ordinary transfers, which are cheap to validate.
	var transfers []types.Tx
	for i := 0; i < 20; i++ {
		transfers = append(transfers, mkTx(t, uint64(i)))
	}
	for i, err := range m.Add(transfers) {
		if err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
	}

	got := m.Take(types.MaxTxsPerBlock)
	var claimsTaken, transfersTaken int
	for i := range got {
		if got[i].Type == types.TxFaucetClaim {
			claimsTaken++
		} else {
			transfersTaken++
		}
	}
	if claimsTaken > MaxFaucetClaimsPerBlock {
		t.Fatalf("handed over %d faucet claims in one block, want at most %d - each costs a full Argon2id evaluation",
			claimsTaken, MaxFaucetClaimsPerBlock)
	}
	if transfersTaken != len(transfers) {
		t.Fatalf("bounded %d cheap transfers out of %d - the bound must apply to claims only",
			len(transfers), len(transfers))
	}
}
