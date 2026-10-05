package mempool

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// testChain is the identifier the pool fixtures are built for: the pool and
// the transactions it admits must agree on it, and a fixed value keeps the
// fixtures independent of any chain package (mempool imports neither).
func testChain() [32]byte { return [32]byte{0x11, 0x22} }

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
	sigHash := tx.SigningHash(testChain())
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
	h := tx.SigningHash(testChain())
	tx.Sig = crypto.Sign(priv, h[:])
	return *tx
}

func TestMempoolAddAndTake(t *testing.T) {
	m := New(10, testChain())
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
	m := New(10, testChain())
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
	m := New(10, testChain())
	tx := mkTx(t, 0)
	tx.Sig[0] ^= 0xFF
	if err := m.Add([]types.Tx{tx})[0]; err == nil {
		t.Fatal("expected a bad signature to be rejected")
	}
}

func TestMempoolRespectsCapacity(t *testing.T) {
	m := New(2, testChain())
	_ = m.Add([]types.Tx{mkTx(t, 0), mkTx(t, 1), mkTx(t, 2)})
	if m.Len() > 2 {
		t.Fatalf("Len = %d exceeds capacity 2", m.Len())
	}
}

func TestMempoolRemove(t *testing.T) {
	m := New(10, testChain())
	tx := mkTx(t, 0)
	_ = m.Add([]types.Tx{tx})
	m.Remove(tx.ID())
	if m.Len() != 0 {
		t.Fatalf("Len = %d after Remove, want 0", m.Len())
	}
}

// TestTakeBoundsFaucetClaimsPerBlock below asserts claimsTaken <=
// MaxFaucetClaimsPerBlock - an inequality against the very constant it reads -
// so raising the constant to 50 or even 10,000 leaves that suite green while
// restoring the unbounded per-block verification the bound exists to prevent.
// The constant's smallness IS the mitigation, so the value itself must be
// pinned here. Why anything near 16 (or above) is not a bound: at the testnet
// tuning one claim costs ~0.125 s of Argon2id to verify and a block is targeted
// every 2 s, so 8 claims already cost ~1.0 s per block and 16 eat the whole
// interval - a higher value just scales the cost back up rather than capping
// it. Figures are Pi-4 estimates pending re-measurement (Testnet's tuning
// comment).
func TestMaxFaucetClaimsPerBlockIsActuallyABound(t *testing.T) {
	if MaxFaucetClaimsPerBlock > 16 {
		t.Fatalf("MaxFaucetClaimsPerBlock = %d - at ~0.125 s of Argon2id per claim against a 2 s block interval (Pi-4 estimate, pending re-measurement), a value this large no longer caps the per-block verification cost, which is the entire point of the bound",
			MaxFaucetClaimsPerBlock)
	}
}

// A mempool full of signature-valid faucet claims must not force the node to
// evaluate an unbounded number of Argon2id puzzles per block. At the testnet
// tuning one claim costs ~0.125 s of CPU (a Pi-4 estimate pending
// re-measurement), so the ten thousand a full node pool holds would cost ~21
// min of work per block; the pool must bound how many claims it will hand over.
func TestTakeBoundsFaucetClaimsPerBlock(t *testing.T) {
	m := New(1000, testChain())

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
			transfersTaken, len(transfers))
	}

	// The claims beyond the bound must be left in the pool for a later block,
	// not dropped: Take removes only what it returns, so the pool still holds
	// the remainder (and nothing else - every transfer was handed over).
	if want := len(claims) - claimsTaken; m.Len() != want {
		t.Fatalf("pool holds %d txs after Take, want %d - the claims past the bound must stay pending, not be dropped",
			m.Len(), want)
	}
	// Those held-back claims drain in insertion order at the bound's rate on
	// the next call, so a flood cannot starve them or jump the queue.
	again := m.Take(types.MaxTxsPerBlock)
	for i := range again {
		if again[i].Type != types.TxFaucetClaim {
			t.Fatalf("second Take returned a non-claim at [%d] - the remainder must be claims only", i)
		}
	}
	if len(again) != MaxFaucetClaimsPerBlock {
		t.Fatalf("second Take returned %d claims, want %d - the counter is per call and the remainder drains in order",
			len(again), MaxFaucetClaimsPerBlock)
	}
	if want := len(claims) - claimsTaken - MaxFaucetClaimsPerBlock; m.Len() != want {
		t.Fatalf("pool holds %d txs after the second Take, want %d", m.Len(), want)
	}
}
