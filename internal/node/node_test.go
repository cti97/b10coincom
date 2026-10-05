package node

import (
	"errors"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

func TestRunOnceProducesAndAppends(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	n := New(c, priv, mempool.New(100, c.Genesis().Hash(), c.AdmissionHead))
	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if b.Header.Height != 1 {
		t.Fatalf("height = %d, want 1", b.Header.Height)
	}
	if c.Height() != 1 {
		t.Fatalf("chain height = %d, want 1", c.Height())
	}
}

func TestRunOnceIncludesMempoolTransactions(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	// Build a signed transfer from devnet dev account 0 to account 1.
	fromPub, fromPriv := genesis.DevAccountKey(0)
	toPub, _ := genesis.DevAccountKey(1)
	from := types.AddressFromPub(fromPub)
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  c.State().Get(from).Nonce,
		Fee:    c.Genesis().Params.MinFeeSparks,
		To:     types.AddressFromPub(toPub),
		Amount: 10 * genesis.SparksPerB10,
	}
	sigHash := tx.SigningHash(c.Genesis().Hash())
	tx.Sig = crypto.Sign(fromPriv, sigHash[:])

	mp := mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)
	if err := mp.Add([]types.Tx{*tx})[0]; err != nil {
		t.Fatalf("mempool.Add: %v", err)
	}
	if mp.Len() != 1 {
		t.Fatalf("mempool length = %d, want 1", mp.Len())
	}

	n := New(c, priv, mp)
	before := c.State().Get(types.AddressFromPub(toPub)).Balance

	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(b.Txs) != 1 {
		t.Fatalf("block contains %d txs, want 1", len(b.Txs))
	}
	if got := c.State().Get(types.AddressFromPub(toPub)).Balance; got != before+10*genesis.SparksPerB10 {
		t.Fatalf("recipient balance = %d, want %d", got, before+10*genesis.SparksPerB10)
	}
	if mp.Len() != 0 {
		t.Fatalf("mempool should be drained, length = %d", mp.Len())
	}
}

func mkTransfer(t *testing.T, nonce uint64) types.Tx {
	t.Helper()
	fromPub, fromPriv := genesis.DevAccountKey(0)
	toPub, _ := genesis.DevAccountKey(1)
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   types.AddressFromPub(fromPub),
		PubKey: fromPub,
		Nonce:  nonce,
		Fee:    1, // mkTransfer's callers open devnet chains, whose minimum is 1
		To:     types.AddressFromPub(toPub),
		Amount: 1,
	}
	sigHash := tx.SigningHash(genesis.Devnet().Hash())
	tx.Sig = crypto.Sign(fromPriv, sigHash[:])
	return *tx
}

// One state-invalid transaction must not discard the valid ones in its batch
// or wedge the node. Take has already drained the mempool, so a transaction
// dropped here is gone forever.
func TestRunOnceEvictsOnlyInvalidTransactions(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()
	mp := mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)

	good := mkTransfer(t, 0)
	bad := mkTransfer(t, 99) // valid signature, impossible nonce
	for i, e := range mp.Add([]types.Tx{good, bad}) {
		if e != nil {
			t.Fatalf("mempool.Add[%d]: %v", i, e)
		}
	}

	n := New(c, priv, mp)
	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(b.Txs) != 1 {
		t.Fatalf("block contains %d transactions, want 1 (the valid one)", len(b.Txs))
	}
	if b.Txs[0].ID() != good.ID() {
		t.Fatal("the wrong transaction was included")
	}
	if mp.Len() != 0 {
		t.Fatalf("mempool length = %d, want 0 (the invalid transaction was evicted)", mp.Len())
	}
	if c.Height() != 1 {
		t.Fatalf("chain height = %d, want 1", c.Height())
	}
}

// A VALID claim must survive the mempool probe and reach a block. The probe
// must mirror the transition a block at head+1 runs: this claim is payable
// ONLY once block 1's emission is credited (the faucet's genesis mint of 50M
// is below the devnet's 100M claim amount), so the old clone-and-apply probe
// that skipped the emission evicted it and the claim was silently dropped.
func TestRunOnceKeepsAValidClaim(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	pub, key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := c.Genesis().Params
	pow, ok := faucet.SolveClaim(pub, 1, p.FaucetPowTarget, p.FaucetPowArgon2, 1<<24)
	if !ok {
		t.Fatal("could not solve the test puzzle")
	}
	claim := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: 0, Epoch: 1, PowNonce: pow}
	sigHash := claim.SigningHash(c.Genesis().Hash())
	claim.Sig = crypto.Sign(key, sigHash[:])

	// Fixture guard: the claim must NEED the block's own emission, so this
	// test discriminates the mirrored probe from a pre-emission one.
	faucet := c.Genesis().FaucetAddress()
	if c.State().Get(faucet).Balance >= p.ClaimAmountSparks {
		t.Fatalf("fixture error: the faucet already holds %d; the claim no longer needs block 1's emission", c.State().Get(faucet).Balance)
	}

	mp := mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)
	if err := mp.Add([]types.Tx{*claim})[0]; err != nil {
		t.Fatalf("mempool.Add: %v", err)
	}

	n := New(c, priv, mp)
	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(b.Txs) != 1 || b.Txs[0].ID() != claim.ID() {
		t.Fatalf("the valid claim did not survive the probe: block carries %d txs (want the claim)", len(b.Txs))
	}
	if mp.Len() != 0 {
		t.Fatalf("mempool length = %d, want 0", mp.Len())
	}
	if got := c.State().Get(types.AddressFromPub(pub)).Balance; got != p.ClaimAmountSparks {
		t.Fatalf("claimant balance = %d, want %d - the claim was not paid", got, p.ClaimAmountSparks)
	}
}

// The probe's filter is CUMULATIVE: each accepted transaction feeds the
// running state the next probe starts from, so two transfers that only chain
// onto each other (same account, nonces 0 and 1) are BOTH kept. Probing each
// candidate against the bare head state would evict the second.
func TestRunOnceProbeFeedsAcceptedTransactionsForward(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()
	mp := mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)

	first, second := mkTransfer(t, 0), mkTransfer(t, 1)
	for i, e := range mp.Add([]types.Tx{first, second}) {
		if e != nil {
			t.Fatalf("mempool.Add[%d]: %v", i, e)
		}
	}

	n := New(c, priv, mp)
	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(b.Txs) != 2 {
		t.Fatalf("block contains %d transactions, want 2 (the chained pair)", len(b.Txs))
	}
	if mp.Len() != 0 {
		t.Fatalf("mempool length = %d, want 0", mp.Len())
	}
}

// A client can re-submit a transaction between Take and a failed block's
// re-add; Mempool.Add then reports ErrDuplicate. That transaction is not
// lost — it is already queued for a later block — so it must not inflate
// the lost count or appear in the lost list.
// devnetHead opens a throwaway devnet chain only to supply the head-state view
// the pool's stateful admission requires. Pools in this file's fixtures are
// otherwise chain-free.
func devnetHead(t *testing.T) mempool.HeadView {
	t.Helper()
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c.AdmissionHead
}

func TestReAddDoesNotCountDuplicatesAsLost(t *testing.T) {
	mp := mempool.New(10, genesis.Devnet().Hash(), devnetHead(t))
	tx := mkTransfer(t, 0)
	if err := mp.Add([]types.Tx{tx})[0]; err != nil {
		t.Fatalf("mempool.Add: %v", err)
	}
	// The scenario only exercises the duplicate path if the transaction is
	// genuinely already present. Assert that, or this test decays into a
	// no-op if mempool dedup ever changes.
	if err := mp.Add([]types.Tx{tx})[0]; !errors.Is(err, mempool.ErrDuplicate) {
		t.Fatalf("precondition: expected ErrDuplicate re-adding an already-present transaction, got %v", err)
	}
	// The same transaction again (deterministic devnet keys: identical ID).
	cause := errors.New("block build failed: test cause")
	err := reAdd(mp, []types.Tx{mkTransfer(t, 0)}, cause)
	if !errors.Is(err, cause) {
		t.Fatalf("expected the cause returned unchanged, got %v", err)
	}
	if strings.Contains(err.Error(), "are lost") {
		t.Fatalf("an already-present transaction was reported as lost: %v", err)
	}
}

// A genuine re-add failure (a full mempool) still strands the transaction
// and must be surfaced: cause kept, count and reasons wrapped with exactly
// one %w so errors.Is keeps working.
func TestReAddCountsRealFailuresAsLost(t *testing.T) {
	mp := mempool.New(1, genesis.Devnet().Hash(), devnetHead(t))
	if err := mp.Add([]types.Tx{mkTransfer(t, 0)})[0]; err != nil {
		t.Fatalf("mempool.Add: %v", err)
	}
	cause := errors.New("block append failed: test cause")
	err := reAdd(mp, []types.Tx{mkTransfer(t, 1)}, cause) // mempool is full
	if !errors.Is(err, cause) {
		t.Fatalf("expected the original cause to stay wrapped, got %v", err)
	}
	if !strings.Contains(err.Error(), "1 of 1 valid transactions could not be re-added to the mempool and are lost") {
		t.Fatalf("expected the stranded transaction to be reported as lost, got %v", err)
	}
}
