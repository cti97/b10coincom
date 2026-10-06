package mempool

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// testChain is the identifier the pool fixtures are built for: the pool and
// the transactions it admits must agree on it, and a fixed value keeps the
// fixtures independent of any chain package (mempool imports neither).
func testChain() [32]byte { return [32]byte{0x11, 0x22} }

// testArgon2 is a trivial Argon2id tuning so the mempool suite solves claims in
// milliseconds. It is the DEVNET shape (64 KiB, one pass), not the testnet one.
var testArgon2 = faucet.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1}

// testPowTarget accepts roughly one digest in two (0x7F then all ones), the
// devnet shape, so a solve takes a couple of Argon2id evaluations.
func testPowTarget() [32]byte {
	var t [32]byte
	for i := range t {
		t[i] = 0xFF
	}
	t[0] = 0x7F
	return t
}

const testEpochBlocks = 1000

// testState is the head the pool admits against. It is constructed, never
// provoked: tests set exactly the accounts they need. EpochBlocks is non-zero
// so claim epochs are usable.
func testState() *state.State {
	return state.NewWithParams(state.Params{
		EpochBlocks: testEpochBlocks,
		PowArgon2:   testArgon2,
		PowTarget:   testPowTarget(),
	})
}

// testHead binds a state and a head height into the pool's HeadView.
func testHead(st *state.State, height uint64) HeadView {
	return func() (*state.State, uint64) { return st, height }
}

// allPassPreTarget is an outer target every digest meets. Tests that exercise
// the STATEFUL admission rules rather than the puzzle cost build their pool
// with it, so a claim needs only the Argon2id solution the state machine
// requires. The shipped target is pinned by
// TestDefaultPreTargetIsTheFaucetPolicy and exercised by the flood test.
func allPassPreTarget() [32]byte {
	var t [32]byte
	for i := range t {
		t[i] = 0xFF
	}
	return t
}

// newTestPool builds a pool with a permissive outer-puzzle target.
func newTestPool(t *testing.T, max int, st *state.State, height uint64) *Mempool {
	t.Helper()
	m := New(max, testChain(), testHead(st, height))
	m.preTarget = allPassPreTarget()
	return m
}

type testKey struct {
	pub  []byte
	priv []byte
	addr types.Address
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return testKey{pub: pub, priv: priv, addr: types.AddressFromPub(pub)}
}

func (k testKey) transfer(t *testing.T, to types.Address, nonce uint64) types.Tx {
	t.Helper()
	tx := &types.Tx{
		Type: types.TxTransfer, From: k.addr, PubKey: k.pub,
		Nonce: nonce, Fee: 1, To: to, Amount: 1,
	}
	h := tx.SigningHash(testChain())
	tx.Sig = crypto.Sign(k.priv, h[:])
	return *tx
}

// claim builds a signed claim with the given epoch and raw puzzle nonce. It
// does not solve anything: callers that need admission use argon2Claim (for a
// permissive pool) or solvedClaim (for the shipped outer target).
func (k testKey) claim(epoch, powNonce uint64) types.Tx {
	return k.claimNonce(epoch, powNonce, 0)
}

// claimNonce is claim with an explicit account nonce, for tests that need a
// second distinct transaction from one key.
func (k testKey) claimNonce(epoch, powNonce, nonce uint64) types.Tx {
	tx := &types.Tx{
		Type: types.TxFaucetClaim, From: k.addr, PubKey: k.pub,
		Nonce: nonce, Epoch: epoch, PowNonce: powNonce,
	}
	h := tx.SigningHash(testChain())
	tx.Sig = crypto.Sign(k.priv, h[:])
	return *tx
}

// argon2Claim solves only the real Argon2id puzzle. It is admissible into a
// pool built by newTestPool, whose outer target is permissive.
func (k testKey) argon2Claim(t *testing.T, epoch uint64) types.Tx {
	t.Helper()
	return k.argon2ClaimNonce(t, epoch, 0)
}

func (k testKey) argon2ClaimNonce(t *testing.T, epoch, nonce uint64) types.Tx {
	t.Helper()
	n, ok := faucet.Solve(k.pub, epoch, testPowTarget(), testArgon2, 1<<20)
	if !ok {
		t.Fatal("could not solve the Argon2id puzzle")
	}
	return k.claimNonce(epoch, n, nonce)
}

// solvedClaim solves BOTH the cheap outer puzzle and the Argon2id one, which is
// what a node's shipped mempool requires at admission (audit R-1).
func (k testKey) solvedClaim(t *testing.T, epoch uint64) types.Tx {
	t.Helper()
	n, ok := faucet.SolveClaim(k.pub, epoch, testPowTarget(), testArgon2, 1<<24)
	if !ok {
		t.Fatal("could not solve the cheap + Argon2id puzzle")
	}
	return k.claim(epoch, n)
}

// nonceFailingPre returns a nonce that does NOT solve the cheap outer puzzle
// for (pub, epoch). It is found by scanning, so the test is deterministic: it
// never depends on a random nonce happening to pass or fail.
func nonceFailingPre(t *testing.T, pub []byte, epoch uint64) uint64 {
	t.Helper()
	for n := uint64(0); n < 1_000_000; n++ {
		if !faucet.MeetsPreTarget(faucet.PreDigest(pub, epoch, n)) {
			return n
		}
	}
	t.Fatal("no nonce failed the cheap outer puzzle")
	return 0
}

func mustAdd(t *testing.T, m *Mempool, txs ...types.Tx) {
	t.Helper()
	for i, err := range m.Add(txs) {
		if err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
	}
}

func TestMempoolAddAndTake(t *testing.T) {
	st := testState()
	m := newTestPool(t, 10, st, 0)
	a, b := newTestKey(t), newTestKey(t)
	mustAdd(t, m, a.transfer(t, b.addr, 0), b.transfer(t, a.addr, 0))
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
	st := testState()
	m := newTestPool(t, 10, st, 0)
	a, b := newTestKey(t), newTestKey(t)
	tx := a.transfer(t, b.addr, 0)
	mustAdd(t, m, tx)
	if err := m.Add([]types.Tx{tx})[0]; !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d, want 1", m.Len())
	}
}

func TestMempoolRejectsBadSignature(t *testing.T) {
	st := testState()
	m := newTestPool(t, 10, st, 0)
	a, b := newTestKey(t), newTestKey(t)
	tx := a.transfer(t, b.addr, 0)
	tx.Sig[0] ^= 0xFF
	if err := m.Add([]types.Tx{tx})[0]; err == nil {
		t.Fatal("expected a bad signature to be rejected")
	}
}

func TestMempoolRespectsCapacity(t *testing.T) {
	st := testState()
	m := newTestPool(t, 2, st, 0)
	a, b := newTestKey(t), newTestKey(t)
	_ = m.Add([]types.Tx{a.transfer(t, b.addr, 0), a.transfer(t, b.addr, 1), a.transfer(t, b.addr, 2)})
	if m.Len() > 2 {
		t.Fatalf("Len = %d exceeds capacity 2", m.Len())
	}
}

func TestMempoolRemove(t *testing.T) {
	st := testState()
	m := newTestPool(t, 10, st, 0)
	a, b := newTestKey(t), newTestKey(t)
	tx := a.transfer(t, b.addr, 0)
	mustAdd(t, m, tx)
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
// pinned here.
func TestMaxFaucetClaimsPerBlockIsActuallyABound(t *testing.T) {
	if MaxFaucetClaimsPerBlock > 16 {
		t.Fatalf("MaxFaucetClaimsPerBlock = %d - at ~0.125 s of Argon2id per claim against a 2 s block interval (Pi-4 estimate, pending re-measurement), a value this large no longer caps the per-block verification cost, which is the entire point of the bound",
			MaxFaucetClaimsPerBlock)
	}
}

// A pool of ADMITTED claims must still hand over at most
// MaxFaucetClaimsPerBlock per block: each costs a full Argon2id evaluation, and
// Take is the one place the node's work per block is bounded.
func TestTakeBoundsFaucetClaimsPerBlock(t *testing.T) {
	m := newTestPool(t, 1000, testState(), 0)

	var claims []types.Tx
	for i := 0; i < 50; i++ {
		claims = append(claims, newTestKey(t).argon2Claim(t, 1))
	}
	mustAdd(t, m, claims...)

	// Plus ordinary transfers, which are cheap to validate.
	var transfers []types.Tx
	pair := newTestKey(t)
	for i := 0; i < 20; i++ {
		transfers = append(transfers, newTestKey(t).transfer(t, pair.addr, 0))
	}
	mustAdd(t, m, transfers...)

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

	// The claims beyond the bound stay in the pool for a later block (the
	// transfers drain immediately).
	if want := len(claims) - claimsTaken; m.Len() != want {
		t.Fatalf("pool holds %d txs after Take, want %d - claims past the bound must stay pending",
			m.Len(), want)
	}
	again := m.Take(types.MaxTxsPerBlock)
	if len(again) != MaxFaucetClaimsPerBlock {
		t.Fatalf("second Take returned %d claims, want %d - the remainder drains in order",
			len(again), MaxFaucetClaimsPerBlock)
	}
}

// THE R-1 regression (audit section 5): 10,000 garbage claims must not wedge
// the pool. Each is a fresh key, the current epoch and a nonce that does not
// solve the cheap outer puzzle - exactly the flood the audit describes, which
// used to cost one signature each and occupy the whole pool. Now each is
// rejected for the price of one BLAKE3 hash, and an honest transfer submitted
// afterwards is admitted.
func TestGarbageClaimFloodDoesNotWedgeThePool(t *testing.T) {
	m := New(1000, testChain(), testHead(testState(), 0))

	const flood = 10_000
	txs := make([]types.Tx, 0, flood)
	for i := 0; i < flood; i++ {
		k := newTestKey(t)
		txs = append(txs, k.claim(1, nonceFailingPre(t, k.pub, 1)))
	}
	for i, err := range m.Add(txs) {
		if !errors.Is(err, ErrBadPrePuzzle) {
			t.Fatalf("flood[%d]: err = %v, want ErrBadPrePuzzle (the cheap outer puzzle must reject it before anything else)", i, err)
		}
	}
	if m.Len() != 0 {
		t.Fatalf("the garbage flood left %d transactions in the pool, want 0", m.Len())
	}

	// The pool is untouched and an honest transfer is admitted immediately.
	honest := newTestKey(t)
	if err := m.Add([]types.Tx{honest.transfer(t, newTestKey(t).addr, 0)})[0]; err != nil {
		t.Fatalf("an honest transfer after a 10,000-claim flood was refused: %v", err)
	}
	if m.Len() != 1 {
		t.Fatalf("pool holds %d txs after the honest transfer, want 1", m.Len())
	}
}

// The shipped default is the faucet's cheap target, so tests that lower it for
// speed cannot silently ship a disabled filter.
func TestDefaultPreTargetIsTheFaucetPolicy(t *testing.T) {
	m := New(100, testChain(), testHead(testState(), 0))
	if m.preTarget != faucet.PreTarget() {
		t.Fatal("New did not install the faucet's cheap outer target")
	}
	k := newTestKey(t)
	if err := m.Add([]types.Tx{k.claim(1, nonceFailingPre(t, k.pub, 1))})[0]; !errors.Is(err, ErrBadPrePuzzle) {
		t.Fatalf("a claim with no outer solution: err = %v, want ErrBadPrePuzzle", err)
	}
	// And a solved claim IS admitted through the shipped target.
	mustAdd(t, m, newTestKey(t).solvedClaim(t, 1))
}

// A fresh flood must never displace an honest pending transaction. Nothing in
// Take or Add evicts to make room: when the claim sub-pool is full a new claim
// is REFUSED (ErrClaimPoolFull), and the honest claim keeps its slot and is
// taken first (insertion order).
func TestFreshFloodDoesNotEvictAnHonestPendingClaim(t *testing.T) {
	m := newTestPool(t, 1000, testState(), 0)

	honestKey := newTestKey(t)
	honest := honestKey.argon2Claim(t, 1)
	mustAdd(t, m, honest)
	for m.claims < MaxFaucetClaimsPerPool {
		mustAdd(t, m, newTestKey(t).argon2Claim(t, 1))
	}
	// The sub-pool is full: the fresh flood is refused, not substituted in.
	err := m.Add([]types.Tx{newTestKey(t).argon2Claim(t, 1)})[0]
	if !errors.Is(err, ErrClaimPoolFull) {
		t.Fatalf("a claim into a full claim sub-pool: err = %v, want ErrClaimPoolFull", err)
	}

	got := m.Take(types.MaxTxsPerBlock)
	if len(got) == 0 || got[0].ID() != honest.ID() {
		t.Fatalf("the honest pending claim was not the first one taken: got %d txs, first is honest = %v",
			len(got), len(got) > 0 && got[0].ID() == honest.ID())
	}
}

// Ageing drops only claims that Take has passed over MaxClaimAgeBlocks times.
// This constructs that state directly: with a one-transaction Take the queued
// claims are skipped repeatedly, and the ones past the age bound are gone while
// the earlier ones were taken. Without ageing the pool would still hold them.
func TestAgeingDropsClaimsTakeKeepsSkipping(t *testing.T) {
	m := newTestPool(t, 1000, testState(), 0)

	const queued = 40
	for i := 0; i < queued; i++ {
		mustAdd(t, m, newTestKey(t).argon2Claim(t, 1))
	}
	// Take(1) once per "block". The claim at the back is skipped on every call
	// until it reaches the front; after MaxClaimAgeBlocks skips it ages out.
	for i := 0; i <= MaxClaimAgeBlocks; i++ {
		m.Take(1)
	}
	if m.Len() != 0 {
		t.Fatalf("pool holds %d claims after %d one-claim Takes, want 0: claims skipped past MaxClaimAgeBlocks must age out",
			m.Len(), MaxClaimAgeBlocks+1)
	}
	if m.claims != 0 {
		t.Fatalf("claim bookkeeping = %d after ageing drained the pool, want 0", m.claims)
	}
	// The freed capacity is reusable.
	mustAdd(t, m, newTestKey(t).argon2Claim(t, 1))
	if m.Len() != 1 {
		t.Fatalf("a fresh claim could not use the capacity ageing freed: Len = %d", m.Len())
	}
}

// A claim is NOT evicted while it is still within its turn - a normal pool
// drains at MaxFaucetClaimsPerBlock per block, far faster than the age bound.
func TestAgeingDoesNotDropAClaimStillInItsTurn(t *testing.T) {
	m := newTestPool(t, 1000, testState(), 0)
	for i := 0; i < MaxFaucetClaimsPerPool; i++ {
		mustAdd(t, m, newTestKey(t).argon2Claim(t, 1))
	}
	m.Take(types.MaxTxsPerBlock) // one block's worth
	want := MaxFaucetClaimsPerPool - MaxFaucetClaimsPerBlock
	if m.Len() != want {
		t.Fatalf("after one Take the pool holds %d claims, want %d - none may age on a single skip",
			m.Len(), want)
	}
}

// Per-sender admission is stateful: the cap is on a sender's PENDING COUNT,
// counted from the pool's own state, so sending more transactions does not
// bypass it. It does not stop a sender with many keys - each address gets its
// own allowance.
func TestPerSenderTransferCapBites(t *testing.T) {
	m := newTestPool(t, 1000, testState(), 0)
	k := newTestKey(t)
	to := newTestKey(t)

	for n := uint64(0); n < MaxPendingTransfersPerSender; n++ {
		mustAdd(t, m, k.transfer(t, to.addr, n))
	}
	err := m.Add([]types.Tx{k.transfer(t, to.addr, MaxPendingTransfersPerSender)})[0]
	if !errors.Is(err, ErrSenderLimit) {
		t.Fatalf("transaction %d from one sender: err = %v, want ErrSenderLimit",
			MaxPendingTransfersPerSender, err)
	}
	// A DIFFERENT sender is unaffected: the cap is per address, which is what
	// an attacker with many keys trivially bypasses.
	mustAdd(t, m, newTestKey(t).transfer(t, to.addr, 0))
}

func TestPerSenderClaimCapBites(t *testing.T) {
	// Head at the last block of epoch 1: epoch 1 (current) and epoch 2 (next)
	// are both admissible, so two DISTINCT claims from one key exist and the
	// per-sender cap, not deduplication, is what refuses the second.
	m := newTestPool(t, 1000, testState(), testEpochBlocks-1)
	k := newTestKey(t)
	mustAdd(t, m, k.argon2Claim(t, 1)) // nonce 0
	// The second claim carries the nonce the pool's sequencing expects
	// (head nonce 0 + the one pending claim = 1), so ONLY the per-sender cap
	// can refuse it - the nonce rule alone would admit it.
	err := m.Add([]types.Tx{k.argon2ClaimNonce(t, 2, 1)})[0]
	if !errors.Is(err, ErrSenderLimit) {
		t.Fatalf("second pending claim from one key: err = %v, want ErrSenderLimit", err)
	}
}

// The claim sub-pool is a SEPARATE bound from total capacity: when it is full
// the pool still has room for ordinary transfers. That separation is what stops
// a claim flood from making every honest POST /tx return ErrFull.
func TestClaimSubPoolCapLeavesRoomForTransfers(t *testing.T) {
	m := newTestPool(t, 1000, testState(), 0)
	for i := 0; i < MaxFaucetClaimsPerPool; i++ {
		mustAdd(t, m, newTestKey(t).argon2Claim(t, 1))
	}
	if err := m.Add([]types.Tx{newTestKey(t).argon2Claim(t, 1)})[0]; !errors.Is(err, ErrClaimPoolFull) {
		t.Fatalf("claim %d: err = %v, want ErrClaimPoolFull", MaxFaucetClaimsPerPool, err)
	}
	// A transfer still fits, even though the claim sub-pool is full.
	mustAdd(t, m, newTestKey(t).transfer(t, newTestKey(t).addr, 0))
}

// Every claim rule the state machine enforces is checked at admission, before
// any Argon2id evaluation, against the head state.
func TestClaimAdmissionIsStateful(t *testing.T) {
	t.Run("wrong epoch", func(t *testing.T) {
		m := newTestPool(t, 100, testState(), 0)
		k := newTestKey(t)
		for _, epoch := range []uint64{0, 2, 99} {
			err := m.Add([]types.Tx{k.argon2Claim(t, epoch)})[0]
			if !errors.Is(err, state.ErrWrongEpoch) {
				t.Fatalf("claim for epoch %d: err = %v, want state.ErrWrongEpoch", epoch, err)
			}
		}
	})

	t.Run("already claimed this epoch", func(t *testing.T) {
		st := testState()
		k := newTestKey(t)
		st.Set(k.addr, state.Account{ClaimedEpoch: 1})
		m := newTestPool(t, 100, st, 0)
		if err := m.Add([]types.Tx{k.argon2Claim(t, 1)})[0]; !errors.Is(err, state.ErrClaimTooSoon) {
			t.Fatalf("err = %v, want state.ErrClaimTooSoon", err)
		}
	})

	t.Run("wrong nonce", func(t *testing.T) {
		st := testState()
		k := newTestKey(t)
		st.Set(k.addr, state.Account{Nonce: 5})
		m := newTestPool(t, 100, st, 0)
		if err := m.Add([]types.Tx{k.argon2Claim(t, 1)})[0]; !errors.Is(err, state.ErrBadNonce) {
			t.Fatalf("err = %v, want state.ErrBadNonce", err)
		}
	})

	t.Run("bad cheap outer puzzle", func(t *testing.T) {
		st := testState()
		k := newTestKey(t)
		m := New(100, testChain(), testHead(st, 0)) // shipped target, not permissive
		if err := m.Add([]types.Tx{k.claim(1, nonceFailingPre(t, k.pub, 1))})[0]; !errors.Is(err, ErrBadPrePuzzle) {
			t.Fatalf("err = %v, want ErrBadPrePuzzle", err)
		}
	})

	t.Run("valid", func(t *testing.T) {
		m := newTestPool(t, 100, testState(), 0)
		mustAdd(t, m, newTestKey(t).argon2Claim(t, 1))
		if m.Len() != 1 {
			t.Fatalf("Len = %d, want 1", m.Len())
		}
	})

	// The next block's epoch is accepted too: a claim solved just before the
	// head advanced targets the epoch that is now current.
	t.Run("next epoch accepted at a boundary", func(t *testing.T) {
		m := newTestPool(t, 100, testState(), testEpochBlocks-1)
		mustAdd(t, m, newTestKey(t).argon2Claim(t, 2))
	})
}

// A transfer whose replay counter the head state has already spent can never
// apply, so stateful admission refuses it. A future nonce is still admitted:
// it may become applicable once its predecessors land.
func TestTransferAdmissionRefusesAStaleNonce(t *testing.T) {
	st := testState()
	k := newTestKey(t)
	st.Set(k.addr, state.Account{Nonce: 5, Balance: 100})
	m := newTestPool(t, 100, st, 0)
	to := newTestKey(t)

	if err := m.Add([]types.Tx{k.transfer(t, to.addr, 3)})[0]; !errors.Is(err, state.ErrBadNonce) {
		t.Fatalf("stale nonce: err = %v, want state.ErrBadNonce", err)
	}
	mustAdd(t, m, k.transfer(t, to.addr, 5))  // exact head nonce
	mustAdd(t, m, k.transfer(t, to.addr, 99)) // a future nonce is still accepted
}
