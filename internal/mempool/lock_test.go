package mempool

import (
	"sync"
	"testing"

	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// S-10: Add used to hold the pool's write lock across EVERY signature in the
// batch, and a batch can be MaxTxsPerBlock = 10,000 (the consensus driver's
// re-add after a failed block), so /status (Len's RLock) and Take blocked for
// seconds. The fix verifies signatures outside the lock and inserts under it.
//
// This test is deterministic, not timing-based: the injected verifier closes
// `entered` and then blocks, so the test knows exactly when Add is inside
// verification, and TryLock/TryRLock report the lock state at that instant.
func TestSignatureVerificationRunsOutsideThePoolLock(t *testing.T) {
	m := newTestPool(t, 20_000, testState(), 0)

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	m.verifyHook = func(*types.Tx) error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	}

	const batch = 10_000 // the largest batch reAdd can pass
	txs := make([]types.Tx, batch)
	for i := range txs {
		txs[i] = types.Tx{Type: types.TxTransfer, Nonce: uint64(i), Amount: 1, Fee: 1}
	}
	done := make(chan []error, 1)
	go func() { done <- m.Add(txs) }()

	<-entered // Add is inside signature verification, before phase 2

	// The write lock must be free. An implementation that verified under the
	// lock would have taken it before calling verify, and this TryLock - the
	// exact lock /status (Len) and Take contend for - would fail.
	if !m.mu.TryLock() {
		close(release)
		t.Fatal("the pool write lock is held while signatures are verified: Add holds it across the batch (audit S-10 regression)")
	}
	m.mu.Unlock()

	// The read lock is free too, so a /status-equivalent read returns now
	// rather than queueing behind the batch.
	if !m.mu.TryRLock() {
		close(release)
		t.Fatal("the pool read lock is held while signatures are verified")
	}
	m.mu.RUnlock()
	if got := m.Len(); got != 0 {
		t.Fatalf("Len() = %d while verification is in progress, want 0: nothing is inserted until phase 2", got)
	}

	close(release)
	if errs := <-done; len(errs) != batch {
		t.Fatalf("Add returned %d results for %d inputs", len(errs), batch)
	}
}

// The other half of the S-10 contract, stated so "what guards what" is on
// record: the pool's own maps - dedup, capacity, per-sender counts, the
// pending-nonce set - ARE protected by the write lock. The head view is called
// under the lock, so blocking it parks Add inside the critical section, and
// both TryLock and TryRLock must then fail. A regression that admitted without
// the lock would pass these Try* calls and corrupt the maps under Take.
func TestStatefulAdmissionHoldsThePoolLock(t *testing.T) {
	st := testState()
	headEntered := make(chan struct{})
	releaseHead := make(chan struct{})
	var once sync.Once
	blockingHead := func() (*state.State, uint64) {
		once.Do(func() { close(headEntered) })
		<-releaseHead
		return st, 0
	}
	m := New(100, testChain(), blockingHead)
	m.preTarget = allPassPreTarget()

	done := make(chan []error, 1)
	go func() {
		done <- m.Add([]types.Tx{{Type: types.TxTransfer, Nonce: 0, Amount: 1, Fee: 1}})
	}()
	<-headEntered // head() runs under the lock: the critical section is held

	if m.mu.TryLock() {
		m.mu.Unlock()
		close(releaseHead)
		t.Fatal("the pool write lock is free inside stateful admission; the pool's maps are unprotected")
	}
	if m.mu.TryRLock() {
		m.mu.RUnlock()
		close(releaseHead)
		t.Fatal("the pool read lock is free inside stateful admission; Len/Take could read a half-updated pool")
	}
	close(releaseHead)
	<-done
}
