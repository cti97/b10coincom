package mempool

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// S-9: stateful admission and the per-sender cap already existed (they came in
// with R-1; see TestPerSenderTransferCapBites and
// TestTransferAdmissionRefusesAStaleNonce), but the nonce check was only a
// FLOOR - "not below the head nonce" - so two DIFFERENT transactions from one
// sender carrying the same nonce both entered the pool. This test pins the
// remaining rule: a sender's PENDING transfer nonces are distinct.
func TestSameNonceTransfersFromOneSenderAreRejected(t *testing.T) {
	m := newTestPool(t, 100, testState(), 0)
	k := newTestKey(t)
	to1, to2 := newTestKey(t), newTestKey(t)

	first := k.transfer(t, to1.addr, 0)
	mustAdd(t, m, first)

	// A different transaction (different recipient, so a different ID) at the
	// same nonce: dedup by ID does not catch it, and the head nonce floor does
	// not either (0 is not below the head's 0). Only the pending-nonce set can
	// refuse it.
	dup := k.transfer(t, to2.addr, 0)
	if dup.ID() == first.ID() {
		t.Fatal("fixture: the two transactions are identical, so dedup - not the nonce rule - would reject the second")
	}
	if err := m.Add([]types.Tx{dup})[0]; !errors.Is(err, state.ErrBadNonce) {
		t.Fatalf("second transfer at nonce 0: err = %v, want state.ErrBadNonce", err)
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d after the same-nonce rejection, want 1 (the first stays)", m.Len())
	}

	// The next nonce is still admitted: the rule refuses a duplicate, not a
	// future nonce.
	mustAdd(t, m, k.transfer(t, to1.addr, 1))
	if m.Len() != 2 {
		t.Fatalf("Len = %d after a legitimate nonce-1 transfer, want 2", m.Len())
	}

	// Removing the first frees its nonce: the set tracks PENDING transactions,
	// not spent ones, and must not leak an entry across Take/Remove. The head
	// state is still at nonce 0, so re-adding nonce 0 is legitimate again.
	m.Remove(first.ID())
	mustAdd(t, m, k.transfer(t, to2.addr, 0))
	if m.Len() != 2 {
		t.Fatalf("Len = %d after removing the nonce-0 transfer and re-adding one, want 2", m.Len())
	}
}
