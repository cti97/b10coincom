package mempool

// M5 Task 1: the three staking types take the transfer's nonce admission. A
// proposer must never be handed two transactions from one key at one nonce,
// because only one of them can apply and the block's second transaction would
// fail the whole block.

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// stake builds a signed staking transaction from this key.
func (k testKey) stake(t *testing.T, typ types.TxType, nonce, amount, fee uint64) types.Tx {
	t.Helper()
	tx := &types.Tx{Type: typ, From: k.addr, PubKey: k.pub, Nonce: nonce, Fee: fee}
	if typ != types.TxWithdraw {
		tx.Amount = amount
	}
	h := tx.SigningHash(testChain())
	tx.Sig = crypto.Sign(k.priv, h[:])
	return *tx
}

// TestMempoolRefusesTwoStakeTransactionsAtOneNonce is the pool-level rule, not a
// block-level one: the second transaction is refused at admission, so it never
// reaches a proposer.
func TestMempoolRefusesTwoStakeTransactionsAtOneNonce(t *testing.T) {
	m := newTestPool(t, 100, testState(), 0)
	k := newTestKey(t)

	first := k.stake(t, types.TxBond, 0, 1_000, 1)
	mustAdd(t, m, first)

	// Every other staking type at the same nonce: the IDs differ (different
	// types), so dedup cannot catch them, and 0 is not below the head nonce,
	// so the nonce FLOOR cannot either. Only the pending-nonce set can.
	for _, tc := range []struct {
		name string
		tx   types.Tx
	}{
		{"Bond", k.stake(t, types.TxBond, 0, 2_000, 1)},
		{"Unbond", k.stake(t, types.TxUnbond, 0, 1_000, 0)},
		{"Withdraw", k.stake(t, types.TxWithdraw, 0, 0, 0)},
	} {
		if tc.tx.ID() == first.ID() {
			t.Fatalf("fixture: the %s transaction is identical to the first, so dedup would reject it", tc.name)
		}
		if err := m.Add([]types.Tx{tc.tx})[0]; !errors.Is(err, state.ErrBadNonce) {
			t.Fatalf("second %s at nonce 0: err = %v, want state.ErrBadNonce", tc.name, err)
		}
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d after the same-nonce refusals, want 1 (the first stays)", m.Len())
	}

	// A stake transaction at a FUTURE nonce is still admitted: it may become
	// applicable when its predecessor lands, and the block filter evicts it
	// otherwise.
	mustAdd(t, m, k.stake(t, types.TxBond, 1, 1_000, 1))
	if m.Len() != 2 {
		t.Fatalf("Len = %d after a nonce-1 bond, want 2", m.Len())
	}

	// Removing the first frees its nonce: the extended bookkeeping must not
	// leak an entry across Remove/Take, or a legitimate re-add would be
	// refused forever.
	m.Remove(first.ID())
	mustAdd(t, m, k.stake(t, types.TxBond, 0, 3_000, 1))
	if m.Len() != 2 {
		t.Fatalf("Len = %d after removing the nonce-0 bond and re-adding one, want 2", m.Len())
	}
}
