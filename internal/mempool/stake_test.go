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

// stakeState is a head state on which staking is configured: the exact shape
// chain.genesisState builds for a real chain (non-zero MinStake, UnbondingEpochs
// and EpochBlocks), with the pool's chain identifier bound into the state so a
// transaction verifies when it is APPLIED, not just when it is admitted.
func stakeState() *state.State {
	return state.NewWithParams(state.Params{
		EpochBlocks:     testEpochBlocks,
		GenesisHash:     testChain(),
		MinFee:          1,
		MinStake:        1_000,
		UnbondingEpochs: 2,
		PowArgon2:       testArgon2,
		PowTarget:       testPowTarget(),
	})
}

// TestMempoolRefusesTwoStakeTransactionsAtOneNonce is the pool-level rule, not a
// block-level one: the second transaction is refused at admission, so it never
// reaches a proposer.
//
// The state is staking-configured and the key is funded because audit ST-5's
// admission now also refuses a stake transaction that cannot apply (a Bond with
// no balance, an Unbond with no bond, a Withdraw with no record). The pending
// nonce is checked BEFORE those map lookups, so this test still isolates the
// bookkeeping rule it names.
func TestMempoolRefusesTwoStakeTransactionsAtOneNonce(t *testing.T) {
	st := stakeState()
	k := newTestKey(t)
	st.Set(k.addr, state.Account{Balance: 10_001})
	m := newTestPool(t, 100, st, 0)

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

// TestMempoolRefusesStakeTransactionsThatCannotApply is audit ST-5. The mempool
// admitted Bond, Unbond and Withdraw with no stateful check beyond the nonce
// floor, so a fresh key - no balance, no bond, no unbonding record - could
// occupy 64 slots with free Withdraw transactions (one per nonce), and sixteen
// such keys filled a 1,000-slot pool for one block, refillable every block.
//
// The fix mirrors admitClaim: the cheap map lookups that make the transaction
// impossible are done at admission, against the head state. Each check is a map
// lookup or one comparison.
func TestMempoolRefusesStakeTransactionsThatCannotApply(t *testing.T) {
	st := stakeState()
	m := newTestPool(t, 1000, st, 0)
	fresh := newTestKey(t)

	// A fresh key: nothing to withdraw, nothing to unbond, nothing to bond.
	for _, tc := range []struct {
		name string
		tx   types.Tx
		want error
	}{
		{"Withdraw with no unbonding record", fresh.stake(t, types.TxWithdraw, 0, 0, 0), state.ErrNothingToWithdraw},
		{"Unbond with no bond", fresh.stake(t, types.TxUnbond, 0, 1, 0), state.ErrUnbondExceedsBond},
		{"Bond with no balance", fresh.stake(t, types.TxBond, 0, 1_000, 1), state.ErrInsufficientFunds},
	} {
		if err := m.Add([]types.Tx{tc.tx})[0]; !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	if m.Len() != 0 {
		t.Fatalf("the pool holds %d transactions after refusing all three, want 0", m.Len())
	}

	// THE FLOOD, exactly as the finding describes it: 16 fresh keys x 64 free
	// Withdraw transactions, each at a distinct nonce so dedup and the
	// pending-nonce set cannot be what stops them. Before the fix every one of
	// the first 1,000 was admitted; now the first is already impossible and the
	// pool stays empty.
	const keys = 16
	admitted := 0
	for i := 0; i < keys; i++ {
		k := newTestKey(t)
		for nonce := uint64(0); nonce < MaxPendingTransfersPerSender; nonce++ {
			err := m.Add([]types.Tx{k.stake(t, types.TxWithdraw, nonce, 0, 0)})[0]
			switch {
			case err == nil:
				admitted++
			case !errors.Is(err, state.ErrNothingToWithdraw):
				t.Fatalf("flood key %d nonce %d: err = %v, want state.ErrNothingToWithdraw", i, nonce, err)
			}
		}
	}
	if admitted != 0 {
		t.Fatalf("the flood admitted %d fee-free Withdraw transactions from keys holding nothing, want 0", admitted)
	}
	if m.Len() != 0 {
		t.Fatalf("the flood left %d transactions in the pool, want 0", m.Len())
	}

	// Positive controls: the SAME rules must not refuse a transaction that can
	// apply. Each key is given exactly the state the transition needs.
	t.Run("a funded bond is admitted", func(t *testing.T) {
		pos := stakeState()
		k := newTestKey(t)
		pos.Set(k.addr, state.Account{Balance: 2_000})
		pm := newTestPool(t, 100, pos, 0)
		mustAdd(t, pm, k.stake(t, types.TxBond, 0, 1_000, 1))
	})

	t.Run("an unbond of an existing bond is admitted", func(t *testing.T) {
		pos := stakeState()
		k := newTestKey(t)
		pos.Set(k.addr, state.Account{Balance: 2_001})
		bond := k.stake(t, types.TxBond, 0, 1_000, 1)
		if err := pos.ApplyTx(&bond); err != nil {
			t.Fatalf("fixture bond: %v", err)
		}
		pm := newTestPool(t, 100, pos, 0)
		mustAdd(t, pm, k.stake(t, types.TxUnbond, 1, 1_000, 0))
	})

	t.Run("a withdraw of an existing record is admitted", func(t *testing.T) {
		pos := stakeState()
		k := newTestKey(t)
		pos.Set(k.addr, state.Account{Balance: 2_001})
		bond := k.stake(t, types.TxBond, 0, 1_000, 1)
		if err := pos.ApplyTx(&bond); err != nil {
			t.Fatalf("fixture bond: %v", err)
		}
		unbond := k.stake(t, types.TxUnbond, 1, 1_000, 0)
		if err := pos.ApplyTx(&unbond); err != nil {
			t.Fatalf("fixture unbond: %v", err)
		}
		pm := newTestPool(t, 100, pos, 0)
		mustAdd(t, pm, k.stake(t, types.TxWithdraw, 2, 0, 0))
	})

	// A state with zero staking parameters cannot apply ANY stake transaction
	// (state.stakeConfigured): the pool refuses it at the door, exactly as
	// admitClaim refuses a claim when EpochBlocks is zero.
	t.Run("an unconfigured state refuses staking at admission", func(t *testing.T) {
		um := newTestPool(t, 100, testState(), 0)
		k := newTestKey(t)
		if err := um.Add([]types.Tx{k.stake(t, types.TxBond, 0, 1_000, 1)})[0]; !errors.Is(err, state.ErrStakeUnconfigured) {
			t.Fatalf("Bond on an unparameterised state: err = %v, want state.ErrStakeUnconfigured", err)
		}
	})
}
