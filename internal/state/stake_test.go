package state

// Tests for M5 Task 1: stake is committed state, and the cooldown is real.
//
// Every test here CONSTRUCTS its state and applies signed transactions to it.
// None of them provokes a transition through a kernel buffer, a clock or a
// timing window: there is nothing to race, so nothing here can pass or fail by
// scheduling.

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

// minStakeSparks is MIN_STAKE, DERIVED rather than asserted: one b10 is
// genesis.SparksPerB10 = 10^8 sparks (internal/genesis/genesis.go), so
//
//	1,000 b10 x 10^8 sparks/b10 = 10^11 sparks.
//
// It is the shipped value of the genesis parameter genesis.Params.MinStakeSparks,
// which chain.genesisState copies into state.Params.MinStake - the floor these
// tests exercise is the parameter, not a second constant.
const minStakeSparks = 1_000 * genesis.SparksPerB10 // = 10^11

// b10 is one b10 in sparks, the unit the plan's "600 then 500" example is
// written in: 600 b10 alone is under the 1,000 b10 floor, 1,100 b10 clears it.
const b10 = genesis.SparksPerB10

// stakeTestEpochBlocks is the epoch length these fixtures use. It is small so a
// cooldown of UnbondingEpochs = 2 epochs is 20 blocks, which a test can walk to;
// the shipped chains use 1,000 (devnet) and 10,000 (testnet) blocks, and the
// arithmetic is the same expression (releaseHeightFor).
const stakeTestEpochBlocks = 10

// stakeCooldown is UNBONDING_BLOCKS for these fixtures: 2 epochs x 10 blocks per
// epoch = 20 blocks.
const stakeCooldown = 2 * stakeTestEpochBlocks

// stakingParams is a state configured for staking at the shipped floor.
func stakingParams() Params {
	return Params{
		MinStake:        minStakeSparks,
		UnbondingEpochs: 2,
		EpochBlocks:     stakeTestEpochBlocks,
		MinFee:          1,
	}
}

// stakeTx builds a signed staking transaction. Withdraw carries no amount.
func stakeTx(t *testing.T, typ types.TxType, pub, priv []byte, from types.Address, nonce, amount, fee uint64) *types.Tx {
	t.Helper()
	tx := &types.Tx{Type: typ, From: from, PubKey: pub, Nonce: nonce, Fee: fee}
	if typ != types.TxWithdraw {
		tx.Amount = amount
	}
	h := tx.SigningHash(testChain())
	tx.Sig = crypto.Sign(priv, h[:])
	return tx
}

func bondTx(t *testing.T, pub, priv []byte, from types.Address, nonce, amount, fee uint64) *types.Tx {
	t.Helper()
	return stakeTx(t, types.TxBond, pub, priv, from, nonce, amount, fee)
}

func unbondTx(t *testing.T, pub, priv []byte, from types.Address, nonce, amount uint64) *types.Tx {
	t.Helper()
	return stakeTx(t, types.TxUnbond, pub, priv, from, nonce, amount, 0)
}

func withdrawTx(t *testing.T, pub, priv []byte, from types.Address, nonce uint64) *types.Tx {
	t.Helper()
	return stakeTx(t, types.TxWithdraw, pub, priv, from, nonce, 0, 0)
}

// stakeTransfer is a transfer that pays a fee: the staking fixtures run with a
// non-zero MinFee (the shipped chains' value), so the plain transfer helper -
// which pays nothing - would fail the fee floor for the wrong reason.
func stakeTransfer(t *testing.T, pub, priv []byte, from types.Address, nonce, amount, fee uint64, to types.Address) *types.Tx {
	t.Helper()
	tx := &types.Tx{Type: types.TxTransfer, From: from, PubKey: pub, Nonce: nonce, Fee: fee, To: to, Amount: amount}
	h := tx.SigningHash(testChain())
	tx.Sig = crypto.Sign(priv, h[:])
	return tx
}

// supplySum is the invariant's left-hand side: the three places a spark can be.
// A stake transaction moves value between the terms; a transfer lowers the sum
// by exactly its fee, which is burned.
func supplySum(s *State) uint64 {
	return s.TotalBalance() + s.TotalBonded() + s.TotalUnbonding()
}

// bondedValidator builds a state holding one validator whose bond was created
// by a real Bond transaction (so the fee and the floor are honoured) and whose
// account holds `spendable` sparks afterwards. The account's nonce is 1.
func bondedValidator(t *testing.T, bondAmount, spendable uint64) (*State, types.Address, []byte, []byte) {
	t.Helper()
	s := NewWithParams(stakingParams())
	addr, pub, priv := keypair(t)
	s.Set(addr, Account{Balance: bondAmount + 1 + spendable}) // 1: the bond's fee
	if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, bondAmount, 1)); err != nil {
		t.Fatalf("fixture bond: %v", err)
	}
	return s, addr, pub, priv
}

// TestMinStakeIsDerivedFromB10 pins the derivation above: if the unit or the
// floor ever moves, this fails rather than letting a wrong derivation sit in a
// comment.
func TestMinStakeIsDerivedFromB10(t *testing.T) {
	if genesis.SparksPerB10 != 100_000_000 {
		t.Fatalf("genesis.SparksPerB10 = %d, want 10^8 sparks per b10", genesis.SparksPerB10)
	}
	if minStakeSparks != 100_000_000_000 {
		t.Fatalf("MIN_STAKE = %d sparks, want 10^11 (1,000 b10)", minStakeSparks)
	}
	// The shipped genesis carries that exact value, so the state floor these
	// tests use and the chain's parameter cannot drift apart.
	if got := genesis.Devnet().Params.MinStakeSparks; got != minStakeSparks {
		t.Fatalf("genesis.Devnet MinStakeSparks = %d, want %d", got, minStakeSparks)
	}
	if got := genesis.Testnet().Params.MinStakeSparks; got != minStakeSparks {
		t.Fatalf("genesis.Testnet MinStakeSparks = %d, want %d", got, minStakeSparks)
	}
}

// TestBondMovesSparksFromSpendableToLocked is the first transition: a bond
// debits the balance by Amount+Fee and credits the bond by Amount.
//
// The three-way sum falls by EXACTLY the fee, not by zero. A Bond pays a fee
// and the fee is burned (applyTransfer's rule, audit S-3); "the sum is
// unchanged" can only hold for the two free transitions, Unbond and Withdraw.
// The plan's wording for this test says "unchanged"; the invariant it states in
// the same paragraph - "a transfer lowers it by exactly its fee (the fee is
// burned)" - is the one the code implements, and this assertion is that rule.
func TestBondMovesSparksFromSpendableToLocked(t *testing.T) {
	s := NewWithParams(stakingParams())
	addr, pub, priv := keypair(t)
	const amount, fee = minStakeSparks, 3
	s.Set(addr, Account{Balance: amount + 10})

	before := supplySum(s)
	if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, amount, fee)); err != nil {
		t.Fatalf("Bond: %v", err)
	}

	acc := s.Get(addr)
	if want := uint64(10 - fee); acc.Balance != want {
		t.Fatalf("balance = %d, want %d (funded %d, bonded %d, fee %d)", acc.Balance, want, amount+10, amount, fee)
	}
	if acc.Nonce != 1 {
		t.Fatalf("nonce = %d, want 1", acc.Nonce)
	}
	if got := s.Bonded(addr); got != amount {
		t.Fatalf("Bonded = %d, want %d", got, amount)
	}
	bond := s.bonds[addr]
	if bond.Height != 0 || !bytes.Equal(bond.Validator, pub) {
		t.Fatalf("bond record = %+v, want height 0 and the signer's key", bond)
	}
	if after := supplySum(s); after != before-fee {
		t.Fatalf("spendable+bonded+unbonding = %d after the bond, want %d (before %d minus the burned fee %d)",
			after, before-fee, before, fee)
	}
}

// TestBondBelowMinStakeIsRefused is the floor, tested at the shipped 1,000 b10
// level. It is the RESULT that is judged, so a fresh 600 b10 bond is refused
// and so is an existing 600 topped up by 399 (999 < 1,000).
func TestBondBelowMinStakeIsRefused(t *testing.T) {
	s := NewWithParams(stakingParams())
	addr, pub, priv := keypair(t)
	s.Set(addr, Account{Balance: 2_000 * b10})

	if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, 600*b10, 1)); !errors.Is(err, ErrStakeBelowMinimum) {
		t.Fatalf("a fresh 600 b10 bond: err = %v, want ErrStakeBelowMinimum", err)
	}
	if got := s.Bonded(addr); got != 0 {
		t.Fatalf("a refused bond left %d sparks locked", got)
	}

	// An existing 600 b10 record (a genesis-seated seat, Height 0, below the
	// floor - exactly what genesis.Validator.Power = 1 produces) topped up by
	// 399 more: the result is 999 b10, still under the floor.
	s.SetBond(addr, Bond{Validator: pub, Amount: 600 * b10, Height: 0})
	if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, 399*b10, 1)); !errors.Is(err, ErrStakeBelowMinimum) {
		t.Fatalf("600 + 399 b10: err = %v, want ErrStakeBelowMinimum", err)
	}
	if got := s.Bonded(addr); got != 600*b10 {
		t.Fatalf("a refused top-up changed the bond to %d, want 600 b10", got)
	}
}

// TestBondAccumulatesToTheFloor: the floor is on the resulting bond, so 500 b10
// added to an existing 600 b10 record is accepted because 1,100 b10 clears it.
// Both routes to that existing record are exercised: one written directly (the
// genesis-seat shape) and one produced by the real transitions (bond 1,400,
// unbond 400, leaving exactly the 1,000 b10 floor — audit ST-1 now forbids a
// partial exit below it, so exactly the floor is the boundary a transition
// can land on).
func TestBondAccumulatesToTheFloor(t *testing.T) {
	t.Run("genesis-shaped existing bond", func(t *testing.T) {
		s := NewWithParams(stakingParams())
		addr, pub, priv := keypair(t)
		s.Set(addr, Account{Balance: 500*b10 + 1})
		s.SetBond(addr, Bond{Validator: pub, Amount: 600 * b10, Height: 0})

		if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, 500*b10, 1)); err != nil {
			t.Fatalf("600 + 500 b10 = 1,100 clears the floor, got %v", err)
		}
		if got := s.Bonded(addr); got != 1_100*b10 {
			t.Fatalf("Bonded = %d, want 1,100 b10", got)
		}
		// The first-recorded key and height survive the top-up.
		if b := s.bonds[addr]; b.Height != 0 || !bytes.Equal(b.Validator, pub) {
			t.Fatalf("bond record = %+v, want the first-recorded key and height 0", b)
		}
	})

	t.Run("bond then partial unbond to the floor then top-up", func(t *testing.T) {
		s, addr, pub, priv := bondedValidator(t, 1_400*b10, 0)
		s.SetHeight(5)
		if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 400*b10)); err != nil {
			t.Fatalf("partial unbond: %v", err)
		}
		if got := s.Bonded(addr); got != 1_000*b10 {
			t.Fatalf("after unbonding 400 b10 of 1,400, Bonded = %d, want 1,000 b10 (the floor)", got)
		}
		// Fund the top-up without changing the bond: a transfer into the
		// account from a second key.
		funder, fpub, fpriv := keypair(t)
		s.Set(funder, Account{Balance: 100*b10 + 10})
		if err := s.ApplyTx(stakeTransfer(t, fpub, fpriv, funder, 0, 100*b10+1, 1, addr)); err != nil {
			t.Fatalf("funding transfer: %v", err)
		}
		if err := s.ApplyTx(bondTx(t, pub, priv, addr, 2, 100*b10, 1)); err != nil {
			t.Fatalf("1,000 + 100 b10 clears the floor, got %v", err)
		}
		if got := s.Bonded(addr); got != 1_100*b10 {
			t.Fatalf("Bonded = %d, want 1,100 b10", got)
		}
	})
}

// TestUnbondingCoinsAreNeitherSpendableNorCounted is the cooldown's two
// purposes, on one constructed state. The third assertion - the transfer of the
// unbonded amount failing - is what a "move but keep spendable" mutant dies on;
// the accessor assertions are what a "leave it in the bond map" mutant dies on.
//
// The fixture bonds 1,600 b10 so the 600 b10 exit leaves exactly the 1,000 b10
// floor bonded: audit ST-1 refuses a partial exit that would leave less.
func TestUnbondingCoinsAreNeitherSpendableNorCounted(t *testing.T) {
	// Bond the whole 1,600 b10 and leave NOTHING spendable, so any transfer
	// that could reach the unbonded sparks would have to credit the balance.
	s, addr, pub, priv := bondedValidator(t, 1_600*b10, 0)
	s.SetHeight(5)
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 600*b10)); err != nil {
		t.Fatalf("Unbond: %v", err)
	}

	// 1. Not counted toward the committee: the bond accessor the derivation
	// reads (Task 2's candidate set) sees only the 1,000 b10 left bonded, and
	// the unbonding amount is in a different map entirely.
	if got, want := s.Bonded(addr), uint64(1_000*b10); got != want {
		t.Fatalf("Bonded = %d, want %d: the unbonded sparks are still counted", got, want)
	}
	if got, want := s.TotalBonded(), uint64(1_000*b10); got != want {
		t.Fatalf("TotalBonded = %d, want %d", got, want)
	}
	if got, want := s.TotalUnbonding(), uint64(600*b10); got != want {
		t.Fatalf("TotalUnbonding = %d, want %d", got, want)
	}
	// The cooldown is 20 blocks and the unbond is at height 5: 5+20 = 25,
	// rounded UP to the next 10-block epoch boundary = 30 (audit ST-4).
	const wantRelease = uint64(30)
	if recs := s.UnbondingOf(addr); len(recs) != 1 || recs[0].Amount != 600*b10 || recs[0].ReleaseHeight != wantRelease {
		t.Fatalf("UnbondingOf = %+v, want one 600 b10 record releasing at %d", recs, wantRelease)
	}

	// 2. Not spendable: the account holds zero spendable sparks, so a transfer
	// against the unbonded amount is refused for insufficient funds - the
	// sparks are not in the balance, whichever way they are spent.
	to, _, _ := keypair(t)
	if err := s.ApplyTx(stakeTransfer(t, pub, priv, addr, 2, 600*b10, 1, to)); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("transfer against unbonding coins: err = %v, want ErrInsufficientFunds", err)
	}

	// 3. And not spendable at ANY point before the release height: a Withdraw
	// at R-1 is refused too, so the coins cannot be moved back early.
	s.SetHeight(wantRelease - 1)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 2)); !errors.Is(err, ErrNothingToWithdraw) {
		t.Fatalf("Withdraw one block early: err = %v, want ErrNothingToWithdraw", err)
	}
}

// TestWithdrawReleasesOnlyMatured: two unbonds land at different heights, so a
// withdraw between them must release the first and leave the second untouched.
// The 2,000 b10 fixture keeps both partial exits legal under audit ST-1's floor
// (400 leaves 1,600; 600 more leaves exactly 1,000).
func TestWithdrawReleasesOnlyMatured(t *testing.T) {
	s, addr, pub, priv := bondedValidator(t, 2_000*b10, 0)

	// Two unbonds in DIFFERENT epoch buckets, so they must stay separate
	// records: height 5 -> 5+20 = 25 -> boundary 30; height 11 -> 31 ->
	// boundary 40 (audit ST-4's rounding).
	s.SetHeight(5)
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 400*b10)); err != nil { // releases at 30
		t.Fatalf("first unbond: %v", err)
	}
	s.SetHeight(11)
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 2, 600*b10)); err != nil { // releases at 40
		t.Fatalf("second unbond: %v", err)
	}
	if got := s.Bonded(addr); got != 1_000*b10 {
		t.Fatalf("Bonded = %d after unbonding 1,000 of the 2,000 b10, want 1,000", got)
	}

	// At the first record's release height only the first is mature.
	s.SetHeight(30)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 3)); err != nil {
		t.Fatalf("Withdraw at the first release height: %v", err)
	}
	if got, want := s.Get(addr).Balance, uint64(400*b10); got != want {
		t.Fatalf("balance = %d, want %d (only the first record is mature)", got, want)
	}
	recs := s.UnbondingOf(addr)
	if len(recs) != 1 || recs[0].Amount != 600*b10 || recs[0].ReleaseHeight != 40 {
		t.Fatalf("remaining records = %+v, want the 600 b10 record releasing at 40", recs)
	}

	// The second matures at its own release height.
	s.SetHeight(40)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 4)); err != nil {
		t.Fatalf("Withdraw at the second release height: %v", err)
	}
	if got, want := s.Get(addr).Balance, uint64(1_000*b10); got != want {
		t.Fatalf("balance = %d, want %d", got, want)
	}
}

// TestWithdrawAtExactlyTheReleaseHeight is the cooldown arithmetic's sharp test:
// R is the epoch boundary at or after the unbond height plus TWO epochs of
// blocks, a withdraw one block before R is refused, at R it pays the exact
// amount, and a second attempt at R is refused because the record is gone - the
// payout happens exactly once.
func TestWithdrawAtExactlyTheReleaseHeight(t *testing.T) {
	s, addr, pub, priv := bondedValidator(t, minStakeSparks, 0)

	const unbondHeight = 7
	s.SetHeight(unbondHeight)
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, minStakeSparks)); err != nil {
		t.Fatalf("Unbond: %v", err)
	}
	// The record's release height is derived, and pinned, as the epoch boundary
	// at or after height + UnbondingEpochs*EpochBlocks: 7 + 2*10 = 27, rounded
	// up to 30 because release heights are multiples of the 10-block epoch
	// (audit ST-4). The cooldown is never shortened, so 30 >= 27.
	const wantRelease = uint64(30)
	if wantRelease < unbondHeight+stakeCooldown {
		t.Fatalf("fixture error: wantRelease %d is earlier than the cooldown's floor %d", wantRelease, unbondHeight+stakeCooldown)
	}
	recs := s.UnbondingOf(addr)
	if len(recs) != 1 || recs[0].ReleaseHeight != wantRelease {
		t.Fatalf("release height = %+v, want %d = the epoch boundary at or after %d + 2 epochs x %d blocks",
			recs, wantRelease, unbondHeight, stakeTestEpochBlocks)
	}

	s.SetHeight(wantRelease - 1)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 2)); !errors.Is(err, ErrNothingToWithdraw) {
		t.Fatalf("Withdraw at R-1 = %d: err = %v, want ErrNothingToWithdraw", wantRelease-1, err)
	}

	s.SetHeight(wantRelease)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 2)); err != nil {
		t.Fatalf("Withdraw at R = %d: %v", wantRelease, err)
	}
	if got, want := s.Get(addr).Balance, uint64(minStakeSparks); got != want {
		t.Fatalf("balance = %d, want exactly %d", got, want)
	}
	if got := s.TotalUnbonding(); got != 0 {
		t.Fatalf("TotalUnbonding = %d after the payout, want 0", got)
	}

	// Exactly once.
	s.SetHeight(wantRelease)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 3)); !errors.Is(err, ErrNothingToWithdraw) {
		t.Fatalf("second Withdraw at R: err = %v, want ErrNothingToWithdraw", err)
	}
	if got, want := s.Get(addr).Balance, uint64(minStakeSparks); got != want {
		t.Fatalf("balance = %d after the second attempt, want %d: a record paid twice", got, want)
	}
}

// TestAStakeTransactionNeverChangesTheSupplySum is the invariant test. It walks
// bond, transfer, unbond, withdraw and asserts that the three-way sum moves by
// exactly the burned fees - the two free transitions conserve it exactly.
func TestAStakeTransactionNeverChangesTheSupplySum(t *testing.T) {
	s := NewWithParams(stakingParams())
	addr, pub, priv := keypair(t)
	recipient, _, _ := keypair(t)

	const start = 3*minStakeSparks + 100
	s.Set(addr, Account{Balance: start})
	burned := uint64(0)

	check := func(step string) {
		t.Helper()
		if got, want := supplySum(s), start-burned; got != want {
			t.Fatalf("after %s: spendable+bonded+unbonding = %d, want %d (start %d, fees burned %d)",
				step, got, want, start, burned)
		}
	}

	// Bond: moves sparks into the bond and burns its fee. The bond is twice the
	// floor so the partial exit below leaves exactly the floor (audit ST-1).
	if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, 2*minStakeSparks, 3)); err != nil {
		t.Fatalf("Bond: %v", err)
	}
	burned += 3
	check("bond")

	// Transfer: lowers the spendable term and burns its fee.
	if err := s.ApplyTx(stakeTransfer(t, pub, priv, addr, 1, 5, 2, recipient)); err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	burned += 2
	check("transfer")

	// Unbond: bond -> unbonding, free.
	s.SetHeight(4)
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 2, minStakeSparks/2)); err != nil {
		t.Fatalf("Unbond: %v", err)
	}
	check("unbond")

	// Withdraw: unbonding -> spendable, free. 4 + 20 = 24, rounded up to the
	// 10-block epoch boundary 30 (audit ST-4).
	s.SetHeight(30)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 3)); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	check("withdraw")

	// And the final shape: bonded keeps the other half, the spendable term got
	// the matured half back.
	if got, want := s.Bonded(addr), uint64(3*minStakeSparks/2); got != want {
		t.Fatalf("Bonded = %d, want %d", got, want)
	}
	if got := s.TotalUnbonding(); got != 0 {
		t.Fatalf("TotalUnbonding = %d, want 0", got)
	}
}

// TestTheStateRootCommitsToBondsAndUnbonding: two states that differ ONLY in a
// bond's amount, and two that differ ONLY in an unbonding record's release
// height, must have different roots. The second is the half that stops the root
// passing with an unrelated hash: it is the one field only the new encoding can
// see.
//
// The "no bonds means the pre-M5 root" half is TestRootGoldenVector and
// TestRootGoldenVectorFourAccounts, which are unchanged by this task and must
// stay green: an empty bond map contributes no leaves. Params alone are not
// hashed, and that is asserted here too.
func TestTheStateRootCommitsToBondsAndUnbonding(t *testing.T) {
	a, pubA, _ := keypair(t)
	b, pubB, _ := keypair(t)
	base := New()
	base.Set(a, Account{Balance: 1_000})
	base.Set(b, Account{Balance: 2_000})

	if NewWithParams(stakingParams()).Root() != New().Root() {
		t.Fatal("adding staking Params moved the state root; Params are protocol configuration, not committed state")
	}

	// A bond moves the root, and its AMOUNT is committed.
	bondA := base.Clone()
	bondA.SetBond(a, Bond{Validator: pubA, Amount: 500, Height: 0})
	bondA2 := base.Clone()
	bondA2.SetBond(a, Bond{Validator: pubA, Amount: 501, Height: 0})
	if bondA.Root() == base.Root() {
		t.Fatal("a bond did not move the state root")
	}
	if bondA.Root() == bondA2.Root() {
		t.Fatal("the state root does not commit to the bonded amount")
	}

	// A bond's HEIGHT and seated key are committed too.
	bondHeight := base.Clone()
	bondHeight.SetBond(a, Bond{Validator: pubA, Amount: 500, Height: 1})
	if bondA.Root() == bondHeight.Root() {
		t.Fatal("the state root does not commit to the bond's height")
	}
	_, pubC, _ := keypair(t)
	bondKey := base.Clone()
	bondKey.SetBond(a, Bond{Validator: pubC, Amount: 500, Height: 0})
	if bondA.Root() == bondKey.Root() {
		t.Fatal("the state root does not commit to the seated public key")
	}

	// The UNFUNDED part is committed (audit ST-3). It decides whether an
	// Unbond pays out or destroys the sparks, so two nodes that disagreed on it
	// would disagree on the balance at the release height; a root that skipped
	// it would let them agree on every leaf and still fork.
	bondUnfunded := base.Clone()
	bondUnfunded.SetBond(a, Bond{Validator: pubA, Amount: 500, Unfunded: 500, Height: 0})
	if bondA.Root() == bondUnfunded.Root() {
		t.Fatal("the state root does not commit to the bond's unfunded (non-withdrawable) part")
	}
	if bondUnfunded.Root() == bondKey.Root() {
		t.Fatal("two different bonds hashed to one leaf")
	}

	// An unbonding record moves the root, and its RELEASE HEIGHT is committed:
	// this is the assertion a root that skips the unbonding leaves fails, and
	// the one a root that hashes only the amount also fails.
	un1 := base.Clone()
	un1.unbonding[a] = []Unbonding{{Amount: 500, ReleaseHeight: 20}}
	un2 := base.Clone()
	un2.unbonding[a] = []Unbonding{{Amount: 500, ReleaseHeight: 21}}
	if un1.Root() == base.Root() {
		t.Fatal("an unbonding record did not move the state root")
	}
	if un1.Root() == un2.Root() {
		t.Fatal("the state root does not commit to the release height")
	}
	if bondA.Root() == un1.Root() {
		t.Fatal("a bond and an unbonding record of the same amount hashed to one leaf")
	}

	// Both stake maps are sorted by address bytes, so insertion order cannot
	// reach the root (a Go map's iteration order is randomised).
	forward := New()
	backward := New()
	addrs := []types.Address{a, b}
	pubs := [][]byte{pubA, pubB}
	for i := range addrs {
		forward.SetBond(addrs[i], Bond{Validator: pubs[i], Amount: uint64(i + 1), Height: 0})
		forward.unbonding[addrs[i]] = []Unbonding{{Amount: uint64(i + 1), ReleaseHeight: uint64(10 * (i + 1))}}
	}
	for i := len(addrs) - 1; i >= 0; i-- {
		backward.SetBond(addrs[i], Bond{Validator: pubs[i], Amount: uint64(i + 1), Height: 0})
		backward.unbonding[addrs[i]] = []Unbonding{{Amount: uint64(i + 1), ReleaseHeight: uint64(10 * (i + 1))}}
	}
	if forward.Root() != backward.Root() {
		t.Fatal("the stake state root depends on insertion order")
	}
}

// TestApplyBlockRollsBackAStakeFailure: ApplyBlock's clone-then-apply contract
// survives the two new maps. A block whose FIRST transaction applies and whose
// second fails must leave the receiver byte-identical - root, bonded total and,
// in the second case, an unbonding record an in-place merge would have mutated.
func TestApplyBlockRollsBackAStakeFailure(t *testing.T) {
	t.Run("valid bond then invalid unbond", func(t *testing.T) {
		s := NewWithParams(stakingParams())
		addr, pub, priv := keypair(t)
		s.Set(addr, Account{Balance: minStakeSparks + 1})

		beforeRoot, beforeBonded, beforeSum := s.Root(), s.TotalBonded(), supplySum(s)
		good := bondTx(t, pub, priv, addr, 0, minStakeSparks, 1)
		// Nonce 1 continues the sender's sequence, so the block cannot fail on
		// the nonce: it fails because the unbond asks for twice the bond the
		// first transaction created.
		bad := unbondTx(t, pub, priv, addr, 1, 2*minStakeSparks)

		next, err := s.ApplyBlock([]types.Tx{*good, *bad})
		if !errors.Is(err, ErrUnbondExceedsBond) {
			t.Fatalf("ApplyBlock err = %v, want ErrUnbondExceedsBond", err)
		}
		if next != nil {
			t.Fatal("a failed block returned a state")
		}
		if s.Root() != beforeRoot {
			t.Fatal("a failed block moved the receiver's state root")
		}
		if s.TotalBonded() != beforeBonded || supplySum(s) != beforeSum {
			t.Fatal("a failed block changed the receiver's bonded or supply totals")
		}
	})

	t.Run("valid unbond that merges, then a failed transfer", func(t *testing.T) {
		// An existing record at release height R, created at height 5, from a
		// 1,500 b10 bond so both exits stay above the floor (audit ST-1).
		s, addr, pub, priv := bondedValidator(t, 1_500*b10, 5)
		s.SetHeight(5)
		if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 300*b10)); err != nil {
			t.Fatalf("fixture unbond: %v", err)
		}
		before := s.UnbondingOf(addr)
		beforeRoot := s.Root()

		// The valid transaction MERGES into that record in place
		// (recs[i].Amount += ...), which is where a shallow Clone would write
		// through a shared backing array. The second transaction fails.
		merge := unbondTx(t, pub, priv, addr, 2, 100*b10)
		recipient, _, _ := keypair(t)
		badNonce := stakeTransfer(t, pub, priv, addr, 99, 1, 1, recipient)

		if _, err := s.ApplyBlock([]types.Tx{*merge, *badNonce}); !errors.Is(err, ErrBadNonce) {
			t.Fatalf("ApplyBlock err = %v, want ErrBadNonce", err)
		}
		after := s.UnbondingOf(addr)
		if len(after) != len(before) || after[0].Amount != before[0].Amount || after[0].ReleaseHeight != before[0].ReleaseHeight {
			t.Fatalf("a failed block mutated the receiver's unbonding record: before %+v, after %+v", before, after)
		}
		if s.Root() != beforeRoot {
			t.Fatal("a failed block moved the receiver's state root")
		}
	})
}

// TestStakeTransactionsSpendTheNonce: the replay guard covers the new types, so
// a replayed Bond/Unbond/Withdraw is refused like a replayed transfer.
func TestStakeTransactionsSpendTheNonce(t *testing.T) {
	// 1,100 b10 bonded so the 100 b10 exit leaves exactly the floor.
	s, addr, pub, priv := bondedValidator(t, 1_100*b10, 0)
	// The bond itself consumed nonce 0.
	replay := bondTx(t, pub, priv, addr, 0, minStakeSparks, 1)
	if err := s.ApplyTx(replay); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("replayed Bond: err = %v, want ErrBadNonce", err)
	}

	s.SetHeight(5)
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 100*b10)); err != nil {
		t.Fatalf("Unbond: %v", err)
	}
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 100*b10)); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("replayed Unbond: err = %v, want ErrBadNonce", err)
	}
	// 5 + 20 = 25, rounded up to the 10-block epoch boundary 30 (audit ST-4).
	s.SetHeight(30)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 2)); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 2)); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("replayed Withdraw: err = %v, want ErrBadNonce", err)
	}
}

// TestStakeTransactionsAreRefusedOnAnUnconfiguredState: New()'s zero Params keep
// the M0-M1 behaviour. A stake transaction is refused cleanly - no panic, no
// division by a zero epoch length - and leaves the state untouched.
func TestStakeTransactionsAreRefusedOnAnUnconfiguredState(t *testing.T) {
	s := New()
	addr, pub, priv := keypair(t)
	s.Set(addr, Account{Balance: minStakeSparks + 1})
	before := s.Root()

	for _, tc := range []struct {
		name string
		tx   *types.Tx
	}{
		{"Bond", bondTx(t, pub, priv, addr, 0, minStakeSparks, 1)},
		{"Unbond", unbondTx(t, pub, priv, addr, 0, minStakeSparks)},
		{"Withdraw", withdrawTx(t, pub, priv, addr, 0)},
	} {
		if err := s.ApplyTx(tc.tx); !errors.Is(err, ErrStakeUnconfigured) {
			t.Fatalf("%s on a zero-Params state: err = %v, want ErrStakeUnconfigured", tc.name, err)
		}
	}
	if s.Root() != before {
		t.Fatal("a refused stake transaction changed the state")
	}

	// A partially configured state is equally unusable: zero EpochBlocks would
	// be a release height with no time in it (and a division by zero if it were
	// ever used as a period).
	partial := NewWithParams(Params{MinStake: minStakeSparks, UnbondingEpochs: 2})
	partial.Set(addr, Account{Balance: minStakeSparks + 1})
	if err := partial.ApplyTx(bondTx(t, pub, priv, addr, 0, minStakeSparks, 1)); !errors.Is(err, ErrStakeUnconfigured) {
		t.Fatalf("Bond with EpochBlocks 0: err = %v, want ErrStakeUnconfigured", err)
	}
}

// TestUnbondAndWithdrawMustNotCarryAFee is the exit rule: an operator may hold
// nothing spendable, so an exit that needed a coin could never be made by the
// operator who needs it most.
func TestUnbondAndWithdrawMustNotCarryAFee(t *testing.T) {
	s, addr, pub, priv := bondedValidator(t, minStakeSparks, 10)
	s.SetHeight(5)
	if err := s.ApplyTx(stakeTx(t, types.TxUnbond, pub, priv, addr, 1, 100*b10, 1)); !errors.Is(err, ErrStakeCarriesFee) {
		t.Fatalf("Unbond with a fee: err = %v, want ErrStakeCarriesFee", err)
	}
	if err := s.ApplyTx(stakeTx(t, types.TxWithdraw, pub, priv, addr, 1, 0, 1)); !errors.Is(err, ErrStakeCarriesFee) {
		t.Fatalf("Withdraw with a fee: err = %v, want ErrStakeCarriesFee", err)
	}
	// A zero-balance operator can still exit: the fixture below holds nothing
	// spendable and the free unbond succeeds.
	zero, zaddr, zpub, zpriv := bondedValidator(t, minStakeSparks, 0)
	zero.SetHeight(5)
	if err := zero.ApplyTx(unbondTx(t, zpub, zpriv, zaddr, 1, minStakeSparks)); err != nil {
		t.Fatalf("an unbond from a zero-balance account: %v", err)
	}
}

// TestBondFeeFloorAndAmountRules covers the remaining Bond refusals.
func TestBondFeeFloorAndAmountRules(t *testing.T) {
	s := NewWithParams(stakingParams())
	addr, pub, priv := keypair(t)
	s.Set(addr, Account{Balance: minStakeSparks + 100})

	if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, 0, 1)); !errors.Is(err, ErrZeroAmount) {
		t.Fatalf("zero-amount Bond: err = %v, want ErrZeroAmount", err)
	}
	if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, minStakeSparks, 0)); !errors.Is(err, ErrFeeTooLow) {
		t.Fatalf("fee-less Bond: err = %v, want ErrFeeTooLow", err)
	}
	// The bond AND the fee must be payable: a balance of exactly the bond is
	// short by the fee.
	s.Set(addr, Account{Balance: minStakeSparks})
	if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, minStakeSparks, 1)); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("bond exactly equal to the balance: err = %v, want ErrInsufficientFunds", err)
	}
}

// TestUnbondRules covers the amount rules: zero, more than is bonded, and an
// unbond from an address that holds no bond at all.
func TestUnbondRules(t *testing.T) {
	s, addr, pub, priv := bondedValidator(t, minStakeSparks, 0)
	s.SetHeight(5)

	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 0)); !errors.Is(err, ErrZeroAmount) {
		t.Fatalf("zero-amount Unbond: err = %v, want ErrZeroAmount", err)
	}
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, minStakeSparks+1)); !errors.Is(err, ErrUnbondExceedsBond) {
		t.Fatalf("Unbond over the bond: err = %v, want ErrUnbondExceedsBond", err)
	}
	// An address with no bond: its bonded amount is zero, so any amount is over.
	stranger, spub, spriv := keypair(t)
	if err := s.ApplyTx(unbondTx(t, spub, spriv, stranger, 0, 1)); !errors.Is(err, ErrUnbondExceedsBond) {
		t.Fatalf("Unbond with no bond: err = %v, want ErrUnbondExceedsBond", err)
	}
	// A full unbond deletes the bond record rather than leaving a zero one.
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, minStakeSparks)); err != nil {
		t.Fatalf("full Unbond: %v", err)
	}
	if _, ok := s.bonds[addr]; ok {
		t.Fatal("a zero remainder left a bond record behind")
	}
	if s.Bonded(addr) != 0 || s.TotalBonded() != 0 {
		t.Fatal("a fully unbonded address still reports bonded stake")
	}
}

// TestUnbondMergesRecordsAtOneReleaseHeight: two unbonds in one block produce
// ONE record whose amount is their sum. Release heights are epoch boundaries
// (audit ST-4), so unbonds in DIFFERENT blocks of one epoch merge too - which is
// what bounds an address's live records. The 1,500 b10 fixture keeps both exits
// above the audit ST-1 floor (1,200 then 1,000).
func TestUnbondMergesRecordsAtOneReleaseHeight(t *testing.T) {
	s, addr, pub, priv := bondedValidator(t, 1_500*b10, 0)
	s.SetHeight(5)
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 300*b10)); err != nil {
		t.Fatalf("first Unbond: %v", err)
	}
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 2, 200*b10)); err != nil {
		t.Fatalf("second Unbond: %v", err)
	}
	recs := s.UnbondingOf(addr)
	if len(recs) != 1 {
		t.Fatalf("UnbondingOf returned %d records, want 1 (same release height merges)", len(recs))
	}
	// 5 + 20 = 25, rounded up to the 10-block epoch boundary 30.
	if recs[0].Amount != 500*b10 || recs[0].ReleaseHeight != 30 {
		t.Fatalf("merged record = %+v, want 500 b10 releasing at 30", recs[0])
	}
}

// TestUnbondRecordsPerAddressAreBoundedByEpochBuckets is ST-4's growth bound at
// the shape the audit describes: one one-spark unbond per block, at zero fee,
// for eighty blocks spread over two unbond bursts. Before the fix that was one
// record per block - each cloned on every ApplyBlock and Probe, hashed into the
// root, replayed on Open and serialised by /account.
//
// Release heights are now epoch boundaries, so an epoch's unbonds share a
// record (at most UnbondingEpochs+1 of them unmatured), and records that have
// already matured are collapsed when the next unbond arrives (so the matured
// ones cost one record, not one per epoch). The count is therefore bounded by
// UnbondingEpochs+2 = 4 for the whole life of the address, whatever the number
// of unbonds, and every spark is still accounted for.
func TestUnbondRecordsPerAddressAreBoundedByEpochBuckets(t *testing.T) {
	// A bond of MIN_STAKE + 80 leaves a floor-clearing remainder after every
	// one-spark exit, so all eighty unbonds are legal.
	s, addr, pub, priv := bondedValidator(t, minStakeSparks+80, 0)
	const burst = 40
	maxLive := uint64(2) + 2 // UnbondingEpochs + 2: the unmatured window plus one matured record
	nonce := uint64(1)
	unbonds := 0

	unbondAt := func(height uint64) {
		t.Helper()
		s.SetHeight(height)
		if err := s.ApplyTx(unbondTx(t, pub, priv, addr, nonce, 1)); err != nil {
			t.Fatalf("one-spark unbond at height %d: %v", height, err)
		}
		nonce++
		unbonds++
		if recs := s.UnbondingOf(addr); uint64(len(recs)) > maxLive {
			t.Fatalf("at height %d the address holds %d live unbonding records, want at most %d (UnbondingEpochs+2): %+v",
				height, len(recs), maxLive, recs)
		}
	}

	// Burst one: consecutive blocks, the per-block spam.
	for i := uint64(1); i <= burst; i++ {
		unbondAt(i)
	}
	// A long gap with no unbond: records mature but are not withdrawn, and no
	// new record is created (nothing grows without an unbond).
	if got := len(s.UnbondingOf(addr)); got > int(maxLive) {
		t.Fatalf("after a %d-block unbond burst the address holds %d records, want at most %d", burst, got, maxLive)
	}
	// Burst two, after 300 blocks: the matured records must be collapsed rather
	// than accumulate one per epoch.
	for i := uint64(301); i <= 300+burst; i++ {
		unbondAt(i)
	}

	recs := s.UnbondingOf(addr)
	var total uint64
	for _, rec := range recs {
		total += rec.Amount
		if rec.ReleaseHeight%stakeTestEpochBlocks != 0 {
			t.Fatalf("record %+v does not release on an epoch boundary of %d blocks", rec, stakeTestEpochBlocks)
		}
	}
	if total != uint64(unbonds) {
		t.Fatalf("the live records hold %d sparks, want all %d unbonded sparks (records must merge, not vanish)", total, unbonds)
	}
	if got, want := s.Bonded(addr), uint64(minStakeSparks); got != want {
		t.Fatalf("Bonded = %d, want the floor %d left behind", got, want)
	}
}

// TestUnbondingOfIsASortedCopy: the accessor must not be a window into
// committed state.
func TestUnbondingOfIsASortedCopy(t *testing.T) {
	s := New()
	addr, _, _ := keypair(t)
	// Inserted out of order on purpose; a hand-built state may hold any order.
	s.unbonding[addr] = []Unbonding{{Amount: 3, ReleaseHeight: 30}, {Amount: 1, ReleaseHeight: 10}, {Amount: 2, ReleaseHeight: 20}}

	before := s.Root()
	got := s.UnbondingOf(addr)
	for i := 1; i < len(got); i++ {
		if got[i-1].ReleaseHeight > got[i].ReleaseHeight {
			t.Fatalf("UnbondingOf is not sorted by release height: %+v", got)
		}
	}
	got[0].Amount = 999
	got[0].ReleaseHeight = 999
	again := s.UnbondingOf(addr)
	if again[0].Amount != 1 || again[0].ReleaseHeight != 10 {
		t.Fatalf("mutating the returned slice changed committed state: %+v", again)
	}
	if s.Root() != before {
		t.Fatal("mutating the returned slice moved the state root")
	}
}

// TestBondAtMaxUint64IsRefusedNotWrapped is the debit side's overflow proof: a
// crafted amount must be REFUSED, never wrap below the balance, and the sender
// must be untouched.
func TestBondAtMaxUint64IsRefusedNotWrapped(t *testing.T) {
	t.Run("amount plus fee wraps the debit", func(t *testing.T) {
		s := NewWithParams(stakingParams())
		addr, pub, priv := keypair(t)
		s.Set(addr, Account{Balance: math.MaxUint64})
		before := s.Root()

		// MaxUint64 + 1 wraps to 0, which would make the debit free.
		if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, math.MaxUint64, 1)); !errors.Is(err, ErrBalanceOverflow) {
			t.Fatalf("Bond of MaxUint64 with a fee: err = %v, want ErrBalanceOverflow", err)
		}
		if s.Root() != before {
			t.Fatal("a refused overflowing bond changed the state")
		}
		if got := s.Get(addr).Balance; got != math.MaxUint64 {
			t.Fatalf("sender balance = %d after the refusal, want %d", got, uint64(math.MaxUint64))
		}
		if got := s.Bonded(addr); got != 0 {
			t.Fatalf("a refused bond locked %d sparks", got)
		}
	})

	t.Run("accumulation wraps the bonded amount", func(t *testing.T) {
		s := NewWithParams(stakingParams())
		addr, pub, priv := keypair(t)
		// An existing bond, and a balance big enough that the debit alone
		// would be legal: only the bonded-side sum can refuse this.
		s.SetBond(addr, Bond{Validator: pub, Amount: 5, Height: 0})
		s.Set(addr, Account{Balance: math.MaxUint64})
		before := s.Root()

		if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, math.MaxUint64, 1)); !errors.Is(err, ErrBalanceOverflow) {
			t.Fatalf("Bond that overflows the bond: err = %v, want ErrBalanceOverflow", err)
		}
		if s.Root() != before {
			t.Fatal("a refused overflowing bond changed the state")
		}
		if got := s.Bonded(addr); got != 5 {
			t.Fatalf("Bonded = %d after the refusal, want 5", got)
		}
	})
}

// TestWithdrawPayoutAtMaxUint64IsRefusedNotWrapped is the credit side's proof:
// a payout that would wrap the balance is refused and the record survives.
func TestWithdrawPayoutAtMaxUint64IsRefusedNotWrapped(t *testing.T) {
	s := NewWithParams(stakingParams())
	addr, pub, priv := keypair(t)
	s.Set(addr, Account{Balance: 1})
	s.unbonding[addr] = []Unbonding{{Amount: math.MaxUint64, ReleaseHeight: 0}}
	before := s.Root()

	s.SetHeight(0)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 0)); !errors.Is(err, ErrBalanceOverflow) {
		t.Fatalf("Withdraw of a MaxUint64 payout into a 1-spark balance: err = %v, want ErrBalanceOverflow", err)
	}
	if s.Root() != before {
		t.Fatal("a refused overflowing payout changed the state")
	}
	if got := s.Get(addr).Balance; got != 1 {
		t.Fatalf("balance = %d after the refusal, want 1", got)
	}
	if recs := s.UnbondingOf(addr); len(recs) != 1 || recs[0].Amount != math.MaxUint64 {
		t.Fatalf("the refused payout consumed the record: %+v", recs)
	}

	// Two mature records whose SUM wraps: the accumulation is checked as it is
	// formed, before any credit.
	s2 := NewWithParams(stakingParams())
	s2.Set(addr, Account{Balance: 0})
	s2.unbonding[addr] = []Unbonding{
		{Amount: math.MaxUint64, ReleaseHeight: 0},
		{Amount: 1, ReleaseHeight: 0},
	}
	s2.SetHeight(0)
	if err := s2.ApplyTx(withdrawTx(t, pub, priv, addr, 0)); !errors.Is(err, ErrBalanceOverflow) {
		t.Fatalf("Withdraw of two records that sum past MaxUint64: err = %v, want ErrBalanceOverflow", err)
	}
	if recs := s2.UnbondingOf(addr); len(recs) != 2 {
		t.Fatalf("the refused payout consumed records: %+v", recs)
	}
}

// TestReleaseHeightArithmetic pins the cooldown derivation, the epoch rounding
// and all three overflow checks directly, so the arithmetic has a test of its
// own rather than only reaching behaviour through a transition.
func TestReleaseHeightArithmetic(t *testing.T) {
	// releaseHeight = the epoch boundary at or after
	// height + UnbondingEpochs*EpochBlocks. Two epochs of ten blocks is twenty
	// blocks: 7 + 2*10 = 27, rounded UP to 30 (audit ST-4). Never down: 27 is
	// not a release height any more, because a release earlier than the
	// cooldown would shorten it.
	if got, err := releaseHeightFor(7, 2, 10); err != nil || got != 30 {
		t.Fatalf("releaseHeightFor(7, 2, 10) = %d, %v; want 30 (27 rounded up)", got, err)
	}
	// Both boundaries: a release that lands exactly on an epoch boundary does
	// not move, and one block before it moves a single block.
	if got, _ := releaseHeightFor(10, 2, 10); got != 30 { // 30, exact boundary
		t.Fatalf("releaseHeightFor(10, 2, 10) = %d, want 30 (already a boundary)", got)
	}
	if got, _ := releaseHeightFor(11, 2, 10); got != 40 { // 31 -> 40
		t.Fatalf("releaseHeightFor(11, 2, 10) = %d, want 40 (31 rounded up)", got)
	}
	// The rounding is a DELAY, never a discount: for a range of heights the
	// release is at or after height + cooldown and strictly before one epoch
	// later. This is the property the cooldown's meaning rests on.
	for h := uint64(0); h < 100; h++ {
		got, err := releaseHeightFor(h, 2, 10)
		if err != nil {
			t.Fatalf("releaseHeightFor(%d, 2, 10): %v", h, err)
		}
		floor := h + 2*10
		if got < floor || got >= floor+10 {
			t.Fatalf("releaseHeightFor(%d, 2, 10) = %d, want in [%d, %d)", h, got, floor, floor+10)
		}
	}
	// One epoch is 17 rounded to 20: the "one EpochBlocks" mutant cannot hide
	// behind the rounding.
	if got, _ := releaseHeightFor(7, 1, 10); got != 20 {
		t.Fatalf("releaseHeightFor(7, 1, 10) = %d, want 20", got)
	}

	// The product overflows 64 bits: MaxUint64*2 has a carry.
	if _, err := releaseHeightFor(0, math.MaxUint64, 2); !errors.Is(err, ErrReleaseHeightOverflow) {
		t.Fatalf("overflowing epoch product: err = %v, want ErrReleaseHeightOverflow", err)
	}
	// The addition overflows: MaxUint64 + 20.
	if _, err := releaseHeightFor(math.MaxUint64, 2, 10); !errors.Is(err, ErrReleaseHeightOverflow) {
		t.Fatalf("overflowing addition: err = %v, want ErrReleaseHeightOverflow", err)
	}
	// The ROUNDING overflows: MaxUint64-24 + 20 = MaxUint64-4, which rounds up
	// by 9 past the end of the domain. A wrapped release would be in the past.
	if _, err := releaseHeightFor(math.MaxUint64-24, 2, 10); !errors.Is(err, ErrReleaseHeightOverflow) {
		t.Fatalf("overflowing rounding: err = %v, want ErrReleaseHeightOverflow", err)
	}
	// A zero epoch length cannot be rounded to and must not divide by zero.
	if _, err := releaseHeightFor(7, 2, 0); !errors.Is(err, ErrStakeUnconfigured) {
		t.Fatalf("zero epoch length: err = %v, want ErrStakeUnconfigured", err)
	}
}

// TestWithdrawWithNothingMatured covers the empty case explicitly.
func TestWithdrawWithNothingMatured(t *testing.T) {
	// 1,100 b10 bonded so the 100 b10 exit leaves exactly the floor.
	s, addr, pub, priv := bondedValidator(t, 1_100*b10, 0)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 1)); !errors.Is(err, ErrNothingToWithdraw) {
		t.Fatalf("Withdraw with no records: err = %v, want ErrNothingToWithdraw", err)
	}
	s.SetHeight(5)
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 100*b10)); err != nil {
		t.Fatalf("Unbond: %v", err)
	}
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 2)); !errors.Is(err, ErrNothingToWithdraw) {
		t.Fatalf("Withdraw with only immature records: err = %v, want ErrNothingToWithdraw", err)
	}
}

// TestUnbondBelowTheFloorIsRefused is the inverse of
// TestBondBelowMinStakeIsRefused (audit ST-1). A committee seats every bond
// with a positive amount, so an Unbond that leaves a positive remainder under
// MIN_STAKE would leave a CANDIDATE worth less than the floor — and the power
// cap's fixed point lifts such a seat to equal power with an honest validator
// (the repository's own 10^12-plus-three-at-one-spark vector converges to four
// seats of power 1). The rule is on the REMAINDER: exactly zero, or at least
// MinStake.
//
// The attack this kills is the whole finding: bond MIN_STAKE, unbond all but
// one spark, and recycle the stake into the next key. The refusal must leave
// the bond, the unbonding map, the nonce and the state ROOT untouched — a
// refused transaction that wrote the decremented bond would be worse than no
// rule at all, because it would leave the one-spark candidate behind while
// returning an error.
func TestUnbondBelowTheFloorIsRefused(t *testing.T) {
	s, addr, pub, priv := bondedValidator(t, minStakeSparks, 0)
	s.SetHeight(5)
	beforeRoot, beforeBonded := s.Root(), s.Bonded(addr)

	// The audit's step: unbond all but one spark.
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, minStakeSparks-1)); !errors.Is(err, ErrStakeBelowMinimum) {
		t.Fatalf("unbond to one spark: err = %v, want ErrStakeBelowMinimum", err)
	}
	if got := s.Bonded(addr); got != beforeBonded {
		t.Fatalf("a refused unbond changed the bond to %d, want %d", got, beforeBonded)
	}
	if recs := s.UnbondingOf(addr); len(recs) != 0 {
		t.Fatalf("a refused unbond created unbonding records: %+v", recs)
	}
	if got := s.Get(addr).Nonce; got != 1 {
		t.Fatalf("a refused unbond consumed a nonce: %d", got)
	}
	if s.Root() != beforeRoot {
		t.Fatal("a refused unbond moved the state root")
	}

	// One spark over the boundary: leaving MIN_STAKE-1 is refused too, so the
	// rule is the remainder and not "all but nothing".
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 1)); !errors.Is(err, ErrStakeBelowMinimum) {
		t.Fatalf("unbond of one spark (leaving MIN_STAKE-1): err = %v, want ErrStakeBelowMinimum", err)
	}

	// And the boundary itself is legal: leaving EXACTLY MinStake is accepted.
	s2, addr2, pub2, priv2 := bondedValidator(t, 1_500*b10, 0)
	s2.SetHeight(5)
	if err := s2.ApplyTx(unbondTx(t, pub2, priv2, addr2, 1, 500*b10)); err != nil {
		t.Fatalf("unbond of 500 b10 leaving exactly MIN_STAKE: %v", err)
	}
	if got := s2.Bonded(addr2); got != minStakeSparks {
		t.Fatalf("Bonded = %d, want exactly MIN_STAKE %d", got, minStakeSparks)
	}

	// A full exit is the other legal remainder (zero), and it still deletes the
	// record.
	if err := s2.ApplyTx(unbondTx(t, pub2, priv2, addr2, 2, minStakeSparks)); err != nil {
		t.Fatalf("full exit from the floor: %v", err)
	}
	if _, ok := s2.bonds[addr2]; ok {
		t.Fatal("a full exit left a bond record behind")
	}
}

// TestASubMinimumGenesisSeatCanOnlyExitInFull is ST-1's carve-out, and it is
// load-bearing rather than defensive: genesis seats are seeded at
// `Amount = Validator.Power` (chain.genesisState), and the devnet and simnet
// fixtures bond their seats at power ONE. Refusing every sub-floor unbond would
// freeze those seats forever — the M5 rotation fixture unbonds exactly such a
// seat, in full, through an ordinary transaction.
//
// So: a bond already below the floor may exit, and only in full. Both halves
// are exercised at the two shapes that exist — a one-spark devnet seat and a
// 600 b10 hand-set seat — because a one-spark bond has no expressible partial
// exit and a 600 b10 one does.
func TestASubMinimumGenesisSeatCanOnlyExitInFull(t *testing.T) {
	// THE ST-1 / ST-3 INTERACTION, decided deliberately. ST-1's carve-out stays:
	// a bond already under the floor may exit, and only in full - the rotation
	// fixture depends on it. ST-3 changes only the PROCEEDS: a genesis seat's
	// bond is unfunded, and an unbond destroys that part instead of recording
	// it, so the exit is legal and pays nothing. Refusing the exit instead
	// (to protect the premine) would freeze exactly the seat M5 rotates.
	t.Run("one-spark devnet seat exits in full, and the spark is destroyed", func(t *testing.T) {
		s := NewWithParams(stakingParams())
		addr, pub, priv := keypair(t)
		// Exactly the genesis initial condition: Amount = Power = 1, and the
		// Unfunded part says no balance paid for it (audit ST-3).
		s.SetBond(addr, Bond{Validator: pub, Amount: 1, Unfunded: 1, Height: 0})
		s.SetHeight(5)

		if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 0, 1)); err != nil {
			t.Fatalf("a one-spark genesis seat must be able to exit (this is the M5 rotation fixture's seat): %v", err)
		}
		if _, ok := s.bonds[addr]; ok {
			t.Fatal("the one-spark seat is still bonded after its full exit")
		}
		if recs := s.UnbondingOf(addr); len(recs) != 0 {
			t.Fatalf("unbonding = %+v, want none: a genesis seat's power is not withdrawable (audit ST-3)", recs)
		}
		s.SetHeight(5 + stakeCooldown)
		if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 1)); !errors.Is(err, ErrNothingToWithdraw) {
			t.Fatalf("withdraw of the exited genesis seat: err = %v, want ErrNothingToWithdraw", err)
		}
		if got := s.Get(addr).Balance; got != 0 {
			t.Fatalf("balance = %d after the exit, want 0: the genesis power is destroyed, not released", got)
		}
	})

	t.Run("600 b10 sub-floor seat cannot exit partially", func(t *testing.T) {
		s := NewWithParams(stakingParams())
		addr, pub, priv := keypair(t)
		s.SetBond(addr, Bond{Validator: pub, Amount: 600 * b10, Unfunded: 600 * b10, Height: 0})
		s.SetHeight(5)
		beforeRoot := s.Root()

		// Every partial remainder of a sub-floor bond is itself sub-floor, so
		// any partial exit is refused ...
		if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 0, 100*b10)); !errors.Is(err, ErrStakeBelowMinimum) {
			t.Fatalf("partial exit from a sub-floor genesis seat: err = %v, want ErrStakeBelowMinimum", err)
		}
		if got := s.Bonded(addr); got != 600*b10 {
			t.Fatalf("a refused partial exit changed the seat's bond to %d", got)
		}
		if s.Root() != beforeRoot {
			t.Fatal("a refused partial exit moved the state root")
		}

		// ... and the full exit is accepted.
		if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 0, 600*b10)); err != nil {
			t.Fatalf("the full exit from a sub-floor genesis seat must be accepted: %v", err)
		}
		if got := s.Bonded(addr); got != 0 {
			t.Fatalf("Bonded = %d after the full exit, want 0", got)
		}
		if recs := s.UnbondingOf(addr); len(recs) != 0 {
			t.Fatalf("the full exit recorded %+v, want no record: the seat is unfunded (audit ST-3)", recs)
		}
	})
}

// TestAGenesisBondIsUnfundedAndUnbondingItReleasesNothing is ST-3's rule at its
// simplest, constructed exactly as chain.genesisState builds a genesis seat: a
// MIN_STAKE bond with Unfunded = Amount and no account behind it. The seat
// leaves when it unbonds, the sparks do not follow it out, and the supply sum
// falls by exactly the grant - the one transition that destroys value, and only
// value the genesis created.
func TestAGenesisBondIsUnfundedAndUnbondingItReleasesNothing(t *testing.T) {
	s := NewWithParams(stakingParams())
	addr, pub, priv := keypair(t)
	s.SetBond(addr, Bond{Validator: pub, Amount: minStakeSparks, Unfunded: minStakeSparks, Height: 0})
	before := supplySum(s)

	s.SetHeight(5)
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 0, minStakeSparks)); err != nil {
		t.Fatalf("a genesis seat must be able to unbond: %v", err)
	}
	if got := s.Bonded(addr); got != 0 {
		t.Fatalf("Bonded = %d after the exit, want 0", got)
	}
	if got := s.TotalUnbonding(); got != 0 {
		t.Fatalf("TotalUnbonding = %d, want 0: the unfunded grant must not become an unbonding record", got)
	}
	if recs := s.UnbondingOf(addr); len(recs) != 0 {
		t.Fatalf("UnbondingOf = %+v, want none", recs)
	}
	if got, want := supplySum(s), before-minStakeSparks; got != want {
		t.Fatalf("supply sum after the genesis exit = %d, want %d: exactly the grant is destroyed", got, want)
	}

	// No height ever pays it out, because no record exists to mature.
	s.SetHeight(5 + stakeCooldown)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 1)); !errors.Is(err, ErrNothingToWithdraw) {
		t.Fatalf("withdraw at the would-be release height: err = %v, want ErrNothingToWithdraw", err)
	}
	if got := s.Get(addr).Balance; got != 0 {
		t.Fatalf("balance = %d, want 0", got)
	}
}

// TestAFundedTopUpOnAGenesisSeatStaysWithdrawable is why Bond.Unfunded exists
// instead of a bare Height == 0 test. A genesis seat that bonds its own funds
// must be able to get THOSE sparks back while the grant is destroyed; a rule
// that burned the whole bond would destroy an operator's money, and one that
// paid the whole bond would pay out the grant.
func TestAFundedTopUpOnAGenesisSeatStaysWithdrawable(t *testing.T) {
	s := NewWithParams(stakingParams())
	addr, pub, priv := keypair(t)
	// The devnet fixture's shape: a one-spark genesis seat ...
	s.SetBond(addr, Bond{Validator: pub, Amount: 1, Unfunded: 1, Height: 0})
	// ... funded with its own MIN_STAKE through an ordinary Bond.
	s.Set(addr, Account{Balance: minStakeSparks + 1}) // +1: the bond's fee
	if err := s.ApplyTx(bondTx(t, pub, priv, addr, 0, minStakeSparks, 1)); err != nil {
		t.Fatalf("topping up a genesis seat: %v", err)
	}
	bond, ok := s.BondOf(addr)
	if !ok || bond.Amount != minStakeSparks+1 || bond.Unfunded != 1 || bond.Height != 0 {
		t.Fatalf("bond after the top-up = %+v, want Amount %d (the grant plus the funded MIN_STAKE), Unfunded 1, Height 0",
			bond, minStakeSparks+1)
	}

	// The genesis spark goes first and is destroyed; the remaining bond is
	// fully funded, which is the ST-1 floor's exact boundary (MIN_STAKE).
	s.SetHeight(3)
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 1)); err != nil {
		t.Fatalf("unbonding the unfunded spark: %v", err)
	}
	if recs := s.UnbondingOf(addr); len(recs) != 0 {
		t.Fatalf("unbonding the genesis spark recorded %+v, want none", recs)
	}
	bond, _ = s.BondOf(addr)
	if bond.Amount != minStakeSparks || bond.Unfunded != 0 {
		t.Fatalf("bond = %+v, want the funded MIN_STAKE with Unfunded 0", bond)
	}

	// The funded part exits normally and IS withdrawable.
	if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 2, minStakeSparks)); err != nil {
		t.Fatalf("unbonding the funded part: %v", err)
	}
	recs := s.UnbondingOf(addr)
	if len(recs) != 1 || recs[0].Amount != minStakeSparks {
		t.Fatalf("unbonding = %+v, want one funded MIN_STAKE record", recs)
	}
	s.SetHeight(recs[0].ReleaseHeight)
	if err := s.ApplyTx(withdrawTx(t, pub, priv, addr, 3)); err != nil {
		t.Fatalf("withdraw of the funded part: %v", err)
	}
	if got := s.Get(addr).Balance; got != minStakeSparks {
		t.Fatalf("balance = %d, want the funded MIN_STAKE back", got)
	}
}

// TestBondAndUnbondingLeafGoldenVectors freezes the exact bytes of the two M5
// leaves and the root of a state that holds one of each (audit ST-8).
//
// This is the test the differential suite cannot be. Every stake-root test
// before it compares two states that differ in ONE field; a state with the right
// root under swap (A,B) and swap (B,A) is indistinguishable to them, so an
// encoder that wrote Height before Amount would pass the whole suite. A fixed
// vector names the order. It is captured ONCE, and the fields are chosen to be
// pairwise distinct for exactly that reason:
//
//	bond      Validator 0xc0..0xdf, Amount 0x0102030405060708,
//	          Unfunded 0x1112131415161718, Height 0x2122232425262728
//	unbonding two records, each (Amount, ReleaseHeight) a distinct value
//
// The vector also pins the domains and the Merkle construction: the root is
// taken from a state with no accounts, one bond and one unbonding record, so it
// is H(0x01 || H(0x00 || bondLeaf) || H(0x00 || unbondingLeaf)) and nothing else.
//
// DO NOT re-capture these from a fresh run to make a failing test pass. A
// changed value is a consensus-encoding change: look at what moved first.
func TestBondAndUnbondingLeafGoldenVectors(t *testing.T) {
	addr := types.Address{
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
		0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
	}
	validator := make([]byte, 32)
	for i := range validator {
		validator[i] = byte(0xc0 + i)
	}
	bond := Bond{
		Validator: validator,
		Amount:    0x0102030405060708,
		Unfunded:  0x1112131415161718,
		Height:    0x2122232425262728,
	}
	records := []Unbonding{
		{Amount: 0x0102030405060708, ReleaseHeight: 0x3132333435363738},
		{Amount: 0x4142434445464748, ReleaseHeight: 0x5152535455565758},
	}

	var wantBondLeaf = [32]byte{
		0x57, 0x22, 0x40, 0xa5, 0xc2, 0x93, 0x3c, 0x62, 0x72, 0x8c, 0xb1, 0x3c, 0x68, 0x8a, 0x14, 0xd1,
		0xd5, 0x2b, 0x2c, 0x51, 0xd5, 0xce, 0x5d, 0x1a, 0xdf, 0x82, 0x6a, 0x2e, 0xa8, 0xfc, 0xb0, 0x44,
	}
	if got := bondLeaf(addr, bond); got != wantBondLeaf {
		t.Fatalf("bond leaf changed:\n got %x\nwant %x", got, wantBondLeaf)
	}

	var wantUnbondingLeaf = [32]byte{
		0xa2, 0xb9, 0x77, 0xf1, 0x1d, 0xb9, 0x02, 0xa8, 0x68, 0x1e, 0xe1, 0x5c, 0xfa, 0xbe, 0x8e, 0x4d,
		0x17, 0xf1, 0xb2, 0x15, 0x4c, 0x01, 0x0e, 0x44, 0x29, 0x48, 0x5f, 0x0f, 0x42, 0xfc, 0xea, 0xc7,
	}
	if got := unbondingLeaf(addr, records); got != wantUnbondingLeaf {
		t.Fatalf("unbonding leaf changed:\n got %x\nwant %x", got, wantUnbondingLeaf)
	}

	// The root of a state whose ONLY leaves are those two: Root must use the
	// same encoders, in the bond-then-unbonding order, under the same Merkle
	// construction. Without this half a leaf helper could drift from Root
	// without any test noticing (the "inert helper" mutant).
	s := NewWithParams(stakingParams())
	s.SetBond(addr, bond)
	s.unbonding[addr] = records
	var wantRoot = [32]byte{
		0xa2, 0xaf, 0x35, 0x57, 0xcf, 0xb5, 0xaa, 0xfe, 0x0e, 0xc2, 0x29, 0x3b, 0xe8, 0x78, 0xb4, 0x13,
		0x2a, 0xcf, 0xe1, 0xc6, 0xee, 0x71, 0x42, 0xcf, 0xc4, 0x98, 0x1a, 0xa1, 0xd4, 0x88, 0x8b, 0xce,
	}
	if got := s.Root(); got != wantRoot {
		t.Fatalf("bond+unbonding golden root changed:\n got %x\nwant %x", got, wantRoot)
	}
}

// TestAnUnbondAtEpochEndAndAtTheBoundarySharesOneReleaseHeight pins the rounding
// rule at the two heights an epoch boundary creates (audit ST-9). With a
// two-epoch cooldown and E-block epochs:
//
//	unbond at E-1: release = E-1 + 2E = 3E-1, rounded UP to 3E
//	unbond at E:   release = E   + 2E = 3E,   already a boundary
//
// so the last block before a boundary is delayed by one block and the first
// block of the new epoch is not delayed at all. That is the whole cost of ST-4's
// record bound, and a "round down" or "round half up" mutant would separate
// these two heights.
func TestAnUnbondAtEpochEndAndAtTheBoundarySharesOneReleaseHeight(t *testing.T) {
	const E = uint64(stakeTestEpochBlocks) // 10
	wantRelease := 3 * E                   // 30
	for _, tc := range []struct {
		name   string
		height uint64
	}{
		{"last block before the boundary (E-1, rounds up)", E - 1},
		{"first block of the boundary (E, exact)", E},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, addr, pub, priv := bondedValidator(t, minStakeSparks, 0)
			s.SetHeight(tc.height)
			if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, minStakeSparks)); err != nil {
				t.Fatalf("unbond at height %d: %v", tc.height, err)
			}
			recs := s.UnbondingOf(addr)
			if len(recs) != 1 {
				t.Fatalf("unbonding = %+v, want one record", recs)
			}
			if recs[0].ReleaseHeight != wantRelease {
				t.Fatalf("unbond at height %d releases at %d, want %d (3E: the cooldown rounded up)",
					tc.height, recs[0].ReleaseHeight, wantRelease)
			}
			// The cooldown must never pay EARLIER than height + UnbondingEpochs*E:
			// the E-1 record is the one the raw sum (29) would have released a
			// block early.
			if raw := tc.height + stakeCooldown; recs[0].ReleaseHeight < raw {
				t.Fatalf("unbond at height %d releases at %d, earlier than the raw cooldown %d",
					tc.height, recs[0].ReleaseHeight, raw)
			}
		})
	}
}

// TestMergeUnbondingRefusesAnOverflow is the record bookkeeping's arithmetic
// guard (audit ST-9). mergeUnbonding sums records twice:
//
//  1. already-matured records collapse into one, and their amounts are added;
//  2. the new amount merges into the record at its release height.
//
// Every sum is checked BEFORE the first write, and a wrapped sum would be a
// record that pays out fewer sparks than it holds while consuming both - a
// silent loss, not a crash. No reachable state can hold such amounts (each was
// debited from a balance), which is exactly why the guard needs a CONSTRUCTED
// state and a test: it is the check that keeps a hand-built state from turning
// the omission into money.
func TestMergeUnbondingRefusesAnOverflow(t *testing.T) {
	t.Run("two matured records whose amounts sum past MaxUint64", func(t *testing.T) {
		s, addr, pub, priv := bondedValidator(t, minStakeSparks+1, 0)
		s.SetHeight(20)
		s.unbonding[addr] = []Unbonding{
			{Amount: math.MaxUint64, ReleaseHeight: 10},
			{Amount: 1, ReleaseHeight: 10},
		}
		beforeRoot := s.Root()

		if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 1)); !errors.Is(err, ErrBalanceOverflow) {
			t.Fatalf("unbond over overflowing matured records: err = %v, want ErrBalanceOverflow", err)
		}
		if s.Root() != beforeRoot {
			t.Fatal("a refused merge moved the state root")
		}
		if got := s.Bonded(addr); got != minStakeSparks+1 {
			t.Fatalf("a refused merge changed the bond to %d, want %d", got, minStakeSparks+1)
		}
	})

	t.Run("a new amount merged at an existing release height overflows", func(t *testing.T) {
		s, addr, pub, priv := bondedValidator(t, minStakeSparks+1, 0)
		s.SetHeight(20)
		release, err := releaseHeightFor(20, 2, stakeTestEpochBlocks) // 40
		if err != nil {
			t.Fatal(err)
		}
		s.unbonding[addr] = []Unbonding{{Amount: math.MaxUint64, ReleaseHeight: release}}
		beforeRoot := s.Root()

		if err := s.ApplyTx(unbondTx(t, pub, priv, addr, 1, 1)); !errors.Is(err, ErrBalanceOverflow) {
			t.Fatalf("unbond merging into an overflowing record: err = %v, want ErrBalanceOverflow", err)
		}
		if s.Root() != beforeRoot {
			t.Fatal("a refused merge moved the state root")
		}
	})
}
