package state

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"slices"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

// Staking is committed state, not a balance with a lock flag (M5 design
// decision 1). A bond is a record - (validator, amount, height) - held
// SEPARATELY from the spendable balance:
//
//	spendable (Account.Balance) + bonded (bonds) + unbonding (unbonding)
//
// is conserved exactly by `Unbond` and `Withdraw`: `Unbond` moves sparks from
// the second term to the third, and `Withdraw` from the third back to the
// first. `Bond` moves only its Amount from the first term to the second; it
// also pays its fee out of the first term and BURNS it (applyBond), so a Bond
// lowers the sum by exactly its fee, just as a transfer does. Unbond and
// Withdraw carry fee 0 by consensus and are the only stake transactions that
// conserve the sum. The fee burn is the only per-transaction destruction;
// emission and faucet claims are chain-level and move the sum as a whole.
//
// The one exception is the genesis bond (audit ST-3): the genesis state writes
// it from no account, and an Unbond DESTROYS its unfunded part instead of
// recording it, so the sum falls by exactly the sparks the genesis created.
// That is deliberate - it is the only way a spark that no balance ever paid for
// can leave the three terms without becoming somebody's money.
//
// The third term is worth NOTHING until its release height: an unbonding
// record is not spendable (it is not in Account.Balance) and not counted (it is
// not in the bond map, so it is not a committee candidate). That is what makes
// the cooldown an economic delay instead of a formality - the coins are gone
// from both uses at once, not merely flagged.
//
// GENESIS IS THE INITIAL CONDITION, not a double count: chain.genesisState
// seats the genesis validators by writing a bond per genesis.Validator
// (Amount = Power, Unfunded = Power, Height = 0), funded by the genesis hash
// rather than by any balance. Height 0 therefore has bonded stake that no
// balance ever paid for, and the invariant above is about the TRANSITIONS, not
// about a chain starting from zero in all three terms. The Unfunded part is
// what keeps that initial condition from being money: see applyUnbond.

// Bond is one validator's locked stake at one address. Validator is the
// ed25519 public key the committee seats (an address is only a hash of it, so
// the key cannot be recovered from the map key). Height is the height at which
// the record was first created; a later Bond that adds to the same address
// keeps the earliest height and the first-recorded key.
//
// Unfunded is the part of Amount that the genesis state created rather than a
// balance funded. It is VOTING POWER, not money (audit ST-3): applyUnbond
// destroys it instead of recording it for withdrawal, so a genesis seat can
// leave the committee but its Power can never be drawn out. A bond a Bond
// transaction created carries Unfunded 0 - every spark its operator paid in is
// withdrawable - and a genesis seat that bonds its own funds on top keeps the
// two parts separate, so its funded sparks stay withdrawable while the grant
// does not. It is committed state (state.Root hashes it): whether an unbond
// pays out is a consensus rule, not a local opinion.
type Bond struct {
	Validator []byte // ed25519 public key: the identity the committee seats
	Amount    uint64 // sparks, locked
	Unfunded  uint64 // sparks in Amount that genesis created; destroyed on Unbond
	Height    uint64 // the height at which it was recorded
}

// Unbonding is a matured-by-height claim on sparks. Amount is released to the
// spendable balance by a Withdraw at any height >= ReleaseHeight.
type Unbonding struct {
	Amount uint64
	// ReleaseHeight is the epoch boundary at or after
	// height + UnbondingEpochs*EpochBlocks (see releaseHeightFor): never
	// earlier than the cooldown, up to one epoch later.
	ReleaseHeight uint64
}

var (
	// ErrStakeUnconfigured reports a stake transaction against a state whose
	// Params hold no staking configuration (the zero value from New, whose
	// M0-M1 behaviour is that staking is unusable, never that it panics or
	// divides by zero).
	ErrStakeUnconfigured = errors.New("state: staking is not parameterised on this chain")
	// ErrStakeBelowMinimum reports a stake transition whose RESULTING bond is
	// under the chain's MinStake: a Bond that would land there, or an Unbond
	// that would LEAVE a positive remainder there (audit ST-1 - a sub-minimum
	// bond is still a committee candidate, and the power cap lifts one spark to
	// a full seat). The floor is on the result, not on one transaction, so
	// several bonds may accumulate to it (a single payment below it is cheap
	// spam: one bond record per attacker-chosen key).
	ErrStakeBelowMinimum = errors.New("state: the resulting bond is below the chain's minimum stake")
	// ErrStakeCarriesFee reports an Unbond or Withdraw with a non-zero fee. An
	// exit is deliberately free (see applyUnbond): a validator may hold nothing
	// spendable, and an exit that needed a coin is one a zero-balance operator
	// could never make, leaving a seat that must leave un-rotatable.
	ErrStakeCarriesFee = errors.New("state: an unbond or withdraw must not carry a fee")
	// ErrUnbondExceedsBond reports an Unbond larger than the address's bond.
	ErrUnbondExceedsBond = errors.New("state: unbond exceeds the bonded amount")
	// ErrNothingToWithdraw reports a Withdraw with no record at or below the
	// current height. It is also what a SECOND withdraw of the same record
	// gets: the first consumed it, so the payout happens exactly once.
	ErrNothingToWithdraw = errors.New("state: no unbonding record has matured")
	// ErrReleaseHeightOverflow reports a release height that cannot be formed.
	// The cooldown is UnbondingEpochs*EpochBlocks, both genesis-controlled
	// uint64s, so the product is overflow-checked before it is added to the
	// height, and the rounding up to the epoch boundary is checked too - a
	// wrapped release height would mature a record in the past.
	ErrReleaseHeightOverflow = errors.New("state: the unbonding release height would overflow")
)

// Bonded returns the address's locked bond in sparks, or 0 if it holds none.
// It reads ONLY the bond map: an unbonding record is not a bond and is not
// counted here, which is the "unbonding coins are not counted" half of the
// cooldown, and the accessor the committee derivation (M5 Task 2) uses.
func (s *State) Bonded(a types.Address) uint64 { return s.bonds[a].Amount }

// HasUnbonding reports whether the address holds ANY unbonding record, mature or
// not. It is one map lookup, and it exists for the mempool's staking admission
// (audit ST-5): a Withdraw from an address with no such record can never apply,
// so the pool need not spend a slot and a signature check holding it. Maturity -
// a height-dependent fact - is deliberately not decided here; execution still
// judges it.
func (s *State) HasUnbonding(a types.Address) bool { return len(s.unbonding[a]) > 0 }

// BondOf returns a copy of the address's bond record and whether it holds one.
// It is the record-level sibling of Bonded (which returns only the amount), for
// callers that must show WHEN the stake was locked and WHICH key it seats - the
// /account view and the tests. The Validator slice is copied, so the caller
// cannot reach committed state through it.
func (s *State) BondOf(a types.Address) (Bond, bool) {
	b, ok := s.bonds[a]
	if !ok {
		return Bond{}, false
	}
	b.Validator = slices.Clone(b.Validator)
	return b, true
}

// UnbondingOf returns a copy of the address's unbonding records sorted by
// ReleaseHeight ascending. It is a COPY so a caller - the RPC /account view,
// the tests - cannot mutate committed state through it.
func (s *State) UnbondingOf(a types.Address) []Unbonding {
	recs := s.unbonding[a]
	if len(recs) == 0 {
		return nil
	}
	out := slices.Clone(recs)
	slices.SortFunc(out, compareUnbonding)
	return out
}

// compareUnbonding orders records by release height, then amount. The amount
// tie-break exists for determinism only: applyUnbond merges records at the same
// release height, so a committed state never holds two. A hand-built state can,
// and the root must still be a function of its contents (a non-stable sort
// would otherwise hash an arbitrary order).
func compareUnbonding(x, y Unbonding) int {
	switch {
	case x.ReleaseHeight < y.ReleaseHeight:
		return -1
	case x.ReleaseHeight > y.ReleaseHeight:
		return 1
	case x.Amount < y.Amount:
		return -1
	case x.Amount > y.Amount:
		return 1
	default:
		return 0
	}
}

// TotalBonded is the sum of every bond. It is a read-only aggregate: like
// TotalBalance it assumes the chain's supply is bounded (every bond was either
// funded from a balance or, at genesis, from a genesis power), so the sum
// cannot wrap in any state a chain builds. A caller that needs the arithmetic
// to be safe against a hand-built state must use checked adds, as the
// committee derivation does.
func (s *State) TotalBonded() uint64 {
	var total uint64
	for _, b := range s.bonds {
		total += b.Amount
	}
	return total
}

// TotalUnbonding is the sum of every unbonding record, on TotalBonded's terms.
func (s *State) TotalUnbonding() uint64 {
	var total uint64
	for _, recs := range s.unbonding {
		for _, rec := range recs {
			total += rec.Amount
		}
	}
	return total
}

// SetBond records a bond directly. LIKE Set AND SetHeight, THIS IS NOT A PUBLIC
// MUTATOR: it exists so chain.genesisState can seed the genesis seats (which no
// balance funds) and so tests can construct committed state exactly. Every bond
// a TRANSACTION creates goes through applyBond, which enforces the fee floor,
// the minimum stake, the balance and the overflow checks; a caller that writes
// through here bypasses all of them. A zero amount prunes the record, exactly
// as Set prunes a zero account.
//
// A genesis seat must also set Unfunded = Amount (chain.genesisState does);
// that field is what makes its exit destroy the power instead of paying it out
// (audit ST-3). Leaving it zero records a grant as if a balance had funded it.
func (s *State) SetBond(a types.Address, b Bond) {
	if b.Amount == 0 {
		delete(s.bonds, a)
		return
	}
	s.bonds[a] = b
}

// stakeConfigured reports whether Params hold the values the staking rules
// need. A zero MinStake, UnbondingEpochs or EpochBlocks makes every stake
// transaction fail with ErrStakeUnconfigured: a zero floor would admit a
// one-spark bond, a zero cooldown would release an unbond at once, and a zero
// epoch length would divide a release height into no time at all.
func (s *State) stakeConfigured() bool {
	return s.params.MinStake > 0 && s.params.UnbondingEpochs > 0 && s.params.EpochBlocks > 0
}

// releaseHeightFor derives an unbonding record's release height:
//
//	releaseHeight = the epoch boundary at or after height + UnbondingEpochs*EpochBlocks
//
// The cooldown is TWO EPOCHS, not two blocks. Derivation: the shipped geneses
// set UnbondingEpochs = 2 (genesis.sharedParams), and EpochBlocks is the
// chain's epoch length in blocks - 1,000 on devnet, 10,000 on testnet - so the
// cooldown is at least 2 x 1,000 = 2,000 devnet blocks and at least
// 2 x 10,000 = 20,000 testnet blocks. It is deliberately expressed in EPOCHS so
// a chain that lengthens its epochs lengthens the cooldown with it: "an epoch"
// is the unit the committee and the faucet already turn on, and a cooldown
// measured in absolute blocks would silently become a smaller fraction of a
// term as epochs grew.
//
// ROUNDING UP TO THE EPOCH BOUNDARY IS THE RECORD BOUND (audit ST-4). Records
// merge only at one release height, so before this rule one one-spark unbond
// per block created one record per block - cloned on every ApplyBlock and
// Probe, hashed into the root, replayed on Open and serialised by /account.
// Every release height is now a multiple of EpochBlocks, so at any height an
// address holds at most UnbondingEpochs+1 UNMATURED records: the release
// heights in (height, height + cooldown + EpochBlocks - 1] are that many
// multiples. Records that have already matured are collapsed when the next
// funded unbond arrives (mergeUnbonding), which keeps the whole list at
// UnbondingEpochs+2 - one matured record plus the unmatured window - for the
// life of the address, however many unbonds it sends.
//
// The costs of the rounding, stated rather than hidden: a release is never
// EARLIER than height + cooldown (rounding is upward), and it can be LATER by
// up to EpochBlocks-1 blocks - just under one epoch - because the unbond lands
// mid-epoch. An unbond whose cooldown ends exactly on a boundary (h + cooldown
// a multiple of EpochBlocks) does not move at all. Withdrawability is therefore
// delayed by 0..E-1 blocks, never advanced, and the cooldown's guarantee ("at
// least UnbondingEpochs epochs") still holds.
//
// Both factors are genesis-controlled, so the product is overflow-checked
// (bits.Mul64 reports the carry) before it is added to the height, and the
// rounding is checked too. A wrapped release height would be a release in the
// past - an unbond that pays out immediately, which is the one thing the
// cooldown must not do.
func releaseHeightFor(height, unbondingEpochs, epochBlocks uint64) (uint64, error) {
	if epochBlocks == 0 {
		// Unreachable through ApplyTx (stakeConfigured refuses it first), but
		// this function now divides by it, so a caller mistake is an error and
		// never a panic.
		return 0, fmt.Errorf("%w: EpochBlocks is zero, so a release height cannot be rounded", ErrStakeUnconfigured)
	}
	hi, cooldown := bits.Mul64(unbondingEpochs, epochBlocks)
	if hi != 0 {
		return 0, fmt.Errorf("%w: %d epochs x %d blocks does not fit in 64 bits",
			ErrReleaseHeightOverflow, unbondingEpochs, epochBlocks)
	}
	if height > math.MaxUint64-cooldown {
		return 0, fmt.Errorf("%w: height %d + cooldown %d", ErrReleaseHeightOverflow, height, cooldown)
	}
	release := height + cooldown
	if rem := release % epochBlocks; rem != 0 {
		roundUp := epochBlocks - rem
		if release > math.MaxUint64-roundUp {
			return 0, fmt.Errorf("%w: rounding %d up to the next %d-block epoch boundary",
				ErrReleaseHeightOverflow, release, epochBlocks)
		}
		release += roundUp
	}
	return release, nil
}

// applyBond moves sparks from the sender's spendable balance into a locked bond
// record. It is the admission path (M5 design decision 4): a bond is a signed,
// fee-paying transaction ordered like any other, not a separate channel.
func (s *State) applyBond(tx *types.Tx) error {
	if !s.stakeConfigured() {
		return fmt.Errorf("%w: MinStake %d, UnbondingEpochs %d, EpochBlocks %d",
			ErrStakeUnconfigured, s.params.MinStake, s.params.UnbondingEpochs, s.params.EpochBlocks)
	}
	if tx.Amount == 0 {
		return ErrZeroAmount
	}
	// The same fee floor a transfer pays (audit S-3), checked before the
	// balance so an underpaying bond is refused for what it got wrong rather
	// than for an incidental lack of funds.
	if tx.Fee < s.params.MinFee {
		return fmt.Errorf("%w: fee %d is below the chain's minimum %d", ErrFeeTooLow, tx.Fee, s.params.MinFee)
	}
	// The sender pays the bond AND the fee. The sum is formed once, with the
	// overflow check, so a crafted pair cannot wrap it below the balance.
	total := tx.Amount + tx.Fee
	if total < tx.Amount {
		return ErrBalanceOverflow
	}

	from := s.Get(tx.From)
	if from.Nonce != tx.Nonce {
		return fmt.Errorf("%w: got %d, want %d", ErrBadNonce, tx.Nonce, from.Nonce)
	}
	if from.Balance < total {
		return fmt.Errorf("%w: have %d, need %d (bond %d + fee %d)", ErrInsufficientFunds, from.Balance, total, tx.Amount, tx.Fee)
	}

	// The accumulation side is overflow-checked too: a second bond adds to the
	// same record, and a wrapped amount would lock less than it says.
	bond := s.bonds[tx.From]
	if bond.Amount > math.MaxUint64-tx.Amount {
		return fmt.Errorf("%w: bonded %d + new %d", ErrBalanceOverflow, bond.Amount, tx.Amount)
	}
	resulting := bond.Amount + tx.Amount
	// The floor is on the RESULT, so 600 followed by 500 is legal (1,100
	// clears a 1,000 floor) while 600 alone is not.
	if resulting < s.params.MinStake {
		return fmt.Errorf("%w: bond would be %d, minimum is %d", ErrStakeBelowMinimum, resulting, s.params.MinStake)
	}

	// Every validation has run; write. The first-recorded key and height are
	// kept on accumulation: VerifySignature forces From == AddressFromPub,
	// so the key of a second bond for one address is the same key, and the
	// record's height is when the stake was first locked.
	if len(bond.Validator) == 0 {
		// Copy: the record must not alias the transaction's slice.
		bond.Validator = slices.Clone(tx.PubKey)
		bond.Height = s.height
	}
	bond.Amount = resulting

	from.Balance -= total
	from.Nonce++
	s.Set(tx.From, from)
	s.SetBond(tx.From, bond)
	return nil
}

// applyUnbond moves sparks from the bond record into an unbonding record whose
// release height is the epoch boundary at or after s.height + the cooldown.
// The coins leave the bond map - they are no longer a committee candidate - and
// do not reach the balance, so they are neither spendable nor counted until the
// release height.
//
// THE UNFUNDED PART IS DESTROYED, NOT RECORDED (audit ST-3). A genesis seat's
// bond was written from no account (chain.genesisState), so recording its exit
// would turn a grant of voting power into withdrawable money: one cooldown
// after a chain starts, the operator would hold Power sparks nobody paid for,
// outside TotalSupplySparks. The exit itself must stay legal - a genesis seat
// is exactly what the rotation fixture unbonds, and a seat that cannot leave is
// a seat that can never rotate - so the split is on the PROCEEDS, not on the
// verb: the unfunded part is burned, the funded part becomes an unbonding
// record. Bond.Unfunded carries the split, so a genesis seat that bonds its own
// funds on top still withdraws those funds; Height == 0 alone would conflate
// the two.
//
// It is DELIBERATELY FREE. A validator may hold nothing spendable (its whole
// balance may be bonded), and an exit that needs a coin is an exit a zero-balance
// operator could never make - which would leave a seat that must leave
// un-rotatable at the next boundary of M5 Task 3.
func (s *State) applyUnbond(tx *types.Tx) error {
	if !s.stakeConfigured() {
		return fmt.Errorf("%w: MinStake %d, UnbondingEpochs %d, EpochBlocks %d",
			ErrStakeUnconfigured, s.params.MinStake, s.params.UnbondingEpochs, s.params.EpochBlocks)
	}
	if tx.Fee != 0 {
		return fmt.Errorf("%w: unbond carries fee %d", ErrStakeCarriesFee, tx.Fee)
	}
	if tx.Amount == 0 {
		return ErrZeroAmount
	}

	from := s.Get(tx.From)
	if from.Nonce != tx.Nonce {
		return fmt.Errorf("%w: got %d, want %d", ErrBadNonce, tx.Nonce, from.Nonce)
	}
	bond := s.bonds[tx.From]
	if tx.Amount > bond.Amount {
		return fmt.Errorf("%w: unbond %d, bonded %d", ErrUnbondExceedsBond, tx.Amount, bond.Amount)
	}
	// THE CANDIDACY FLOOR, as a state invariant (audit ST-1). Committee seats
	// every bond with a positive amount, and applyPowerCap's fixed point then
	// equalises a one-spark seat with a whale - the repository's own vector
	// (10^12 plus three at one spark) converges to four seats of power 1, so
	// three one-spark seats hold 3/4 of the committee and can commit alone.
	// An Unbond therefore leaves either nothing or at least MinStake.
	//
	// The carve-out is the `remainder == 0` half of the rule, and it needs no
	// special case. A bond ALREADY below the floor - a genesis seat, which
	// chain.genesisState seeds at Amount = Power, so the devnet and simnet
	// fixtures sit at one spark - cannot leave a partial remainder that clears
	// the floor, because every partial remainder is smaller than the bond. Its
	// only legal exit is the full one, which is `remainder == 0`: a genesis
	// seat can leave, it cannot leave a sub-minimum bond behind.
	remainder := bond.Amount - tx.Amount
	if remainder != 0 && remainder < s.params.MinStake {
		return fmt.Errorf("%w: unbond %d of %d would leave %d bonded, below the minimum %d; exit in full or leave at least the minimum",
			ErrStakeBelowMinimum, tx.Amount, bond.Amount, remainder, s.params.MinStake)
	}

	release, err := releaseHeightFor(s.height, s.params.UnbondingEpochs, s.params.EpochBlocks)
	if err != nil {
		return err
	}

	// ST-3's split. The unfunded sparks leave the bond and are destroyed; only
	// the funded remainder is owed to the address. `unfundedOut` can be the
	// whole amount (a pure genesis seat, the rotation fixture's case) or zero
	// (every bond a Bond transaction created); a hand-built state can put
	// Unfunded above Amount, which min() floors.
	unfundedOut := min(tx.Amount, bond.Unfunded)
	fundedOut := tx.Amount - unfundedOut

	// The funded part's record list, with both normalisations applied and every
	// sum checked BEFORE the first write. ApplyTx's contract is that a rejected
	// transaction leaves the receiver untouched, and chain.SelectApplicable runs
	// many candidates against one shared state on exactly that promise.
	recs := s.unbonding[tx.From]
	if fundedOut > 0 {
		var err error
		if recs, err = mergeUnbonding(recs, s.height, release, fundedOut); err != nil {
			return err
		}
	}

	// Every validation has run; write. The bond keeps the height and key it
	// was first recorded with (genesis, for a genesis seat), and drops only the
	// part that left - including from Unfunded, so a later unbond cannot burn
	// the same grant twice.
	bond.Unfunded -= unfundedOut
	if remainder == 0 {
		delete(s.bonds, tx.From)
	} else {
		bond.Amount = remainder
		s.bonds[tx.From] = bond
	}
	if fundedOut > 0 {
		s.unbonding[tx.From] = recs
	}
	from.Nonce++
	s.Set(tx.From, from)
	return nil
}

// mergeUnbonding is applyUnbond's record bookkeeping, kept separate so all of
// it runs before the first write and so the bound is a property of one function.
// Two normalisations, both sum-checked:
//
//  1. Every record ALREADY mature at height is collapsed into one record whose
//     release height is the earliest of theirs and whose amount is their sum.
//     This cannot change what a withdrawal pays: a Withdraw releases every
//     record with ReleaseHeight <= the withdrawing block's height, height only
//     grows, and all of these records are already <= height - so they are
//     indistinguishable to every future Withdraw. It is what keeps the record
//     count constant rather than growing by one per epoch for an address that
//     never withdraws (audit ST-4).
//  2. The new amount is merged into the record at its own release height, or
//     appended as a new record when none is at that height.
//
// The caller has already checked that amount is a funded exit; a pure genesis
// exit never reaches here, so it never rewrites other records.
func mergeUnbonding(recs []Unbonding, height, release, amount uint64) ([]Unbonding, error) {
	out := make([]Unbonding, 0, len(recs)+1)
	matured := Unbonding{}
	mergedMatured := false
	for _, rec := range recs {
		if rec.ReleaseHeight > height {
			out = append(out, rec)
			continue
		}
		if !mergedMatured {
			matured = rec
			mergedMatured = true
			continue
		}
		if matured.Amount > math.MaxUint64-rec.Amount {
			return nil, fmt.Errorf("%w: matured records %d + %d", ErrBalanceOverflow, matured.Amount, rec.Amount)
		}
		matured.Amount += rec.Amount
		if rec.ReleaseHeight < matured.ReleaseHeight {
			matured.ReleaseHeight = rec.ReleaseHeight
		}
	}
	if mergedMatured {
		out = append(out, matured)
	}
	for i := range out {
		if out[i].ReleaseHeight != release {
			continue
		}
		if out[i].Amount > math.MaxUint64-amount {
			return nil, fmt.Errorf("%w: unbonding %d + new %d", ErrBalanceOverflow, out[i].Amount, amount)
		}
		out[i].Amount += amount
		return out, nil
	}
	return append(out, Unbonding{Amount: amount, ReleaseHeight: release}), nil
}

// applyWithdraw releases EVERY unbonding record that has matured
// (ReleaseHeight <= s.height) to the spendable balance, in one transaction.
// A record is releasable at exactly its release height - the rule is <=, not <
// - so a record created at h with cooldown c pays out from h+c onward.
//
// Like applyUnbond it is free. It errors with ErrNothingToWithdraw when no
// record is mature, which is also what a SECOND withdraw of the same record
// gets: the first consumed every mature record, so the payout happens exactly
// once.
func (s *State) applyWithdraw(tx *types.Tx) error {
	if !s.stakeConfigured() {
		return fmt.Errorf("%w: MinStake %d, UnbondingEpochs %d, EpochBlocks %d",
			ErrStakeUnconfigured, s.params.MinStake, s.params.UnbondingEpochs, s.params.EpochBlocks)
	}
	if tx.Fee != 0 {
		return fmt.Errorf("%w: withdraw carries fee %d", ErrStakeCarriesFee, tx.Fee)
	}

	from := s.Get(tx.From)
	if from.Nonce != tx.Nonce {
		return fmt.Errorf("%w: got %d, want %d", ErrBadNonce, tx.Nonce, from.Nonce)
	}

	// Sum what is mature, overflow-checked as it is formed: a wrapped total
	// would credit less than the records hold and consume them anyway.
	recs := s.unbonding[tx.From]
	var mature uint64
	var matured int
	for i := range recs {
		if recs[i].ReleaseHeight > s.height {
			continue
		}
		if mature > math.MaxUint64-recs[i].Amount {
			return fmt.Errorf("%w: matured total %d + record %d", ErrBalanceOverflow, mature, recs[i].Amount)
		}
		mature += recs[i].Amount
		matured++
	}
	if matured == 0 {
		return ErrNothingToWithdraw
	}
	// The credit side carries the same guard a transfer's recipient gets.
	if from.Balance > math.MaxUint64-mature {
		return fmt.Errorf("%w: balance %d + released %d", ErrBalanceOverflow, from.Balance, mature)
	}

	// Every validation has run; write. Rebuild the address's slice with the
	// immature records only: a record released here is gone, so a second
	// Withdraw cannot pay it again.
	kept := make([]Unbonding, 0, len(recs)-matured)
	for i := range recs {
		if recs[i].ReleaseHeight > s.height {
			kept = append(kept, recs[i])
		}
	}
	if len(kept) == 0 {
		delete(s.unbonding, tx.From)
	} else {
		s.unbonding[tx.From] = kept
	}

	from.Balance += mature
	from.Nonce++
	s.Set(tx.From, from)
	return nil
}

// ---------------------------------------------------------------------------
// Committee derivation (M5 Task 2)
// ---------------------------------------------------------------------------

const (
	// powerCapDivisor is §6.3's 1/4. It is a RATIO of the seated total, not a
	// stake level, and it is the same ratio consensus.Config carries as
	// PowerCapNum/PowerCapDen. Validate rejects only a share ABOVE it
	// (power*den > total*num), so a seat holding exactly a quarter is legal -
	// which is why the clamp below uses integer division and allows equality.
	powerCapDivisor uint64 = 4

	// powerCapMinSeats is the smallest committee the 1/4 cap can bind on. With
	// fewer than four seats the largest holder necessarily holds at least a
	// third - the largest is never below the average 1/n, and n < 4 - so 1/4
	// is unsatisfiable there. Below this many seats the cap is not applied at
	// all, which is exactly the escape consensus.Config expresses by
	// configuring 1/1 for such a committee (Validate's per-validator
	// comparison against 1/1 can never fail). There is no second rule: the
	// derivation emits the raw stakes and the config layer says 1/1.
	powerCapMinSeats = 4

	// committeeMaxCapPasses bounds the fixed-point clamp. The bound is
	// DERIVED, not guessed. A binding pass sets every power above T/4 to T/4;
	// the slowest case is three seats pinned at one large value M with the
	// rest tiny, where the gap g = M - min shrinks by three quarters a pass
	// (g' = g - ceil(g/4)), so the pass count is
	//
	//	log_{4/3}(g) = log2(g) * ln2/ln(4/3) = 2.41 * log2(g).
	//
	// Over the whole uint64 domain log2(g) <= 64, so at most ~155 passes, and
	// the measured worst case is 148 (three at 2^64-1, one at 1 spark). The
	// plan said 64; that is NOT enough, and not only for adversarial inputs:
	// three seats at 10^12 with one at 1 spark needs 94 passes, and three at
	// 2^51 (the shipped 21,000,000 b10 supply cap is 2.1e15 = 2^50.9) with one
	// at MIN_STAKE needs ~121, so 64 would refuse to seat a committee a real
	// chain can reach - a liveness halt presented as an arithmetic error. 256
	// is the next power of two above the proven bound, and the explicit
	// non-convergence error stays as a guard on that analysis rather than as
	// an approximation.
	committeeMaxCapPasses = 256
)

var (
	// ErrNoCandidates reports a state with no bond that can be seated. It is an
	// error, not an empty slice: an empty committee reaching
	// consensus.NewEngine fails there with ErrEmptyCommittee, a message about
	// the engine when the fact is about the state.
	ErrNoCandidates = errors.New("state: no bonded candidate can be seated")
	// ErrZeroCommittee reports a state whose Params carry no CommitteeSize. A
	// zero seat count would derive an empty committee for every height, which
	// is the same failure one layer later and harder to read.
	ErrZeroCommittee = errors.New("state: CommitteeSize is zero")
	// ErrCommitteePowerOverflow reports a seated total that does not fit in a
	// uint64. Every share and every clamp is computed from T, so a wrapped T
	// would make every share wrong - it is refused, never emitted.
	ErrCommitteePowerOverflow = errors.New("state: the seated voting power overflows uint64")
	// ErrZeroPowerSeat reports a derivation that would emit a seat with no
	// power. consensus.Config.Validate refuses such a committee
	// (ErrZeroPower), so this is the same refusal one layer earlier with a
	// message about the state. It is unreachable from a bond map whose
	// candidates all hold at least one spark and that seats four or more: T is
	// then at least 4 and T/4 at least 1, so no clamp can produce a zero. It
	// stays as the check that the arithmetic still agrees with that argument.
	ErrZeroPowerSeat = errors.New("state: the derivation would seat a validator with no voting power")
	// ErrPowerCapNotConverged reports a clamp that did not reach a fixed point
	// within committeeMaxCapPasses. The derivation returns the error rather
	// than an approximation: a committee whose cap does not hold is one
	// consensus.Config.Validate refuses, so approximating would move the
	// failure somewhere with a worse message instead of removing it.
	ErrPowerCapNotConverged = errors.New("state: the power cap did not reach a fixed point")
)

// committeeCandidate is one bond record as the derivation sees it: the map key
// (the address), the key the seat would carry, and the locked amount.
type committeeCandidate struct {
	address types.Address
	key     []byte
	amount  uint64
}

// compareCandidates orders candidates by stake descending, then by public-key
// BYTES ascending, then - for a total order only - by address bytes.
//
// The key tie-break is §6.3's and it is deliberately on the key, not on the
// address: an address is a hash of the key, so its byte order is unrelated to
// the key's, and a sort by address (or by the address STRING) would pick a
// different winner among equal stakes. The address tie-break can only matter
// for two bond records carrying the same key, which committed state cannot
// hold - SetBond is keyed by address and a later Bond for one address keeps
// the first-recorded key, so key and address are one-to-one through
// AddressFromPub. A hand-built state can still hold the pair, and a sort with
// equal keys and equal amounts would then hash an arbitrary map order, so the
// address makes the order total and the derivation deterministic for every
// state, not merely every reachable one.
//
// THE KEY TIE-BREAK IS GRINDABLE, and that is accepted rather than hidden
// (audit RT-8). Among candidates with EQUAL bonded stake, the seat boundary
// runs through raw public-key bytes, and a key's owner chooses those bytes
// when it generates the key: an attacker who wants to outrank an equally
// staked honest candidate - or to win the last free seat - can generate keys
// until its key sorts first, at the cost of keygen attempts and one bond per
// try. Nothing here makes that impossible, and nothing safety-critical rests
// on the order: the order decides WHO holds a seat among equally staked
// candidates, never whether the derivation is deterministic (every node sorts
// the same bytes identically) or how much power a seat carries (the cap is a
// function of the seated total). The alternative - ordering by address - is
// just as grindable (an address is a key hash), and a secret or committee-voted
// tie-break would put a non-state input into a pure function of committed
// state. Grinding also competes for seats at a cost of MIN_STAKE per attempt,
// and ST-1's floor plus the epoch cooldown bound how fast seats can be retried.
func compareCandidates(x, y committeeCandidate) int {
	switch {
	case x.amount > y.amount:
		return -1
	case x.amount < y.amount:
		return 1
	}
	if c := bytes.Compare(x.key, y.key); c != 0 {
		return c
	}
	return bytes.Compare(x.address[:], y.address[:])
}

// Committee returns the seats derived from THIS state: the top CommitteeSize
// candidates by bonded stake (ties by public-key bytes, ascending), each power
// capped at a quarter of the seated total. Which height this state is decides
// which epoch's committee it is; the function itself knows nothing of heights.
//
// It is a PURE FUNCTION OF COMMITTED STATE and that is load-bearing, not
// stylistic. It reads s.params (protocol configuration every node holding this
// state already agrees on) and s.bonds (committed), and nothing else: no wall
// clock, no network, no Peers(), no cache, no s.height. Two nodes with the same
// committed state must derive the same committee, or they cannot agree on a
// block - and the failure would look like a liveness bug, not a determinism
// bug. In particular the bond map's iteration order is randomised by Go, so the
// candidates are sorted before anything is selected, and the comparator is a
// total order over the map's entries so the result does not depend on the order
// the map yields them in.
//
// The cap is applied AFTER selecting, never instead of it: a validator that
// ranks in the top CommitteeSize is seated even when its stake is far above a
// quarter of the seated total, and its power is reduced to the cap. Excluding
// over-cap holders instead would drop seats the stake ranking earned and would
// make the seat set depend on the cap, not on the ranking. §6.3's table wants
// the former: the cap "keeps one operator below the 1/3 threshold".
//
// Powers are the derivation's output; the cap ratio itself is the consensus
// config's (1/4 at four or more seats, 1/1 below - see powerCapMinSeats).
func (s *State) Committee() ([]genesis.Validator, error) {
	if s.params.CommitteeSize <= 0 {
		return nil, ErrZeroCommittee
	}

	// Candidates are bond records with a positive amount. An unbonding record
	// is not in the bond map at all (applyUnbond deletes or decrements the
	// bond and writes the record to s.unbonding), so coins in cooldown are
	// not candidates and a fully withdrawn seat is gone - the cooldown's
	// "neither spendable nor counted" half.
	candidates := make([]committeeCandidate, 0, len(s.bonds))
	for addr, b := range s.bonds {
		if b.Amount == 0 {
			continue
		}
		candidates = append(candidates, committeeCandidate{address: addr, key: b.Validator, amount: b.Amount})
	}
	if len(candidates) == 0 {
		return nil, ErrNoCandidates
	}

	slices.SortFunc(candidates, compareCandidates)

	seats := len(candidates)
	if s.params.CommitteeSize < seats {
		seats = s.params.CommitteeSize
	}

	powers := make([]uint64, seats)
	for i := range powers {
		powers[i] = candidates[i].amount
	}
	if seats >= powerCapMinSeats {
		var err error
		if powers, err = applyPowerCap(powers); err != nil {
			return nil, err
		}
	}

	committee := make([]genesis.Validator, seats)
	for i := range committee {
		// Clone the key: the returned committee must not alias committed
		// state, or a caller could mutate a bond through it.
		committee[i] = genesis.Validator{PubKey: slices.Clone(candidates[i].key), Power: powers[i]}
	}
	return committee, nil
}

// applyPowerCap is the fixed-point clamp: each pass takes T once and clamps
// every member against that same T, repeating until a pass changes nothing.
//
// A single pass is not safe. The pass is measured against T, and clamping
// changes T, so one pass leaves the residual holders over the ratio they were
// just checked against: a holder of 99% of the stake, clamped once, ends at
// 96% of the shrunken total and could still commit alone. Repeating the pass
// against the recomputed total converges to the point where no member exceeds
// T/4 - the property the cap exists to buy, and the one
// consensus.Config.Validate checks.
//
// The pass structure is also what makes the result independent of the order the
// validators are visited in: every clamp in a pass uses the same T, so a
// permutation of the input yields a permutation of the output at every pass.
func applyPowerCap(powers []uint64) ([]uint64, error) {
	out := slices.Clone(powers)
	for pass := 0; ; pass++ {
		if pass == committeeMaxCapPasses {
			return nil, fmt.Errorf("%w after %d passes", ErrPowerCapNotConverged, committeeMaxCapPasses)
		}
		total, ok := sumPowers(out)
		if !ok {
			return nil, ErrCommitteePowerOverflow
		}
		limit := total / powerCapDivisor
		changed := false
		for i := range out {
			if out[i] > limit {
				out[i] = limit
				changed = true
			}
		}
		if !changed {
			for i := range out {
				if out[i] == 0 {
					return nil, fmt.Errorf("%w: seat %d has zero power", ErrZeroPowerSeat, i)
				}
			}
			return out, nil
		}
	}
}

// sumPowers sums powers with a checked add, reporting whether the total fit in
// a uint64. The clamp divides T, so a wrapped T would make every share wrong.
func sumPowers(powers []uint64) (uint64, bool) {
	var total uint64
	for _, p := range powers {
		next, carry := bits.Add64(total, p, 0)
		if carry != 0 {
			return 0, false
		}
		total = next
	}
	return total, true
}
