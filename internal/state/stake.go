package state

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"slices"

	"github.com/cti97/b10coincom/internal/types"
)

// Staking is committed state, not a balance with a lock flag (M5 design
// decision 1). A bond is a record - (validator, amount, height) - held
// SEPARATELY from the spendable balance:
//
//	spendable (Account.Balance) + bonded (bonds) + unbonding (unbonding)
//
// is conserved by every stake transaction. `Bond` moves sparks from the first
// term to the second, `Unbond` from the second to the third, and `Withdraw`
// from the third back to the first. No transaction creates or destroys a spark:
// a transfer lowers the sum by exactly its fee, which is burned. Emission and
// faucet claims are chain-level and move the sum as a whole.
//
// The third term is worth NOTHING until its release height: an unbonding
// record is not spendable (it is not in Account.Balance) and not counted (it is
// not in the bond map, so it is not a committee candidate). That is what makes
// the cooldown an economic delay instead of a formality - the coins are gone
// from both uses at once, not merely flagged.
//
// GENESIS IS THE INITIAL CONDITION, not a double count: chain.genesisState
// seats the genesis validators by writing a bond per genesis.Validator
// (Amount = Power, Height = 0), funded by the genesis hash rather than by any
// balance. Height 0 therefore has bonded stake that no balance ever paid for,
// and the invariant above is about the TRANSITIONS, not about a chain starting
// from zero in all three terms.

// Bond is one validator's locked stake at one address. Validator is the
// ed25519 public key the committee seats (an address is only a hash of it, so
// the key cannot be recovered from the map key). Height is the height at which
// the record was first created; a later Bond that adds to the same address
// keeps the earliest height and the first-recorded key.
type Bond struct {
	Validator []byte // ed25519 public key: the identity the committee seats
	Amount    uint64 // sparks, locked
	Height    uint64 // the height at which it was recorded
}

// Unbonding is a matured-by-height claim on sparks. Amount is released to the
// spendable balance by a Withdraw at any height >= ReleaseHeight.
type Unbonding struct {
	Amount        uint64
	ReleaseHeight uint64 // height + UnbondingEpochs*EpochBlocks
}

var (
	// ErrStakeUnconfigured reports a stake transaction against a state whose
	// Params hold no staking configuration (the zero value from New, whose
	// M0-M1 behaviour is that staking is unusable, never that it panics or
	// divides by zero).
	ErrStakeUnconfigured = errors.New("state: staking is not parameterised on this chain")
	// ErrStakeBelowMinimum reports a Bond whose RESULTING bond is under the
	// chain's MinStake. The floor is on the result, not on one transaction, so
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
	// height - a wrapped release height would mature a record in the past.
	ErrReleaseHeightOverflow = errors.New("state: the unbonding release height would overflow")
)

// Bonded returns the address's locked bond in sparks, or 0 if it holds none.
// It reads ONLY the bond map: an unbonding record is not a bond and is not
// counted here, which is the "unbonding coins are not counted" half of the
// cooldown, and the accessor the committee derivation (M5 Task 2) uses.
func (s *State) Bonded(a types.Address) uint64 { return s.bonds[a].Amount }

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
//	releaseHeight = height + UnbondingEpochs * EpochBlocks
//
// The cooldown is TWO EPOCHS, not two blocks. Derivation: the shipped geneses
// set UnbondingEpochs = 2 (genesis.sharedParams), and EpochBlocks is the
// chain's epoch length in blocks - 1,000 on devnet, 10,000 on testnet - so the
// cooldown is 2 x 1,000 = 2,000 devnet blocks and 2 x 10,000 = 20,000 testnet
// blocks. It is deliberately expressed in EPOCHS so a chain that lengthens its
// epochs lengthens the cooldown with it: "an epoch" is the unit the committee
// and the faucet already turn on, and a cooldown measured in absolute blocks
// would silently become a smaller fraction of a term as epochs grew.
//
// Both factors are genesis-controlled, so the product is overflow-checked
// (bits.Mul64 reports the carry) before it is added to the height with a second
// check. A wrapped release height would be a release in the past - an unbond
// that pays out immediately, which is the one thing the cooldown must not do.
func releaseHeightFor(height, unbondingEpochs, epochBlocks uint64) (uint64, error) {
	hi, cooldown := bits.Mul64(unbondingEpochs, epochBlocks)
	if hi != 0 {
		return 0, fmt.Errorf("%w: %d epochs x %d blocks does not fit in 64 bits",
			ErrReleaseHeightOverflow, unbondingEpochs, epochBlocks)
	}
	if height > math.MaxUint64-cooldown {
		return 0, fmt.Errorf("%w: height %d + cooldown %d", ErrReleaseHeightOverflow, height, cooldown)
	}
	return height + cooldown, nil
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
// release height is s.height + the cooldown. The coins leave the bond map -
// they are no longer a committee candidate - and do not reach the balance, so
// they are neither spendable nor counted until the release height.
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

	release, err := releaseHeightFor(s.height, s.params.UnbondingEpochs, s.params.EpochBlocks)
	if err != nil {
		return err
	}

	// Locate the record this amount merges into - a record at the SAME release
	// height, which is what bounds unbond spam by distinct heights rather than
	// by transactions - and check the merge for overflow BEFORE the first
	// write. ApplyTx's contract is that a rejected transaction leaves the
	// receiver untouched, and chain.SelectApplicable runs many candidates
	// against one shared state on exactly that promise.
	recs := s.unbonding[tx.From]
	mergeAt := -1
	for i := range recs {
		if recs[i].ReleaseHeight == release {
			if recs[i].Amount > math.MaxUint64-tx.Amount {
				return fmt.Errorf("%w: unbonding %d + new %d", ErrBalanceOverflow, recs[i].Amount, tx.Amount)
			}
			mergeAt = i
			break
		}
	}

	// Every validation has run; write.
	if remainder := bond.Amount - tx.Amount; remainder == 0 {
		delete(s.bonds, tx.From)
	} else {
		bond.Amount = remainder
		s.bonds[tx.From] = bond
	}
	if mergeAt >= 0 {
		recs[mergeAt].Amount += tx.Amount
	} else {
		s.unbonding[tx.From] = append(recs, Unbonding{Amount: tx.Amount, ReleaseHeight: release})
	}
	from.Nonce++
	s.Set(tx.From, from)
	return nil
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
