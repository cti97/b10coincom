package consensus

import (
	"errors"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrEmptyCommittee = errors.New("consensus: committee must not be empty")
	ErrPowerCap       = errors.New("consensus: a validator holds more than the permitted share of voting power")
	ErrNotValidator   = errors.New("consensus: key is not in the committee")
	// ErrZeroPower covers a listed validator with no voting power. This case
	// used to surface as ErrEmptyCommittee, the wrong category: the committee
	// is non-empty, one of its entries is malformed.
	ErrZeroPower = errors.New("consensus: a validator holds zero voting power")
	// ErrPowerOverflow reports a committee whose voting powers sum past 2^64.
	// Every power-relative computation (Quorum, Proposer's pick, the cap
	// comparison) works from that sum, so a wrapped one is refused rather
	// than run on.
	ErrPowerOverflow = errors.New("consensus: total voting power overflows uint64")
	// ErrBadConfig rejects parameters that are wrong at the config layer
	// itself: timeouts that do not grow, a zero power-cap denominator, and a
	// power cap above the spec's 1/4 ceiling.
	ErrBadConfig = errors.New("consensus: invalid consensus configuration")
)

// Config is the consensus parameters a validator needs. It is derived from the
// genesis of the chain it is validating.
type Config struct {
	Committee []genesis.Validator

	// TimeoutBase is the round-0 timeout and TimeoutStep the extra time added per
	// further round. Timeouts must grow, or a slow network would thrash through
	// rounds faster than messages can arrive; Validate rejects a non-positive
	// base or a negative step.
	TimeoutBase int64 // in milliseconds; int64 so the engine stays clock-free
	TimeoutStep int64

	// PowerCapNum/PowerCapDen bound any one validator's share of total power. The
	// spec requires 1/4: a validator holding more than a third could commit
	// conflicting blocks alone, so the cap keeps every operator below it.
	// Validate rejects a configured ratio above 1/4 for committees of four or
	// more (below four it cannot bind, see Validate) and a zero denominator.
	PowerCapNum uint64
	PowerCapDen uint64
}

// Validate rejects a configuration the engine could not run safely.
//
// The power-cap ceiling is enforced only where it can bind. With fewer than
// four validators the largest holder necessarily holds at least total/3 (the
// largest is never below the average, 1/n of total, and n < 4), so no ratio
// below 1/3 can ever hold there and a single- or two-validator chain could
// not exist under the spec's 1/4 ceiling at all. A configured ratio above 1/4
// is therefore rejected only for committees of four or more; below that, the
// per-validator comparison against the configured ratio still applies.
func (c Config) Validate() error {
	if len(c.Committee) == 0 {
		return ErrEmptyCommittee
	}
	if c.TimeoutBase <= 0 {
		return fmt.Errorf("%w: TimeoutBase must be positive, got %d", ErrBadConfig, c.TimeoutBase)
	}
	if c.TimeoutStep < 0 {
		return fmt.Errorf("%w: TimeoutStep must not be negative, got %d", ErrBadConfig, c.TimeoutStep)
	}
	if c.PowerCapDen == 0 {
		return fmt.Errorf("%w: zero power-cap denominator", ErrBadConfig)
	}
	if len(c.Committee) >= 4 {
		// num/den > 1/4  <=>  4*num > den. 4*num is formed by bits.Mul64: a num
		// above 2^62 would wrap a raw uint64 product to a small value and slip
		// past this very check.
		if hi, lo := bits.Mul64(c.PowerCapNum, 4); hi != 0 || lo > c.PowerCapDen {
			return fmt.Errorf("%w: power cap %d/%d exceeds the spec ceiling of 1/4",
				ErrBadConfig, c.PowerCapNum, c.PowerCapDen)
		}
	}
	total, ok := totalPower(c.Committee)
	if !ok {
		// A wrapped total would corrupt every power comparison downstream:
		// the cap comparison, the quorum threshold and the proposer pick are
		// all computed from it. Refuse the committee instead of running on a
		// wrapped value.
		return ErrPowerOverflow
	}
	num := new(big.Int).SetUint64(c.PowerCapNum)
	den := new(big.Int).SetUint64(c.PowerCapDen)
	numTotal := new(big.Int).Mul(num, new(big.Int).SetUint64(total))
	for i, v := range c.Committee {
		if v.Power == 0 {
			return fmt.Errorf("%w: validator %d has zero power", ErrZeroPower, i)
		}
		// power/total > num/den  <=>  power*den > total*num, computed in big.Int
		// because power*den can exceed uint64 for adversarial inputs (power near
		// 2^64 with den > 1 wraps, silently passing a validator over the cap).
		if new(big.Int).Mul(new(big.Int).SetUint64(v.Power), den).Cmp(numTotal) > 0 {
			return fmt.Errorf("%w: validator %d holds %d of %d", ErrPowerCap, i, v.Power, total)
		}
	}
	return nil
}

// TotalPower is the sum of every validator's voting power.
//
// The sum is an UNCHECKED uint64 add, and so is everything built on it
// (Quorum's threshold, Proposer's pick, the cap comparison): if the powers
// sum past 2^64, all of these would silently run on a wrapped value instead
// of the committee's real voting power. Validate refuses any committee whose
// power sum overflows (ErrPowerOverflow), so a validated Config always has an
// exact total here. The shipped domain cannot get near the wrap besides that
// guard: validator power is backed by stake (M5 staking makes the binding
// explicit), and the total supply is capped at 2.1e15 sparks ≈ 2^51 - even a
// genesis that granted every spark as voting power would sit over 4000x
// below 2^63.
func (c Config) TotalPower() uint64 {
	t, _ := totalPower(c.Committee)
	return t
}

// totalPower sums the committee's powers, reporting whether the sum fit in a
// uint64.
func totalPower(vals []genesis.Validator) (uint64, bool) {
	var sum uint64
	for _, v := range vals {
		next, carry := bits.Add64(sum, v.Power, 0)
		if carry != 0 {
			return 0, false
		}
		sum = next
	}
	return sum, true
}

// Quorum is the power required to commit: two thirds of TOTAL power, plus one so
// the boundary is strictly greater.
//
// It is deliberately NOT two thirds of ONLINE power. Taking validators offline
// must make quorum harder, not easier - otherwise an attacker who silences a
// third of the set would lower the bar far enough to commit alone.
//
// quorumFor never forms 2*total, so the threshold is exact for every uint64
// total. The one residue it cannot repair is a TotalPower sum that wrapped
// before getting here; Validate refuses such a committee upstream (see
// TotalPower).
func (c Config) Quorum() uint64 { return quorumFor(c.TotalPower()) }

// quorumFor is the smallest q with q > 2*total/3, computed WITHOUT forming 2*total:
// that product overflows for total >= 2^63, and a wrapped quorum would let a small
// minority of the voting power commit alone.
func quorumFor(total uint64) uint64 {
	q := 2*(total/3) + 1
	if total%3 >= 2 {
		q++ // the truncated third had a remainder of 2, so one more is needed
	}
	return q
}

// CommitteeAt returns the committee that validates a height. Validator-set
// changes take effect at epoch boundaries in M5 (staking); until then this is the
// genesis set at every height, and the seam exists so M5 has somewhere to plug in
// without touching the engine.
//
// It has NO READER yet (audit C-17), and that is a recorded decision rather than
// an oversight: every current reader uses cfg.Committee directly, because with
// one fixed committee a height-taking accessor is a no-op no test could
// distinguish from the field read. The seam is a signature M5 fills in, not a
// working indirection. When epoch-bound set changes arrive, the readers that
// must vary by height - Proposer, VoteSet.Add's membership and power lookup,
// IndexOf - take the height and call THIS method, and that change is reviewable
// as the behavioural change it is. Routing those readers through this method
// today would create call sites that pass a height the method ignores: the
// appearance of a seam without a single changed decision.
func (c Config) CommitteeAt(height uint64) []genesis.Validator { return c.Committee }

// IndexOf returns the committee index of a public key, or -1.
func (c Config) IndexOf(pub []byte) int {
	for i := range c.Committee {
		if string(c.Committee[i].PubKey) == string(pub) {
			return i
		}
	}
	return -1
}

// Proposer returns the validator that proposes at (height, round), drawn from
// the committee weighted by voting power. The draw is INDEPENDENT for every
// (height, round): there is no rotation and no remembered position, so a
// validator can be drawn twice in a row, and over many draws each validator
// is chosen in proportion to its power (pinned by
// TestProposerFavoursHeavierValidators).
//
// The choice is a pure function of the arguments, so every validator computes
// the same proposer with no communication. The parent hash seeds the draw, so
// the proposer at (h, r) stays unknown until block h-1 is fixed.
//
// The parent hash is also the one biasable input, and the bias is real: the
// proposer of block h-1 chooses what goes into block h-1, and every such
// choice changes parent(h), and with it every draw at (h, r). A proposer can
// grind its own block content - retrying variants until the next draw names
// itself - and steer the following proposer ONE height at a time. That is
// liveness/fairness bias only: it cannot forge another validator's proposal
// or break safety, and each next proposer holds the same lever on the height
// after.
//
// The grind's FREE input is closed (audit C-14). The audit's cost model rested
// on timestamps being unconstrained; S-8 pinned them. The consensus engine's
// pre-vote seam is Chain.ValidateConsensusNext, which requires the block's
// timestamp to be EXACTLY its parent's plus one, and Driver.build constructs
// exactly that - so a proposer cannot vary the timestamp to re-roll parent(h)
// and expect any honest validator to prevote the result. What is left is the
// block's transaction content, bounded by the mempool and priced by S-3's
// minimum fee, and a proposer grinding that content is choosing among a
// genuinely small space per height. The pin itself is pinned by
// timestamp_test.go's ValidateConsensusNext cases; this comment states where
// C-14's unbounded-cost claim stops being true.
//
// A divergence here would not break safety - the other validators would simply
// refuse to prevote - but it would stall liveness on every round, which is why it
// is pinned by a test.
func (c Config) Proposer(height uint64, round uint32, parent [32]byte) []byte {
	e := types.NewEncoder()
	e.U64(height)
	e.U32(round)
	e.Fixed32(parent)
	seed := crypto.HashParts([]byte("b10coin-proposer"), e.Bytes())

	total := c.TotalPower()
	pick := new(big.Int).Mod(new(big.Int).SetBytes(seed[:]), new(big.Int).SetUint64(total)).Uint64()

	var cum uint64
	for i := range c.Committee {
		cum += c.Committee[i].Power
		if pick < cum {
			return c.Committee[i].PubKey
		}
	}
	return c.Committee[len(c.Committee)-1].PubKey // unreachable: pick < total
}
