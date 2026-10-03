package consensus

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrEmptyCommittee = errors.New("consensus: committee must not be empty")
	ErrPowerCap       = errors.New("consensus: a validator holds more than the permitted share of voting power")
	ErrNotValidator   = errors.New("consensus: key is not in the committee")
)

// Config is the consensus parameters a validator needs. It is derived from the
// genesis of the chain it is validating.
type Config struct {
	Committee []genesis.Validator

	// TimeoutBase is the round-0 timeout and TimeoutStep the extra time added per
	// further round. Timeouts must grow, or a slow network would thrash through
	// rounds faster than messages can arrive.
	TimeoutBase int64 // in milliseconds; int64 so the engine stays clock-free
	TimeoutStep int64

	// PowerCapNum/PowerCapDen bound any one validator's share of total power. The
	// spec requires 1/4: a validator holding more than a third could commit
	// conflicting blocks alone, so the cap keeps every operator below it.
	PowerCapNum uint64
	PowerCapDen uint64
}

// Validate rejects a committee the engine could not run safely.
func (c Config) Validate() error {
	if len(c.Committee) == 0 {
		return ErrEmptyCommittee
	}
	total := c.TotalPower()
	if total == 0 {
		return ErrEmptyCommittee
	}
	if c.PowerCapDen == 0 {
		return fmt.Errorf("%w: zero power-cap denominator", ErrPowerCap)
	}
	// power/total > num/den  <=>  power*den > total*num, computed in big.Int
	// because power*den can exceed uint64 for adversarial inputs (power near
	// 2^64 with den > 1 wraps, silently passing a validator over the cap).
	num := new(big.Int).SetUint64(c.PowerCapNum)
	den := new(big.Int).SetUint64(c.PowerCapDen)
	numTotal := new(big.Int).Mul(num, new(big.Int).SetUint64(total))
	for i, v := range c.Committee {
		if v.Power == 0 {
			return fmt.Errorf("%w: validator %d has zero power", ErrEmptyCommittee, i)
		}
		if new(big.Int).Mul(new(big.Int).SetUint64(v.Power), den).Cmp(numTotal) > 0 {
			return fmt.Errorf("%w: validator %d holds %d of %d", ErrPowerCap, i, v.Power, total)
		}
	}
	return nil
}

// TotalPower is the sum of every validator's voting power.
func (c Config) TotalPower() uint64 {
	var t uint64
	for _, v := range c.Committee {
		t += v.Power
	}
	return t
}

// Quorum is the power required to commit: two thirds of TOTAL power, plus one so
// the boundary is strictly greater.
//
// It is deliberately NOT two thirds of ONLINE power. Taking validators offline
// must make quorum harder, not easier - otherwise an attacker who silences a
// third of the set would lower the bar far enough to commit alone.
func (c Config) Quorum() uint64 { return quorumFor(c.TotalPower()) }

func quorumFor(total uint64) uint64 { return 2*total/3 + 1 }

// CommitteeAt returns the committee that validates a height. Validator-set
// changes take effect at epoch boundaries in M5 (staking); until then this is the
// genesis set at every height, and the seam exists so M5 has somewhere to plug in
// without touching the engine.
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

// Proposer returns the validator that proposes at (height, round), chosen by
// weighted round-robin over voting power.
//
// The choice is a pure function of the arguments, so every validator computes the
// same proposer with no communication. The parent hash seeds it so an adversary
// cannot predict or bias the order far ahead; height and round advance it.
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
