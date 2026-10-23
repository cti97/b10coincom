package state_test

// The cross-package agreement pin for M5 Task 2.
//
// This file is in the EXTERNAL test package on purpose: internal/consensus
// imports internal/state, so an in-package test importing consensus would be an
// import cycle. The external package may import both.
//
// Its job is the one thing neither package can test alone: state.Committee's
// derivation must PASS consensus.Config.Validate. The derivation must not rely
// on Validate to reject an over-capped committee - a committee that only fails
// at construction halts a running chain instead of seating a safe one - and
// Validate must not be relaxed to accommodate the derivation.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// minStakeSparks is MIN_STAKE (1,000 b10) in sparks; the shipped value of
// genesis.Params.MinStakeSparks, which is the least a real bond can hold.
const minStakeSparks = 1_000 * genesis.SparksPerB10

// capForSeats is the power-cap ratio the consensus config must carry for a
// committee of n seats: 1/4 at four or more, 1/1 below. It mirrors
// consensus.PowerCapFor, which the plan adds in Task 3 with the per-height
// wiring; that function does not exist yet, so calling it here would be doing
// Task 3's work. Stating the rule locally is what makes this test pin the
// AGREEMENT between the two implementations of one rule rather than assume it.
func capForSeats(n int) (num, den uint64) {
	if n >= consensusPowerCapMinSeats {
		return 1, 4
	}
	return 1, 1
}

// consensusPowerCapMinSeats is the smallest committee a 1/4 cap can bind on,
// restated here (not imported) so this test fails if either side's threshold
// moves. Below four seats the largest holder necessarily holds at least a
// third, so 1/4 is unsatisfiable and the config carries 1/1 instead.
const consensusPowerCapMinSeats = 4

// derive builds a state holding one bond per stake, in the order given, seats
// `seats` of them (0 = all), and returns the derived committee along with the
// same seats expressed as RAW voting power - the committee the pre-M5 world
// (genesis seats with Power = stake) would have presented for the same ranking.
// The raw list is what the derivation has to improve on, so the table can show
// it was doing work rather than restating Validate.
func derive(t *testing.T, stakes []uint64, seats int) (committee, raw []genesis.Validator) {
	t.Helper()
	if seats == 0 {
		seats = len(stakes)
	}
	s := state.NewWithParams(state.Params{CommitteeSize: seats})
	for _, amount := range stakes {
		pub, _, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		s.SetBond(types.AddressFromPub(pub), state.Bond{Validator: pub, Amount: amount})
		raw = append(raw, genesis.Validator{PubKey: pub, Power: amount})
	}
	c, err := s.Committee()
	if err != nil {
		t.Fatalf("Committee: %v", err)
	}
	return c, raw[:seats]
}

// config assembles the consensus configuration a validator would build from a
// committee, with the cap the seat count calls for.
func config(committee []genesis.Validator) consensus.Config {
	c := consensus.Config{
		Committee:   committee,
		TimeoutBase: 2_000,
		TimeoutStep: 1_000,
	}
	c.PowerCapNum, c.PowerCapDen = capForSeats(len(committee))
	return c
}

// TestEveryDerivedCommitteePassesConsensusValidate is the table test. Each row
// is a distribution, the derived committee must Validate with the cap the seat
// count calls for, and where the RAW seats would have been refused under 1/4
// the row pins that too - that is the work the derivation is doing, not a
// tautology.
func TestEveryDerivedCommitteePassesConsensusValidate(t *testing.T) {
	const big = 1<<51 - 1 // just under the shipped 2.1e15-spark supply cap
	rows := []struct {
		name   string
		stakes []uint64 // in stake-descending order: the first `seats` are the seats
		seats  int      // 0 = one seat per stake
		// rawCapIsRefused: a config built from the raw seats at 1/4 must fail
		// with ErrPowerCap, proving the derivation changed something.
		rawCapIsRefused bool
	}{
		{
			name:   "flat 4 (each exactly a quarter)",
			stakes: repeatStake(minStakeSparks, 4),
			// Each is exactly 1/4, and Validate rejects only ABOVE 1/4.
			rawCapIsRefused: false,
		},
		{
			name:            "flat 6",
			stakes:          repeatStake(minStakeSparks, 6),
			rawCapIsRefused: false,
		},
		{
			name:            "flat 21",
			stakes:          repeatStake(big, 21),
			rawCapIsRefused: false,
		},
		{
			name:            "skewed (one holder at 99.9% of the stake)",
			stakes:          []uint64{1_000_000_000_000_000, 1_000_000_000_000, 1_000_000_000_000, 1_000_000_000_000},
			rawCapIsRefused: true,
		},
		{
			name:            "three dominant, the slowest clamp",
			stakes:          []uint64{big, big, big, 1},
			rawCapIsRefused: true,
		},
		{
			name:            "three seats (the below-four escape)",
			stakes:          repeatStake(minStakeSparks, 3),
			rawCapIsRefused: true,
		},
		{
			// More candidates than seats. The cap must be measured against the
			// SEATED total: measuring it against every candidate's total would
			// leave the leader over a quarter of the committee that actually
			// sits, which is what the mutant that caps "all candidates" does.
			name:            "more candidates than seats (400 outside the seats)",
			stakes:          append([]uint64{100}, repeatStake(1, 400)...),
			seats:           4,
			rawCapIsRefused: true,
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			wantSeats := row.seats
			if wantSeats == 0 {
				wantSeats = len(row.stakes)
			}
			committee, raw := derive(t, row.stakes, row.seats)
			if len(committee) != wantSeats {
				t.Fatalf("seats = %d, want %d", len(committee), wantSeats)
			}

			cfg := config(committee)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("the derived committee does not pass consensus.Config.Validate: %v\ncommittee: %s",
					err, format(committee))
			}

			// The cap the derivation emitted must hold against the total the
			// config will actually compute - restated here so a Validate change
			// cannot hide a derivation that stopped clamping.
			var total uint64
			for _, v := range committee {
				total += v.Power
			}
			if len(committee) >= consensusPowerCapMinSeats {
				for i, v := range committee {
					if v.Power*4 > total {
						t.Fatalf("seat %d holds %d of %d, above a quarter (the config layer accepts it, "+
							"but the derivation did not clamp): %s", i, v.Power, total, format(committee))
					}
				}
			}

			if row.rawCapIsRefused {
				rawCfg := consensus.Config{
					Committee:   raw,
					TimeoutBase: 2_000,
					TimeoutStep: 1_000,
					PowerCapNum: 1,
					PowerCapDen: 4,
				}
				if err := rawCfg.Validate(); !errors.Is(err, consensus.ErrPowerCap) {
					t.Fatalf("the RAW seats were expected to be refused by the 1/4 cap, got %v", err)
				}
			}
		})
	}
}

// TestAThreeSeatCommitteeNeedsTheOneOverOneEscape is the 4 -> 3 arithmetic.
//
// Four equal seats hold exactly a quarter each, and a 1/4 config validates them
// (Validate refuses only a share ABOVE the cap). Lose one seat and the three
// that remain hold a third each - ABOVE 1/4, so a 1/4 config is refused with
// ErrPowerCap. That is the sense in which "4 -> 3" is unsatisfiable: not under
// the derivation, which emits the raw stakes below four seats and says so, but
// under a 1/4 cap. The brief's escape is the 1/1 ratio for committees below
// four seats, and with it the same three seats validate.
//
// A 6 -> 5 rotation needs no escape: five equal seats hold a fifth each
// (0.20 < 0.25) and validate under the ordinary 1/4 cap. That is why the
// milestone's rotation fixture is 6 -> 5, and why --rotate-demo requires five
// or more validators.
func TestAThreeSeatCommitteeNeedsTheOneOverOneEscape(t *testing.T) {
	// Four equal seats: exactly a quarter each.
	four, _ := derive(t, repeatStake(minStakeSparks, 4), 0)
	if err := config(four).Validate(); err != nil {
		t.Fatalf("four equal seats must validate under 1/4: %v", err)
	}

	// One leaves: three equal seats, a third each.
	three, _ := derive(t, repeatStake(minStakeSparks, 3), 0)
	quarter := consensus.Config{
		Committee: three, TimeoutBase: 2_000, TimeoutStep: 1_000,
		PowerCapNum: 1, PowerCapDen: 4,
	}
	if err := quarter.Validate(); !errors.Is(err, consensus.ErrPowerCap) {
		t.Fatalf("three equal seats under a 1/4 cap = %v, want ErrPowerCap: each holds a third", err)
	}
	if err := config(three).Validate(); err != nil {
		t.Fatalf("three equal seats under the 1/1 escape must validate: %v", err)
	}

	// Six equal seats: a sixth each, then one leaves and five hold a fifth.
	six, _ := derive(t, repeatStake(minStakeSparks, 6), 0)
	if err := config(six).Validate(); err != nil {
		t.Fatalf("six equal seats must validate under 1/4: %v", err)
	}
	five, _ := derive(t, repeatStake(minStakeSparks, 5), 0)
	if len(five) != 5 {
		t.Fatalf("seats = %d, want 5", len(five))
	}
	for i, v := range five {
		if v.Power != minStakeSparks {
			t.Fatalf("seat %d power = %d, want an unclamped %d: 1/5 is under the cap", i, v.Power, minStakeSparks)
		}
	}
	if err := config(five).Validate(); err != nil {
		t.Fatalf("a 6 -> 5 rotation must validate under the ordinary 1/4 cap: %v", err)
	}
}

// repeatStake returns n copies of one stake.
func repeatStake(stake uint64, n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = stake
	}
	return out
}

func format(c []genesis.Validator) string {
	out := ""
	for _, v := range c {
		out += fmt.Sprintf("%x:%d ", v.PubKey, v.Power)
	}
	return out
}
