package consensus

import (
	"math"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
)

// cappedCommittee builds n equal seats with the power cap the production rule
// assigns to that size. evenCommittee hardcodes 1/4, which is right for the
// four-seat floor and up but REFUSES three seats (each holds 1/3): the
// three-seat fixture is uncapped (PowerCapFor(3) = 1/1), which is exactly the
// shape the live chain runs and the shape this file is about.
func cappedCommittee(t *testing.T, n int, power uint64) Config {
	t.Helper()
	vals := make([]genesis.Validator, 0, n)
	for i := 0; i < n; i++ {
		vals = append(vals, testValidator(i, power))
	}
	num, den := PowerCapFor(n)
	c := Config{Committee: vals, TimeoutBase: 1, TimeoutStep: 1, PowerCapNum: num, PowerCapDen: den}
	if err := c.Validate(); err != nil {
		t.Fatalf("committee of %d seats rejected: %v", n, err)
	}
	return c
}

// A majority attestation jumps the WHOLE gap, not a bounded stride.
//
// The live shape this pins (2026-11-28): three seats, one restarted at round 0
// by the stall watchdog while the other two ran on. The restarted seat held
// evidence from both survivors at round 500 - two of three, a majority of the
// committee - and the bounded stride made it climb 16 rounds per timeout, each
// timeout growing with the round. It took ~8 minutes and the height still had
// not decided when the seat was restarted again. With the majority branch one
// timeout lands on the attested round and the buffered votes are adopted there,
// which is the difference between a resync and an outage.
func TestAMajorityAttestationJumpsTheWholeGap(t *testing.T) {
	const gap = uint32(500)
	cfg := cappedCommittee(t, 3, 1) // total 3, quorum 3: the three-seat fixture
	parent := crypto.HashParts([]byte("jump-majority-parent"))
	someID := crypto.HashParts([]byte("jump-majority-block"))
	idx := 1
	h := round0ProposerHeight(t, cfg, idx, false, parent)
	e := newTestEngine(t, cfg, idx, h, parent)

	for _, seat := range []int{0, 2} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, seat, MsgPrevote, h, gap, someID))); err != nil {
			t.Fatal(err)
		}
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round()})
	if e.Round() != gap {
		t.Fatalf("a majority-attested jump landed at round %d, want %d: two of three seats signing at round %d is where the committee is, and pacing that 16 rounds at a time is what made a resync an outage", e.Round(), gap, gap)
	}
}

// The bounded stride remains for everyone else: a sub-majority claim (half the
// power on an even committee) must not move the engine more than one stride,
// because the member naming it cannot prove the rest of the committee is there.
func TestASubMajorityAttestationJumpsOnlyABoundedStride(t *testing.T) {
	const claim = uint32(500)
	cfg := evenCommittee(t, 4, 1) // total 4: two seats are exactly half, not more
	parent := crypto.HashParts([]byte("jump-submajority-parent"))
	someID := crypto.HashParts([]byte("jump-submajority-block"))
	idx := 3
	h := round0ProposerHeight(t, cfg, idx, false, parent)
	e := newTestEngine(t, cfg, idx, h, parent)

	for _, seat := range []int{0, 1} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, seat, MsgPrevote, h, claim, someID))); err != nil {
			t.Fatal(err)
		}
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round()})
	if e.Round() != maxRoundEscalation {
		t.Fatalf("a half-power claim moved the engine to round %d, want the bounded stride %d: two of four seats is not a majority and cannot name a round the committee must be in", e.Round(), maxRoundEscalation)
	}
}

// MaxUint32 is clamped even on the majority path: OnTimeout's wrap guard returns
// silently at that round, so jumping there would eject the validator from the
// height rather than resync it.
func TestAMajorityJumpAtMaxUint32IsClampedToTheLastReachableRound(t *testing.T) {
	cfg := cappedCommittee(t, 3, 1)
	parent := crypto.HashParts([]byte("jump-wrap-parent"))
	someID := crypto.HashParts([]byte("jump-wrap-block"))
	idx := 0
	h := round0ProposerHeight(t, cfg, idx, false, parent)
	e := newTestEngine(t, cfg, idx, h, parent)

	for _, seat := range []int{1, 2} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, seat, MsgPrevote, h, math.MaxUint32, someID))); err != nil {
			t.Fatal(err)
		}
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round()})
	if e.Round() != math.MaxUint32-1 {
		t.Fatalf("a MaxUint32 majority claim landed at round %d, want %d: the wrap guard would silently return forever at MaxUint32", e.Round(), uint32(math.MaxUint32-1))
	}
}
