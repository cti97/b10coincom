package consensus

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

// TestALoneLiveSeatAheadPastTheRoundWindowStallsAQuorumMarginCommittee
// constructs the state that the live CI failure matches and that no amount of
// waiting repairs.
//
// THE SHAPE, as numbers. TestAValidatorThatJoinsLateCatchesUpOverTCP in
// internal/devnet starts THREE of a FOUR-seat committee, so quorum is 3 and
// the live set is EXACTLY quorum: seat 3 - the late joiner - does not exist
// yet. If one of the three live seats runs a few rounds ahead of the other two,
// nothing brings it back:
//
//   - A quorum needs three votes IN THE SAME ROUND, and an engine casts its
//     vote in the round it is currently in. All three live engines must
//     therefore be in one round: the gap has to reach 0.
//   - maxRoundEscalation freezes the timeout ladder (driver.go). From round 16
//     on, every round of every engine runs the SAME fixed cadence, so each
//     engine leaves one round per timeout and the gap is INVARIANT. Before the
//     cap the +1 ladder closes a gap because the engine further behind is the
//     one with the shorter timeout; past the cap that asymmetry is gone, and
//     the ladder is provably unable to close a gap it did not close before it.
//   - The only other closer is jumpTarget (engine.go), whose bar is
//     total - quorum + 1 = 2 of the FOUR CONFIGURED seats. One live seat holds
//     1, below the bar, so the laggards step +1 and never jump.
//     TestTimeoutJumpNeedsDistinctMembersNotOneByzantine pins that refusal on
//     purpose - a jump on one member's claim follows it into rounds nobody else
//     is in and never comes back - and the price is that one live seat alone
//     ahead is unrecoverable, while that same seat's ABSENCE blocks every
//     quorum.
//
// Nothing here reads a clock or a socket: the rounds are put in place by calling
// OnTimeout, the same transition driver.go's Tick drives, and the invariant is
// asserted on the rounds themselves.
func TestALoneLiveSeatAheadPastTheRoundWindowStallsAQuorumMarginCommittee(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	if q, total := cfg.Quorum(), cfg.TotalPower(); q != 3 || total != 4 {
		t.Fatalf("fixture: quorum %d of total power %d, want the 3-of-4 this case is about", q, total)
	}
	parent := crypto.HashParts([]byte("a-quorum-margin-committee"))
	const h uint64 = 1

	// The live seats are 0, 1 and 2. Seat 3 is the offline one - in the failing
	// test, the late joiner that does not exist yet - and it is seat 3's power
	// that keeps the jump bar at 2 while only ONE live seat is ahead.
	lead := newTestEngine(t, cfg, 0, h, parent)
	behind1 := newTestEngine(t, cfg, 1, h, parent)
	behind2 := newTestEngine(t, cfg, 2, h, parent)
	live := []*Engine{lead, behind1, behind2}

	// Every engine past the timeout cap: from there the cadence is fixed, which
	// is the state in which a gap stops closing.
	for r := uint32(0); r < maxRoundEscalation; r++ {
		for _, e := range live {
			if err := e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round()}); err != nil {
				t.Fatal(err)
			}
		}
	}
	const gap = futureVoteRounds + 1
	for r := uint32(0); r < gap; r++ {
		// Only the leader diverges: driver.go's Tick fires on the WALL clock, so
		// an engine whose clock or whose frame dispatch runs ahead of its peers
		// steps alone. This is the state a `-race` run under CPU contention
		// produces; nothing here produces it by racing anything.
		if err := lead.OnTimeout(TimeoutEvent{Height: h, Round: lead.Round()}); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := behind1.Round(), maxRoundEscalation; got != want {
		t.Fatalf("fixture: laggard at round %d, want %d", got, want)
	}
	if got, want := lead.Round(), maxRoundEscalation+gap; got != want {
		t.Fatalf("fixture: leader at round %d, want %d", got, want)
	}

	// The leader's attestation reaches a laggard: it is evidence of a future
	// round and NOTHING ELSE. No tally is created for that round, so the vote
	// cannot count towards any quorum the laggard can complete.
	blockX := crypto.HashParts([]byte("the-round-the-leader-is-in"))
	if err := behind1.OnMessage(EncodeVote(voteFrom(t, cfg, 0, MsgPrevote, h, lead.Round(), blockX))); err != nil {
		t.Fatal(err)
	}
	if behind1.sets[lead.Round()] != nil {
		t.Fatalf("the leader's round-%d vote was tallied by a laggard at round %d (%d rounds apart): "+
			"only a round inside withinWindow's %d-round window may be tallied",
			lead.Round(), behind1.Round(), lead.Round()-behind1.Round(), futureVoteRounds)
	}
	if len(behind1.future) != 1 {
		t.Fatalf("the leader's future-round claim was not recorded as evidence: %d entries", len(behind1.future))
	}

	// And the jump gate refuses, exactly as
	// TestTimeoutJumpNeedsDistinctMembersNotOneByzantine requires: the bar is 2
	// of the four CONFIGURED seats and one live seat is 1. Step is the only move
	// the ladder has.
	if bar, got := cfg.TotalPower()-cfg.Quorum()+1, behind1.jumpTarget(); got != 0 {
		t.Fatalf("fixture: the jump bar is %d and one live seat of four holds 1, yet jumpTarget returned %d", bar, got)
	}

	// THE INVARIANT: the cadence is fixed, so every engine leaves one and only
	// one round per timeout - a step, never a jump. Run the ladder and the gap
	// neither closes nor widens: the laggards never reach the round the leader
	// is in, so no round ever holds three votes and the height never decides.
	for i := 0; i < 40; i++ {
		before := [3]uint32{lead.Round(), behind1.Round(), behind2.Round()}
		for _, e := range live {
			if err := e.OnTimeout(TimeoutEvent{Height: h, Round: e.Round()}); err != nil {
				t.Fatal(err)
			}
		}
		for j, e := range live {
			if got, want := e.Round(), before[j]+1; got != want {
				t.Fatalf("timeout %d moved live seat %d from round %d to %d, want the +1 step to %d: "+
					"a jump here would follow one live seat's claim, which is exactly what the gate forbids; "+
					"a stall here would mean the ladder can no longer leave the round", i+1, j, before[j], got, want)
			}
		}
		if got := int(lead.Round()) - int(behind1.Round()); got != int(gap) {
			t.Fatalf("after %d further timeouts the gap is %d, want the invariant %d: if the ladder can "+
				"close a divergence it closes it here, and if it cannot the height is permanently undecidable",
				i+1, got, gap)
		}
		if got := int(lead.Round()) - int(behind2.Round()); got != int(gap) {
			t.Fatalf("after %d further timeouts the second laggard is %d rounds behind, want %d", i+1, got, gap)
		}
	}
	for i, e := range live {
		if _, committed := e.Committed(); committed {
			t.Fatalf("live seat %d committed at a height whose live set was exactly quorum: the fixture "+
				"was supposed to be undecidable", i)
		}
	}
}
