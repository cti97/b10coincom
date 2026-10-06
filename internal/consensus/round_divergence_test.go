package consensus

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/transport"
)

// ROUND DIVERGENCE PAST THE TIMEOUT CAP, AND WHY THE CAP IS GONE.
//
// This file replaces TestALoneLiveSeatAheadPastTheRoundWindowStallsAQuorumMarginCommittee,
// which constructed this state and then ASSERTED that it could never be left:
// it drove forty further timeouts and required the round gap to stay exactly
// where it started. That test was a faithful model of a real CI stall - three
// validators of a four-seat devnet, one of them a few rounds ahead - and it was
// the wrong thing to pin. The recovery below is the same construction with the
// expectation inverted, and the mechanism it now rests on is the one the cap
// removed.
//
// THE SHAPE (unchanged). TestAValidatorThatJoinsLateCatchesUpOverTCP in
// internal/devnet starts THREE of a FOUR-seat committee, so quorum is 3 and the
// live set is EXACTLY quorum: seat 3 - the late joiner - does not exist yet. If
// one of the three live seats runs a few rounds ahead of the other two, the
// height cannot decide until the gap reaches 0:
//
//   - A quorum needs three votes IN THE SAME ROUND, and an engine casts its
//     vote in the round it is currently in. All three live engines must
//     therefore be in one round: the gap has to reach 0.
//   - The other closer, jumpTarget (engine.go), has a bar of
//     total - quorum + 1 = 2 of the FOUR CONFIGURED seats. One live seat holds
//     1, below the bar, so the laggards step +1 and never jump - and that
//     refusal is DELIBERATE and stays: TestTimeoutJumpNeedsDistinctMembersNotOneByzantine
//     pins it, because a jump on one member's claim follows it into rounds
//     nobody else is in and never comes back. This file is careful to hold
//     that property, not to trade it away: the mechanism below moves the
//     ROUND not at all, and its proof is that no claim can move anyone.
//
// THE MECHANISM, and why the tension dissolves. maxRoundEscalation used to
// SATURATE the ladder (driver.go): every round from 16 on ran the same fixed
// cadence. Equal cadence means each engine leaves exactly one round per
// timeout, so a round gap was an INVARIANT - not a slow recovery but an
// absorbing state. Before the cap the ladder was the round-resynchronizer: a
// deadline that is STRICTLY INCREASING in the round gives the engine further
// behind the SHORTER timeout, so it fires sooner, gains a round, and closes the
// gap. Restoring that strict monotonicity (Tick re-arms at
// TimeoutBase + round*TimeoutStep) closes the gap with no evidence at all.
//
// That is what keeps property (A) - one Byzantine must not be able to drag a
// validator into a round nobody else is in - and not by a margin. The old
// refusal is against a claim; the new cadence never reads a claim. Its deadline
// is a function of the engine's OWN round and nothing else, so a lying member,
// a below-bar coalition, and an absent member all change the schedule by
// exactly zero. A mechanism that used below-bar evidence to shorten the
// cadence - the tempting alternative - would break (A) outright: the victim
// would walk to the liar's claimed round, the honest quorum of three would be
// short one member, and a single Byzantine could halt a bare-quorum committee
// permanently. TestTheRoundsCadenceIsDeafToASingleMembersFutureRoundClaim pins
// the distinction, and it is the test that kills that alternative.
//
// Nothing here reads a clock or a socket. The drivers are stepped on a virtual
// reading by Driver.Tick - the same transition the field's wall clock drives -
// and the divergence is put in place by ticking ONE driver's reading ahead,
// never by racing two.

// TestALoneLiveSeatAheadPastTheRoundWindowRecoversByTheCadenceAsymmetry is the
// constructed stall, now recovering. The live set is exactly quorum (three of
// four seats, the fourth silent), one live seat is a full round-window past the
// old cap, and the jump gate refuses on every timeout of the recovery, so the
// only thing that can close the gap is the ladder's asymmetry. It does: the
// live seats come back into one round and the height commits.
func TestALoneLiveSeatAheadPastTheRoundWindowRecoversByTheCadenceAsymmetry(t *testing.T) {
	ds, chs, net, _ := fourValidatorsOneSilentFixture(t)
	defer func() {
		for _, ch := range chs {
			_ = ch.Close()
		}
	}()

	if q, total := ds[0].cfg.Quorum(), ds[0].cfg.TotalPower(); q != 3 || total != 4 {
		t.Fatalf("fixture: quorum %d of total power %d, want the 3-of-4 this case is about", q, total)
	}

	// PHASE 1 - construct the divergence. Every engine is past the timeout cap
	// first: all three live seats are driven to round maxRoundEscalation
	// TOGETHER on one reading, which is precisely the state in which the
	// saturated ladder stopped closing a gap. Tick fires on the WALL clock, so
	// an engine whose clock or whose frame dispatch runs ahead of its peers
	// then steps alone; here seat 0's reading is the only one advanced from
	// there. That is the state a `-race` run under CPU contention produces, and
	// no clock and no race produce it here: `now` is the driver's own virtual
	// reading and `timeoutAt` is read back off the driver, so the ladder
	// exercised is the real one.
	now := int64(0)
	for _, d := range ds {
		d.Tick(now) // arms each seat's round-0 deadline
	}
	for ds[2].Round() < maxRoundEscalation {
		now += driveStep
		for _, d := range ds {
			d.Tick(now)
		}
	}
	for i, d := range ds {
		if got := d.Round(); got != maxRoundEscalation {
			t.Fatalf("fixture: live seat %d is at round %d, want all three at the cap %d", i, got, maxRoundEscalation)
		}
	}
	const gap = futureVoteRounds + 1
	for ds[0].Round() < maxRoundEscalation+gap {
		now = ds[0].timeoutAt
		ds[0].Tick(now)
	}
	if got := ds[0].Round(); got != maxRoundEscalation+gap {
		t.Fatalf("fixture: the lead is at round %d, want %d", got, maxRoundEscalation+gap)
	}
	if ds[1].Round() != maxRoundEscalation || ds[2].Round() != maxRoundEscalation {
		t.Fatalf("fixture: the laggards are at rounds %d and %d, want %d: only seat 0's reading ran on",
			ds[1].Round(), ds[2].Round(), maxRoundEscalation)
	}

	// PHASE 2 - one shared clock from here on, exactly as Tick serves three
	// real nodes: every live seat sees the same reading and the network
	// delivers between them. The gap is the spread of the live rounds, and the
	// height commits only when it reaches 0.
	leadStart := ds[0].Round()
	closedAt, commitAt, leadRoundsAtClose := -1, -1, -1
	const budget = 8000 // 80 virtual seconds at driveStep = 10ms
	for i := 0; i < budget; i++ {
		now += driveStep
		for j, d := range ds {
			// The bar is 2 of the four CONFIGURED seats and only ONE member
			// (seat 0) ever attests ahead, so the gate is deaf: no jump is
			// available to this recovery, on any timeout, and a jump would be
			// a failure of (A) rather than a recovery.
			if target := d.eng.jumpTarget(); target != 0 {
				t.Fatalf("live seat %d held a jump target of round %d before its timeout: one member's claim (bar %d of the four configured seats) must not reach the gate",
					j, target, d.cfg.TotalPower()-d.cfg.Quorum()+1)
			}
			before := d.Round()
			d.Tick(now)
			if after := d.Round(); after > before+1 {
				t.Fatalf("live seat %d advanced from round %d to round %d on ONE timeout: recovery must not follow one member's claim, it must step",
					j, before, after)
			}
		}
		net.Advance(netStep)

		hi, lo := ds[0].Round(), ds[0].Round()
		for _, d := range ds[1:] {
			if r := d.Round(); r > hi {
				hi = r
			} else if r < lo {
				lo = r
			}
		}
		if closedAt < 0 && chs[0].Height() == 0 && hi == lo {
			closedAt, leadRoundsAtClose = i, int(ds[0].Round())-int(leadStart)
		}
		if chs[0].Height() >= 1 && chs[1].Height() >= 1 && chs[2].Height() >= 1 {
			commitAt = i
			break
		}
	}

	if closedAt < 0 {
		t.Fatalf("the three live seats never came back into one round within %d drive steps: the round gap past the timeout cap is an INVARIANT again, the height can never decide, and the shape is permanent - three live seats of four, one ahead, is exactly the three-Raspberry-Pi case", budget)
	}
	if commitAt < 0 {
		t.Fatalf("the live seats closed the gap at drive step %d but no height committed within the remaining %d steps: convergence of the rounds is not enough, and the committee is still parked",
			closedAt, budget-closedAt)
	}
	t.Logf("recovery: every live seat back in one round at drive step %d (%d rounds after the lead's round %d), height 1 committed at step %d",
		closedAt, leadRoundsAtClose, leadStart, commitAt)

	// The commit is real and agreed: one block per chain, all three the same.
	for i, ch := range chs[1:] {
		if ch.Height() != chs[0].Height() {
			t.Fatalf("live seat %d sits at height %d while seat 0 sits at %d", i+1, ch.Height(), chs[0].Height())
		}
		if id, want := ch.Head().ID(), chs[0].Head().ID(); id != want {
			t.Fatalf("live seat %d head %x differs from seat 0's %x at the same height", i+1, id[:8], want[:8])
		}
	}
}

// The ladder's asymmetry is the whole mechanism above, so it must not be
// possible to trap a round pair inside a flat cadence: from every round the
// next round's deadline is STRICTLY longer. This is the property audit C-2's
// saturation removed, stated as the thing that must hold at every round rather
// than only below a cap - and it is what makes the fix forced instead of tuned,
// because an integer schedule that has no flat step anywhere cannot be capped
// or sub-linear at all.
//
// The fixture is the blocked-quorum pair (quorum 2, one live validator): the
// height can never commit, so the ladder rides out on its own, and the ghost
// never votes, so no future-round evidence ever accumulates and the raw ladder
// is what this measures.
func TestRoundTimeoutsNeverSaturateSoTheLadderAlwaysClosesAGap(t *testing.T) {
	d, ch, _, _, _, _ := blockedQuorumFixture(t)
	defer func() { _ = ch.Close() }()

	now := int64(5) // below the first deadline: arms the ladder at +TimeoutBase
	const rounds = maxRoundEscalation + 8
	prev := int64(0)
	for r := uint32(0); r < rounds; r++ {
		d.Tick(now)
		if d.eng.Round() != r {
			t.Fatalf("fixture: the engine is at round %d, want %d", d.eng.Round(), r)
		}
		delta := d.timeoutAt - d.now
		if want := roundBase + int64(r)*roundStep; delta != want {
			t.Fatalf("round %d's deadline is TimeoutBase+%d*TimeoutStep = %d, want %d: a saturated ladder gives every round past maxRoundEscalation the same deadline, and one round of the same deadline as another is a round pair no laggard can ever leave",
				r, r, delta, want)
		}
		if r > 0 && delta <= prev {
			t.Fatalf("round %d's deadline %d is not STRICTLY longer than round %d's %d: the cadence has a flat step, so an engine at round %d can never gain on an engine at round %d, and a committee that diverged across that pair stays diverged for good",
				r, delta, r-1, prev, r-1, r)
		}
		prev = delta
		now = d.timeoutAt
	}
	// The old cap's shape really is absent: past the old cap the deadline is
	// still growing, so the engine further behind keeps the shorter timeout.
	capped := roundBase + int64(maxRoundEscalation)*roundStep
	if got := d.timeoutAt - d.now; got <= capped {
		t.Fatalf("at round %d the deadline is %d, at or below the capped value %d: the ladder saturated again, so the catch-up asymmetry is gone from this round on",
			rounds-1, got, capped)
	}
}

// Property (A), kept and pinned at the level where it now lives. A single
// member's claim must not move a validator into a round nobody else is in - and
// with the ladder restored that means it must not move EITHER half of where a
// validator goes: not the round (the jump gate's refusal,
// TestTimeoutJumpNeedsDistinctMembersNotOneByzantine) and not the CADENCE
// either, which is the new half and the one this covers.
//
// The two drivers below are the same committee, the same height and the same
// starting round. One is injected a signed, verified claim from a committee
// member - seat 3, not even live, the shape of a Byzantine - naming round
// 2^30; the other hears nothing. They are then advanced on one shared virtual
// reading. If the claim could shorten the cadence, the two deadlines would
// part company, the claim-holder would run out ahead of a committee still at
// its round, and one Byzantine could hold a bare-quorum committee permanently
// short of its quorum. They do not part company: round for round the deadlines
// are identical, and the claim-holder takes the same +1 step as the control.
func TestTheRoundsCadenceIsDeafToASingleMembersFutureRoundClaim(t *testing.T) {
	ds, chs, _, _ := fourValidatorsOneSilentFixture(t)
	defer func() {
		for _, ch := range chs {
			_ = ch.Close()
		}
	}()

	heard, quiet := ds[0], ds[1]
	// Seat 3 is the silent seat: it has no engine, so a claim signed by it is
	// exactly one member's claim arriving from off the committee's live set.
	claim := voteFrom(t, heard.cfg, 3, MsgPrevote, 1, 1<<30, crypto.HashParts([]byte("a-round-nobody-is-in")))
	heard.OnMessage(transport.Message{Data: EncodeVote(claim)})
	if len(heard.eng.future) != 1 {
		t.Fatalf("fixture: the claim was not recorded as future-round evidence: %d entries", len(heard.eng.future))
	}
	if target := heard.eng.jumpTarget(); target != 0 {
		t.Fatalf("one member's claim reached the jump gate (%d): the bar is %d of the four configured seats",
			target, heard.cfg.TotalPower()-heard.cfg.Quorum()+1)
	}

	now := int64(0)
	const rounds = int(maxRoundEscalation) + 8 // through and past the old cap
	for r := 0; r < rounds; r++ {
		now += driveStep
		heard.Tick(now)
		quiet.Tick(now)
		if heard.Round() != quiet.Round() {
			t.Fatalf("round %d: the claim-holder is at round %d and the control at round %d - a single member's claim moved the ladder",
				r, heard.Round(), quiet.Round())
		}
		if got, want := heard.timeoutAt-heard.now, quiet.timeoutAt-quiet.now; got != want {
			t.Fatalf("round %d: the claim-holder's next deadline is %d and the control's is %d - a claim shortened the cadence, which is how one Byzantine drags a validator out of its committee and holds a quorum-margin height down for good",
				r, got, want)
		}
		if r == 1 && heard.Round() != 1 {
			t.Fatalf("on its first timeout the claim-holder is at round %d, want the +1 step to 1", heard.Round())
		}
	}
}
