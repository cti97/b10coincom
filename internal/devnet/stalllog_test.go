package devnet

// Constructed-state proof for the node's stall line (stall.go).
//
// These tests do NOT provoke a stall with a timing race. Each one BUILDS the
// state the line is supposed to describe - a committee at one height for more
// than the threshold number of rounds, with and without the voting power that
// could make a quorum, and a height that has since advanced - and then asserts
// what the node says. A real stall would prove only that a line can be printed;
// a constructed state proves it reads the right facts.
//
// Every validator here runs with its tick and wave loops an hour apart, so the
// only clock the driver sees is the test's own virtual clock: nothing in the
// driver advances except through the calls below.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/transport"
)

// attestPeer installs on v exactly what one verified HELLO installs: the
// signed member identity and the transport name it arrived on. recordHeight is
// the single function the HELLO path calls, so this builds the same catch-up
// table a live committee would, with no socket and no race.
func attestPeer(t *testing.T, v *Validator, who string, via string, height uint64) {
	t.Helper()
	v.recordHeight(who, transport.PeerID(via), height)
}

// TestANodeInAStallSaysSoOnceWithRoundTalliesAndPeers is the finding's shape:
// three live seats of a four-seat committee, every peer attested, every round
// timed out with no proposal and no votes. Below the threshold the node is
// silent; at it, the node emits one line naming the round, the tallies and the
// peers; a second poll at the same height says nothing.
func TestANodeInAStallSaysSoOnceWithRoundTalliesAndPeers(t *testing.T) {
	vs := quietValidators(t, 4)
	live := vs[:3]
	v := live[0]
	for seat := 1; seat < 3; seat++ {
		attestPeer(t, v, string(live[seat].pub), fmt.Sprintf("v%d", seat), 0)
	}

	// One round short of the threshold: a merely slow height must not be
	// called a stall.
	reachRound(t, live, stallReportRounds-1)
	if line, ok := v.stallReportOnce(); ok {
		t.Fatalf("a node %d rounds into a height reported a stall at a threshold of %d: %s",
			stallReportRounds-1, stallReportRounds, line)
	}

	// The threshold round: the constructed state the line is for.
	reachRound(t, live, stallReportRounds)
	// The other two live seats prevoted NIL in the round this engine just
	// left, delivered through the node's real receive path. This is the CI
	// shape exactly: frames ARRIVED, all three live seats agreed on nil, and
	// still nothing committed - which the line must show, not merely "zero
	// votes".
	for seat := 1; seat < 3; seat++ {
		feed(v, seatVote(t, seat, consensus.MsgPrevote, 1, stallReportRounds-1, [32]byte{}))
	}
	line, ok := v.stallReportOnce()
	if !ok {
		t.Fatalf("a node that has timed out %d rounds at height 0 with quorum-many peers said nothing", stallReportRounds)
	}
	t.Logf("stall line: %s", line)
	for _, want := range []string{
		"b10coin: no block for 8 rounds",
		"height 0 (round 8, step propose)",
		"quorum reachable with 3 of 4 power (quorum 3)",
		"peers=2[seat1/v1 h=0, seat2/v2 h=0]",
		"proposal=absent",
		"tallies r7 (last round with a vote)",
		"prevote votes=3 power=3 quorum=3 nil=3 ids=[00000000:3]",
		"precommit votes=0 power=0 quorum=3 nil=0",
		"selfprevote=nil",
		"restart the committee together",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("the stall line does not say %q:%s", want, line)
		}
	}

	// ONCE per height: the tick loop calls this every tick, and a stall that
	// lasts minutes must not become a log flood.
	if again, ok := v.stallReportOnce(); ok {
		t.Fatalf("the same stuck height was reported twice:%s", again)
	}
}

// TestALoneSeatNamesTheUnreachableQuorumOnce is the S-1 shape at its smallest:
// one live seat of three cannot make the quorum of 3 by arithmetic, so no round
// here can commit. That used to be SILENT - the reachable-quorum line
// suppresses itself by design and this branch simply returned - which is how a
// real ten-seat halt logged nothing for nine minutes. It now gets its own line,
// naming the power it can reach, the quorum, the seats it hears nothing from
// and the cause; and it is still once per height.
func TestALoneSeatNamesTheUnreachableQuorumOnce(t *testing.T) {
	vs := quietValidators(t, 3)
	live := vs[:1] // seats 1 and 2 never run: no peers, no HELLOs
	v := vs[0]
	// The tick loop's first observation, at round 0: without it the watcher
	// would see the height for the first time AT the threshold and (correctly)
	// count from there, which is a different test.
	v.stallReportOnce()
	reachRound(t, live, stallReportRounds)
	line, ok := v.stallReportOnce()
	if !ok {
		t.Fatal("a lone seat whose 1 of 3 power cannot reach the quorum of 3 said nothing: the permanent-halt shape is silent again")
	}
	t.Logf("unreachable-quorum line: %s", line)
	for _, want := range []string{
		"no block for 8 rounds",
		"the quorum is UNREACHABLE",
		"this node can reach 1 of 3 power and the quorum is 3",
		"2 more power is needed",
		"the committee for height 1 DOES derive (3 seats)",
		"not a missing derivation",
		"seats with no node behind them",
		"2[seat1 power=1, seat2 power=1]",
		"peers=0[]",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("the unreachable-quorum line does not say %q:%s", want, line)
		}
	}
	// It is NOT the reachable-quorum line: that one asserts a quorum exists and
	// is failing, which is false here (audit B-4's rule, applied to the other
	// half of the diagnosis).
	for _, bad := range []string{"quorum reachable", "cannot be derived"} {
		if strings.Contains(line, bad) {
			t.Fatalf("the unreachable-quorum line says %q, which is false at this height:%s", bad, line)
		}
	}
	if again, ok := v.stallReportOnce(); ok {
		t.Fatalf("the same unreachable height was reported twice:%s", again)
	}
}

// TestAStallOnAnUnderivableCommitteeDoesNotPrintAQuorum pins audit B-4: when
// the committee for the next height cannot be derived, the stall line must not
// print a quorum at all.
//
// The state is constructed: three live seats of four are attested (so the OLD
// fallback would have had a non-empty genesis set to measure against and would
// have printed "quorum reachable with 3 of 4 power (quorum 3)"), and then the
// validator's per-height committee source is replaced with one that fails. The
// driver keeps its own copy of the config, so it keeps ticking; only the
// watcher's lookup sees the failure. The genesis committee is asserted non-empty
// first: without that check the absence of a quorum in the line would prove
// nothing, because the fallback would have had nothing to print either.
func TestAStallOnAnUnderivableCommitteeDoesNotPrintAQuorum(t *testing.T) {
	vs := quietValidators(t, 4)
	live := vs[:3]
	v := live[0]
	for seat := 1; seat < 3; seat++ {
		attestPeer(t, v, string(live[seat].pub), fmt.Sprintf("v%d", seat), 0)
	}
	v.mu.Lock()
	if len(v.cfgC.Committee) != 4 {
		v.mu.Unlock()
		t.Fatalf("fixture: the genesis committee holds %d seats, so the old fallback had nothing to measure a quorum against and this test would be vacuous", len(v.cfgC.Committee))
	}
	v.cfgC.CommitteeFor = func(h uint64) ([]genesis.Validator, error) {
		return nil, fmt.Errorf("constructed: no committee for height %d", h)
	}
	v.mu.Unlock()

	reachRound(t, live, stallReportRounds-1)
	// The tick loop polls every round, so the watcher has already seen this
	// height below the threshold: that observation is what fixes reachFrom at
	// the round the height began in, exactly as the existing stall-line tests
	// establish it. Nothing may be said one round short.
	if line, pre := v.stallReportOnce(); pre {
		t.Fatalf("a height %d rounds in reported before the threshold of %d:%s", stallReportRounds-1, stallReportRounds, line)
	}
	reachRound(t, live, stallReportRounds)
	line, ok := v.stallReportOnce()
	if !ok {
		t.Fatal("a height whose next committee cannot be derived said nothing: the operator is left with a silent chain")
	}
	t.Logf("underivable-committee stall line: %s", line)
	for _, bad := range []string{"quorum reachable", "power (quorum", "of 4 power"} {
		if strings.Contains(line, bad) {
			t.Fatalf("the line prints quorum arithmetic measured against the genesis set (%q in it):%s", bad, line)
		}
	}
	for _, want := range []string{
		"no block for 8 rounds",
		"height 0 (round 8",
		"the committee for height 1 cannot be derived",
		"constructed: no committee for height 1",
		"no quorum is reported",
		"Driver.HaltError",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("the line does not say %q:%s", want, line)
		}
	}
	if again, ok := v.stallReportOnce(); ok {
		t.Fatalf("the same undeducible height was reported twice:%s", again)
	}
}

// TestTheStallLineReArmsAtTheNextHeight pins the reset: the line is
// once per HEIGHT, not once per process. The state is constructed exactly as
// production advances it - a block appended by the chain's own writer and the
// driver rebuilt at the new head, which is what every catch-up adoption does.
func TestTheStallLineReArmsAtTheNextHeight(t *testing.T) {
	vs := quietValidators(t, 4)
	live := vs[:3]
	v := live[0]
	for seat := 1; seat < 3; seat++ {
		attestPeer(t, v, string(live[seat].pub), fmt.Sprintf("v%d", seat), 0)
	}
	// The tick loop sees every height from its round 0; so does this test.
	v.stallReportOnce()
	reachRound(t, live, stallReportRounds)
	if _, ok := v.stallReportOnce(); !ok {
		t.Fatalf("fixture: no stall line at the first height, so the re-arm cannot be tested")
	}

	parent := v.Chain().Head().ID()
	pub := v.cfgC.Proposer(1, 0, parent)
	seat := genesis.SeatOfPubKey(v.cfgC.Committee, pub)
	if seat < 0 {
		t.Fatalf("fixture: the drawn proposer is not in the committee")
	}
	ts := v.Chain().Head().Header.Timestamp + 1
	blk, err := v.Chain().Build(simnet.ValidatorKey(seat), nil, ts)
	if err != nil {
		t.Fatalf("building the block that advances the head: %v", err)
	}
	if err := v.Chain().Append(blk); err != nil {
		t.Fatalf("appending the block that advances the head: %v", err)
	}
	if err := v.rebuildDriver(); err != nil {
		t.Fatalf("rebuilding the driver at the adopted head: %v", err)
	}
	if got := v.Height(); got != 1 {
		t.Fatalf("fixture: the head is at height %d, want 1", got)
	}

	// The same committee, one height later, stalls the same way.
	v.stallReportOnce()
	reachRound(t, live, stallReportRounds)
	line, ok := v.stallReportOnce()
	if !ok {
		t.Fatalf("a node stalled at the NEXT height stayed silent: the once-per-height report never re-armed")
	}
	if !strings.Contains(line, "height 1 (round 8") {
		t.Fatalf("the re-armed line names the wrong height:%s", line)
	}
}

// TestAStallLineCountsOnlyRoundsWithAReachableQuorum is the false positive of
// the M5 network re-run (2026-10-30): a node that climbed rounds while its
// peers were down reported a REACHABLE-QUORUM stall the instant a peer came
// back, because the round NUMBER was already past the threshold. It then
// recovered in seconds. The rounds that count for that line are the ones
// entered with a reachable quorum.
//
// The outage itself is no longer silent (testrun 2026-11-06, S-1): a node that
// cannot see a quorum says so ONCE, in its own line, after the threshold. That
// line and the reachable one are separate latches, which is what lets this test
// keep asserting the original property - when the peers come back, the
// reachable line does not fire until eight rounds have been spent WITH the
// quorum in reach - without the earlier outage suppressing it.
func TestAStallLineCountsOnlyRoundsWithAReachableQuorum(t *testing.T) {
	vs := quietValidators(t, 4)
	live := vs[:3]
	v := live[0]
	// The outage: nobody heard from, sixteen rounds climbed, every one observed.
	// Below the threshold: silence. At it: the unreachable-quorum line, ONCE.
	firedAt := uint32(0)
	for r := uint32(0); r <= 2*stallReportRounds; r += 4 {
		reachRound(t, live, r)
		line, ok := v.stallReportOnce()
		switch {
		case r < stallReportRounds && ok:
			t.Fatalf("a node %d rounds into an outage reported anything:%s", r, line)
		case r == stallReportRounds && !ok:
			t.Fatalf("a node that could not reach a quorum said nothing at round %d: the permanent-halt shape is silent (S-1)", r)
		case r == stallReportRounds:
			if !strings.Contains(line, "the quorum is UNREACHABLE") {
				t.Fatalf("the outage reported the wrong shape at round %d:%s", r, line)
			}
			firedAt = r
		case ok:
			t.Fatalf("the same outage was reported again at round %d (first at %d):%s", r, firedAt, line)
		}
	}
	// The peers come back. Round 16 is past the threshold by number, but no
	// round has yet been spent with the quorum in reach.
	for seat := 1; seat < 3; seat++ {
		attestPeer(t, v, string(live[seat].pub), fmt.Sprintf("v%d", seat), 0)
	}
	if line, ok := v.stallReportOnce(); ok {
		t.Fatalf("the node reported a stall the moment its quorum came back (round %d):%s", v.Round(), line)
	}
	from := v.Round()
	reachRound(t, live, from+stallReportRounds-1)
	if line, ok := v.stallReportOnce(); ok {
		t.Fatalf("a stall was reported after %d rounds with a reachable quorum, threshold %d:%s", stallReportRounds-1, stallReportRounds, line)
	}
	reachRound(t, live, from+stallReportRounds)
	line, ok := v.stallReportOnce()
	if !ok {
		t.Fatalf("%d rounds with a reachable quorum and no block, and the node said nothing", stallReportRounds)
	}
	if want := fmt.Sprintf("(round %d,", from+stallReportRounds); !strings.Contains(line, want) {
		t.Fatalf("the line does not name round %d:%s", from+stallReportRounds, line)
	}
}

// TestAPeerThatDropsOutRestartsTheStallCount: the quorum must be reachable at
// EVERY round counted. A peer whose HELLO expires mid-count - the node being
// stopped next in a one-at-a-time restart - disarms the count, and it starts
// again from the round the quorum is back.
func TestAPeerThatDropsOutRestartsTheStallCount(t *testing.T) {
	vs := quietValidators(t, 4)
	live := vs[:3]
	v := live[0]
	attest := func() {
		for seat := 1; seat < 3; seat++ {
			attestPeer(t, v, string(live[seat].pub), fmt.Sprintf("v%d", seat), 0)
		}
	}
	attest()
	v.stallReportOnce()
	reachRound(t, live, stallReportRounds/2)
	v.stallReportOnce()
	// The peers' HELLOs expire: the waves move past the TTL with no refresh.
	v.peerHMu.Lock()
	v.wave += peerHeightTTL + 1
	v.peerHMu.Unlock()
	reachRound(t, live, stallReportRounds/2+1)
	if line, ok := v.stallReportOnce(); ok {
		t.Fatalf("a node whose peers had expired reported a stall:%s", line)
	}
	attest()
	reachRound(t, live, stallReportRounds)
	if line, ok := v.stallReportOnce(); ok {
		t.Fatalf("the rounds before the peers dropped out were still counted (round %d):%s", v.Round(), line)
	}
}

// driveClock ticks the validators one tick at a time with the virtual clock
// advancing by step per tick, from now to until, and returns the clock it
// reached. Unlike reachRound it does NOT jump the clock: it builds the state a
// live node actually passes through - "eight rounds in, but only five seconds
// old" - which is the N-3 hiccup and cannot be built by a helper that advances
// a thousand seconds per round.
func driveClock(t *testing.T, vs []*Validator, from, until, step int64) int64 {
	t.Helper()
	now := from
	for now < until {
		now += step
		for _, v := range vs {
			v.mu.Lock()
			v.drv.Tick(now)
			v.drv.Observe()
			v.mu.Unlock()
		}
	}
	return now
}

// TestASecondsLongHiccupIsNotAStall is N-3, both halves at once.
//
// BEFORE: eight rounds at one height was the whole threshold, and the shipped
// ladder (200 ms base + 100 ms step) spends those eight rounds in about 4.4 s -
// so normal ten-seat running fired the line in bursts and the documented
// one-at-a-time restart (longest gap 8.4 s) produced 20 of them, while the
// README promised a line for a stall that "can hold for minutes".
//
// AFTER: the state is constructed with a clock that moves the way the tick loop
// moves it. At 5 s the node has ALREADY passed the old round threshold - the
// test asserts that, so it cannot pass vacuously - and says nothing. Past
// stallReportAfter the same stall is old enough and is reported.
func TestASecondsLongHiccupIsNotAStall(t *testing.T) {
	vs := quietValidators(t, 4)
	live := vs[:3]
	v := live[0]
	for seat := 1; seat < 3; seat++ {
		attestPeer(t, v, string(live[seat].pub), fmt.Sprintf("v%d", seat), 0)
	}
	v.stallReportOnce() // the tick loop's round-0 observation

	now := driveClock(t, live, 0, 5_000, 50)
	rounds := v.Round()
	if rounds < stallReportRounds {
		t.Fatalf("fixture: five seconds bought only %d rounds, so this test does not reach the OLD threshold and would prove nothing", rounds)
	}
	if line, ok := v.stallReportOnce(); ok {
		t.Fatalf("a 5 s hiccup (%d rounds at one height) fired the stall line: the threshold is still rounds alone:%s", rounds, line)
	}

	driveClock(t, live, now, int64(stallReportAfter/time.Millisecond)+5_000, 50)
	line, ok := v.stallReportOnce()
	if !ok {
		t.Fatalf("a stall older than %v said nothing: the time gate suppressed a real one", stallReportAfter)
	}
	t.Logf("stall line after the time threshold: %s", line)
	if !strings.Contains(line, "quorum reachable with 3 of 4 power (quorum 3)") {
		t.Fatalf("the time-gated line is not the reachable-quorum one:%s", line)
	}
	if strings.Contains(line, "no block for 8 rounds") {
		t.Fatalf("the line still claims the constant 8 rounds after crossing a time threshold:%s", line)
	}
}

// TestASyncingNodeDoesNotCryStall is N-3's other half: a node with a certified
// head still to fetch is catching up, not stalled. The suppression uses the
// same selection maybeCatchUp pulls on, so the two cannot disagree.
func TestASyncingNodeDoesNotCryStall(t *testing.T) {
	vs := quietValidators(t, 4)
	live := vs[:3]
	v := live[0]
	for seat := 1; seat < 3; seat++ {
		attestPeer(t, v, string(live[seat].pub), fmt.Sprintf("v%d", seat), 0)
	}
	// One peer announces a head well above ours: a certified block this node
	// has not fetched yet. We are behind, and pulling is what we are doing.
	attestPeer(t, v, string(live[1].pub), "v1", 100)
	v.stallReportOnce()
	now := driveClock(t, live, 0, int64(stallReportAfter/time.Millisecond)+5_000, 50)
	if line, ok := v.stallReportOnce(); ok {
		t.Fatalf("a node with a certified head to fetch reported a stall while syncing:%s", line)
	}

	// The same peer, now level with us: there is nothing left to fetch, so a
	// height that does not move is a real stall again.
	v.peerHMu.Lock()
	st := v.peerH[string(live[1].pub)]
	if st == nil {
		v.peerHMu.Unlock()
		t.Fatal("fixture: the peer is not in the catch-up table")
	}
	st.height = 0
	v.peerHMu.Unlock()

	// Enter another round: while the quorum is in reach the watcher samples
	// reachability once per round, so a second poll at the same round is
	// deliberately free.
	driveClock(t, live, now, now+2_000, 50)
	line, ok := v.stallReportOnce()
	if !ok {
		t.Fatal("the sync suppression outlived the catch-up: a level node that cannot commit said nothing")
	}
	if !strings.Contains(line, "quorum reachable with 3 of 4 power (quorum 3)") {
		t.Fatalf("the line after the catch-up is not the reachable-quorum one:%s", line)
	}
}

// nodelessBondValidators builds S-1's shape as a CONSTRUCTED STATE: a ten-seat
// genesis whose eight fixture seats hold power 1 and whose last two hold 4 each
// with no node behind them. 4 + 4 of 16 is the 1/4 cap's fixed point for two
// 10^11 bonds against eight power-1 seats, and quorumFor(16) is 11 - so eight
// live power is below quorum for as long as those two seats have no node. Only
// the eight seated keys are started: the two silent seats never run.
func nodelessBondValidators(t *testing.T) []*Validator {
	t.Helper()
	g := simnet.Committee(10)
	g.Validators[8].Power = 4
	g.Validators[9].Power = 4
	vs := make([]*Validator, 8)
	for i := range vs {
		v, err := StartValidator(ValidatorConfig{
			Dir:       t.TempDir(),
			Genesis:   g,
			Key:       simnet.ValidatorKey(i),
			TickEvery: time.Hour,
			WaveEvery: time.Hour,
		})
		if err != nil {
			t.Fatalf("starting validator %d over the capped genesis: %v", i, err)
		}
		vs[i] = v
	}
	t.Cleanup(func() { closeAll(vs) })
	return vs
}

// TestAnUnreachableQuorumWithNodelessSeatsSaysSoOnce is S-1's exact case: two
// bonded seats with no node behind them leave 8 of 16 power live against a
// quorum of 11, so no block can commit and no Unbond can be included. The run
// that found it froze for over nine minutes and the nodes logged NOTHING.
//
// The line must (a) exist, (b) name the reachable power, the total and the
// quorum, (c) name the silent seats WITH their power so an operator knows which
// node to start, (d) say the cause is seats with no node behind them and not a
// derivation failure, and (e) be emitted once per height.
func TestAnUnreachableQuorumWithNodelessSeatsSaysSoOnce(t *testing.T) {
	vs := nodelessBondValidators(t)
	v := vs[0]
	for seat := 1; seat < len(vs); seat++ {
		attestPeer(t, v, string(vs[seat].pub), fmt.Sprintf("v%d", seat), 0)
	}
	v.stallReportOnce() // the tick loop's round-0 observation
	reachRound(t, vs, stallReportRounds)

	line, ok := v.stallReportOnce()
	if !ok {
		t.Fatal("two nodeless seats left 8 of 16 power live against a quorum of 11 and the node said nothing: S-1's silent halt is back")
	}
	t.Logf("nodeless-seat halt line: %s", line)
	for _, want := range []string{
		"the quorum is UNREACHABLE",
		"this node can reach 8 of 16 power and the quorum is 11",
		"3 more power is needed",
		"the committee for height 1 DOES derive (10 seats)",
		"not a missing derivation",
		"seats with no node behind them",
		"2[seat8 power=4, seat9 power=4]",
		"peers=7[",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("the nodeless-seat line does not say %q:%s", want, line)
		}
	}
	// The reachable-quorum line would assert a quorum exists and is failing to
	// commit. Neither is true here, and printing it would be the lie B-4 is
	// about, one set over.
	for _, bad := range []string{"quorum reachable", "nothing commits", "cannot be derived"} {
		if strings.Contains(line, bad) {
			t.Fatalf("the nodeless-seat line says %q, which is false at this height:%s", bad, line)
		}
	}
	if again, ok := v.stallReportOnce(); ok {
		t.Fatalf("the same permanent halt was reported twice:%s", again)
	}
}

// TestThePeerListNamesSeatsByTheirGenesisSeat is N-4. The committee derived at
// a boundary is ordered by bonded stake and then by key bytes, so a genesis
// seat's INDEX in it is a permutation of the genesis order: on this fixture key
// 0 sits at index 4 and key 4 at index 8. Labelling peers with that index made
// seat 0 print `peers=9[seat0, seat1, seat2, seat3, seat5, …]` - it looked like
// the node listing itself and omitting seat4 - while the mapping was exact and
// the NUMBER was the wrong name. The list now uses the genesis seat, which is
// the name `--index` and the transport's "vN" already use, so it can be read
// against the rest of the run.
func TestThePeerListNamesSeatsByTheirGenesisSeat(t *testing.T) {
	vs := quietValidators(t, 10)
	for _, v := range vs {
		for seat := range vs {
			if vs[seat] == v {
				continue
			}
			attestPeer(t, v, string(vs[seat].pub), fmt.Sprintf("v%d", seat), 0)
		}
	}
	// Fixture: prove the reordering this test is about is actually present, so
	// a later derivation change cannot make the test pass vacuously.
	vals, err := vs[0].cfgC.CommitteeAt(1)
	if err != nil {
		t.Fatalf("the committee for height 1: %v", err)
	}
	if got := genesis.SeatOfPubKey(vals, vs[0].pub); got != 4 {
		t.Fatalf("fixture: genesis seat 0 holds committee index %d, not 4, so this test no longer exercises the reordering", got)
	}
	if got := genesis.SeatOfPubKey(vals, vs[4].pub); got != 8 {
		t.Fatalf("fixture: genesis seat 4 holds committee index %d, not 8, so this test no longer exercises the reordering", got)
	}
	for _, v := range vs {
		v.stallReportOnce() // the tick loop's round-0 observation
	}
	reachRound(t, vs, stallReportRounds)

	line0, ok := vs[0].stallReportOnce()
	if !ok {
		t.Fatal("seat 0 said nothing, so its peer list cannot be read")
	}
	t.Logf("seat 0's stall line: %s", line0)
	want0 := "peers=9[seat1/v1 h=0, seat2/v2 h=0, seat3/v3 h=0, seat4/v4 h=0, seat5/v5 h=0, seat6/v6 h=0, seat7/v7 h=0, seat8/v8 h=0, seat9/v9 h=0]"
	if !strings.Contains(line0, want0) {
		t.Fatalf("seat 0's peer list is not the other nine genesis seats (%q missing):%s", want0, line0)
	}
	if strings.Contains(line0, "seat0/") {
		t.Fatalf("seat 0 lists itself:%s", line0)
	}

	line4, ok := vs[4].stallReportOnce()
	if !ok {
		t.Fatal("seat 4 said nothing, so its peer list cannot be read")
	}
	t.Logf("seat 4's stall line: %s", line4)
	want4 := "peers=9[seat0/v0 h=0, seat1/v1 h=0, seat2/v2 h=0, seat3/v3 h=0, seat5/v5 h=0, seat6/v6 h=0, seat7/v7 h=0, seat8/v8 h=0, seat9/v9 h=0]"
	if !strings.Contains(line4, want4) {
		t.Fatalf("seat 4's peer list is not the other nine genesis seats (%q missing):%s", want4, line4)
	}
	if strings.Contains(line4, "seat4/") {
		t.Fatalf("seat 4 lists itself:%s", line4)
	}
	if !strings.Contains(line4, "seat8/v8") {
		t.Fatalf("seat 4 does not name seat 8 - the seat the index-based list omitted:%s", line4)
	}
}
