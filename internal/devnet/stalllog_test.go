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

// TestALoneSeatDoesNotCryStallWithoutAReachableQuorum is the other half of "at
// a height where it believes a quorum should exist": one live seat of three
// cannot make the quorum of 3 by arithmetic, so its stall is EXPECTED, not a
// warning. The node must stay silent even past the round threshold.
func TestALoneSeatDoesNotCryStallWithoutAReachableQuorum(t *testing.T) {
	vs := quietValidators(t, 3)
	live := vs[:1] // seats 1 and 2 never run: no peers, no HELLOs
	reachRound(t, live, stallReportRounds)
	if line, ok := vs[0].stallReportOnce(); ok {
		t.Fatalf("a lone seat whose 1 of 3 power cannot reach the quorum of 3 reported a stall:%s", line)
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
// peers were down - an expected stall, its quorum unreachable - reported a
// stall the instant a peer came back, because the round NUMBER was already
// past the threshold. It then recovered in seconds. The rounds that count are
// the ones entered with a reachable quorum.
func TestAStallLineCountsOnlyRoundsWithAReachableQuorum(t *testing.T) {
	vs := quietValidators(t, 4)
	live := vs[:3]
	v := live[0]
	// The outage: nobody heard from, sixteen rounds climbed, every one observed.
	for r := uint32(0); r <= 2*stallReportRounds; r += 4 {
		reachRound(t, live, r)
		if line, ok := v.stallReportOnce(); ok {
			t.Fatalf("a node that could not reach a quorum reported a stall at round %d:%s", r, line)
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
