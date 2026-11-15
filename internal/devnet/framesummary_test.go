package devnet

// The node-layer pin for the per-kind frame counters: the summary renders, it is
// attached to the stall line an operator actually reads, and a live committee
// puts real consensus traffic in BOTH directions of it.
//
// This file exists because the counters' whole value is that they turn "no votes
// arrived" into a number. A summary that renders but is never printed, or that
// counts only one direction, would leave the next stalled run exactly where the
// 2026-11-15 one was.

import (
	"strings"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
	"github.com/cti97/b10coincom/internal/transport/tcp"
)

// TestFrameSummaryNamesEveryBucketAtZero pins the shape an operator sees on a
// quiet node: every bucket named, so a reader does not have to guess what "h"
// or "p" meant, and the counters at zero rather than missing.
func TestFrameSummaryNamesEveryBucketAtZero(t *testing.T) {
	v := startListening(t, 0, 4)
	defer closeAll([]*Validator{v})
	got := v.FrameSummary()
	for _, want := range []string{
		"frames sent/recv[",
		"hello 0/0", "proposal 0/0", "prevote 0/0", "precommit 0/0",
		"exchange 0/0", "sync 0/0", "other 0/0",
		"queued=", "qdrop=", "links=",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("frame summary %q does not name %q", got, want)
		}
	}
}

// TestTheStallLineCarriesTheFrameCounters is the deliverable in one assertion:
// the line a stalled run prints must carry the per-kind counts, because it is
// the only output a stalled operator has. The tallies say "one vote"; this says
// whether the other two were never sent, never received, or dropped.
func TestTheStallLineCarriesTheFrameCounters(t *testing.T) {
	v := startListening(t, 0, 4)
	defer closeAll([]*Validator{v})
	line := v.stallLine(0, 0, stallBoard{total: 4, quorum: 3, power: 3})
	if !strings.Contains(line, "frames sent/recv[") {
		t.Fatalf("the stall line does not carry the frame counters: %s", line)
	}
	if !strings.Contains(line, "proposal 0/0") || !strings.Contains(line, "prevote 0/0") {
		t.Fatalf("the stall line's frame counters do not name the consensus buckets: %s", line)
	}
	// And the unreachable-quorum sibling, which is the other "nothing commits"
	// shape an operator meets.
	unreach := v.stallUnreachableLine(0, 3, stallBoard{total: 4, quorum: 3, power: 2})
	if !strings.Contains(unreach, "frames sent/recv[") {
		t.Fatalf("the unreachable-quorum line does not carry the frame counters: %s", unreach)
	}
}

// TestALiveCommitteeCountsConsensusFramesInBothDirections is the counter's
// contract against real consensus traffic, not a synthetic send: three seats
// commit through a relay, and a seat's summary must show proposals and prevotes
// both SENT and RECEIVED. If the send or receive placement were wrong (counted
// after dispatch, or only on the broadcast caller), this is the test that goes
// red.
func TestALiveCommitteeCountsConsensusFramesInBothDirections(t *testing.T) {
	rl := relay.New(relay.Options{})
	defer rl.Close()
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	vs := make([]*Validator, 3)
	for i := 0; i < 3; i++ {
		v, err := StartValidator(ValidatorConfig{Dir: t.TempDir(), Index: i, Validators: 4})
		if err != nil {
			t.Fatal(err)
		}
		vs[i] = v
		if err := v.ConnectRelay(rl.Addr().String()); err != nil {
			t.Fatal(err)
		}
	}
	defer closeAll(vs)
	waitAllReach(t, vs, 3, 60*time.Second)

	// Read after a commit: the frames that committed it have been sent and
	// received. The counters are atomic, so no lock and no quiescence needed.
	st := vs[0].ttp.FrameStats()
	consensus := func(c [tcp.NumFrameKinds]uint64) uint64 {
		return c[tcp.FrameProposal] + c[tcp.FramePrevote] + c[tcp.FramePrecommit]
	}
	if consensus(st.Totals.Sent) == 0 {
		t.Fatalf("a committing seat sent no proposals or votes: %s", vs[0].FrameSummary())
	}
	if consensus(st.Totals.Recv) == 0 {
		t.Fatalf("a committing seat received no proposals or votes from its peers: %s", vs[0].FrameSummary())
	}
	// HELLOs are the control the incident needs: they must ALSO be moving. A
	// run where only HELLOs move is the failure this instrumentation names, and
	// this half of the assertion keeps the control comparable. They are sent on
	// the wave cadence, which is slower than a fast commit, so wait for one
	// rather than racing the first tick: a zero here would then mean the HELLO
	// path is uncounted, not that the wave had not fired.
	waitFor(t, "a HELLO in both directions", 5*time.Second, func() bool {
		s := vs[0].ttp.FrameStats().Totals
		return s.Sent[tcp.FrameHello] > 0 && s.Recv[tcp.FrameHello] > 0
	})
}
