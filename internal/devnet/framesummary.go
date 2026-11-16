package devnet

// The node-layer rendering of the transport's per-link frame counters
// (internal/transport/tcp/framecounts.go).
//
// WHY IT IS ON THE STALL LINE. The 2026-11-15 incident left one line and a
// relay: "peers=2, tallies r23: prevote votes=1 power=1 quorum=3 nil=1" and
// "forwarded ~14 frames/s, dropped flat". Those two facts are consistent with
// THREE faults - never sent, sent but not received, received but refused - and
// the operator had to guess which. The stall line is the one place a stalled
// run is already read, so the numbers belong beside the tallies that raise the
// question: how many proposals, prevotes and precommits were SENT on each link,
// how many were WRITTEN to the socket, and how many were RECEIVED. HELLOs are
// the control: a run where hello moves in both directions while the consensus
// buckets stay at zero is admission working and consensus traffic missing.
//
// IT IS CHEAP AND OFF THE HOT PATH. The transport keeps atomics per link (one
// increment at enqueue, one after a successful write, one after a read); this
// file runs only when the once-per-height stall watcher fires. Nothing here is
// per frame.

import (
	"fmt"
	"strings"

	"github.com/cti97/b10coincom/internal/transport/tcp"
)

// FrameSummary renders this node's per-link frame counters compactly:
//
//	frames sent/recv[hello 3/12 proposal 0/0 prevote 58/1 precommit 57/1 exchange 1/2 sync 0/0 other 12/13] queued=0 qdrop=0 gated=0 paced=0 links=1[relay:93.115.53.244:7001]
//
// "sent" is accepted into the write queue, "recv" is read off the socket before
// any admission or routing decision. queued is sent-minus-written: frames this
// node committed to the link that have not reached the kernel yet (a local
// backlog, not a network loss). Per-link detail follows when there is more than
// one link; a relay star has exactly one, and naming it says which connection
// the numbers are about.
func (v *Validator) FrameSummary() string {
	if v.ttp == nil {
		return "frames n/a (no transport)"
	}
	st := v.ttp.FrameStats()
	var b strings.Builder
	b.WriteString("frames sent/recv[")
	for k := tcp.FrameKind(0); k < tcp.NumFrameKinds; k++ {
		if k > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s %d/%d", tcp.FrameKindName(k), st.Totals.Sent[k], st.Totals.Recv[k])
	}
	fmt.Fprintf(&b, "] queued=%d qdrop=%d gated=%d paced=%d links=%d",
		st.Totals.SentTotal()-st.Totals.WrittenTotal(),
		st.Totals.Dropped, st.Totals.Gated, st.Totals.RelayPaced, len(st.Peers))
	if len(st.Peers) == 1 {
		fmt.Fprintf(&b, "[%s]", st.Peers[0].Peer)
	} else if len(st.Peers) > 1 {
		b.WriteByte('[')
		for i, p := range st.Peers {
			if i > 0 {
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "%s %d/%d", p.Peer, p.SentTotal(), p.RecvTotal())
		}
		b.WriteByte(']')
	}
	return b.String()
}

// FrameVerdict is the second half of the same answer: where the frames went
// AFTER they were received. The per-kind counters say "received"; this says
// whether the node's own router accepted them (routed), refused them before
// verification (refused: a non-member key or a height outside the live
// window), dropped a duplicate, or could not classify the bytes (unknown) -
// and then what the ENGINE did with the ones it got (a vote for another height,
// a vote too early or too late in the round, a proposal for another round, a
// proposal from the wrong proposer).
//
// THE FOUR-WAY SPLIT THIS CLOSES. A stalled line saying "tallies=1" has four
// possible causes and they need four different fixes:
//
//   - sent=0 (the engine or send path never emitted): frames summary, zero sent;
//   - sent>0, received=0 (the relay or the network): frames summary;
//   - received>0, routed=0 (the router refused): THIS line, refused/dup/unknown;
//   - routed>0, tallies=1 (the engine dropped it as foreign/early/late): THIS
//     line, engine[...].
//
// It reads only counters the node already keeps, and it runs only when the
// once-per-height stall watcher fires.
func (v *Validator) FrameVerdict() string {
	if v.drv == nil || v.rt == nil {
		return "routed n/a (no driver)"
	}
	d := v.drv.DiagCounters()
	return fmt.Sprintf("routed=%d refused=%d dup=%d unknown=%d engine[otherheight=%d early=%d late=%d foreignprop=%d wrongprop=%d dupprop=%d dupvote=%d]",
		v.framesIn.Load(), v.rt.RefusedBeforeVerify(), v.rt.DuplicatesDropped(), v.rt.UnknownDropped(),
		d.OtherHeightVotes, d.EarlyVotes, d.LateVotes, d.ForeignProposals,
		d.WrongProposerProposals, d.DuplicateProposals, d.DuplicateVotes)
}
