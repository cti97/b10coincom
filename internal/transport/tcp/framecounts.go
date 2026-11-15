package tcp

// Per-link frame accounting: WHAT was sent and received, by message kind, on
// EVERY connection. It exists because "the votes did not arrive" is three
// different faults that the committed height cannot tell apart:
//
//   - the node never SENT them (an engine or a send-path condition),
//   - the node sent them and the far end never RECEIVED them (the relay, the
//     socket, the peer's accept path), or
//   - the node received them and its own router dropped them (membership,
//     height window, dedup, admission).
//
// The 2026-11-15 three-host stall had only "each node tallies its own vote"
// and a relay saying it forwarded ~14 frames/s. That is consistent with all
// three, so the next stalled run has to answer it with numbers. This file is
// the node-side half of that answer; internal/devnet's stall line renders it.
//
// THE RELAY IS UNTOUCHED BY THIS. The relay's "parse nothing" posture is a
// security property of that process, not a ban on the NODE observing its own
// traffic. These counters live at the node's socket boundary, where the bytes
// are already the node's own, and they READ ONE BYTE to pick a counter slot.
//
// WHAT THE CLASSIFICATION IS NOT: it is never a decision. No value computed
// here changes control flow, admission, routing or framing. The router keeps
// its verified-decode discipline (internal/consensus/router.go) and would keep
// working with these counters wrong or deleted. A tag byte is a CLAIM used only
// to choose a bucket; a frame with a consensus tag that does not verify is
// still a frame the router refuses, and an unknown tag lands in "other".
//
// The two unions are disjoint by construction (wire.WireTagFloor = 0x80), but
// the consensus tags 1/2/3 are written here as literals on purpose: package
// tcp must not import package consensus (the transport is the boundary
// consensus is allowed to know about, not the reverse), and those three values
// are wire values that "never renumber" (internal/consensus/message.go). A
// test pins them against the consensus package so a rename cannot drift.

import (
	"sort"
	"sync/atomic"

	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

// FrameKind names one bucket of the per-link counters. The order is the order
// the summary prints in, and it never changes: a log line whose field order
// moves run to run is not one you can diff.
type FrameKind uint8

const (
	// FrameHello is a signed HELLO (wire.MsgHello): the peer-admission
	// heartbeat. It is the control for "HELLOs arrive but consensus frames do
	// not" - if this bucket moves in both directions while proposal/vote stay
	// at zero received, admission is not the fault.
	FrameHello FrameKind = iota
	// FrameProposal is a consensus proposal (consensus.MsgProposal = 1). It
	// carries a whole block, so it is the one consensus frame whose size is
	// not bounded by the message envelope.
	FrameProposal
	// FramePrevote is a consensus prevote (consensus.MsgPrevote = 2).
	FramePrevote
	// FramePrecommit is a consensus precommit (consensus.MsgPrecommit = 3).
	FramePrecommit
	// FramePeerExchange is an address advertisement (wire.MsgPeerExchange),
	// sent by the node's own wave loop and never by the consensus engine.
	FramePeerExchange
	// FrameBlockSync is either half of the catch-up pair
	// (wire.MsgBlockSyncReq / wire.MsgBlockSyncResp).
	FrameBlockSync
	// FrameOther is anything else: the direct handshake's ID frame, a frame
	// this build does not know, or an empty payload. A steady nonzero RECEIVED
	// count here while the node runs is a mixed-version or hostile peer, and it
	// is the bucket that says so.
	FrameOther

	// NumFrameKinds is the number of buckets. It is the array width.
	NumFrameKinds
)

// frameKindNames is indexed by FrameKind. Short names because the summary is
// appended to an already-long stall line.
var frameKindNames = [NumFrameKinds]string{
	FrameHello:        "hello",
	FrameProposal:     "proposal",
	FramePrevote:      "prevote",
	FramePrecommit:    "precommit",
	FramePeerExchange: "exchange",
	FrameBlockSync:    "sync",
	FrameOther:        "other",
}

// FrameKindName returns the summary name of a kind, or "?" for a value outside
// the union (a caller bug, never a wire value).
func FrameKindName(k FrameKind) string {
	if int(k) < len(frameKindNames) {
		return frameKindNames[k]
	}
	return "?"
}

// ClassifyFrame reports which counter bucket a payload belongs in. It reads at
// most one byte and never fails: every payload has a bucket.
//
// It is exported so a test (and internal/devnet's own accounting, if it ever
// wants it) can classify the SAME bytes the transport saw, instead of growing a
// second, divergent copy of the tag list.
func ClassifyFrame(data []byte) FrameKind {
	if len(data) == 0 {
		return FrameOther
	}
	switch data[0] {
	case 1: // consensus.MsgProposal
		return FrameProposal
	case 2: // consensus.MsgPrevote
		return FramePrevote
	case 3: // consensus.MsgPrecommit
		return FramePrecommit
	}
	switch wire.MsgType(data[0]) {
	case wire.MsgHello:
		return FrameHello
	case wire.MsgBlockSyncReq, wire.MsgBlockSyncResp:
		return FrameBlockSync
	case wire.MsgPeerExchange:
		return FramePeerExchange
	}
	return FrameOther
}

// frameCounts is one connection's counters. Two directions, one array each,
// all atomic: the reader and the writer touch this connection concurrently and
// an operator may read it from a third goroutine.
//
// SENT is incremented when a frame is ACCEPTED INTO the write queue (enqueue),
// not when the call that produced it returned: the queue is the last place the
// node chooses to keep a frame, so "sent" here means "the node committed this
// frame to the wire" (a queue-full drop is counted separately in dropped, so a
// frame can never be invisible).
//
// WRITTEN is incremented after wire.WriteFrame returns nil, so written <= sent
// always, and the GAP is the node's own backlog: frames queued but not yet on
// the socket. A stall where sent grows, written grows, and RECEIVED at the peer
// stays zero is the relay or the network; sent growing while written lags by
// the queue depth is this link's writer.
//
// RECEIVED is incremented the instant a complete frame is read off the socket,
// BEFORE pacing, admission or dispatch can delay or drop it. That placement is
// the whole point: a vote that arrives and is then refused by the router is
// still "received", and the router's own counters say why it was dropped. A
// received counter placed after dispatch would hide exactly the drop this
// instrumentation exists to find.
type frameCounts struct {
	sent    [NumFrameKinds]atomic.Uint64
	written [NumFrameKinds]atomic.Uint64
	recv    [NumFrameKinds]atomic.Uint64
}

// PeerFrameStats is one link's snapshot. Sent/Written/Recv are indexed by
// FrameKind and are COPIES, so the caller may render them without holding any
// lock. Dropped is the count of frames this link refused because its write
// queue was full (the silent Broadcast drop, audit N-11's documented policy);
// Gated and RateLimited are the receive-side drops that happen after Recv.
type PeerFrameStats struct {
	Peer        transport.PeerID
	Sent        [NumFrameKinds]uint64
	Written     [NumFrameKinds]uint64
	Recv        [NumFrameKinds]uint64
	Dropped     uint64
	Gated       uint64
	RateLimited uint64
	RelayPaced  uint64
}

// SentTotal, WrittenTotal and RecvTotal sum a snapshot's per-kind buckets. They
// exist so a caller renders the link's size without re-implementing the loop,
// and so "sent but not received" is one subtraction instead of a manual walk.
func (p PeerFrameStats) SentTotal() uint64    { return sumKinds(p.Sent[:]) }
func (p PeerFrameStats) WrittenTotal() uint64 { return sumKinds(p.Written[:]) }
func (p PeerFrameStats) RecvTotal() uint64    { return sumKinds(p.Recv[:]) }

func sumKinds(v []uint64) uint64 {
	var n uint64
	for _, x := range v {
		n += x
	}
	return n
}

// FrameStats is the whole transport's snapshot plus a deterministic peer order.
// Peers is sorted by name, the same discipline Peers() keeps, so a logged
// summary is diffable across runs.
type FrameStats struct {
	Peers  []PeerFrameStats
	Totals PeerFrameStats
}

// FrameStats snapshots every known connection's frame counters. It takes the
// transport mutex only to read the registry; the counters themselves are
// atomic, so the reader and writer goroutines are never blocked by it.
//
// It is called from a diagnostic path (a stall line, a harness report), never
// per frame, so its allocation is not on any hot path.
func (t *TcpTransport) FrameStats() FrameStats {
	t.mu.Lock()
	conns := make(map[transport.PeerID]*conn, len(t.conns))
	for id, c := range t.conns {
		conns[id] = c
	}
	t.mu.Unlock()

	var out FrameStats
	for id, c := range conns {
		p := PeerFrameStats{
			Peer:        id,
			Dropped:     c.dropped.Load(),
			Gated:       c.gated.Load(),
			RateLimited: c.rateLimited.Load(),
			RelayPaced:  c.relayPaced.Load(),
		}
		for k := FrameKind(0); k < NumFrameKinds; k++ {
			p.Sent[k] = c.frames.sent[k].Load()
			p.Written[k] = c.frames.written[k].Load()
			p.Recv[k] = c.frames.recv[k].Load()
			out.Totals.Sent[k] += p.Sent[k]
			out.Totals.Written[k] += p.Written[k]
			out.Totals.Recv[k] += p.Recv[k]
		}
		out.Totals.Dropped += p.Dropped
		out.Totals.Gated += p.Gated
		out.Totals.RateLimited += p.RateLimited
		out.Totals.RelayPaced += p.RelayPaced
		out.Peers = append(out.Peers, p)
	}
	sort.Slice(out.Peers, func(i, j int) bool { return out.Peers[i].Peer < out.Peers[j].Peer })
	return out
}
