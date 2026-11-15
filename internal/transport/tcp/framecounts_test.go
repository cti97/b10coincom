package tcp

// Tests for the per-link, per-kind frame counters (framecounts.go). They pin the
// two properties the 2026-11-15 vote-stall investigation depends on:
//
//   - the buckets are CLASSIFIED from the same tags every decoder uses (a
//     renumbered consensus or wire tag fails here, not in a live run), and
//   - SENT and RECEIVED are counted at the two ends of a real socket, so
//     "sent prevotes, received none" is something a run can print.

import (
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/wire"
)

// TestFrameClassificationAgreesWithTheTagUnions imports the unions themselves
// rather than repeating their numbers: the counters are only trustworthy if a
// bucket means what the decoder means by the same byte. The consensus tags are
// wire values that "never renumber"; this test is what makes that promise
// something a CI run checks.
func TestFrameClassificationAgreesWithTheTagUnions(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want FrameKind
	}{
		{"empty", nil, FrameOther},
		{"proposal", []byte{byte(consensus.MsgProposal), 0}, FrameProposal},
		{"prevote", []byte{byte(consensus.MsgPrevote), 0}, FramePrevote},
		{"precommit", []byte{byte(consensus.MsgPrecommit), 0}, FramePrecommit},
		{"hello", []byte{byte(wire.MsgHello), 0}, FrameHello},
		{"sync-req", []byte{byte(wire.MsgBlockSyncReq), 0}, FrameBlockSync},
		{"sync-resp", []byte{byte(wire.MsgBlockSyncResp), 0}, FrameBlockSync},
		{"exchange", []byte{byte(wire.MsgPeerExchange), 0}, FramePeerExchange},
		{"handshake-id", []byte("v0"), FrameOther},
		{"unknown-consensus-tag", []byte{4}, FrameOther},
		{"unknown-wire-tag", []byte{0x90}, FrameOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyFrame(tc.data); got != tc.want {
				t.Fatalf("ClassifyFrame(%x) = %s, want %s", tc.data, FrameKindName(got), FrameKindName(tc.want))
			}
		})
	}
	// The three consensus tags stay below the wire floor, so the buckets can
	// never collide: if a future wire tag was added below 0x80 the router's
	// disjointness argument (audit N-5) would be gone, and this file would
	// silently mis-bucket it.
	for _, tag := range []byte{byte(consensus.MsgProposal), byte(consensus.MsgPrevote), byte(consensus.MsgPrecommit)} {
		if wire.MsgType(tag) >= wire.WireTagFloor {
			t.Fatalf("consensus tag %#x is at or above wire.WireTagFloor %#x", tag, wire.WireTagFloor)
		}
	}
}

// TestFrameCountersCountBothDirectionsPerLink drives one real connection and
// asserts the counts at BOTH ends: what a sent was accepted into its queue and
// written to the socket, and what b read off it. The direct handshake's ID
// frames land in "other", so every assertion is a DELTA from a baseline taken
// once the peers are up.
func TestFrameCountersCountBothDirectionsPerLink(t *testing.T) {
	a := listen(t, Options{LocalID: "a"})
	b := listen(t, Options{LocalID: "b"})
	if err := b.Dial(a.Addr().String()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeersIs(t, a, "[b]")
	waitPeersIs(t, b, "[a]")

	baseA := a.FrameStats()
	baseB := b.FrameStats()
	if len(baseA.Peers) != 1 || baseA.Peers[0].Peer != "b" {
		t.Fatalf("a's stat peers = %v, want exactly [b]", baseA.Peers)
	}

	// One frame per consensus bucket, plus a HELLO and a PEER_EXCHANGE, from a
	// to b. The payloads are tag-prefixed byte strings on purpose: the transport
	// is opaque, and this test is about what the link counted, not what the
	// router would have done with them.
	hello := wire.EncodeHello(&wire.Hello{ChainID: "c", Height: 7})
	exchange := wire.EncodePeerExchange(&wire.PeerExchange{Height: 7, Addrs: []string{"192.0.2.7:7001"}})
	frames := [][]byte{
		hello,
		{byte(consensus.MsgProposal), 0x01},
		{byte(consensus.MsgPrevote), 0x02},
		{byte(consensus.MsgPrecommit), 0x03},
		exchange,
	}
	got := new(recorder)
	b.OnMessage(got.collect)
	for _, f := range frames {
		if err := a.Broadcast(f); err != nil {
			t.Fatalf("Broadcast: %v", err)
		}
	}
	waitFor(t, "b receiving every bucket", 5*time.Second, func() bool {
		return len(got.payloads()) == len(frames)
	})

	want := map[FrameKind]int{
		FrameHello:        1,
		FrameProposal:     1,
		FramePrevote:      1,
		FramePrecommit:    1,
		FramePeerExchange: 1,
	}
	afterA, afterB := a.FrameStats(), b.FrameStats()
	for kind, n := range want {
		if d := int(afterA.Totals.Sent[kind] - baseA.Totals.Sent[kind]); d != n {
			t.Fatalf("a sent %d %s frames, want %d", d, FrameKindName(kind), n)
		}
		if d := int(afterB.Totals.Recv[kind] - baseB.Totals.Recv[kind]); d != n {
			t.Fatalf("b received %d %s frames, want %d", d, FrameKindName(kind), n)
		}
	}
	// WRITTEN is not behind SENT once the peer has received them: the writer
	// drains what the queue accepts, and the receive proves the write landed.
	for kind := FrameKind(0); kind < NumFrameKinds; kind++ {
		if afterA.Totals.Written[kind] < afterA.Totals.Sent[kind] {
			t.Fatalf("%s: written (%d) < sent (%d) after delivery", FrameKindName(kind),
				afterA.Totals.Written[kind], afterA.Totals.Sent[kind])
		}
	}
	// The reverse direction is counted separately, not inferred: b's HELLO is
	// its own SENT, and a's RECEIVED.
	if err := b.Send("a", wire.EncodeHello(&wire.Hello{ChainID: "c", Height: 8})); err != nil {
		t.Fatalf("Send: %v", err)
	}
	waitFor(t, "a receiving b's hello", 5*time.Second, func() bool {
		return a.FrameStats().Totals.Recv[FrameHello] > afterA.Totals.Recv[FrameHello]
	})
	if d := a.FrameStats().Totals.Sent[FrameHello] - afterA.Totals.Sent[FrameHello]; d != 0 {
		t.Fatalf("a's own sent-hello count moved when b sent one: delta %d", d)
	}
}

// TestFrameStatsReportsAnUnknownPeerAsNoLinks pins the empty shape: a
// diagnostic that prints a link it does not have would send an operator
// hunting a connection that never existed.
func TestFrameStatsReportsAnUnknownPeerAsNoLinks(t *testing.T) {
	a := listen(t, Options{LocalID: "a"})
	st := a.FrameStats()
	if len(st.Peers) != 0 {
		t.Fatalf("a fresh transport reports %d links, want 0", len(st.Peers))
	}
	for kind := FrameKind(0); kind < NumFrameKinds; kind++ {
		if st.Totals.Sent[kind] != 0 || st.Totals.Recv[kind] != 0 {
			t.Fatalf("a fresh transport reports %s traffic: sent=%d recv=%d", FrameKindName(kind),
				st.Totals.Sent[kind], st.Totals.Recv[kind])
		}
	}
}

// TestFrameKindNamesCoverEveryBucket keeps the summary line honest: a bucket
// with no name would print "?" into an operator's stall line.
func TestFrameKindNamesCoverEveryBucket(t *testing.T) {
	for kind := FrameKind(0); kind < NumFrameKinds; kind++ {
		if name := FrameKindName(kind); name == "?" || name == "" {
			t.Fatalf("frame kind %d has no name", kind)
		}
	}
	if FrameKindName(NumFrameKinds) != "?" || FrameKindName(200) != "?" {
		t.Fatal("an out-of-union kind did not render as ?")
	}
}
