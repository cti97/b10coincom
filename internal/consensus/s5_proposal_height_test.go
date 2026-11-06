package consensus

// Audit S-5 (2026-11-06): the proposal branch decoded a whole block - up to the
// frame bound - before any height or membership check, because the proposer key
// is the envelope's last field. The transport serialises every reader under one
// dispatch mutex, so a peer could stall every consensus frame behind one block
// decode per frame, at distinct (height, round) pairs that dedup cannot collapse
// (its key needs the validator identity the decode yields).
//
// The fix peeks the envelope's Height, which sits at a CONSTANT offset in the
// fixed prefix, and drops a foreign-height proposal before the block is
// decoded. These tests pin the three things that make the filter safe and the
// one thing that makes it cheap:
//
//   - the offset is exact, not guessed (the peek agrees with the decoder for
//     every height, including the varint-width boundaries);
//   - the window cannot reject an honest proposal, because it contains the
//     height the live engine judges;
//   - an honest proposal at the live height is still prevoted end to end, and a
//     proposal at the just-committed head is still not refused;
//   - a foreign-height frame is refused WITHOUT a decode attempt, proven by the
//     counter a decode failure would have moved, and by zero allocations for a
//     1 MiB frame.

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/cti97/b10coincom/internal/transport"
)

// TestProposalHeightPeekAgreesWithTheDecodedEnvelope pins the wire-offset
// contract the filter rests on. If EncodeProposal's field order ever changes,
// the peek would read a block length or a round as a height and the filter
// would start rejecting honest proposals; this test fails first and names why.
func TestProposalHeightPeekAgreesWithTheDecodedEnvelope(t *testing.T) {
	rig := newRouterRig(t)
	// One valid block is enough: the peek reads only the fixed prefix, and the
	// block sits AFTER every field it reads, so its size cannot move the offset.
	base := rig.signedProposal(rig.ch.Height()+1, 0)

	for _, height := range []uint64{0, 1, 255, 256, 1<<32 - 1, 1 << 63, math.MaxUint64} {
		for _, round := range []uint32{0, 7} {
			p := *base
			p.Height = height
			p.Round = round
			frame := EncodeProposal(&p)

			if len(frame) < proposalPrefixBytes {
				t.Fatalf("height %d: a valid proposal encoded to %d bytes, shorter than the peeked prefix (%d)", height, len(frame), proposalPrefixBytes)
			}
			peeked, ok := peekProposalHeight(frame)
			if !ok {
				t.Fatalf("height %d: peekProposalHeight refused a proposal frame", height)
			}
			decoded, err := DecodeProposal(frame)
			if err != nil {
				t.Fatalf("height %d round %d: the frame the peek accepted does not decode: %v", height, round, err)
			}
			if peeked != decoded.Height {
				t.Fatalf("the peeked height is %d but the decoded envelope says %d: the fixed offset is wrong (offset %d, %d bytes big-endian)", peeked, decoded.Height, proposalHeightOffset, proposalHeightBytes)
			}
			// The byte-level claim itself, stated once so the offset constants
			// cannot drift from the encoder unnoticed.
			if got := binary.BigEndian.Uint64(frame[proposalHeightOffset:proposalPrefixBytes]); got != height {
				t.Fatalf("the encoder put %d at offset %d, want the envelope height %d", got, proposalHeightOffset, height)
			}
		}
	}

	// The peek must decline everything that is not a full proposal prefix, so
	// the decoder (not the filter) names a malformed frame.
	baseFrame := EncodeProposal(base)
	cases := map[string][]byte{
		"empty":            {},
		"too short":        baseFrame[:proposalPrefixBytes-1],
		"a prevote":        EncodeVote(&Vote{Type: MsgPrevote, Height: 5}),
		"a precommit":      EncodeVote(&Vote{Type: MsgPrecommit, Height: 5}),
		"a wire-tagged":    {byte(0x80), 0, 0, 0, 0, 0, 0, 0, 0},
		"a zero tag frame": make([]byte, proposalPrefixBytes),
	}
	for name, frame := range cases {
		if h, ok := peekProposalHeight(frame); ok {
			t.Fatalf("%s: peeked a height (%d) out of a frame that is not a proposal; the filter would judge the wrong bytes", name, h)
		}
	}
}

// TestTheProposalHeightWindowContainsTheEngineHeight is the safety argument as a
// test: the filter cannot reject a proposal the engine would accept only if the
// engine's own height is inside the window it tests. The driver builds its
// engine for chain head + 1, so this asserts the property against the REAL
// engine height rather than against the arithmetic in a comment.
func TestTheProposalHeightWindowContainsTheEngineHeight(t *testing.T) {
	rig := newRouterRig(t)
	rec := &recordingTransport{Transport: silentInner{}}
	d := mustDriver(t, rig.cfg, rig.ch, rig.priv, rec, nil)

	live := d.eng.Height()
	if want := rig.ch.Height() + 1; live != want {
		t.Fatalf("fixture: the engine judges height %d, want chain head + 1 = %d", live, want)
	}
	if ok, known := rig.rt.proposalHeightInWindow(live); !known || !ok {
		t.Fatalf("the live engine height %d is OUTSIDE the router's proposal window: an honest proposal would be dropped before its block was decoded", live)
	}
	// The just-committed head is also inside the window (a stale re-proposal is
	// ignored by the engine, never by the transport), and nothing above the
	// engine's height is.
	if ok, known := rig.rt.proposalHeightInWindow(rig.ch.Height()); !known || !ok {
		t.Fatalf("the committed head %d is outside the proposal window; the window is narrower than the vote window it reuses", rig.ch.Height())
	}
	for _, future := range []uint64{live + 1, live + 2, live + 1000} {
		if ok, known := rig.rt.proposalHeightInWindow(future); !known || ok {
			t.Fatalf("a proposal for future height %d is inside the window; the engine cannot act on it and it must not be decoded", future)
		}
	}
}

// TestAnHonestProposalAtTheLiveHeightIsStillPrevoted is the acceptance half,
// end to end through the real router and the real driver: the filter must let
// the frame through and the engine must prevote it, which is what "accepted"
// means for a proposal.
func TestAnHonestProposalAtTheLiveHeightIsStillPrevoted(t *testing.T) {
	rig := newRouterRig(t)
	rec := &recordingTransport{Transport: silentInner{}}
	d := mustDriver(t, rig.cfg, rig.ch, rig.priv, rec, nil)
	live := d.eng.Height()

	p := rig.signedProposal(live, 0)
	frame := EncodeProposal(p)

	if !rig.rt.Route(transport.Message{From: "v0", Data: frame}) {
		t.Fatalf("a member-signed proposal at the live height %d was not routed to the engine: the S-5 height filter rejected an honest proposal", live)
	}
	if got := rig.rt.RefusedBeforeVerify(); got != 0 {
		t.Fatalf("the honest proposal at the live height was counted refused (%d times) before verification", got)
	}

	d.OnMessage(transport.Message{From: "v0", Data: frame})
	var prevoted bool
	for _, raw := range rec.broadcasts {
		v, err := DecodeVote(raw)
		if err != nil || v.Type != MsgPrevote {
			continue
		}
		if v.Height == live && v.Round == 0 {
			prevoted = true
		}
	}
	if !prevoted {
		t.Fatal("the engine did not prevote an honest proposal at its own live height after the S-5 filter passed it: the filter is rejecting or maiming honest proposals")
	}
}

// TestAProposalAtTheCommittedHeadIsNotRefused covers the other legitimate
// height in the window: the head this node has just committed. The engine
// ignores such a re-proposal (the height is decided), but the transport must not
// be the component that silently drops it - votes at head are still tallied into
// the commit that finishes it, so the window has to be the same two heights for
// proposals.
func TestAProposalAtTheCommittedHeadIsNotRefused(t *testing.T) {
	rig := newRouterRig(t)
	head := rig.ch.Height()
	if head == 0 {
		t.Fatal("fixture: the rig did not commit a head block")
	}
	p := rig.signedProposal(head, 0)
	rig.rt.Route(transport.Message{From: "v0", Data: EncodeProposal(p)})
	if got := rig.rt.RefusedBeforeVerify(); got != 0 {
		t.Fatalf("a proposal at the committed head %d was refused before verification (%d times): the proposal window is narrower than the vote window", head, got)
	}
}

// TestAForeignHeightProposalIsDroppedBeforeItsBlockIsDecoded is the cost proof,
// as a counter rather than a clock. The frame carries a proposal tag, a
// FOREIGN height, and a block length prefix that declares bytes which are not
// there - so DecodeProposal cannot succeed on it. If the router decoded first,
// the frame would be counted UnknownDropped (it decoded as nothing); it is
// counted RefusedBeforeVerify instead, which is only reachable when the height
// was read from the fixed prefix and rejected BEFORE any decode was attempted.
func TestAForeignHeightProposalIsDroppedBeforeItsBlockIsDecoded(t *testing.T) {
	rig := newRouterRig(t)
	foreign := rig.ch.Height() + 2

	frame := make([]byte, 0, proposalPrefixBytes+1)
	frame = append(frame, byte(MsgProposal))
	var h [8]byte
	binary.BigEndian.PutUint64(h[:], foreign)
	frame = append(frame, h[:]...)
	var r [4]byte
	binary.BigEndian.PutUint32(r[:], 0)
	frame = append(frame, r[:]...)
	frame = append(frame, 0x7f) // a block length of 127 bytes, with none behind it

	if rig.rt.Route(transport.Message{From: "v0", Data: frame}) {
		t.Fatal("a proposal for a foreign height was routed to the engine")
	}
	if got := rig.rt.RefusedBeforeVerify(); got != 1 {
		t.Fatalf("RefusedBeforeVerify = %d, want 1: a foreign-height proposal was not refused", got)
	}
	if got := rig.rt.UnknownDropped(); got != 0 {
		t.Fatalf("UnknownDropped = %d: the frame reached DecodeProposal and failed there, so the height gate ran AFTER the decode - the whole block was decoded first, which is the finding", got)
	}
}

// TestAForeignHeightProposalCostsNoDecode measures the cost the finding is
// about. A 1 MiB frame for a foreign height must be refused with ZERO
// allocations: DecodeProposal's VarBytes copies the declared block into a fresh
// slice before decoding it, so the pre-fix path allocates ~1 MiB per frame. The
// allocation count is a deterministic number, unlike a wall-clock measurement,
// so the pin cannot flake on a slow host.
func TestAForeignHeightProposalCostsNoDecode(t *testing.T) {
	rig := newRouterRig(t)
	foreign := rig.ch.Height() + 2

	payload := make([]byte, 1<<20) // the frame bound, one full-size proposal
	payload[0] = byte(MsgProposal)
	binary.BigEndian.PutUint64(payload[proposalHeightOffset:], foreign)
	binary.BigEndian.PutUint32(payload[proposalHeightOffset+proposalHeightBytes:], 1)
	// The rest is a block body DecodeProposal would copy and parse. Nothing in
	// the fixed prefix depends on it, which is the point.
	msg := transport.Message{From: "v0", Data: payload}

	routed := 0
	refusedBefore := rig.rt.RefusedBeforeVerify()
	allocs := testing.AllocsPerRun(20, func() {
		if rig.rt.Route(msg) {
			routed++
		}
	})
	if routed != 0 {
		t.Fatalf("%d of the measured proposals for a foreign height were routed to the engine", routed)
	}
	if allocs != 0 {
		t.Fatalf("a foreign-height 1 MiB proposal costs %.1f allocations per Route, want 0: the block was decoded before the height was checked (audit S-5)", allocs)
	}
	// AllocsPerRun runs the function at least once more as a warm-up, so the
	// counter may exceed the measured run count; the bound below is the one
	// claim that matters, that every call was refused.
	if got := rig.rt.RefusedBeforeVerify() - refusedBefore; got < 20 {
		t.Fatalf("RefusedBeforeVerify moved %d times over the measured runs, want at least 20: a foreign-height frame was not refused", got)
	}
}
