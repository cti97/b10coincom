package consensus

// PEER_EXCHANGE's consensus-side pins: the message is framed and decoded by
// internal/wire, but its whole point is that consensus never reads it as
// evidence. These tests sit here because only this package can see the
// consensus decoders (internal/wire cannot import them without a cycle), so
// this is the one place both sides of the tag boundary are visible.

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

// TestTheConsensusDecodersRejectAPeerExchangeFrame pins audit N-5's boundary
// from the consensus side: 0x83 is above wire.WireTagFloor, so a vote, a
// proposal and a HELLO decoder must all refuse the frame on its FIRST byte
// rather than decode into it. This is what stops an address list from being
// read as a vote by any path; the router's own branches then place the frame
// in the wire stream (TestTheRouterDeliversPeerExchangeOffTheConsensusPath).
func TestTheConsensusDecodersRejectAPeerExchangeFrame(t *testing.T) {
	frame := wire.EncodePeerExchange(&wire.PeerExchange{Addrs: []string{"203.0.113.4:6001"}})
	if len(frame) == 0 || wire.MsgType(frame[0]) != wire.MsgPeerExchange {
		t.Fatalf("the frame does not open with the PEER_EXCHANGE tag: %x", frame)
	}
	if v, err := DecodeVote(frame); err == nil || v != nil {
		t.Fatalf("DecodeVote accepted a PEER_EXCHANGE frame: (%v, %v)", v, err)
	}
	if p, err := DecodeProposal(frame); err == nil || p != nil {
		t.Fatalf("DecodeProposal accepted a PEER_EXCHANGE frame: (%v, %v)", p, err)
	}
	if h, err := wire.DecodeHello(frame); err == nil || h != nil {
		t.Fatalf("DecodeHello accepted a PEER_EXCHANGE frame: (%v, %v)", h, err)
	}
	// The reverse direction is pinned in internal/wire: 1..3 and every other
	// wire tag fail DecodePeerExchange. Both halves together make the tag
	// boundary a property of the pair, not of one table.
}

// TestTheRouterDeliversPeerExchangeOffTheConsensusPath routes a real frame
// through the router and requires the three properties design decision 5
// promises:
//
//   - the callback sees it, and the frame is consumed (Route reports false -
//     nothing for the engine);
//   - it is not counted as unknown garbage, and it is NOT recorded in the
//     seen-set: dedup belongs to verified votes and proposals only, and
//     letting address frames into it would let repeated advertisements evict
//     real vote keys under the bucket ceiling;
//   - it creates no path for a stranger: the very next honest, verified vote
//     for the same (validator, height, round, type) tuple still reaches the
//     engine, and only a genuine repeat is dropped as a duplicate.
func TestTheRouterDeliversPeerExchangeOffTheConsensusPath(t *testing.T) {
	var gotFrom transport.PeerID
	var gotAddrs []string
	r := &MessageRouter{
		Dedup: transport.NewDedup(0),
		OnPeerExchange: func(from transport.PeerID, p *wire.PeerExchange) {
			gotFrom, gotAddrs = from, p.Addrs
		},
	}
	frame := wire.EncodePeerExchange(&wire.PeerExchange{Addrs: []string{"203.0.113.4:6001", "[2001:db8::7]:6002"}})
	if r.Route(transport.Message{From: "v3", Data: frame}) {
		t.Fatal("a PEER_EXCHANGE frame was routed to the engine as consensus")
	}
	if gotFrom != "v3" || len(gotAddrs) != 2 {
		t.Fatalf("the callback saw (%q, %v), want (v3, two addresses)", gotFrom, gotAddrs)
	}
	if got := r.PeerExchangesSeen(); got != 1 {
		t.Fatalf("PeerExchangesSeen = %d, want 1", got)
	}
	if got := r.UnknownDropped(); got != 0 {
		t.Fatalf("a PEER_EXCHANGE frame was counted as garbage (%d): the router has no branch for it", got)
	}

	// The frame must not have pre-seeded any vote's key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	honest := &Vote{Type: MsgPrevote, Height: 9, Round: 2, Validator: pub}
	h := honest.SigningHash()
	honest.Sig = crypto.Sign(priv, h[:])
	if r.Dedup.Has(voteDedupKey(honest)) {
		t.Fatal("a PEER_EXCHANGE frame recorded a dedup key: address traffic entered the consensus seen-set")
	}
	if !r.Route(transport.Message{From: "v3", Data: EncodeVote(honest)}) {
		t.Fatal("the honest vote after a PEER_EXCHANGE frame was dropped")
	}
	if r.Route(transport.Message{From: "v3", Data: EncodeVote(honest)}) {
		t.Fatal("a duplicate honest vote was routed twice")
	}
	if got := r.DuplicatesDropped(); got != 1 {
		t.Fatalf("DuplicatesDropped = %d, want 1 (only the genuine repeat)", got)
	}
	if got := r.PeerExchangesSeen(); got != 1 {
		t.Fatalf("routing a vote changed PeerExchangesSeen to %d", got)
	}
}
