package consensus

// The router's own pins. The scenario and integration tests exercise routing
// INDIRECTLY (through running validators); these pin the classification
// DIRECTLY, frame by frame, because the failure mode of a bad router is
// silence: a frame consumed by the wrong stream never reappears as an error,
// only as a committee that stopped committing.

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/types"
	"github.com/cti97/b10coincom/internal/wire"
)

// TestDedupIsConsultedOnlyAfterVerify is audit N-7's ordering proof: the
// seen-set must record a key only for a message whose signature ALREADY
// verified. The attack it closes is censorship, not forgery: a stranger who
// reaches the port sends a frame carrying an honest validator's key and the
// honest vote's (validator, height, round, type), signed by nobody. If Seen
// ran before Verify, that frame would record the key and the honest vote -
// arriving a moment later - would be dropped as a duplicate, so anyone who
// can reach the port could silence any vote. The test drives exactly that
// sequence: a forged frame with the honest key's shape, then the honest
// signed vote with the SAME key, then a genuine duplicate.
func TestDedupIsConsultedOnlyAfterVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	honest := &Vote{Type: MsgPrevote, Height: 9, Round: 2, Validator: pub}
	h := honest.SigningHash()
	honest.Sig = crypto.Sign(priv, h[:])

	// The forgery: the SAME tuple (validator, height, round, type) with a
	// signature the stranger cannot produce.
	forged := &Vote{Type: MsgPrevote, Height: 9, Round: 2, Validator: pub, Sig: []byte("forged")}

	r := &MessageRouter{Dedup: transport.NewDedup(0)}
	if r.Route(transport.Message{From: "stranger", Data: EncodeVote(forged)}) {
		t.Fatal("a vote with a bad signature was routed as consensus")
	}
	if r.Dedup.Has(voteDedupKey(honest)) {
		t.Fatal("the forged frame pre-seeded the honest vote's dedup key: Seen ran BEFORE Verify")
	}
	// The honest vote over the same key must still be delivered.
	if !r.Route(transport.Message{From: "v1", Data: EncodeVote(honest)}) {
		t.Fatal("the honest vote was dropped: a forged frame recorded its dedup key (Seen before Verify)")
	}
	// And a genuine duplicate is now dropped, which is the dedup working.
	if r.Route(transport.Message{From: "v1", Data: EncodeVote(honest)}) {
		t.Fatal("a duplicate honest vote was routed twice")
	}
	if got := r.DuplicatesDropped(); got != 1 {
		t.Fatalf("DuplicatesDropped = %d, want 1", got)
	}
	// A proposal's key is its own: the same validator/height/round under the
	// proposal type must not collide with the prevote key.
	p := &Proposal{Height: 9, Round: 2, Validator: pub}
	ph := p.SigningHash()
	p.Sig = crypto.Sign(priv, ph[:])
	if !r.Route(transport.Message{From: "v1", Data: EncodeProposal(p)}) {
		t.Fatal("a proposal collided with a vote's dedup key")
	}
}

// TestWireTagsAreDisjointFromConsensusTags pins audit N-5: no wire message
// tag may equal a consensus message tag, and every wire tag must sit at or
// above wire.WireTagFloor. The two unions travel the same connection and are
// told apart by their first byte before any body is decoded, so a collision
// is a routing hazard rather than a cosmetic one - the pre-fix 1/2/3 overlap
// fed every prevote and precommit into the sync layer and cost every HELLO a
// wasted vote-and-proposal decode. The test is a table of the ACTUAL wire
// tags against the ACTUAL consensus tags, so adding either union without
// moving the boundary fails here rather than on a live committee.
func TestWireTagsAreDisjointFromConsensusTags(t *testing.T) {
	wireTags := map[string]wire.MsgType{
		"MsgHello":         wire.MsgHello,
		"MsgBlockSyncReq":  wire.MsgBlockSyncReq,
		"MsgBlockSyncResp": wire.MsgBlockSyncResp,
	}
	consensusTags := map[string]MsgType{
		"MsgProposal":  MsgProposal,
		"MsgPrevote":   MsgPrevote,
		"MsgPrecommit": MsgPrecommit,
	}
	for wn, wt := range wireTags {
		if uint8(wt) < uint8(wire.WireTagFloor) {
			t.Errorf("%s = %#x is below wire.WireTagFloor %#x: the wire union has grown into the consensus range", wn, uint8(wt), uint8(wire.WireTagFloor))
		}
		for cn, ct := range consensusTags {
			if wt == wire.MsgType(ct) {
				t.Errorf("%s tag %#x collides with consensus %s tag %#x", wn, uint8(wt), cn, uint8(ct))
			}
		}
	}
}

// silentInner is the no-op transport the fixture's recording wrapper passes
// through: no delivery, no peers, nothing to wait on.
type silentInner struct{}

func (silentInner) Broadcast([]byte) error              { return nil }
func (silentInner) Send(transport.PeerID, []byte) error { return nil }
func (silentInner) OnMessage(func(transport.Message))   {}
func (silentInner) Peers() []transport.PeerID           { return nil }
func (silentInner) Close() error                        { return nil }

// routerRig is one committed chain (the fixture validator committed height 1
// through the REAL driver - propose, prevote, precommit, append - so the
// syncer's certificate archive holds real evidence) and a router wired over
// that syncer: exactly the node's shape, at fixture scale. The fixture needs
// no network: a quorum of one commits from its own votes, and the routing
// under test needs no delivery at all - each Route is called by hand.
type routerRig struct {
	rt      *MessageRouter
	cfg     Config
	ch      *chain.Chain
	vals    []genesis.Validator
	priv    ed25519PrivateKey
	replies map[transport.PeerID][][]byte
}

func newRouterRig(t *testing.T) *routerRig {
	t.Helper()
	g := genesis.Devnet()
	g.ChainID = "b10coin-router-test"
	g.Params.ChainID = g.ChainID
	pub := testCommitteeKey(0).Public().(ed25519PublicKey)
	g.Validators = []genesis.Validator{{PubKey: pub, Power: 1}}
	g.Params.CommitteeSize = 1

	ch, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })

	cfg := Config{Committee: g.Validators, TimeoutBase: 10, TimeoutStep: 5, PowerCapNum: 1, PowerCapDen: 1}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{Transport: silentInner{}}
	sy := NewSyncer(ch, rec, testCommitteeKey(0))
	d := mustDriver(t, cfg, ch, testCommitteeKey(0), rec, nil)
	d.CommitWitness = sy.RecordCommit
	d.Tick(0)
	if ch.Height() != 1 {
		t.Fatalf("fixture: the one-validator committee did not commit height 1 (height %d)", ch.Height())
	}

	rig := &routerRig{
		rt:      NewMessageRouter(sy),
		cfg:     cfg,
		ch:      ch,
		vals:    g.Validators,
		priv:    testCommitteeKey(0),
		replies: map[transport.PeerID][][]byte{},
	}
	rig.rt.SendReply = func(to transport.PeerID, frame []byte) error {
		rig.replies[to] = append(rig.replies[to], append([]byte(nil), frame...))
		return nil
	}
	return rig
}

// signedProposal builds the fixture validator's proposal at (height, round)
// over the rig's chain: what StartProposing puts on the wire.
func (r *routerRig) signedProposal(height uint64, round uint32) *Proposal {
	blk, err := r.ch.Build(r.priv, nil, r.ch.Head().Header.Timestamp+1)
	if err != nil {
		panic(fmt.Sprintf("fixture: %v", err))
	}
	p := &Proposal{
		Height: height, Round: round, Block: *blk, ValidRound: -1,
		Validator: testCommitteeKey(0).Public().(ed25519PublicKey),
	}
	h := p.SigningHash()
	p.Sig = crypto.Sign(r.priv, h[:])
	return p
}

// TestTheRouterDrivesEveryVerifiedConsensusMessage requires committee-signed
// prevote, precommit and proposal frames to come back TRUE (the engine's to
// consume) even though the router carries a live syncer: the consensus
// branches run FIRST, so a verified consensus frame can never be re-parsed as
// the same-tagged wire frame - prevote and BLOCK_SYNC_REQ share tag 2,
// precommit and BLOCK_SYNC_RESP share tag 3, proposal and HELLO share tag 1.
// Routing by tag alone would deliver every vote into the sync layer; this is
// the hazard's direct pin.
func TestTheRouterDrivesEveryVerifiedConsensusMessage(t *testing.T) {
	rig := newRouterRig(t)

	var nonNil [32]byte
	nonNil[0] = 7
	// head+1 is the live engine's height, so it is inside the router's height
	// window (audit C-8) and reaches Verify; a vote far outside the window is
	// refused before its signature, which the window test pins. Classification,
	// not height relevance, is this test's subject.
	inWindow := rig.ch.Height() + 1
	cases := map[string][]byte{
		"prevote":   EncodeVote(voteFrom(t, rig.cfg, 0, MsgPrevote, inWindow, 2, nonNil)),
		"precommit": EncodeVote(voteFrom(t, rig.cfg, 0, MsgPrecommit, inWindow, 2, nonNil)),
		"proposal":  EncodeProposal(rig.signedProposal(inWindow, 0)),
	}
	for name, frame := range cases {
		if got := rig.rt.Route(transport.Message{From: "v0", Data: frame}); !got {
			t.Fatalf("%s: a verifying consensus message was not routed to the engine", name)
		}
	}
	if got := rig.rt.SyncRequestsServed(); got != 0 {
		t.Fatalf("consensus traffic served a sync request %d times: a same-tagged wire branch swallowed a vote", got)
	}
	if got := rig.rt.SyncRepliesFiled(); got != 0 {
		t.Fatalf("consensus traffic filed a sync reply %d times", got)
	}
}

// TestTheRouterNeverMisroutesWireFrames pins the other direction: wire frames
// whose first byte sits inside the consensus tag range must land in the WIRE
// branches. The signed request here decodes as a prevote-shaped byte stream
// (the same tag 2) far enough that only the SIGNATURE check keeps the
// classification honest; a bare-tag router would have fed it to the engine.
func TestTheRouterNeverMisroutesWireFrames(t *testing.T) {
	rig := newRouterRig(t)

	// HELLO (tag 1 - the proposal's tag).
	h := &wire.Hello{ChainID: "b10coin-router-test", Validator: testCommitteeKey(0).Public().(ed25519PublicKey), Height: 12}
	hh := routerTestHelloHash(h)
	h.Sig = crypto.Sign(rig.priv, hh[:])
	if got := rig.rt.Route(transport.Message{From: "v0", Data: wire.EncodeHello(h)}); got {
		t.Fatal("a HELLO was routed to the engine: the proposal branch accepted wire bytes")
	}

	// BLOCK_SYNC_REQ (tag 2 - the prevote's tag), from a signed member; the
	// reply goes back to the asker.
	req := &wire.BlockSyncReq{From: 1, To: 1, Requester: testCommitteeKey(0).Public().(ed25519PublicKey)}
	q := syncReqHash(req)
	req.Sig = crypto.Sign(rig.priv, q[:])
	if got := rig.rt.Route(transport.Message{From: "v0", Data: wire.EncodeBlockSyncReq(req)}); got {
		t.Fatal("a BLOCK_SYNC request was routed to the engine")
	}
	if got := rig.rt.SyncRequestsServed(); got != 1 {
		t.Fatalf("signed request served %d times, want 1", got)
	}
	if got := len(rig.replies[transport.PeerID("v0")]); got != 1 {
		t.Fatalf("the answered request's reply was sent %d times, want 1", got)
	}

	// A stranger's signature is refused by the syncer's own gate: the router
	// routes the frame to the right consumer, and the auth gate stays shut.
	_, strangerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	bad := &wire.BlockSyncReq{From: 1, To: 1, Requester: strangerPriv.Public().(ed25519PublicKey)}
	bq := syncReqHash(bad)
	bad.Sig = crypto.Sign(strangerPriv, bq[:])
	if got := rig.rt.Route(transport.Message{From: "v9", Data: wire.EncodeBlockSyncReq(bad)}); got {
		t.Fatal("a stranger's request was routed to the engine")
	}
	if got := len(rig.replies[transport.PeerID("v9")]); got != 0 {
		t.Fatalf("a stranger's request produced %d replies, want 0: Handle's refusal must be silence", got)
	}

	// BLOCK_SYNC_RESP (tag 3 - the precommit's tag): filed for the pull.
	if got := rig.rt.Route(transport.Message{From: "v1", Data: wire.EncodeBlockSyncResp(&wire.BlockSyncResp{})}); got {
		t.Fatal("a BLOCK_SYNC response was routed to the engine")
	}
	if got := rig.rt.SyncRepliesFiled(); got != 1 {
		t.Fatalf("response filed %d times, want 1", got)
	}
}

// TestTheRouterRefusesAndCountsGarbage requires frames that decode as nothing
// to be counted and dropped, and never driven into an engine or a syncer.
func TestTheRouterRefusesAndCountsGarbage(t *testing.T) {
	rig := newRouterRig(t)
	cases := map[string][]byte{
		"empty":          {},
		"unknown tag":    {0x42},
		"truncated vote": {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"random bytes":   {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef},
	}
	for name, frame := range cases {
		if got := rig.rt.Route(transport.Message{From: "v0", Data: frame}); got {
			t.Fatalf("%s: garbage was routed to the engine", name)
		}
	}
	if got := rig.rt.UnknownDropped(); got != 4 {
		t.Fatalf("UnknownDropped = %d, want 4", got)
	}
	if got := rig.rt.SyncRepliesFiled(); got != 0 {
		t.Fatalf("garbage filed as sync replies %d times", got)
	}

	// An unsigned vote fails the VERIFIED consensus branch - the engine never
	// sees it - whatever its bytes then read as (a wire branch or the count).
	// head+1 is the in-window height, so this pins the SIGNATURE gate itself
	// rather than the height window (which has its own test below).
	sigless := voteFrom(t, rig.cfg, 0, MsgPrevote, rig.ch.Height()+1, 0, [32]byte{})
	sigless.Sig = nil
	if got := rig.rt.Route(transport.Message{From: "v0", Data: EncodeVote(sigless)}); got {
		t.Fatal("an unsigned vote was routed to the engine: the vote branch did not VERIFY")
	}
}

// routerTestHelloHash mirrors the DEVNET hello hash field for field (the
// consensus package cannot import devnet; if devnet's hash shape changes,
// this pin fails and both sides get looked at).
func routerTestHelloHash(h *wire.Hello) [32]byte {
	e := types.NewEncoder()
	e.VarBytes([]byte(h.ChainID))
	e.VarBytes(h.Validator)
	e.U64(h.Height)
	return crypto.HashParts([]byte("b10coin-hello"), e.Bytes())
}

// TestTheRouterDefersSyncServingToItsAsyncServer is the C-4 async pin: when a
// node installs AsyncServe, the router hands the request over and returns
// WITHOUT running Answer on the dispatch goroutine. The rig's syncer CAN answer
// this request inline (its chain holds a certified height 1), so if the async
// branch were removed the router would send a reply frame - holding the
// transport's dispatch lock across a window of disk reads and quorum-many
// verifies, and stalling every consensus frame behind it.
func TestTheRouterDefersSyncServingToItsAsyncServer(t *testing.T) {
	rig := newRouterRig(t)

	var handed atomic.Int64
	rig.rt.AsyncServe = func(transport.Message) { handed.Add(1) }

	req := &wire.BlockSyncReq{From: 1, To: 1, Nonce: 1, Requester: testCommitteeKey(0).Public().(ed25519PublicKey)}
	q := syncReqHash(req)
	req.Sig = crypto.Sign(rig.priv, q[:])

	if got := rig.rt.Route(transport.Message{From: "v0", Data: wire.EncodeBlockSyncReq(req)}); got {
		t.Fatal("a BLOCK_SYNC request was routed to the engine")
	}
	if got := handed.Load(); got != 1 {
		t.Fatalf("the async server received %d requests, want 1", got)
	}
	// The request was handed over, not served: the counter must read 0 until
	// the worker that ran Handle reports an answer (round 7, F4). Pre-fix the
	// increment sat before the handoff, so a shed request was counted as
	// served.
	if got := rig.rt.SyncRequestsServed(); got != 0 {
		t.Fatalf("a merely QUEUED request was counted as served (%d): the counter must mean served, not queued", got)
	}
	// The node's worker reports the answer it produced; that is what moves the
	// counter.
	rig.rt.NoteServed()
	if got := rig.rt.SyncRequestsServed(); got != 1 {
		t.Fatalf("after the worker served the request the counter reads %d, want 1", got)
	}
	if got := len(rig.replies[transport.PeerID("v0")]); got != 0 {
		t.Fatalf("the router served the request INLINE (%d reply frame(s) sent): a slow answer on the dispatch goroutine would stall every consensus frame behind it", got)
	}
}
