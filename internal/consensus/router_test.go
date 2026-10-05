package consensus

// The router's own pins. The scenario and integration tests exercise routing
// INDIRECTLY (through running validators); these pin the classification
// DIRECTLY, frame by frame, because the failure mode of a bad router is
// silence: a frame consumed by the wrong stream never reappears as an error,
// only as a committee that stopped committing, on top of the 1-3 tag
// collision the two message unions share.

import (
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
	d := NewDriver(cfg, ch, testCommitteeKey(0), rec, nil)
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
	cases := map[string][]byte{
		"prevote":   EncodeVote(voteFrom(t, rig.cfg, 0, MsgPrevote, 9, 2, nonNil)),
		"precommit": EncodeVote(voteFrom(t, rig.cfg, 0, MsgPrecommit, 9, 2, nonNil)),
		"proposal":  EncodeProposal(rig.signedProposal(9, 0)),
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
	sigless := voteFrom(t, rig.cfg, 0, MsgPrevote, 3, 0, [32]byte{})
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
	if got := rig.rt.SyncRequestsServed(); got != 1 {
		t.Fatalf("the served-request counter reads %d, want 1", got)
	}
	if got := len(rig.replies[transport.PeerID("v0")]); got != 0 {
		t.Fatalf("the router served the request INLINE (%d reply frame(s) sent): a slow answer on the dispatch goroutine would stall every consensus frame behind it", got)
	}
}
