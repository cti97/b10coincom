package consensus

// The BLOCK_SYNC tests run one puller and one server over an in-process
// loopback transport: Send serves the request through the server Syncer's real
// Handle and files the answer with the puller's Receive, synchronously. That
// exercises both roles - encode, sign, verify, bound, decode, Append - through
// the frames a real connection would carry, with no goroutine or clock: the
// delivery order is fixed by the test, so a failure replays exactly.

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/types"
	"github.com/cti97/b10coincom/internal/wire"
)

const (
	syncPullerID = "v0" // the behind (or level) validator: pulls
	syncServerID = "v1" // the ahead validator: serves
)

// syncLoopback is the transport the puller is wired to. Send delivers the
// request frame to serve, a *Syncer answer the way a peer's connection loop
// would (Handle -> respFrame), and hands the answer to the puller's Receive
// synchronously, the way sim would deliver it at the next Advance. It records
// every request it was given so tests can assert what was ASKED, and respOverride
// lets a test serve bytes no honest peer would.
type syncLoopback struct {
	puller       *Syncer
	server       *Syncer
	sent         []*wire.BlockSyncReq
	respOverride func() []byte
}

func (l *syncLoopback) Send(to transport.PeerID, data []byte) error {
	if to != syncServerID {
		// The loopback models one destination; anything else is the same
		// error a real transport gives for an unknown or disconnected peer.
		return fmt.Errorf("sync loopback: %q is not a peer here", to)
	}
	req, err := wire.DecodeBlockSyncReq(data)
	if err != nil {
		return fmt.Errorf("sync loopback: the puller sent a frame that is not a BLOCK_SYNC request: %v", err)
	}
	l.sent = append(l.sent, req)
	if l.respOverride != nil {
		if raw := l.respOverride(); raw != nil {
			l.puller.Receive(to, raw)
		}
		return nil
	}
	resp, ok := l.server.Handle(data)
	if ok {
		l.puller.Receive(to, resp)
	}
	return nil // refusal is silence: no frame, no transport error
}

func (l *syncLoopback) Broadcast([]byte) error {
	return errors.New("sync loopback: nothing in these tests broadcasts")
}
func (l *syncLoopback) OnMessage(func(transport.Message)) {} // not routed here
func (l *syncLoopback) Peers() []transport.PeerID         { return []transport.PeerID{syncServerID} }
func (l *syncLoopback) Close() error                      { return nil }

// syncFixture builds two chains over one shared genesis: puller's chain stands
// at pullHeight, the server's chain is grown to serverHeight with signed empty
// blocks. Both sequences are byte-identical when both are grown to the same
// height, which is what lets convergence be asserted by head ID.
type syncFixture struct {
	g        *genesis.Genesis
	puller   *Syncer
	pullCh   *chain.Chain
	loop     *syncLoopback
	server   *Syncer
	serverCh *chain.Chain
	priv     ed25519PrivateKey // syncPullerID's key
	serverPr ed25519PrivateKey // syncServerID's key
}

func newSyncFixture(t *testing.T, pullTo, serverTo uint64) *syncFixture {
	t.Helper()
	priv := testCommitteeKey(0)
	peerPriv := testCommitteeKey(1)
	pub := priv.Public().(ed25519PublicKey)
	peerPub := peerPriv.Public().(ed25519PublicKey)

	g := genesis.Devnet()
	g.Validators = []genesis.Validator{
		{PubKey: pub, Power: 1},
		{PubKey: peerPub, Power: 1},
	}
	g.Params.CommitteeSize = 2

	var err error
	f := &syncFixture{g: g, priv: priv, serverPr: peerPriv}
	f.pullCh, err = chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.serverCh, err = chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	grow := func(ch *chain.Chain, signer ed25519PrivateKey, to uint64) {
		t.Helper()
		for ch.Height() < to {
			b, err := ch.Build(signer, nil, ch.Head().Header.Timestamp+1)
			if err != nil {
				t.Fatal(err)
			}
			if err := ch.Append(b); err != nil {
				t.Fatal(err)
			}
		}
	}
	grow(f.pullCh, priv, pullTo)
	grow(f.serverCh, peerPriv, serverTo)

	f.loop = &syncLoopback{}
	f.puller = NewSyncer(f.pullCh, f.loop, priv)
	f.server = NewSyncer(f.serverCh, f.loop, peerPriv)
	f.loop.puller = f.puller
	f.loop.server = f.server
	return f
}

// syncSignReq signs a request the way PullAndAdopt does, for tests that talk
// to Answer directly.
func syncSignReq(t *testing.T, priv ed25519PrivateKey, from, to uint64) *wire.BlockSyncReq {
	t.Helper()
	req := &wire.BlockSyncReq{From: from, To: to, Requester: priv.Public().(ed25519PublicKey)}
	h := syncReqHash(req)
	req.Sig = crypto.Sign(priv, h[:])
	return req
}

// assertHeadsEqual is the convergence assertion: after an honest pull the
// puller's chain IS the server's chain - same height, same head identity.
func assertHeadsEqual(t *testing.T, f *syncFixture, where string) {
	t.Helper()
	if f.pullCh.Height() != f.serverCh.Height() {
		t.Fatalf("%s: puller is at height %d, server at %d: not converged", where, f.pullCh.Height(), f.serverCh.Height())
	}
	if f.pullCh.Head().ID() != f.serverCh.Head().ID() {
		got, want := f.pullCh.Head().ID(), f.serverCh.Head().ID()
		t.Fatalf("%s: puller's head is %x, server's %x: the chains do not agree on the head block", where, got[:8], want[:8])
	}
}

func TestASyncerPullsAndAdoptsMissedBlocks(t *testing.T) {
	f := newSyncFixture(t, 0, 3)

	if err := f.puller.PullAndAdopt(1); err != nil {
		t.Fatalf("an honest pull of an honest range failed: %v", err)
	}
	assertHeadsEqual(t, f, "after the pull")

	// The blocks came in through the ordinary path: each one is IN the
	// store, and every adopted block parents its predecessor, exactly as a
	// committed block would.
	genesisBlk, err := f.pullCh.BlockAt(0)
	if err != nil {
		t.Fatal(err)
	}
	prevID := genesisBlk.ID()
	for h := uint64(1); h <= f.pullCh.Height(); h++ {
		blk, err := f.pullCh.BlockAt(h)
		if err != nil {
			t.Fatalf("block %d did not survive the pull: %v", h, err)
		}
		if blk.Header.ParentHash != prevID {
			t.Fatalf("adopted block %d parents %x, want the block it was pulled behind (%x)", h, blk.Header.ParentHash[:8], prevID[:8])
		}
		prevID = blk.ID()
	}

	// The pull SIGNED its requests as a committee member: each recorded frame
	// authenticates the way a consensus message does. An unsigned pull would
	// be refused by every honest answerer, which is worth pinning here where
	// the wire shape is chosen.
	if len(f.loop.sent) == 0 {
		t.Fatal("no BLOCK_SYNC request ever went out")
	}
	for i, req := range f.loop.sent {
		if err := verifySyncReq(req, f.g.Validators); err != nil {
			t.Fatalf("recorded request %d does not authenticate: %v", i, err)
		}
	}
}

func TestSyncerRefusesBlocksThatDoNotValidate(t *testing.T) {
	t.Run("a block the state machine refuses", func(t *testing.T) {
		f := newSyncFixture(t, 0, 0)
		// The hostile server answers with a block that DECODES, PASSES
		// STRUCTURE, CARRIES A VALID COMMITTEE SIGNATURE over its header, and
		// still fails - in the state machine: its only transaction is a
		// fully-shaped transfer whose signature does not verify, so ApplyBlock
		// refuses it. Nothing about the frame is malformed; only the validator
		// inside the puller's own chain can tell the block is poison.
		head := f.pullCh.Head()
		st, err := f.pullCh.Probe(nil)
		if err != nil {
			t.Fatal(err)
		}
		sender, _, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		// A well-formed transfer whose Ed25519 signature is garbage: it encodes,
		// decodes, carries a consistent From/PubKey pair - and fails
		// VerifySignature the instant the state machine reaches it.
		badTx := types.Tx{
			Type:   types.TxTransfer,
			From:   types.AddressFromPub(sender),
			PubKey: sender,
			Nonce:  0,
			To:     types.AddressFromPub(f.priv.Public().(ed25519PublicKey)),
			Amount: 7,
			Sig:    []byte("a signature nobody's key produced"),
		}
		bad := &types.Block{
			Header: types.Header{
				Height:     head.Header.Height + 1,
				ParentHash: head.ID(),
				StateRoot:  st.Root(),
				TxRoot:     types.ComputeTxRoot([]types.Tx{badTx}),
				Timestamp:  head.Header.Timestamp + 1,
				Proposer:   f.serverPr.Public().(ed25519PublicKey),
			},
			Txs: []types.Tx{badTx},
		}
		if err := badTx.VerifySignature(); err == nil {
			t.Fatal("fixture: the poisoned transaction unexpectedly verifies")
		}
		if _, err := f.pullCh.Probe(bad.Txs); err == nil {
			t.Fatal("fixture: the poisoned block's transaction unexpectedly applies")
		}
		h := bad.Header.SigningHash()
		bad.Sig = crypto.Sign(f.serverPr, h[:])
		if err := f.pullCh.Append(bad); err == nil {
			t.Fatal("fixture: the poisoned block unexpectedly appends locally")
		}
		if _, err := types.DecodeBlock(bad.Encode()); err != nil {
			t.Fatalf("fixture: the poisoned block does not even decode: %v", err)
		}
		raw := wire.EncodeBlockSyncResp(&wire.BlockSyncResp{Blocks: [][]byte{bad.Encode()}})
		f.loop.respOverride = func() []byte { return raw }

		headID := f.pullCh.Head().ID()
		height := f.pullCh.Height()
		err = f.puller.PullAndAdopt(1)
		if err == nil {
			t.Fatal("a pull served poison returned nil: catch-up trusted its source")
		}
		if !strings.Contains(err.Error(), "does not adopt") {
			t.Fatalf("the pull stopped for the wrong reason (%v), not the state machine's refusal", err)
		}
		if f.pullCh.Height() != height {
			t.Fatalf("height moved to %d: the served block got into the chain", f.pullCh.Height())
		}
		if f.pullCh.Head().ID() != headID {
			moved := f.pullCh.Head().ID()
			t.Fatalf("head moved to %x: the chain changed under a refused block", moved[:8])
		}
		// The puller is not stuck: it did not burn its state on the poison.
		stored, err := f.pullCh.BlockAt(height)
		if err != nil {
			t.Fatal(err)
		}
		if f.pullCh.Head().ID() != stored.ID() {
			t.Fatal("head and stored block diverged after a refusal")
		}
	})

	t.Run("a block whose proposer signature is broken", func(t *testing.T) {
		// The second poison class: a PERFECT block - right parent, right
		// height, right state root, an applyable (here empty) body - whose
		// proposer signature does not verify. Append refuses it on
		// provenance: nobody's key vouches that these are the committed
		// bytes. This is the class a fast-path adoption that skips Append's
		// signature check (the chain's own replay path must skip them, for
		// stored blocks that Open has already authenticated) would happily
		// install - so the pull has to be proven against it too.
		f := newSyncFixture(t, 0, 0)
		// Built against the (shared) genesis state, so the ONLY defect this
		// block carries is the one the test gives it below.
		good, err := f.serverCh.Build(f.serverPr, nil, f.serverCh.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		gh := good.Header.SigningHash()
		if !crypto.Verify(good.Header.Proposer, gh[:], good.Sig) {
			t.Fatal("fixture: the source block does not carry a valid proposer signature")
		}
		_, strangerPriv, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		good.Sig = crypto.Sign(strangerPriv, gh[:]) // a signature nobody's key vouches for
		if err := f.pullCh.Append(good); err == nil {
			t.Fatal("fixture: a broken-signature block unexpectedly appends")
		}
		raw := wire.EncodeBlockSyncResp(&wire.BlockSyncResp{Blocks: [][]byte{good.Encode()}})
		f.loop.respOverride = func() []byte { return raw }

		headID, height := f.pullCh.Head().ID(), f.pullCh.Height()
		err = f.puller.PullAndAdopt(1)
		if err == nil {
			t.Fatal("a pull served an unvouched block and returned nil")
		}
		if !strings.Contains(err.Error(), "does not adopt") {
			t.Fatalf("the pull stopped for the wrong reason (%v)", err)
		}
		if f.pullCh.Height() != height || f.pullCh.Head().ID() != headID {
			t.Fatal("the chain adopted a block whose proposer signature does not verify")
		}
	})
}

func TestSyncerRefusesBytesThatAreNotABlock(t *testing.T) {
	f := newSyncFixture(t, 0, 0)
	raw := wire.EncodeBlockSyncResp(&wire.BlockSyncResp{Blocks: [][]byte{{0xde, 0xad}}})
	f.loop.respOverride = func() []byte { return raw }
	headID, height := f.pullCh.Head().ID(), f.pullCh.Height()
	if err := f.puller.PullAndAdopt(1); err == nil {
		t.Fatal("served garbage returned nil")
	}
	if f.pullCh.Height() != height || f.pullCh.Head().ID() != headID {
		t.Fatal("the chain changed on undecodable served bytes")
	}
}

func TestSyncerAdoptsNothingWhenAlreadyCurrent(t *testing.T) {
	f := newSyncFixture(t, 2, 2)

	headID, height := f.pullCh.Head().ID(), f.pullCh.Height()
	for _, from := range []uint64{0, 1, 2, 3} {
		if err := f.puller.PullAndAdopt(from); err != nil {
			t.Fatalf("PullAndAdopt(%d) on a current chain errored: %v", from, err)
		}
	}
	if f.pullCh.Height() != height || f.pullCh.Head().ID() != headID {
		t.Fatal("pulling on a current chain changed the chain")
	}
	// The peer was ASKED (there is no local fact about the peer's height),
	// and every ask named the height above the head - never a range the
	// chain already holds.
	for i, req := range f.loop.sent {
		if req.From != height+1 {
			t.Fatalf("request %d asked from %d on a chain current at %d: an adopted range was re-asked", i, req.From, height)
		}
	}
}

func TestSyncerRePullingTheSameRangeTwiceChangesNothing(t *testing.T) {
	f := newSyncFixture(t, 0, 2)

	if err := f.puller.PullAndAdopt(1); err != nil {
		t.Fatalf("first pull failed: %v", err)
	}
	assertHeadsEqual(t, f, "after the first pull")
	headID, height := f.pullCh.Head().ID(), f.pullCh.Height()

	// The same `from` a second time must be a no-op, not a stream of refused
	// appends and not an error a caller would read as a failed catch-up: the
	// adopted prefix is skipped and the peer - which has nothing more -
	// answers with silence.
	if err := f.puller.PullAndAdopt(1); err != nil {
		t.Fatalf("re-pull of an adopted range errored: %v", err)
	}
	if f.pullCh.Height() != height || f.pullCh.Head().ID() != headID {
		t.Fatal("the re-pull changed the chain")
	}
	if len(f.loop.sent) != 2 {
		t.Fatalf("two pulls produced %d requests", len(f.loop.sent))
	}
	firstFrom, secondFrom := f.loop.sent[0].From, f.loop.sent[1].From
	if firstFrom != 1 {
		t.Fatalf("the first pull asked from %d, want 1", firstFrom)
	}
	if secondFrom != height+1 {
		t.Fatalf("the re-pull asked from %d, want the height above the new head (%d): adopted blocks were re-asked", secondFrom, height+1)
	}
}

func TestSyncerRefusesRangesBeyondTheBound(t *testing.T) {
	f := newSyncFixture(t, 0, 6)
	f.server.MaxBlocksPerResponse = 4 // the bound under test is the answerer's
	f.puller.MaxBlocksPerResponse = 4

	// The ANSWER side is under test, so the requests go to the server - the
	// chain whose height (6) could actually serve what the bound refuses.
	// Both fixture keys are in the validator set, so the signature is not
	// what refuses anything here.
	ask := func(from, to uint64) (*wire.BlockSyncResp, error) {
		return f.server.Answer(syncSignReq(t, f.priv, from, to))
	}

	// Width 5 over a bound of 4: refused with the bound error, not served
	// short.
	if _, err := ask(1, 5); !errors.Is(err, ErrRangeTooBig) {
		t.Fatalf("a range of 5 over a bound of 4 gave %v, want ErrRangeTooBig", err)
	}
	// The bound holds even when the chain HAS the blocks: removing the check
	// must be observable, which requires the chain to be able to answer.
	if f.serverCh.Height() < 6 {
		t.Fatalf("fixture: chain height %d cannot expose an unbounded answer", f.serverCh.Height())
	}
	// Bound EXACTLY: a range as wide as the bound is served whole.
	resp, err := ask(1, 4)
	if err != nil {
		t.Fatalf("a range exactly at the bound was refused: %v", err)
	}
	if uint64(len(resp.Blocks)) != 4 {
		t.Fatalf("a bound-wide answer served %d blocks", len(resp.Blocks))
	}
	// And the count is bounded BEFORE allocation: a request whose width is
	// both over the bound and astronomically large must return the bound
	// error - the arithmetic must never form the wrapped count that width
	// MaxUint64+1 would produce.
	if _, err := ask(0, math.MaxUint64); !errors.Is(err, ErrRangeTooBig) {
		t.Fatalf("the maximal range gave %v, want ErrRangeTooBig", err)
	}
}

func TestSyncerRefusesImpossibleRanges(t *testing.T) {
	f := newSyncFixture(t, 0, 6)
	f.server.MaxBlocksPerResponse = 4 // same answerer's-bound placement
	f.puller.MaxBlocksPerResponse = 4

	ask := func(from, to uint64) (*wire.BlockSyncResp, error) {
		return f.server.Answer(syncSignReq(t, f.priv, from, to))
	}

	// Backwards = the wire's only zero-length shape. Ranges are inclusive on
	// both ends, so To==From asks exactly one block; the only range that
	// selects nothing is To<From, which is refused, never answered empty.
	if _, err := ask(3, 2); !errors.Is(err, ErrBadSyncRange) {
		t.Fatalf("a backwards range gave %v, want ErrBadSyncRange", err)
	}
	// The "give me nothing above the head" shape a confused requester sends:
	// From one past the head, To the head. It selects nothing - refused.
	if _, err := ask(7, 6); !errors.Is(err, ErrBadSyncRange) {
		t.Fatalf("the empty range above the head gave %v, want ErrBadSyncRange", err)
	}
	// A single block is a legal range, not a zero-length one.
	if resp, err := ask(3, 3); err != nil || len(resp.Blocks) != 1 {
		t.Fatalf("a one-block range gave (%d blocks, %v)", len(resp.Blocks), err)
	}
	// Starting above the local height: refused with its own error, not
	// answered empty and not served short.
	if _, err := ask(7, 9); !errors.Is(err, ErrRangeAhead) {
		t.Fatalf("a range starting above the head gave %v, want ErrRangeAhead", err)
	}
	// A range that only EXTENDS past the height is served short - that is
	// how a windowed pull learns its peer ran out. (Width 4 is exactly the
	// bound, so the bound is not what answers here.)
	resp, err := ask(5, 8)
	if err != nil {
		t.Fatalf("a range extending past the head was refused: %v", err)
	}
	if len(resp.Blocks) != 2 {
		t.Fatalf("heights 5..6 of a height-6 chain served %d blocks", len(resp.Blocks))
	}
	// Ordering pin: the bound is decided BEFORE the height lookup and any
	// allocation, so a range that is both oversized and future-named comes
	// back as the BOUND error, never as the height error and never as an
	// (allocated) short answer.
	if _, err := ask(7, math.MaxUint64); !errors.Is(err, ErrRangeTooBig) {
		t.Fatalf("an oversized future range gave %v, want the bound error first", err)
	}
}

func TestSyncerServesTheEncodedRangeItWasAskedFor(t *testing.T) {
	f := newSyncFixture(t, 0, 6)

	resp, err := f.server.Answer(syncSignReq(t, f.priv, 2, 5))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Blocks) != 4 {
		t.Fatalf("served %d blocks for heights 2..5", len(resp.Blocks))
	}
	for i, raw := range resp.Blocks {
		blk, err := types.DecodeBlock(raw)
		if err != nil {
			t.Fatalf("served bytes for block %d do not decode: %v", i, err)
		}
		want, err := f.serverCh.BlockAt(uint64(2 + i))
		if err != nil {
			t.Fatal(err)
		}
		if blk.ID() != want.ID() {
			gotID, wantID := blk.ID(), want.ID()
			t.Fatalf("served block at height %d is %x, the chain holds %x", 2+i, gotID[:8], wantID[:8])
		}
	}
}

func TestSyncerPullsAcrossSeveralWindows(t *testing.T) {
	f := newSyncFixture(t, 0, 5)
	f.puller.MaxBlocksPerResponse = 2

	if err := f.puller.PullAndAdopt(1); err != nil {
		t.Fatalf("a three-window pull failed: %v", err)
	}
	assertHeadsEqual(t, f, "after three windows")

	// Windows must CHAIN: [1,2] full, [3,4] full, [5,...] short - a pull
	// that stops after its first full window never converges, and one that
	// re-asks an adopted height double-counts the head.
	if len(f.loop.sent) != 3 {
		t.Fatalf("pulling 5 blocks in windows of 2 sent %d requests", len(f.loop.sent))
	}
	for i, want := range []uint64{1, 3, 5} {
		if f.loop.sent[i].From != want {
			t.Fatalf("request %d asked from %d, want %d", i, f.loop.sent[i].From, want)
		}
	}
}

func TestSyncerRefusesUnsignedOrForeignRequests(t *testing.T) {
	f := newSyncFixture(t, 0, 2)
	ask := func(req *wire.BlockSyncReq) error {
		_, err := f.server.Answer(req)
		return err
	}

	// Unsigned.
	req := syncSignReq(t, f.priv, 1, 2)
	req.Sig = nil
	if !errors.Is(ask(req), ErrBadSyncAuth) {
		t.Fatalf("an unsigned request gave %v, want ErrBadSyncAuth", ask(req))
	}
	// Signed by a key outside the validator set.
	_, strangerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	req = syncSignReq(t, strangerPriv, 1, 2)
	if !errors.Is(ask(req), ErrBadSyncAuth) {
		t.Fatalf("a stranger's request gave %v, want ErrBadSyncAuth", ask(req))
	}
	// A real signature over different terms (replay bait): sign one range,
	// present another.
	req = syncSignReq(t, f.priv, 1, 2)
	req.To = 2
	req.From = 2
	if !errors.Is(ask(req), ErrBadSyncAuth) {
		t.Fatalf("a re-ranged signature gave %v, want ErrBadSyncAuth", ask(req))
	}
	// And the frame layer: a frame that does not decode, and a frame whose
	// range is refused, both send nothing.
	if _, ok := f.server.Handle([]byte{0x01}); ok {
		t.Fatal("Handle answered a frame that is not a BLOCK_SYNC request")
	}
	if _, ok := f.server.Handle(wire.EncodeBlockSyncReq(func() *wire.BlockSyncReq {
		r := syncSignReq(t, f.priv, 1, 2)
		r.Sig = nil
		return r
	}())); ok {
		t.Fatal("Handle answered an unauthenticated request instead of refusing it")
	}
}

func TestSyncerPullFromAPartitionedPeerIsAnError(t *testing.T) {
	// A transport refusal (unknown peer here) is the caller's problem: the
	// pull returns the error rather than reading silence as caught-up.
	f := newSyncFixture(t, 0, 2)
	f.puller.Peer = "nobody"
	if err := f.puller.PullAndAdopt(1); err == nil {
		t.Fatal("sending to an unknown peer reported success")
	}
}
