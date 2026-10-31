package devnet

// Audit A-3: over the relay a HELLO carries the EMPTY binding (there is no
// per-member challenge on a shared link - see tcp.PeerChallenges), so any
// stranger on a token-less relay, or any token holder, can replay a member's
// OLD signed HELLO. recordHeight used to OVERWRITE the member's height with
// whatever the replay said, so a replayed low-height HELLO dragged every
// member's entry down to or below the lagging node's own head; tallestPeer then
// selected nobody and the node never pulled, even while holding good direct
// links (the entry is keyed by member, so the relay replay overwrote the direct
// attestation's height and `via`).
//
// The first test drives the replay through the REAL policy path: a real relay
// connection, a real member-signed HELLO at an old height, observeHello exactly
// as the router calls it. The state is constructed (the quiet validator at
// height 0, the member's fresh attestation recorded at 50), never raced.
//
// The second test is the safety half the fix must not break: a one-way height
// must not let a LYING member inflate itself into a permanent catch-up source.
// It cannot: the write is reachable only for a signed committee HELLO, and
// tallestPeer's cap and the per-member demotion are what bound the claim - the
// `proven` flag H-1 removed was write-only, not a guard.

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/relay"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/transport/tcp"
	"github.com/cti97/b10coincom/internal/wire"
)

func TestAReplayedLowHelloOverTheRelayCannotLowerTheRecordedHeight(t *testing.T) {
	v := startQuietValidator(t) // head 0: a lagging node
	member := memberKey(v, 1)
	// The member's fresh attestation, three-plus blocks ahead: the entry a
	// verified direct HELLO at 50 leaves (recordHeight is the single writer the
	// observer calls; the direct half is pinned by the PX-2 tests).
	v.recordHeight(member, "v1", 50)

	// A real relay link: the path with no per-member challenge.
	rl := relay.New(relay.Options{})
	defer rl.Close()
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	raddr := rl.Addr().String()
	if err := v.ConnectRelay(raddr); err != nil {
		t.Fatal(err)
	}
	relayName := tcp.RelayPeerName(raddr)
	waitFor(t, "the relay link to register", 5*time.Second, func() bool {
		return hasPeer(v, relayName)
	})

	// THE REPLAY: the member's genuine signature over an OLD height, arriving
	// over the relay exactly as the router would deliver it. The empty binding
	// is what the relay path demands (and all it can demand).
	memberPriv := simnet.ValidatorKey(1)
	old := &wire.Hello{
		ChainID:   v.g.ChainID,
		Validator: memberPriv.Public().(ed25519.PublicKey),
		Height:    0,
		Nonce:     nil,
	}
	hh := helloHash(old)
	old.Sig = crypto.Sign(memberPriv, hh[:])
	v.observeHello(relayName, old)

	v.peerHMu.Lock()
	st := v.peerH[member]
	gotHeight, gotVia := st.height, st.via
	v.peerHMu.Unlock()
	// BEFORE: recordHeight assigned 0 (and via=relayName), the lagging node's
	// own head, and selection had nothing above it.
	if gotHeight != 50 {
		t.Fatalf("a replayed low-height HELLO lowered the recorded height to %d, want 50: a stale frame is not a fresh claim (audit A-3)", gotHeight)
	}
	if gotVia != "v1" {
		t.Fatalf("the stale replay moved the member's pull target to %q, want the direct attestation \"v1\"", gotVia)
	}

	// The lagging node still has a source: the member at 50 is selectable, and
	// maybeCatchUp actually sends the pull.
	who, via, h := v.tallestPeer()
	if who != member || via != "v1" || h <= v.Height() {
		t.Fatalf("the lagging node selected %q via %q at %d (head %d): it has no catch-up source", who, via, h, v.Height())
	}
	var pulledWho string
	var pulledVia transport.PeerID
	v.pull = func(uint64) error {
		pulledWho, pulledVia = string(v.sy.Expect), v.sy.Peer
		return nil
	}
	v.maybeCatchUp()
	if pulledWho != member || pulledVia != "v1" {
		t.Fatalf("maybeCatchUp pulled from %q via %q, want the member via its direct link", pulledWho, pulledVia)
	}

	// A NON-member cannot write the entry at all, whatever height it claims:
	// the membership check is before recordHeight, so the high-water mark can
	// only ever hold a value a seated key signed.
	_, strangerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	forged := &wire.Hello{
		ChainID:   v.g.ChainID,
		Validator: strangerPriv.Public().(ed25519.PublicKey),
		Height:    1 << 62,
	}
	fh := helloHash(forged)
	forged.Sig = crypto.Sign(strangerPriv, fh[:])
	v.observeHello(relayName, forged)
	v.peerHMu.Lock()
	got := len(v.peerH)
	v.peerHMu.Unlock()
	if got != 1 {
		t.Fatalf("a non-member's HELLO added a peer-table entry: %d entries, want only the member", got)
	}
}

func TestAHighWaterHeightCannotCaptureTheCatchUpSource(t *testing.T) {
	v := startQuietValidator(t) // head 0
	liar := memberKey(v, 2)
	honest := memberKey(v, 1)

	// The liar's OWN signed claim, as large as it likes. The high-water mark
	// stores it, because a member's signed height is all the table can know.
	v.recordHeight(liar, "v2", 1<<62)
	// NOT A CATCH-UP SOURCE FOREVER: selection caps it one window above the
	// higher of our head and what a pull from it ever reached. The one-way
	// height dwarfs nothing.
	win := v.peerWindow()
	if who, _, h := v.tallestPeer(); who != liar || h != v.Height()+win {
		t.Fatalf("the lying height was selected at %d, want the relative cap %d (head %d, window %d)", h, v.Height()+win, v.Height(), win)
	}

	v.recordHeight(honest, "v1", 3)
	type pick struct {
		who string
		via transport.PeerID
	}
	var picked []pick
	v.pull = func(uint64) error {
		picked = append(picked, pick{who: string(v.sy.Expect), via: v.sy.Peer})
		if string(v.sy.Expect) == honest {
			for v.ch.Height() < 3 {
				blk, err := v.ch.Build(v.priv, nil, v.ch.Head().Header.Timestamp+1)
				if err != nil {
					return err
				}
				if err := v.ch.Append(blk); err != nil {
					return err
				}
			}
		}
		return nil
	}

	v.maybeCatchUp() // the capped liar is tried once and substantiates nothing
	// The liar's high HELLO keeps arriving (a replay of it is all a replayer
	// can produce). A replayed HELLO must not clear the demotion: only a pull
	// that reaches the claim does.
	v.recordHeight(liar, "v2", 1<<62)
	v.maybeCatchUp()

	if len(picked) != 2 || picked[0].who != liar || picked[1].who != honest || picked[1].via != "v1" {
		t.Fatalf("the lying height captured the catch-up source: picks %v, want the liar once then the honest member via v1", picked)
	}
	if got := v.Height(); got != 3 {
		t.Fatalf("the honest peer's blocks were not adopted: height %d, want 3", got)
	}
	// The liar stays out while its demotion stands, however often the high
	// frame is replayed.
	v.recordHeight(liar, "v2", 1<<62)
	v.maybeCatchUp()
	if len(picked) != 2 {
		t.Fatalf("a third wave pulled from %v: replaying the high HELLO cleared the demotion", picked)
	}
}

// TestAReplayedCurrentHeightHelloOverTheRelayStillMovesVia is A-3's documented
// residual, pinned as CURRENT behaviour (section 6 item 2). The review's desired
// property - a replayed current-height member HELLO over the relay must not move
// `via` off a nonce-bound direct connection - is not true today, and this test
// says so rather than leaving a gap somebody could mistake for a fix.
//
// The state is built through the real paths, not a race: b dials a, both sides
// broadcast their production HELLOs, a advances two blocks, and b records a's
// current height via a's own socket ("v1"). Then b has a relay link (no peer
// challenge, empty binding) and A's genuine current-height HELLO, replayed there,
// ties the recorded height. recordHeight keeps the high-water height but moves
// `via` on an EQUAL height, so the relay becomes the catch-up source. recordHeight
// limits that to "cannot lower", not "cannot move": a direct nonce-bound
// attestation does not yet outrank a relay one.
func TestAReplayedCurrentHeightHelloOverTheRelayStillMovesVia(t *testing.T) {
	b := startQuietListener(t, 0)
	a := startQuietListener(t, 1)

	// A genuine nonce-bound direct link. b dials a (the operator-configured
	// path); both production broadcastHello calls run; b records a `via` "v1".
	if err := b.ttp.AddPeer(a.Addr()); err != nil {
		t.Fatalf("b dialling a: %v", err)
	}
	waitFor(t, "b to register its dial of a", 5*time.Second, func() bool {
		return hasPeer(b, "v1")
	})
	b.broadcastHello()
	waitFor(t, "a to admit b", 10*time.Second, func() bool {
		return hasPeer(a, "v0")
	})
	a.broadcastHello()
	waitFor(t, "b to record a via the direct socket", 10*time.Second, func() bool {
		b.peerHMu.Lock()
		defer b.peerHMu.Unlock()
		st := b.peerH[string(a.pub)]
		return st != nil && st.via == "v1"
	})

	// a advances two blocks and broadcasts its current height. The HELLO over
	// the direct socket carries that socket's two challenges, so b records the
	// CURRENT height `via` "v1" - the state the relay replay is about to move.
	for i := 0; i < 2; i++ {
		blk, err := a.Chain().Build(a.priv, nil, a.Chain().Head().Header.Timestamp+1)
		if err != nil {
			t.Fatalf("a building height %d: %v", a.Chain().Height()+1, err)
		}
		if err := a.Chain().Append(blk); err != nil {
			t.Fatalf("a appending height %d: %v", blk.Header.Height, err)
		}
	}
	a.broadcastHello()
	waitFor(t, "b to record a's current height via the direct socket", 10*time.Second, func() bool {
		b.peerHMu.Lock()
		defer b.peerHMu.Unlock()
		st := b.peerH[string(a.pub)]
		return st != nil && st.height == a.Height() && st.via == "v1"
	})

	// b's relay link: one socket for every member, no peer challenge, so the
	// HELLO that travels it carries the empty binding.
	rl := relay.New(relay.Options{})
	defer rl.Close()
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	relayName := tcp.RelayPeerName(rl.Addr().String())
	if err := b.ConnectRelay(rl.Addr().String()); err != nil {
		t.Fatalf("b connecting the relay: %v", err)
	}
	waitFor(t, "b's relay link to register", 5*time.Second, func() bool {
		return hasPeer(b, relayName)
	})

	// THE REPLAY: a's genuine current-height HELLO, carrying the empty binding
	// the relay path demands. Any holder of that frame - the relay, any stranger
	// on a token-less relay - can present it.
	replay := &wire.Hello{
		ChainID:   b.g.ChainID,
		Validator: a.pub,
		Height:    a.Height(),
		Nonce:     nil,
	}
	hh := helloHash(replay)
	replay.Sig = crypto.Sign(a.priv, hh[:])
	b.observeHello(relayName, replay)

	b.peerHMu.Lock()
	st := b.peerH[string(a.pub)]
	b.peerHMu.Unlock()
	if st == nil || st.height != a.Height() {
		t.Fatalf("the replay changed the recorded height (entry %+v, want a's current %d)", st, a.Height())
	}
	// CURRENT BEHAVIOUR, and the residual: the equal height moved `via`. When
	// this is fixed (a direct nonce-bound attestation outranking a relay one),
	// this assertion flips and A-3's residual note goes with it.
	if st.via != relayName {
		t.Fatalf("the replayed current-height HELLO did not move `via` to the relay (got %q): this test pins the residual; if it is fixed, update it and A-3's record", st.via)
	}
	if who, via, h := b.tallestPeer(); who != string(a.pub) || via != relayName || h != a.Height() {
		t.Fatalf("the relay replay did not become the pull target: who=%q via=%q h=%d, want a's key via the relay at %d", who, via, h, a.Height())
	}
}
