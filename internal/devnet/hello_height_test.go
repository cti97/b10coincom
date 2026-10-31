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
