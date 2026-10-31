package devnet

// Audit A-2, BEFORE and AFTER, on the exact shape the finding names: a
// committee member M collects a HELLO that ANOTHER member A signed, and
// presents it at a third node B on M's OWN socket. Once B admits that socket,
// B records A's height `via` it, and every catch-up pull for A goes to M, which
// answers nothing: A is demoted and is never a usable sync source at B.
//
// The state is CONSTRUCTED, never raced. B and A are quiet validators (one
// wave an hour, no automatic ticks). M is a raw socket that performs the real
// ID+challenge handshake:
//
//  1. M dials B, learns B's fresh challenge bL, and keeps that socket open;
//  2. M makes A DIAL it (an operator-configured AddPeer, the same path an
//     operator or a seated member's signed hint reaches), and sends bL as its
//     OWN challenge on that link - the "as its own nonce, sends B's nonce" step;
//  3. A's production broadcastHello signs a HELLO over that link's binding;
//  4. M replays the captured frame to B on the socket from step 1.
//
// BEFORE the fix the signed material was the receiver's challenge alone, which
// on the A--M link IS bL: B's equality check passed, the frame was a valid
// member signature, and the socket was admitted as A. AFTER the fix the signed
// material is BOTH challenges (wire.HelloBinding: the sender's own, then the
// receiver's), so A's frame carries aL||bL while B demands M's own challenge
// followed by bL. aL is a value B never issued and that M cannot make B accept;
// the relayed copy is therefore useless, and M's socket stays a gated stranger.
//
// Both halves are shown: the replay is refused, and a genuinely bound HELLO
// over a real A--B connection still admits A and becomes the pull target, so
// the gate is not merely refusing everything.

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/wire"
)

// startQuietListener starts one fixture-mode validator that listens but never
// ticks or waves on its own; the test drives every HELLO by hand.
func startQuietListener(t *testing.T, seat int) *Validator {
	t.Helper()
	v, err := StartValidator(ValidatorConfig{
		Dir:                 t.TempDir(),
		Index:               seat,
		Validators:          4,
		Listen:              "127.0.0.1:0",
		AllowLocalPeerHints: true,
		TickEvery:           time.Hour,
		WaveEvery:           time.Hour,
	})
	if err != nil {
		t.Fatalf("starting listening validator %d: %v", seat, err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// dialRawPeer completes the transport's handshake as the DIALER against a
// listening node: it reads the node's announced ID, writes its own, reads the
// node's 32-byte challenge, and writes the challenge it chooses. It returns the
// socket, a reader positioned after the handshake, the node's challenge and the
// value this side sent.
func dialRawPeer(t *testing.T, addr, id string, wantNonce []byte) (net.Conn, *bufio.Reader, []byte, []byte) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("raw dial %s: %v", addr, err)
	}
	br := bufio.NewReader(c)
	if _, err := wire.ReadFrame(br, 4096); err != nil { // the listener's ID
		t.Fatalf("reading the listener's ID: %v", err)
	}
	if err := wire.WriteFrame(c, []byte(id)); err != nil {
		t.Fatalf("writing the raw ID: %v", err)
	}
	theirs, err := wire.ReadFrame(br, 64) // the listener's challenge
	if err != nil {
		t.Fatalf("reading the listener's challenge: %v", err)
	}
	ours := wantNonce
	if ours == nil {
		ours = bytes.Repeat([]byte{0x5a}, 32)
	}
	if err := wire.WriteFrame(c, ours); err != nil {
		t.Fatalf("writing the raw challenge: %v", err)
	}
	return c, br, theirs, ours
}

// acceptRawPeer completes the same handshake as the LISTENER against a node
// that dials it, choosing the challenge it sends. It is the attacker's socket
// on the member-A side.
func acceptRawPeer(t *testing.T, ln net.Listener, id string, challenge []byte) (net.Conn, *bufio.Reader, []byte) {
	t.Helper()
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("accepting the member's dial: %v", err)
	}
	br := bufio.NewReader(c)
	if _, err := wire.ReadFrame(br, 4096); err != nil { // the dialer's ID
		t.Fatalf("reading the dialer's ID: %v", err)
	}
	if err := wire.WriteFrame(c, []byte(id)); err != nil {
		t.Fatalf("writing the raw ID: %v", err)
	}
	theirs, err := wire.ReadFrame(br, 64) // the dialer's challenge
	if err != nil {
		t.Fatalf("reading the dialer's challenge: %v", err)
	}
	if err := wire.WriteFrame(c, challenge); err != nil {
		t.Fatalf("writing the chosen challenge: %v", err)
	}
	return c, br, theirs
}

func TestAMemberCannotBindAnotherMembersHelloToItsOwnSocket(t *testing.T) {
	b := startQuietListener(t, 0) // the node that records the identity
	a := startQuietListener(t, 1) // the member whose HELLO is stolen

	// 1. M's own socket at B. It announces "m", learns B's challenge, and stays
	// unadmitted: it has proved nothing yet.
	connB, _, bLocal, mNonce := dialRawPeer(t, b.Addr(), "m", nil)
	defer connB.Close()

	// 2. M's socket at A. A is made to DIAL it (the operator-configured path;
	// a seated member's signed hint reaches the same place). M's chosen
	// challenge is bLocal - the value B will demand - which is the whole trick:
	// the peer chooses the challenge it sends the member.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := a.ttp.AddPeer(ln.Addr().String()); err != nil {
		t.Fatalf("making A dial the attacker: %v", err)
	}
	connA, brA, aLocal := acceptRawPeer(t, ln, "m", bLocal)
	defer connA.Close()
	waitFor(t, "A to register the attacker's link", 5*time.Second, func() bool {
		return hasPeer(a, "m")
	})

	// 3. A's production HELLO over that link, captured by M.
	a.broadcastHello()
	frame, err := wire.ReadFrame(brA, 1<<20)
	if err != nil {
		t.Fatalf("reading A's HELLO: %v", err)
	}
	stolen, err := wire.DecodeHello(frame)
	if err != nil {
		t.Fatalf("A's captured frame is not a HELLO: %v", err)
	}
	if !bytes.Equal(stolen.Validator, a.pub) || stolen.Height != a.Height() {
		t.Fatalf("the captured frame is not A's HELLO: %x at %d", stolen.Validator, stolen.Height)
	}
	// The frame names A's OWN challenge and then B's - A's real binding for the
	// socket M chose to receive it on. B requires M's challenge, then B's own.
	if !bytes.Equal(stolen.Nonce, wire.HelloBinding(aLocal, bLocal)) {
		t.Fatalf("A's HELLO does not carry both challenges of its socket: got %x, want aLocal||bLocal", stolen.Nonce)
	}
	bDemands := wire.HelloBinding(mNonce, bLocal)
	if bytes.Equal(stolen.Nonce, bDemands) {
		t.Fatal("the captured frame is byte-for-byte what B demands: the test did not construct the misbinding")
	}

	// 4. THE ATTACK: M presents A's HELLO on M's own socket at B.
	gatedBefore := b.ttp.GatedFrames()
	if err := wire.WriteFrame(connB, frame); err != nil {
		t.Fatalf("replaying A's HELLO to B: %v", err)
	}
	// Wait for the replay to be CLASSIFIED (refused here, or - pre-fix - admitted),
	// so the assertions below say which outcome happened rather than racing it.
	waitFor(t, "the replayed HELLO to be classified", 5*time.Second, func() bool {
		return b.ttp.GatedFrames() > gatedBefore || hasPeer(b, "m")
	})

	if hasPeer(b, "m") {
		t.Fatal("a member's stolen HELLO admitted the attacker's socket: B now speaks to M as A (audit A-2)")
	}
	b.peerHMu.Lock()
	_, recorded := b.peerH[string(a.pub)]
	b.peerHMu.Unlock()
	if recorded {
		t.Fatal("B recorded A's height via the attacker's socket: a HELLO signed for one socket moved `via` on another (audit A-2)")
	}
	if who, via, _ := b.tallestPeer(); who != "" {
		t.Fatalf("the replayed HELLO became B's catch-up source: %x via %q", []byte(who), via)
	}
	if b.ttp.GatedFrames() <= gatedBefore {
		t.Fatal("the replayed frame was neither admitted nor counted as gated: it did not reach the admission gate")
	}

	// NOT REFUSE-EVERYTHING. B dials A for real; the two exchange each other's
	// challenges, both production broadcastHello calls run, and A must be
	// admitted and recorded on A's own socket ("v1"), not on the attacker's.
	if err := b.ttp.AddPeer(a.Addr()); err != nil {
		t.Fatalf("B's genuine dial of A: %v", err)
	}
	waitFor(t, "B to register its genuine dial of A", 5*time.Second, func() bool {
		return hasPeer(b, "v1")
	})
	b.broadcastHello()
	waitFor(t, "A to admit B's genuinely bound HELLO", 10*time.Second, func() bool {
		return hasPeer(a, "v0")
	})
	a.broadcastHello()
	waitFor(t, "B to record A on A's own socket", 10*time.Second, func() bool {
		b.peerHMu.Lock()
		defer b.peerHMu.Unlock()
		st := b.peerH[string(a.pub)]
		return st != nil && st.via == "v1"
	})
	if who, via, h := b.tallestPeer(); who != string(a.pub) || via != "v1" || h != a.Height() {
		t.Fatalf("the honest HELLO did not become the pull target: who=%q via=%q h=%d (A is at %d)", who, via, h, a.Height())
	}
}
