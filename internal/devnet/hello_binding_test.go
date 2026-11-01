package devnet

// Audit A-2: what commit-then-reveal closes, and what it does not.
//
// A committee member M collects a HELLO that ANOTHER member A signed, and
// presents it at a third node B on M's OWN socket. This test pins the ordering
// the commitment DOES close - M chooses its own half at A, learns A's
// challenge, then tries to present A's challenge at B and B's at A - and shows
// that A refuses a reveal that does not hash to M's commitment.
//
// It does NOT show that M cannot succeed at all, because M can (fix review,
// section 3): instead of choosing its own half, M copies A's commitment to B
// and B's commitment to A, relays the two reveals, and A and B end up holding
// the same challenge pair. That is a relay, not a substitution, and no value
// exchanged over plaintext TCP between unauthenticated parties can prevent it.
// The harm it could do is closed where it can be: a silent pull demotes the
// SOCKET it went down, never the member (hello_relay_path_test.go), so A's
// genuine path at B keeps serving.
//
// The ordering pinned here, step by step:
//
//  1. M has a socket to A (A dials it through an operator-configured AddPeer,
//     the same path a seated member's signed hint reaches). M commits its own
//     half BEFORE A reveals aL, then learns aL;
//  2. M dials B and presents aL as its own challenge. B's expected HELLO
//     binding is now HelloBinding(aL, bL);
//  3. M can only reveal the half it committed to A, so A's HELLO is bound to
//     aL||blind, not the aL||bL pair B demands; a reveal of bL instead closes
//     the socket;
//  4. A's HELLO forwarded to B is refused: the binding does not match.
//
// The state is CONSTRUCTED: B and A are quiet validators (one wave an hour, no
// automatic ticks); every HELLO is driven by hand.

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/transport/tcp"
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

// openDialedPeer accepts a node's dial and completes the ID exchange from the
// raw side. It does NOT touch the challenge exchange, so the caller chooses
// every step of it.
func openDialedPeer(t *testing.T, ln net.Listener, id string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("accepting the member's dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	br := bufio.NewReader(c)
	if _, err := wire.ReadFrame(br, 4096); err != nil { // the dialer's ID
		t.Fatalf("reading the dialer's ID: %v", err)
	}
	if err := wire.WriteFrame(c, []byte(id)); err != nil {
		t.Fatalf("writing the raw ID: %v", err)
	}
	return c, br
}

// openRawPeer dials a listening node and completes the ID exchange.
func openRawPeer(t *testing.T, addr, id string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("raw dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	br := bufio.NewReader(c)
	if _, err := wire.ReadFrame(br, 4096); err != nil { // the listener's ID
		t.Fatalf("reading the listener's ID: %v", err)
	}
	if err := wire.WriteFrame(c, []byte(id)); err != nil {
		t.Fatalf("writing the raw ID: %v", err)
	}
	return c, br
}

// commitChallenge sends H(challenge) - this side's committed half - and returns
// the node's own commitment. challenge must already be fixed; that is the point
// of the protocol.
func commitChallenge(t *testing.T, c net.Conn, br *bufio.Reader, challenge []byte) []byte {
	t.Helper()
	sent := tcp.ConnectionCommitment(challenge)
	if err := wire.WriteFrame(c, sent[:]); err != nil {
		t.Fatalf("sending the challenge commitment: %v", err)
	}
	theirs, err := wire.ReadFrame(br, 64)
	if err != nil {
		t.Fatalf("reading the node's challenge commitment: %v", err)
	}
	if len(theirs) != len(sent) {
		t.Fatalf("the node's commitment is %d bytes, want %d", len(theirs), len(sent))
	}
	return theirs
}

// readChallenge reads the node's revealed challenge and checks it against the
// commitment the node made first.
func readChallenge(t *testing.T, br *bufio.Reader, commitment []byte) []byte {
	t.Helper()
	theirs, err := wire.ReadFrame(br, 64)
	if err != nil {
		t.Fatalf("reading the node's challenge: %v", err)
	}
	want := tcp.ConnectionCommitment(theirs)
	if !bytes.Equal(want[:], commitment) {
		t.Fatalf("the node's reveal does not match its commitment: %x vs %x", theirs, commitment)
	}
	return theirs
}

// revealChallenge sends this side's committed challenge.
func revealChallenge(t *testing.T, c net.Conn, challenge []byte) {
	t.Helper()
	if err := wire.WriteFrame(c, challenge); err != nil {
		t.Fatalf("revealing the challenge: %v", err)
	}
}

func TestAMemberCannotBindAnotherMembersHelloToItsOwnSocket(t *testing.T) {
	b := startQuietListener(t, 0) // the node that records the identity
	a := startQuietListener(t, 1) // the member whose HELLO is stolen

	// 1. A's socket to M. A is made to DIAL M (the operator-configured path; a
	// seated member's signed hint reaches the same place). M's half is fixed by
	// a commitment BEFORE A reveals aL; it learns aL and still holds its reveal.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := a.ttp.AddPeer(ln.Addr().String()); err != nil {
		t.Fatalf("making A dial the attacker: %v", err)
	}
	connA, brA := openDialedPeer(t, ln, "m")
	blind := bytes.Repeat([]byte{0x11}, 32) // chosen before aL is known
	aCommit := commitChallenge(t, connA, brA, blind)
	aLocal := readChallenge(t, brA, aCommit) // the real order: aL first

	// 2. M's own socket at B, presenting A's challenge as its own: B's expected
	// binding is now aL||bL.
	connB, brB := openRawPeer(t, b.Addr(), "m")
	bCommit := commitChallenge(t, connB, brB, aLocal)
	bLocal := readChallenge(t, brB, bCommit)
	revealChallenge(t, connB, aLocal)

	// 3. M's best remaining move on A's socket: reveal the half it committed to.
	// A's HELLO is bound to aL||blind, NOT to the aL||bL pair B demands, and no
	// later write can change that.
	revealChallenge(t, connA, blind)
	waitFor(t, "A to register the attacker's link", 5*time.Second, func() bool {
		return hasPeer(a, "m")
	})
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
	if !bytes.Equal(stolen.Nonce, wire.HelloBinding(aLocal, blind)) {
		t.Fatalf("A's HELLO does not carry both challenges of its socket: got %x, want aLocal||blind", stolen.Nonce)
	}
	if bytes.Equal(stolen.Nonce, wire.HelloBinding(aLocal, bLocal)) {
		t.Fatal("A signed the aL||bL pair the attacker needed: the commitment did not fix M's half")
	}

	// 4. THE ATTACK: M presents the one frame A would sign on M's socket at B.
	gatedBefore := b.ttp.GatedFrames()
	if err := wire.WriteFrame(connB, frame); err != nil {
		t.Fatalf("replaying A's HELLO to B: %v", err)
	}
	// Wait for the replay to be CLASSIFIED so the assertions below say which
	// outcome happened rather than racing it.
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

	// 5. THE REVIEW'S LITERAL STEP 3, shown refused. A second, separately
	// configured socket: M commits one challenge and then answers A with B's.
	// A must reject the reveal (it does not hash to the commitment) and close
	// the socket without signing a HELLO. This is what makes the substitution
	// impossible rather than merely mismatched.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln2.Close() })
	if err := a.ttp.AddPeer(ln2.Addr().String()); err != nil {
		t.Fatalf("making A dial the attacker's second socket: %v", err)
	}
	connA2, brA2 := openDialedPeer(t, ln2, "n")
	blind2 := bytes.Repeat([]byte{0x22}, 32)
	aCommit2 := commitChallenge(t, connA2, brA2, blind2)
	_ = readChallenge(t, brA2, aCommit2)
	// The literal review step: "M sends B's challenge to A as its challenge".
	if err := wire.WriteFrame(connA2, bLocal); err != nil {
		t.Fatalf("substituting B's challenge for the committed one: %v", err)
	}
	_ = connA2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := wire.ReadFrame(brA2, 1<<20); err == nil {
		t.Fatal("A signed a HELLO for a reveal that did not match its commitment: the challenge can be substituted after the commitment (audit A-2)")
	} else if ne, isTimeout := err.(net.Error); isTimeout && ne.Timeout() {
		t.Fatal("A did not CLOSE the socket after a reveal that did not match its commitment: the substitution was accepted and the handshake is still running (audit A-2)")
	}

	// NOT REFUSE EVERYTHING. B dials A for real; the two exchange each other's
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
