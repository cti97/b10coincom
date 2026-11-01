package devnet

// Audit A-2, the harm, pinned at the layer that can close it.
//
// A plaintext handshake cannot stop a committee member M that holds a socket
// to A and a socket to B from relaying A's and B's handshakes to each other:
// M copies each side's commitment to the other, relays the reveals, and both
// nodes end up with the same challenge pair. A's HELLO then verifies on M's
// socket at B, and B records A's height `via` M. What the catch-up table CAN
// guarantee is that this buys M nothing: a pull sent down M's socket that
// answers nothing must rotate B away from THAT SOCKET, not away from the
// member, so A's genuine path keeps serving.
//
// The state is constructed: the member's HELLO arrives on two sockets, the
// genuine one first and the relayed one second (the order a relay can always
// arrange), and the pull seam answers only on the genuine socket.

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

// TestACommitmentRelayAdmitsTheSocketButCannotStarveTheGenuinePath is the
// two-socket member at the socket level, pinned as what it IS: a relay the
// handshake cannot refuse, whose socket the catch-up table can still rotate
// away from. The attacker M holds a socket A dialled and a socket M dialled to
// B, copies each node's commitment to the other, relays the reveals, and
// forwards A's HELLO to B. B admits M's socket as A - that is the limit of a
// plaintext handshake, and a test that claimed otherwise would be wrong - and
// then B's genuine link to A is what a silent pull through M falls back to.
func TestACommitmentRelayAdmitsTheSocketButCannotStarveTheGenuinePath(t *testing.T) {
	b := startQuietListener(t, 0)
	a := startQuietListener(t, 1)

	// A's socket to M (A dials it), and M's socket to B.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := a.ttp.AddPeer(ln.Addr().String()); err != nil {
		t.Fatalf("making A dial the attacker: %v", err)
	}
	connA, brA := openDialedPeer(t, ln, "m")
	connB, brB := openRawPeer(t, b.Addr(), "m")

	// THE RELAY. Both nodes send their commitment first; M needs nothing of
	// its own, only to carry each frame across.
	aCommit := readFrameWithin(t, brA, "A's commitment")
	bCommit := readFrameWithin(t, brB, "B's commitment")
	writeFrameOrFail(t, connA, bCommit)
	writeFrameOrFail(t, connB, aCommit)
	aLocal := readFrameWithin(t, brA, "A's challenge")
	bLocal := readFrameWithin(t, brB, "B's challenge")
	writeFrameOrFail(t, connA, bLocal)
	writeFrameOrFail(t, connB, aLocal)

	waitFor(t, "A to register the attacker's link", 5*time.Second, func() bool {
		return hasPeer(a, "m")
	})
	a.broadcastHello()
	frame := readFrameWithin(t, brA, "A's HELLO")
	stolen, err := wire.DecodeHello(frame)
	if err != nil {
		t.Fatalf("A's captured frame is not a HELLO: %v", err)
	}
	if !bytes.Equal(stolen.Nonce, wire.HelloBinding(aLocal, bLocal)) {
		t.Fatalf("A did not sign the relayed pair: got %x, want aL||bL", stolen.Nonce)
	}
	writeFrameOrFail(t, connB, frame)
	// The limit, stated by the test rather than hidden: B admits the relayed
	// socket as A and records A on it.
	waitFor(t, "B to admit the relayed socket as A", 5*time.Second, func() bool {
		b.peerHMu.Lock()
		defer b.peerHMu.Unlock()
		st := b.peerH[string(a.pub)]
		return st != nil && st.paths["m"] != nil
	})

	// B's genuine link to A, both HELLOs over the real sockets.
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
	waitFor(t, "B to record A on A's own socket too", 10*time.Second, func() bool {
		b.peerHMu.Lock()
		defer b.peerHMu.Unlock()
		st := b.peerH[string(a.pub)]
		return st != nil && st.paths["v1"] != nil
	})

	// A pull down the relayed socket that answers nothing demotes THAT socket;
	// the member's genuine socket is the next pick.
	b.beginWave()
	b.demotePeer(string(a.pub), "m", 0)
	if who, via, _ := b.tallestPeer(); who != string(a.pub) || via != "v1" {
		t.Fatalf("after the relayed socket went silent the pick is %x via %q, want A via v1 (audit A-2)", []byte(who), via)
	}
}

func readFrameWithin(t *testing.T, br interface {
	Read([]byte) (int, error)
}, what string) []byte {
	t.Helper()
	f, err := wire.ReadFrame(br, 1<<20)
	if err != nil {
		t.Fatalf("reading %s: %v", what, err)
	}
	return f
}

func writeFrameOrFail(t *testing.T, c net.Conn, frame []byte) {
	t.Helper()
	if err := wire.WriteFrame(c, frame); err != nil {
		t.Fatalf("relaying a frame: %v", err)
	}
}

// anyPathDemoted reports the latest wave any of the member's sockets is demoted
// until, or 0 when none is.
func anyPathDemoted(v *Validator, who string) uint64 {
	v.peerHMu.Lock()
	defer v.peerHMu.Unlock()
	var until uint64
	if st := v.peerH[who]; st != nil {
		for _, p := range st.paths {
			if p.demoted > until {
				until = p.demoted
			}
		}
	}
	return until
}

func TestASilentRelayedSocketDoesNotStarveTheMembersGenuinePath(t *testing.T) {
	v := startQuietValidator(t) // head 0
	member := memberKey(v, 1)

	// The member's signed HELLO, at the same height, on its own socket and
	// then on the socket a relaying member holds.
	v.recordHeight(member, "v1", 3)
	v.recordHeight(member, "m", 3)

	type pick struct {
		who string
		via transport.PeerID
	}
	var picked []pick
	v.pull = func(uint64) error {
		picked = append(picked, pick{who: string(v.sy.Expect), via: v.sy.Peer})
		if v.sy.Peer != "v1" {
			return errors.New("the relayed socket answers nothing")
		}
		for v.ch.Height() < 3 {
			blk, err := v.ch.Build(v.priv, nil, v.ch.Head().Header.Timestamp+1)
			if err != nil {
				return err
			}
			if err := v.ch.Append(blk); err != nil {
				return err
			}
		}
		return nil
	}

	// Two waves are enough: whichever socket is tried first, a silent one is
	// rotated away from and the member's other socket is tried next.
	v.maybeCatchUp()
	v.maybeCatchUp()

	if got := v.Height(); got != 3 {
		t.Fatalf("the member's genuine socket never served: height %d after picks %v (audit A-2: a silent relayed socket demoted the MEMBER, not the socket)", got, picked)
	}
	servedByGenuine := false
	for _, p := range picked {
		if p.who != member {
			t.Fatalf("a pull went to %x, want only the member", []byte(p.who))
		}
		if p.via == "v1" {
			servedByGenuine = true
		}
	}
	if !servedByGenuine {
		t.Fatalf("no pull reached the member's own socket: picks %v", picked)
	}

	// The member stays a catch-up source on its genuine socket while the
	// relayed one sits out its demotion.
	v.recordHeight(member, "v1", 6)
	v.recordHeight(member, "m", 6)
	if who, via, _ := v.tallestPeer(); who != member || via != "v1" {
		t.Fatalf("after the silent socket failed, the next pick is %x via %q, want the member via v1", []byte(who), via)
	}
}
