package tcp

// The per-connection challenge (audit PX-2) is the material a HELLO signature is
// bound to, so its two properties are pinned directly rather than inferred from
// a replay test: both ends must AGREE on the pair, and the two values must be
// FRESH (distinct across connections and across ends). A relay connection has
// neither, and reports nil rather than a fake value - the caller must be able to
// tell "no peer challenge" from "a challenge that happens to be empty".

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/wire"
)

func TestADirectConnectionExchangesTwoDistinctAgreedChallenges(t *testing.T) {
	a := listen(t, Options{LocalID: "a"})
	b := listen(t, Options{LocalID: "b"})
	if err := a.AddPeer(b.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if err := b.AddPeer(a.Addr().String()); err != nil {
		t.Fatal(err)
	}
	// Exactly one of the cross-dials survives the rank; whichever it is, each
	// side must hold the pair (our challenge, theirs) for the peer name.
	waitFor(t, "both sides to register one connection to the other", 5*time.Second, func() bool {
		return len(a.Peers()) == 1 && len(b.Peers()) == 1
	})

	aPeer := a.Peers()[0]
	bPeer := b.Peers()[0]
	aOurs, aTheirs, ok := a.ConnNonces(aPeer)
	if !ok {
		t.Fatalf("no nonces for a's peer %q", aPeer)
	}
	bOurs, bTheirs, ok := b.ConnNonces(bPeer)
	if !ok {
		t.Fatalf("no nonces for b's peer %q", bPeer)
	}
	if len(aOurs) != connectionNonceBytes || len(bOurs) != connectionNonceBytes {
		t.Fatalf("challenge widths: a %d B, b %d B, want %d", len(aOurs), len(bOurs), connectionNonceBytes)
	}
	// Agreement: what a must echo is exactly what b checks, and vice versa.
	if !bytes.Equal(aTheirs, bOurs) {
		t.Fatal("a's peer challenge is not the value b generated: the two ends disagree on the HELLO binding")
	}
	if !bytes.Equal(bTheirs, aOurs) {
		t.Fatal("b's peer challenge is not the value a generated: the two ends disagree on the HELLO binding")
	}
	if bytes.Equal(aOurs, bOurs) {
		t.Fatal("both ends generated the SAME challenge: a captured HELLO would be replayable across the pair's directions")
	}

	// And a fresh connection gets a fresh challenge, so a captured HELLO for the
	// old socket is useless on the new one.
	oldA := append([]byte(nil), aOurs...)
	aPeerName := aPeer
	_ = a.Close()
	reopened := listen(t, Options{LocalID: "a"})
	if err := reopened.AddPeer(b.Addr().String()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the reopened a to register a fresh connection", 5*time.Second, func() bool {
		for _, p := range reopened.Peers() {
			if ours, _, ok := reopened.ConnNonces(p); ok && !bytes.Equal(ours, oldA) {
				return true
			}
		}
		return false
	})
	_ = aPeerName
}

// TestOurHelloIsOfferedOnlyWhereItCanAdmitUs pins the exact predicate behind
// audit PX-2's mutual bootstrap, because getting it wrong in either direction
// breaks something silent:
//
//   - a GATED connection this node DIALED (a learned hint) MUST receive our
//     HELLO. It is unadmitted here, but the peer on the other end is gated too,
//     and it admits us only after our signed HELLO arrives. Excluding it would
//     deadlock every learned link forever - the node and the peer each waiting
//     for the other's HELLO.
//   - an ACCEPTED, still-unadmitted stranger MUST NOT. It dialed us; it has
//     proved nothing, and handing it our signed height (one frame per wave, for
//     a socket we never chose) is exactly the free amplification the admission
//     gate exists to deny a squatter.
func TestOurHelloIsOfferedOnlyWhereItCanAdmitUs(t *testing.T) {
	tp := listen(t, Options{LocalID: "v0", Admit: func([]byte, []byte) bool { return false }})

	// The accepted stranger: a raw socket that completes the handshake and
	// sends nothing Admit accepts. It is registered but NOT a peer.
	stranger := rawDial(t, tp.Addr().String())
	if err := wire.WriteFrame(stranger, []byte("stranger")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(stranger)
	if _, err := wire.ReadFrame(br, maxHandshakeIDBytes); err != nil {
		t.Fatal(err)
	}
	rawAnswerNonce(t, stranger, br)
	waitFor(t, "the accepted stranger to install", 5*time.Second, func() bool {
		tp.mu.Lock()
		defer tp.mu.Unlock()
		return len(tp.conns) == 1
	})
	if got := tp.PeerChallenges(); len(got) != 0 {
		t.Fatalf("our HELLO would be offered to an unadmitted ACCEPTED stranger: %v", got)
	}

	// The learned dial: installed gated, dialled by us. Our HELLO must go there.
	server, client := net.Pipe()
	defer client.Close()
	learned, err := tp.install(server, "203.0.113.9:6001", true, false, true, "learned")
	if err != nil {
		t.Fatal(err)
	}
	learned.localNonce = bytes.Repeat([]byte{0x11}, connectionNonceBytes)
	learned.remoteNonce = bytes.Repeat([]byte{0x22}, connectionNonceBytes)
	tp.start(learned)
	challenges := tp.PeerChallenges()
	got, ok := challenges["learned"]
	if !ok {
		t.Fatalf("our HELLO is NOT offered to a gated learned dial: the link can never bootstrap (%v)", challenges)
	}
	if !bytes.Equal(got, learned.remoteNonce) {
		t.Fatalf("the challenge offered to the learned dial is not the value the peer generated")
	}
	if _, ok := challenges["stranger"]; ok {
		t.Fatal("the unadmitted accepted stranger is in PeerChallenges")
	}
}
