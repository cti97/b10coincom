package devnet

// Audit PX-2, BEFORE and AFTER, on the exact shape the finding names: a member
// HELLO captured off a connection is replayed on a HINT-DIALLED socket, and the
// pre-fix admission accepted it because the signature was valid and the frame
// had no connection binding.
//
// The captured frame is the one a relay exposes to every registered stranger: a
// genuine member HELLO signed with the seat's key over the chain id and the
// member's height, with the EMPTY nonce a relay connection carries (one socket
// serves every member, so there is no peer challenge to bind). That frame is
// byte-for-byte a valid HELLO under the old rules.
//
// After the fix the hint-dialled connection is GATED and the frame is not even
// offered to the signature check: its nonce is empty, the connection's challenge
// is 32 fresh bytes, and admission refuses on the equality. The node records no
// height, so `via` cannot move and the stranger is not a sync pull target. The
// second half sends a HELLO bound to THIS connection's nonce to prove the gate
// is not merely refusing everything.

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/transport/tcp"
	"github.com/cti97/b10coincom/internal/wire"
)

// mustLocalNonce reads the challenge this node generated for a live connection.
// A connection is only visible (Peers, ConnNonces) once its handshake is done,
// so this cannot race the exchange.
func mustLocalNonce(t *testing.T, v *Validator, peer transport.PeerID) []byte {
	t.Helper()
	ours, _, ok := v.ttp.ConnNonces(peer)
	if !ok {
		t.Fatalf("no connection is registered under %q", peer)
	}
	return ours
}

func TestACapturedMemberHelloDoesNotAdmitAHintDialledStranger(t *testing.T) {
	v := startFrozen(t, true)

	// The captured frame: seat 1's signed HELLO as a relay stranger sees it.
	priv := simnet.ValidatorKey(1)
	captured := &wire.Hello{
		ChainID:   v.g.ChainID,
		Validator: priv.Public().(ed25519.PublicKey),
		Height:    v.Height(),
		Nonce:     nil,
	}
	hh := helloHash(captured)
	captured.Sig = crypto.Sign(priv, hh[:])
	frame := wire.EncodeHello(captured)

	// The stranger that will receive the replay. It is a real transport, so it
	// speaks the ID and nonce handshakes exactly as a hostile node would.
	stranger, err := tcp.New(tcp.Options{LocalID: "stranger"})
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	if err := stranger.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}

	// A member advertises the stranger's address: v dials it as a LEARNED peer.
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{stranger.Addr().String()}))
	waitFor(t, "the learned dial to complete at the stranger", 5*time.Second, func() bool {
		return len(stranger.Peers()) == 1
	})

	// THE replay: a perfectly signed member HELLO, on the wrong connection.
	if err := stranger.Send("v0", frame); err != nil {
		t.Fatalf("the stranger could not send its captured HELLO: %v", err)
	}
	// Wait for the replay to be CLASSIFIED - gated here, or (pre-fix) admitted.
	// Asserting the gated counter alone would make the before/after unreadable
	// (a pre-fix run simply never gates), so the wait is on either outcome and
	// the assertions below say which one must hold.
	waitFor(t, "the replayed HELLO to be classified (gated, or admitted)", 5*time.Second, func() bool {
		return v.ttp.GatedFrames() >= 1 || hasPeer(v, "stranger")
	})
	if who, via, _ := v.tallestPeer(); who != "" {
		t.Fatalf("the replayed member HELLO was accepted: the sync pull target is now %x via %q - a valid signature signed for ANOTHER connection moved `via` (audit PX-2)", []byte(who), via)
	}
	if hasPeer(v, "stranger") {
		t.Fatal("a replayed member HELLO admitted a hint-dialled stranger: the connection was not bound to its nonce (audit PX-2)")
	}

	// The node SENDS its own HELLO to a gated socket it dialled (the peer needs
	// it to admit us), so a hostile peer can echo it straight back: a valid
	// signature, the right connection nonce, and no proof of anything. It must
	// not admit either.
	echo := &wire.Hello{
		ChainID:   v.g.ChainID,
		Validator: v.pub,
		Height:    v.Height(),
		Nonce:     mustLocalNonce(t, v, "stranger"),
	}
	eh := helloHash(echo)
	echo.Sig = crypto.Sign(v.priv, eh[:])
	gatedBefore := v.ttp.GatedFrames()
	if err := stranger.Send("v0", wire.EncodeHello(echo)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the echoed self-HELLO to be gated", 5*time.Second, func() bool {
		return v.ttp.GatedFrames() > gatedBefore
	})
	if hasPeer(v, "stranger") {
		t.Fatal("this node's OWN HELLO, echoed by the stranger, admitted it: our own signature is not a peer's proof (audit PX-2)")
	}
	if who, via, _ := v.tallestPeer(); who != "" {
		t.Fatalf("the echoed self-HELLO moved the sync pull target: %x via %q", []byte(who), via)
	}

	// NOT REFUSE-EVERYTHING: a HELLO bound to THIS connection's challenge is
	// admitted and becomes the pull target. The stranger cannot produce one -
	// it has no committee key - but the transport hands the test the value so
	// the positive half is pinned rather than assumed.
	ours := mustLocalNonce(t, v, "stranger")
	bound := &wire.Hello{
		ChainID:   v.g.ChainID,
		Validator: priv.Public().(ed25519.PublicKey),
		Height:    v.Height(),
		Nonce:     ours,
	}
	bh := helloHash(bound)
	bound.Sig = crypto.Sign(priv, bh[:])
	if err := stranger.Send("v0", wire.EncodeHello(bound)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the connection-bound HELLO to admit the learned peer", 5*time.Second, func() bool {
		return hasPeer(v, "stranger")
	})
	if who, via, _ := v.tallestPeer(); who != string(priv.Public().(ed25519.PublicKey)) || via != "stranger" {
		t.Fatalf("the bound HELLO did not become the pull target: who=%q via=%q", who, via)
	}
}
