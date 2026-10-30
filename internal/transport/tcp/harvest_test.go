package tcp

// Audit PX-3's pin, BEFORE and AFTER: a registered stranger on a token-less
// relay can still make a token-configured node answer the gate (the relay
// forwards the public greeting, a challenge the stranger chose, and the public
// accepted frame into the node's handshake), but what the relay forwards onward
// must never be the token. It is an HMAC of the challenge under the token.
//
// The relay here is the real one, started WITHOUT an access token - the
// misconfiguration from the finding - so it registers every socket immediately
// and forwards every frame byte-for-byte. No fake relay is involved: the
// forwarding the test reads is the relay's own.

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
	"github.com/cti97/b10coincom/internal/wire"
)

// TestATokenlessRelayForwardsNoProofOfTheToken is the harvest, after the fix.
// The stranger registers first and drives the whole gate: greeting, a challenge
// it invents, and the accepted frame. The node, configured with a token, reads
// them (it cannot tell a forwarded frame from the relay's own - documented
// residual) and answers. The frame the stranger then receives is the answer.
//
// The assertion is deliberately absolute: the answer must NOT be the token. A
// mutant that restores the constant-greeting-then-token exchange makes the
// stranger read the token itself and fails here WITHOUT printing it.
func TestATokenlessRelayForwardsNoProofOfTheToken(t *testing.T) {
	rl := relay.New(relay.Options{MaxFrameBytes: 4096, MaxConns: 16, MaxConnsPerIP: 16, WriteQueueBytes: 1 << 16})
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer rl.Close()

	// The stranger: a raw registered connection. A token-less relay admits it
	// immediately (that is the finding's premise).
	stranger, err := net.Dial("tcp", rl.Addr().String())
	if err != nil {
		t.Fatalf("stranger dial: %v", err)
	}
	defer stranger.Close()
	deadline := time.Now().Add(5 * time.Second)
	for rl.Stats().Conns != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := rl.Stats().Conns; got != 1 {
		t.Fatalf("the token-less relay registered %d connections, want 1 (the stranger)", got)
	}

	// A challenge the STRANGER invents: the node cannot tell it from the
	// relay's own, which is the point of the residual.
	challenge := make([]byte, wire.RelayGateNonceBytes, wire.MaxRelayGateChallengeBytes)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatal(err)
	}
	challenge = append(challenge, []byte("relay.example:7001")...)

	harvested := make(chan []byte, 1)
	go func() {
		// The relay forwards only to connections registered AT FORWARDING TIME
		// (message-bus semantics), so the stranger must wait for the node's relay
		// socket to register before it writes - otherwise its frames go to
		// nobody. Conns is that observable: the token-less relay registers the
		// node's socket immediately, before the node's gate read.
		reg := time.Now().Add(10 * time.Second)
		for rl.Stats().Conns < 2 && time.Now().Before(reg) {
			time.Sleep(5 * time.Millisecond)
		}
		// greeting, challenge, accepted - all forwarded by the relay into the
		// node's gate handshake, all three indistinguishable from the relay's.
		_ = wire.WriteFrame(stranger, wire.RelayGateGreeting)
		_ = wire.WriteFrame(stranger, challenge)
		_ = wire.WriteFrame(stranger, wire.RelayGateAccepted)
		_ = stranger.SetReadDeadline(time.Now().Add(10 * time.Second))
		frame, err := wire.ReadFrame(stranger, 1<<16)
		if err != nil {
			harvested <- nil
			return
		}
		harvested <- frame
	}()

	token := []byte("sixteen-byte-tok")
	tp := listen(t, Options{
		LocalID: "v0", RelayAccessToken: token,
		HandshakeTimeout: 3 * time.Second,
		BackoffBase:      time.Hour, BackoffMax: time.Hour, // exactly one dial
	})
	if err := tp.AddRelay(rl.Addr().String()); err != nil {
		t.Fatalf("AddRelay: %v", err)
	}

	var frame []byte
	select {
	case frame = <-harvested:
	case <-time.After(15 * time.Second):
		t.Fatal("the stranger never received the node's gate answer")
	}
	if frame == nil {
		t.Fatal("the stranger's read failed: the node sent nothing, so the harvest could not be measured")
	}
	if bytes.Equal(frame, token) {
		t.Fatal("a stranger on a token-less relay harvested the relay access token ITSELF: the gate sent the secret and the relay forwarded it (audit PX-3)")
	}
	if !bytes.Equal(frame, wire.RelayGateProof(token, challenge)) {
		t.Fatalf("the forwarded answer is not the challenge's HMAC (%d bytes); the gate is not the challenge-response it claims", len(frame))
	}
	// And it is a fixed-width answer, not the token with anything around it.
	if len(frame) != wire.RelayGateMACBytes {
		t.Fatalf("the forwarded answer is %d bytes, want the fixed %d-byte MAC", len(frame), wire.RelayGateMACBytes)
	}
}

// TestAGateProofIsNotReplayableOnAnotherConnection is the nonce's half of PX-3:
// even a REAL relay's answer, and even the token holder's own answer, is bound
// to the challenge of the connection it was computed for. A second connection
// that presents the first connection's proof is refused, counted unauthorized,
// and never registered.
func TestAGateProofIsNotReplayableOnAnotherConnection(t *testing.T) {
	token := []byte("a-shared-sixteen-byte-token")
	rl := relay.New(relay.Options{MaxFrameBytes: 4096, MaxConns: 8, MaxConnsPerIP: 8, WriteQueueBytes: 1 << 16, AccessToken: token})
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer rl.Close()

	// Connection one: a legitimate holder completes the gate and keeps its
	// proof, exactly as the relay forwarded it (an on-path observer, or the
	// relay itself, has these bytes).
	first, err := net.Dial("tcp", rl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	greeting, err := wire.ReadFrame(first, 1<<16)
	if err != nil || !bytes.Equal(greeting, wire.RelayGateGreeting) {
		t.Fatalf("first connection greeting: %q, %v", greeting, err)
	}
	challengeOne, err := wire.ReadFrame(first, wire.MaxRelayGateChallengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	proofOne := wire.RelayGateProof(token, challengeOne)
	if err := wire.WriteFrame(first, proofOne); err != nil {
		t.Fatal(err)
	}
	if got, err := wire.ReadFrame(first, 1<<16); err != nil || !bytes.Equal(got, wire.RelayGateAccepted) {
		t.Fatalf("first connection accepted frame: %q, %v", got, err)
	}

	// Connection two: read its own (different) challenge, then present the
	// FIRST connection's proof. The nonce makes it wrong here.
	second, err := net.Dial("tcp", rl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := wire.ReadFrame(second, 1<<16); err != nil {
		t.Fatal(err)
	}
	challengeTwo, err := wire.ReadFrame(second, wire.MaxRelayGateChallengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(challengeOne, challengeTwo) {
		t.Fatal("two connections received the same gate challenge: the nonce is not fresh")
	}
	if err := wire.WriteFrame(second, proofOne); err != nil {
		t.Fatal(err)
	}
	waitClosedConn(t, second, "a replayed gate proof")
	deadline := time.Now().Add(5 * time.Second)
	for rl.Stats().Unauthorized < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := rl.Stats().Unauthorized; got < 1 {
		t.Fatalf("Unauthorized = %d after a replayed proof, want at least 1", got)
	}
	if got := rl.Stats().Conns; got != 1 {
		t.Fatalf("the replayed proof registered a connection: Conns = %d, want the one legitimate holder", got)
	}
}
