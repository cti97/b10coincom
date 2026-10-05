package devnet

// The relay-stranger proof (audit round 7, F1). The reviewer's attack: a
// stranger dials the relay, sees every BLOCK_SYNC request in the clear (the
// nonce is not secret), and returns an empty answer. On the relay every member
// and every stranger share ONE transport name (relay:<addr>), so pre-fix the
// sender check was vacuous, the forged empty answer was accepted, the pull read
// "caught up", and maybeCatchUp demoted the shared relay name - which skipped
// every honest member behind that relay for the next waves. Repeated each
// cycle, the validator never rejoined.
//
// This test runs the real topology: honest validators and a late joiner dial
// one real relay; a stranger dials the SAME relay and forges an empty answer to
// every request it sees. Post-fix the forged answer is refused (no committee
// signature), the honest member's signed answer is accepted, and the late
// joiner converges by ADOPTING blocks. The relay still parses nothing: the
// signatures ride inside the opaque frames it forwards.

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
	"github.com/cti97/b10coincom/internal/wire"
)

// startRelayStranger dials the relay as a stranger and answers every
// BLOCK_SYNC request it sees with an empty, unsigned envelope that echoes the
// request's nonce - exactly the reviewer's forgery, buildable by anyone who
// can read the forwarded bytes. It returns the live connection and a counter
// of forged answers sent.
func startRelayStranger(t *testing.T, raddr string) (net.Conn, *atomic.Uint64) {
	t.Helper()
	conn, err := net.Dial("tcp", raddr)
	if err != nil {
		t.Fatalf("the stranger could not dial the relay: %v", err)
	}
	forged := &atomic.Uint64{}
	go func() {
		for {
			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return
			}
			payload, err := wire.ReadFrame(conn, relay.DefaultMaxFrameBytes)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue // idle between requests: keep watching
				}
				return // the relay or this test closed the socket
			}
			req, err := wire.DecodeBlockSyncReq(payload)
			if err != nil {
				continue // not a request: the relay forwards everything
			}
			// The forgery: the right nonce, no responder key, no signature.
			forged.Add(1)
			_ = wire.WriteFrame(conn, wire.EncodeBlockSyncResp(&wire.BlockSyncResp{Nonce: req.Nonce}))
		}
	}()
	return conn, forged
}

// TestAStrangerOnTheRelayCannotStallTheLateJoiner is the end-to-end F1 proof.
// A stranger forges an empty answer to every catch-up request on the relay; the
// late joiner must still converge by adoption.
func TestAStrangerOnTheRelayCannotStallTheLateJoiner(t *testing.T) {
	rl := relay.New(relay.Options{MaxConnsPerIP: 16})
	defer rl.Close()
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	raddr := rl.Addr().String()

	// The stranger is registered BEFORE any validator speaks, so it sees every
	// request the relay forwards from the first wave on.
	stranger, forged := startRelayStranger(t, raddr)
	defer stranger.Close()

	vs := make([]*Validator, 4)
	for i := 0; i < 3; i++ {
		v, err := StartValidator(ValidatorConfig{Dir: t.TempDir(), Index: i, Validators: 4})
		if err != nil {
			t.Fatal(err)
		}
		vs[i] = v
		if err := v.ConnectRelay(raddr); err != nil {
			t.Fatal(err)
		}
	}
	defer closeAll(vs)
	waitAllReach(t, vs[:3], 4, 120*time.Second)

	late, err := StartValidator(ValidatorConfig{Dir: t.TempDir(), Index: 3, Validators: 4})
	if err != nil {
		t.Fatal(err)
	}
	vs[3] = late
	if err := late.ConnectRelay(raddr); err != nil {
		t.Fatal(err)
	}

	// The late joiner must adopt its way up despite the forgery on the wire.
	h := waitConvergedEqual(t, vs, 6, 150*time.Second)
	waitAdopted(t, late, 1, 10*time.Second)
	if forged.Load() == 0 {
		t.Fatal("the stranger never forged an answer: the attack this test names did not run")
	}
	// And it is a member again, not a spectator: the committee keeps
	// committing and the returned member votes at the current height.
	waitAllReach(t, vs, h+6, 150*time.Second)
	assertIdenticalHistory(t, vs, h+6)
	assertVotesAtOrAbove(t, late, uint64(h), 150*time.Second)
}
