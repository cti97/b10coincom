package relay

import (
	"bytes"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/wire"
)

// syncBuffer is a log sink safe for the writes made by the gate's handshake
// goroutines, which run concurrently with the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// gateRefusalDrain dials the relay, consumes the two gate frames it is owed,
// sends payload (nil sends nothing), and then reads until the relay closes the
// socket. Draining first is what keeps the exchange deterministic: closing a
// socket with unread received bytes can turn the FIN into an RST, which would
// discard the frame under test and log a socket error instead of a refusal.
func gateRefusalDrain(t *testing.T, addr string, payload []byte) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialling the relay: %v", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting the socket deadline: %v", err)
	}
	if payload != nil {
		// The relay writes greeting then challenge before it reads; a refusal
		// is only measured after both are on the wire, so consume them rather
		// than racing the write.
		for i := 0; i < 2; i++ {
			if _, err := wire.ReadFrame(c, wire.MaxRelayGateChallengeBytes); err != nil {
				t.Fatalf("reading gate frame %d: %v", i+1, err)
			}
		}
		if err := wire.WriteFrame(c, payload); err != nil {
			t.Fatalf("writing the refused frame: %v", err)
		}
	}
	var scratch [256]byte
	for {
		if _, err := c.Read(scratch[:]); err != nil {
			return // closed by the relay: the refusal is complete
		}
	}
}

// TestTheGateRefusalNamesItsReasonAndCannotFloodTheLog pins the one line the
// 2026-11-14 outage needed (docs/bug-2026-11-14-relay-gate.md). The gate counted
// `unauthorized` and said nothing, so every counter reading was compatible with
// every hypothesis and eight diagnoses were wrong before the right one.
//
// Two properties, both required together:
//
//   - the line names the REASON, including the shape that actually occurred: a
//     2-byte first frame is a node's transport ID, and that means the dialer
//     has no access token configured;
//   - the line is RATE-LIMITED. The refusal path is reachable by anyone who can
//     open a socket, so a per-refusal line would let a stranger write the
//     operator's log at will. A burst is folded into one line plus a suppressed
//     count.
func TestTheGateRefusalNamesItsReasonAndCannotFloodTheLog(t *testing.T) {
	buf := &syncBuffer{}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	rl := New(Options{
		AccessToken:   []byte("0123456789abcdef"),
		AccessTimeout: 150 * time.Millisecond,
	})
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer rl.Close()
	addr := rl.Addr().String()
	waitUnauthorized := func(want uint64, what string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if rl.Stats().Unauthorized >= want {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		t.Fatalf("the relay counted %d unauthorized, want %d (%s)", rl.Stats().Unauthorized, want, what)
	}

	// 1. A dialer that says nothing: after --access-timeout the gate refuses it
	//    and the line must say that, not "a frame was wrong".
	gateRefusalDrain(t, addr, nil)
	waitUnauthorized(1, "a silent dial")
	if s := buf.String(); !strings.Contains(s, "gate refused") || !strings.Contains(s, "--access-timeout") {
		t.Fatalf("the refusal of a silent dial is not named in the log:\n%s", s)
	}

	// Let the rate-limit window pass so the burst below starts a fresh line.
	time.Sleep(gateRefusalLogInterval + 100*time.Millisecond)

	// 2. The outage's shape: 40 dialers that announce a 2-byte transport ID
	//    where the 32-byte proof belongs. All 40 are refusals; the log must say
	//    why, and must NOT grow by 40 lines.
	const burst = 40
	for i := 0; i < burst; i++ {
		gateRefusalDrain(t, addr, []byte("v0"))
	}
	waitUnauthorized(1+burst, "the burst of identity frames")
	logged := buf.String()
	if !strings.Contains(logged, "transport ID") || !strings.Contains(logged, "NO access token") {
		t.Fatalf("the refusal of a 2-byte opening frame does not name the cause (a transport ID, so no access token on the dialer):\n%s", logged)
	}
	if got := strings.Count(logged, "gate refused"); got >= burst {
		t.Fatalf("the relay wrote %d refusal lines for %d refusals: the line is not rate-limited and a stranger can flood the log with it", got, burst)
	}
	if got := strings.Count(logged, "gate refused"); got > 3 {
		t.Fatalf("the relay wrote %d refusal lines for %d refusals; want the burst folded into at most a line or two", got, burst)
	}

	// 3. A right-sized MAC that does not compare is a different cause, and the
	//    line must distinguish it - after the suppression count has been folded
	//    into a later line, so the operator still sees the volume.
	time.Sleep(gateRefusalLogInterval + 100*time.Millisecond)
	gateRefusalDrain(t, addr, make([]byte, wire.RelayGateMACBytes))
	waitUnauthorized(2+burst, "a wrong-width-matching MAC")
	if s := buf.String(); !strings.Contains(s, "did not match this connection's challenge") {
		t.Fatalf("a 32-byte wrong proof is not distinguished from a short frame:\n%s", s)
	}
	if s := buf.String(); !strings.Contains(s, "more since the last line") {
		t.Fatalf("the suppressed refusals were dropped instead of counted; a burst must not make the log quieter than the truth:\n%s", s)
	}
}
