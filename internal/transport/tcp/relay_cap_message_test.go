package tcp

// Testrun N-2: the relay applies its connection caps AT ACCEPT, before any
// access-token greeting, and closes the socket. A token-configured node then
// sees only EOF while it waits for the greeting, and its log line used to blame
// the token - which sent the operator of a Docker-bridge or NAT deployment to
// the wrong problem, because the real cause was --max-conns-per-ip (a per
// PREFIX cap, 8 by default, shared by everyone behind one IPv4 /24).
//
// The state is CONSTRUCTED: a listener that accepts and closes immediately is
// exactly what the relay's accept-time refusal looks like to the node - no
// timing, no load, no race.

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
)

func TestARelayRefusedAtAcceptIsNotBlamedOnTheToken(t *testing.T) {
	// The relay's refusal, minus the relay: accept, close, no byte written.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	buf := captureLog(t)
	token := []byte("0123456789abcdef0123456789abcdef")
	tp := listen(t, Options{
		LocalID: "v0", RelayAccessToken: token,
		BackoffBase: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond,
	})
	tp.OnMessage(func(transport.Message) {})
	if err := tp.AddRelay(ln.Addr().String()); err != nil {
		t.Fatalf("AddRelay: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "--max-conns-per-ip") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	logged := buf.String()
	if logged == "" {
		t.Fatal("a relay that closes at accept produced no log line at all")
	}
	// What the operator must be told: the cap, the prefix grouping, the shared
	// budget, the counter that distinguishes the two causes, and the flag to
	// change (never the token).
	for _, want := range []string{
		"--max-conns-per-ip",
		"per-source-PREFIX cap is 8",
		"/24",                        // the grouping that catches a NAT/bridge/LAN
		"--max-conns",                // the other accept-time cap
		"refused-connection counter", // how to tell the two causes apart
		"instead of changing the token",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("the node's relay-refusal line does not mention %q:\n%s", want, logged)
		}
	}
	// The token cause must still be named: a relay with no gate produces the
	// same EOF, and dropping that sentence would send the next operator to the
	// other wrong problem.
	if !strings.Contains(logged, "did not announce the access-token gate") {
		t.Errorf("the line no longer names the token-less-relay cause:\n%s", logged)
	}
}
