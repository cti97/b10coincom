package devnet

// The M5 networking Lows PX-6, PX-7 and PX-8, each pinned on constructed state:
// a parsed-address policy table for the ranges and the relay reservation, a
// recording dial seam for the budget, and a frozen node for the advertisement.
// Nothing here waits for a real network's timing except where the assertion is
// "this socket appeared / never appeared", and then it polls an observable.

import (
	"bytes"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
	"github.com/cti97/b10coincom/internal/transport/tcp"
)

// TestAPeerHintMayNotNameTheRelayThisNodeDials is audit PX-6, end to end.
//
// The relay is configured in its v4-mapped spelling and the hint names the
// plain one: the SAME endpoint, a different literal string. The outbound
// registry is keyed by that literal string, so before the fix the hint opened a
// second maintainer, and that maintainer dialled the relay in DIRECT mode. On a
// token-gated relay every such dial is refused at the gate, so it was a
// perpetual unauthorized redial: doubled traffic on a token-less relay, a
// counter climbing forever on a gated one.
func TestAPeerHintMayNotNameTheRelayThisNodeDials(t *testing.T) {
	token := []byte("0123456789abcdef-relay-token")
	rl := relay.New(relay.Options{AccessToken: token})
	defer rl.Close()
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	raddr := rl.Addr().String() // 127.0.0.1:PORT, the spelling the hint will use
	port := netip.MustParseAddrPort(raddr).Port()
	// The same endpoint as the operator configured it: a different string.
	mapped := fmt.Sprintf("[::ffff:127.0.0.1]:%d", port)

	v, err := StartValidator(ValidatorConfig{
		Dir:                 t.TempDir(),
		Index:               0,
		Validators:          4,
		Listen:              "127.0.0.1:0",
		AllowLocalPeerHints: true,
		Relay:               []string{mapped}, // reserved AND dialled at start
		RelayAccessToken:    token,
		TickEvery:           time.Hour,
		WaveEvery:           time.Hour,
	})
	if err != nil {
		t.Fatalf("StartValidator: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	waitPeer(t, v, tcp.RelayPeerName(mapped), 5*time.Second)

	// Constructed "before": exactly one maintainer owns exactly one relay-mode
	// connection. The reservation is taken before the dial, so this is the whole
	// state the hint meets.
	if got := v.ttp.MaintainerCount(); got != 1 {
		t.Fatalf("MaintainerCount = %d, want the one relay maintainer", got)
	}
	if got := len(v.ttp.Peers()); got != 1 {
		t.Fatalf("peers = %v, want only the relay", v.ttp.Peers())
	}

	// The hint names the relay's own IP:port in its plain spelling.
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{raddr}))
	if got := v.PeerHintsRefused(); got != 1 {
		t.Fatalf("PeerHintsRefused = %d after a hint naming the relay, want 1", got)
	}
	if got := v.PeerHintsAdopted(); got != 0 {
		t.Fatalf("PeerHintsAdopted = %d, want 0: the relay is not a dial target", got)
	}
	// The deterministic half: no second maintainer exists for the hint's
	// spelling. The learned-dial path is the only way a hint can dial.
	if v.ttp.Maintains(raddr) {
		t.Fatalf("a hint opened a second maintainer for %q: that is the direct-mode connection to the relay", raddr)
	}
	if got := v.ttp.MaintainerCount(); got != 1 {
		t.Fatalf("MaintainerCount = %d after the hint, want 1", got)
	}
	// The consequence half: with no direct-mode dial, the gated relay never
	// counts an unauthorized handshake. (A refused direct dial would send its
	// ID frame where the gate expects a 32-byte MAC.)
	time.Sleep(300 * time.Millisecond)
	if got := rl.Stats().Unauthorized; got != 0 {
		t.Fatalf("the relay counted %d unauthorized handshakes; a hint must not make this node dial it directly", got)
	}
	if got := rl.Stats().Conns; got != 1 {
		t.Fatalf("the relay holds %d connections, want only the relay-mode one", got)
	}
}

// TestAZonedIPv6HintCostsOneBudgetSlot is audit PX-7's second half. A zone names
// an interface on the SENDER's machine, so two spellings of one address are one
// target; before the fix each spelling was a fresh lifetime-budget slot.
func TestAZonedIPv6HintCostsOneBudgetSlot(t *testing.T) {
	v := startFrozen(t, false)
	dials := recordPeerDial(v)

	v.observePeerExchange("v1", memberHint(t, v, 1, []string{"[2001:db8::7%25en0]:6002"}))
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{"[2001:db8::7%en1]:6002"}))
	if len(*dials) != 1 {
		t.Fatalf("two zone spellings of one address produced %d dials (%v), want exactly 1", len(*dials), *dials)
	}
	if (*dials)[0] != "[2001:db8::7]:6002" {
		t.Fatalf("dialled %q, want the zone-free canonical address", (*dials)[0])
	}
	if got := v.LearnedPeerAddrs(); got != 1 {
		t.Fatalf("LearnedPeerAddrs = %d, want 1: one target, one budget slot", got)
	}
	if got := v.PeerHintsDuplicates(); got != 1 {
		t.Fatalf("PeerHintsDuplicates = %d, want 1: the second spelling is a duplicate", got)
	}
}

// syncBuf is a log sink the test can read while the node writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestAWildcardListenerSaysOnceThatItAdvertisesNothing is audit PX-8's second
// half: a listener exists, but `0.0.0.0:PORT` names no reachable endpoint, so
// PEER_EXCHANGE sends nothing. The silence used to be total; now the operator
// hears it exactly once rather than once per (every fourth) wave.
func TestAWildcardListenerSaysOnceThatItAdvertisesNothing(t *testing.T) {
	v, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      0,
		Validators: 4,
		Listen:     "0.0.0.0:0",
		TickEvery:  time.Hour,
		WaveEvery:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	if got := v.advertisableAddr(); got != "" {
		t.Fatalf("a wildcard listener advertises %q, want nothing", got)
	}

	var buf syncBuf
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	for i := 0; i < 4; i++ {
		v.sendPeerExchange()
	}
	if got := strings.Count(buf.String(), "advertising nothing"); got != 1 {
		t.Fatalf("the advertisement warning appeared %d times after four waves, want once; log:\n%s", got, buf.String())
	}
	if got := v.PeerExchangesSent(); got != 0 {
		t.Fatalf("PeerExchangesSent = %d, want 0", got)
	}
}

// TestAnAdvertiseOverrideMakesAForwardedListenerDialable is audit PX-8's first
// half: `--listen 0.0.0.0:7001` behind a forwarded port advertises the public
// IP:port the operator gave, and a hint naming that same address is refused
// (it is this node, reached through its own router).
func TestAnAdvertiseOverrideMakesAForwardedListenerDialable(t *testing.T) {
	const advertised = "203.0.113.9:7001"
	v, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      0,
		Validators: 4,
		Listen:     "0.0.0.0:0",
		Advertise:  advertised,
		TickEvery:  time.Hour,
		WaveEvery:  time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	if got := v.advertisableAddr(); got != advertised {
		t.Fatalf("advertisableAddr = %q, want the override %q", got, advertised)
	}
	v.sendPeerExchange()
	if got := v.PeerExchangesSent(); got != 1 {
		t.Fatalf("PeerExchangesSent = %d, want 1: a forwardable listener must advertise", got)
	}
	v.observePeerExchange("v1", memberHint(t, v, 1, []string{advertised}))
	if got := v.PeerHintsRefused(); got != 1 {
		t.Fatalf("a hint naming this node's own advertised address was not refused (refused=%d)", got)
	}
}

// TestAdvertiseMustBeALiteralDialableAddress pins the construction rules: a
// wildcard or port-0 advertisement is refused at start (it would ask peers for a
// dial that cannot complete), and --advertise without a listener is refused
// because nothing would accept the dial.
func TestAdvertiseMustBeALiteralDialableAddress(t *testing.T) {
	for _, tc := range []struct {
		name      string
		listen    string
		advertise string
	}{
		{"no listener", "", "203.0.113.9:7001"},
		{"hostname", "0.0.0.0:0", "relay.example.com:7001"},
		{"wildcard", "0.0.0.0:0", "0.0.0.0:7001"},
		{"port zero", "0.0.0.0:0", "203.0.113.9:0"},
		{"multicast", "0.0.0.0:0", "224.0.0.1:7001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := StartValidator(ValidatorConfig{
				Dir:        t.TempDir(),
				Index:      0,
				Validators: 4,
				Listen:     tc.listen,
				Advertise:  tc.advertise,
				TickEvery:  time.Hour,
				WaveEvery:  time.Hour,
			})
			if v != nil {
				_ = v.Close()
			}
			if err == nil {
				t.Fatalf("StartValidator accepted advertise %q with listen %q", tc.advertise, tc.listen)
			}
		})
	}
}
