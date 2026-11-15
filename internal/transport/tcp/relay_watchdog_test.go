package tcp

// The tests in this file pin the RELAY-LINK SILENCE WATCHDOG: the node-side
// answer to a relay link that stays open at the socket layer while delivering
// nothing at the application layer.
//
// Why this is a distinct failure class from the idle read deadline. The relay
// answers TCP keepalive probes in the KERNEL, so a relay that holds the socket
// but stops forwarding (its writer parked, its send queue full toward this
// node) never fails the connection and never makes the kernel keepalive fire.
// The node cannot tell it apart from an idle link by anything the socket says.
// The generic IdleReadTimeout eventually closes a silent socket, but it does so
// silently and only after two minutes - long enough for the whole committee to
// sit at one height at 10-15 blocks/s with nothing in the log saying which link
// went quiet or for how long. The watchdog keeps a per-link last-frame age,
// and if a link that has PROVEN it can deliver (at least one frame) then goes
// silent past DefaultRelaySilenceTimeout, it logs the address and the measured
// silence and closes the link so the maintainer dials a fresh one.
//
// The relay fake below is a raw listener, not internal/relay: the point of
// these tests is the NODE's behaviour, and a raw sink can be told to accept and
// then stop reading/writing in exactly the shape the incident had. relay.go's
// own tests remain the relay's contract.

import (
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

// relaySink is a deliberately dumb stand-in for a relay: it accepts every
// dial, hands each connection to handle with its accept ordinal, and owns the
// sockets so a failing test cannot leak them into the next one.
type relaySink struct {
	ln       net.Listener
	handle   func(n int, nc net.Conn, done <-chan struct{})
	accepted atomic.Int64
	done     chan struct{}
	mu       sync.Mutex
	conns    []net.Conn
}

func newRelaySink(t *testing.T, handle func(n int, nc net.Conn, done <-chan struct{})) *relaySink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the fake relay: %v", err)
	}
	s := &relaySink{ln: ln, handle: handle, done: make(chan struct{})}
	go s.accept()
	t.Cleanup(func() {
		close(s.done)
		_ = s.ln.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, nc := range s.conns {
			_ = nc.Close()
		}
	})
	return s
}

func (s *relaySink) addr() string { return s.ln.Addr().String() }

func (s *relaySink) accept() {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		n := int(s.accepted.Add(1))
		s.mu.Lock()
		s.conns = append(s.conns, nc)
		s.mu.Unlock()
		go s.handle(n, nc, s.done)
	}
}

// relayLinkConfig is the transport configuration every test here shares: the
// generic idle deadline and the write deadline are pushed far out so that the
// watchdog is the only thing that can end the link, and the backoff curve is
// short so a redial lands inside the test.
func relayLinkConfig(silence time.Duration) Options {
	return Options{
		LocalID:             "v0",
		IdleReadTimeout:     time.Hour,
		WriteTimeout:        10 * time.Second,
		RelaySilenceTimeout: silence,
		BackoffBase:         5 * time.Millisecond,
		BackoffMax:          10 * time.Millisecond,
	}
}

func relayLinkIsUp(tp *TcpTransport, name transport.PeerID) bool {
	for _, p := range tp.Peers() {
		if p == name {
			return true
		}
	}
	return false
}

// measuredSilence extracts the duration the watchdog reports for the link.
var measuredSilence = regexp.MustCompile(`no frame received for ([0-9]+(?:\.[0-9]+)?(?:ms|s))`)

func hasPayload(rec *recorder, want string) bool {
	for _, p := range rec.payloads() {
		if p == want {
			return true
		}
	}
	return false
}

// TestARelayLinkThatFallsSilentIsTornDownLoggedAndRedialled is the incident
// reproduced on loopback. The fake relay accepts the node's relay dial, sends
// ONE frame (proving the link can deliver), then stops reading and writing -
// the socket stays open, the node's writes fill the kernel buffer, and the
// node's receive path hears nothing more. Every symptom in the incident
// follows from that shape: the socket is open, `ss` would show bytes queued
// toward the peer, HELLOs no longer arrive, and consensus stops while the
// process looks healthy.
//
// The contract asserted is the whole fix, not a proxy:
//   - the watchdog notices the silence inside the bound;
//   - it LOGS, naming the link's address and the measured silence;
//   - the link is torn down and the maintainer re-establishes it;
//   - traffic resumes on the fresh socket (the relay sends on it and the node
//     dispatches it), so the recovery is real rather than a dead registration.
func TestARelayLinkThatFallsSilentIsTornDownLoggedAndRedialled(t *testing.T) {
	logs := captureLog(t)
	const silence = 160 * time.Millisecond
	const proof = "proof-of-life"
	const resumed = "traffic-resumed"

	sink := newRelaySink(t, func(n int, nc net.Conn, done <-chan struct{}) {
		if n == 1 {
			// The one frame that proves the link can deliver. Then the wedge:
			// DO NOT read, DO NOT write, and - crucially - DO NOT close. The
			// socket must stay open, or the kernel would report EOF and the
			// reader would recover without the watchdog.
			_ = wire.WriteFrame(nc, []byte(proof))
			return
		}
		// Every later link is healthy: it reads what the node writes and keeps
		// sending, so the recovered link must not be torn down again.
		go func() {
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if err := wire.WriteFrame(nc, []byte(resumed)); err != nil {
						return
					}
				}
			}
		}()
		_, _ = io.Copy(io.Discard, nc)
	})

	tp, err := New(relayLinkConfig(silence))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	rec := &recorder{}
	tp.OnMessage(rec.collect)

	name := RelayPeerName(sink.addr())
	if err := tp.AddRelay(sink.addr()); err != nil {
		t.Fatalf("AddRelay: %v", err)
	}
	waitFor(t, "the relay link to be installed", 5*time.Second, func() bool {
		return relayLinkIsUp(tp, name)
	})
	waitFor(t, "the proof-of-life frame to be dispatched", 5*time.Second, func() bool {
		return hasPayload(rec, proof)
	})

	// Fill the writer: the wedge must be the ordinary one - bytes the node is
	// trying to send on a socket the far end has stopped reading - not a link
	// the node has simply left alone.
	filler := []byte(strings.Repeat("x", 4096))
	go func() {
		for {
			if err := tp.Send(name, filler); err != nil {
				return // the watchdog closed the link (or the queue filled)
			}
		}
	}()

	waitFor(t, "the relay-silence line naming the link and its measured silence", 3*time.Second, func() bool {
		line := logs.String()
		return strings.Contains(line, sink.addr()) && strings.Contains(line, "no frame received")
	})
	line := logs.String()
	if !strings.Contains(line, silence.String()) {
		t.Fatalf("the silence line does not carry the bound %s that was chosen (the log must state why the link was judged wedged):\n%s", silence, line)
	}
	if !strings.Contains(line, "presumed wedged") {
		t.Fatalf("the silence line does not say the link was presumed wedged:\n%s", line)
	}
	// The MEASURED silence, not just the bound: the operator's question is
	// "how long was it quiet", and the answer must be in the line.
	m := measuredSilence.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("the silence line does not carry the measured silence (want \"no frame received for <duration>\"):\n%s", line)
	}
	measured, err := time.ParseDuration(m[1])
	if err != nil {
		t.Fatalf("the measured silence %q is not a duration: %v", m[1], err)
	}
	if measured < silence {
		t.Fatalf("the line reports a measured silence of %v, below the bound %v it fired on:\n%s", measured, silence, line)
	}

	waitFor(t, "a redial after the watchdog teardown", 5*time.Second, func() bool {
		return sink.accepted.Load() >= 2
	})
	waitFor(t, "traffic resuming on the fresh link", 5*time.Second, func() bool {
		return hasPayload(rec, resumed)
	})

	// And it must stay recovered: the second link keeps delivering, so no
	// further silence line may appear.
	time.Sleep(3 * silence)
	if n := strings.Count(logs.String(), "presumed wedged"); n != 1 {
		t.Fatalf("the watchdog fired %d times, want exactly 1: a link that recovered must not be torn down again:\n%s", n, logs.String())
	}
	if got := sink.accepted.Load(); got != 2 {
		t.Fatalf("the fake relay accepted %d connections, want 2 (the wedged one and the redial)", got)
	}
}

// TestARelayLinkWithSteadyTrafficIsNotTornDown is the no-false-positive half
// the incident's speed makes tempting to skip: a link that delivers a frame
// every 20 ms against a 120 ms bound must survive many bounds' worth of time
// without a teardown or a line. A watchdog that measured "time since a
// CONSENSUS frame" or that fired on a slow round would fail here.
func TestARelayLinkWithSteadyTrafficIsNotTornDown(t *testing.T) {
	logs := captureLog(t)
	const silence = 120 * time.Millisecond

	sink := newRelaySink(t, func(n int, nc net.Conn, done <-chan struct{}) {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := wire.WriteFrame(nc, []byte("heartbeat")); err != nil {
					return
				}
			}
		}
	})

	tp, err := New(relayLinkConfig(silence))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	rec := &recorder{}
	tp.OnMessage(rec.collect)

	name := RelayPeerName(sink.addr())
	if err := tp.AddRelay(sink.addr()); err != nil {
		t.Fatalf("AddRelay: %v", err)
	}
	waitFor(t, "the relay link to be installed", 5*time.Second, func() bool {
		return relayLinkIsUp(tp, name)
	})
	waitFor(t, "the first heartbeat", 5*time.Second, func() bool {
		return hasPayload(rec, "heartbeat")
	})

	deadline := time.Now().Add(6 * silence)
	for time.Now().Before(deadline) {
		if got := sink.accepted.Load(); got != 1 {
			t.Fatalf("a link with steady traffic was torn down and redialled (%d accepts, want 1):\n%s", got, logs.String())
		}
		if !relayLinkIsUp(tp, name) {
			t.Fatalf("a link with steady traffic disappeared from Peers():\n%s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(logs.String(), "presumed wedged") {
		t.Fatalf("a link with steady traffic was judged wedged:\n%s", logs.String())
	}
}

// TestAQuietRelayLinkIsNotPresumedWedged pins the documented handling of a
// quiet-but-live link: a relay link that has NEVER delivered a frame is not
// evidence of a wedge. This is the lone-validator shape - the relay has no
// other member behind it, so it forwards nobody's HELLOs - and it is also the
// shape just after install, before the first frame arrives. Churning such a
// link every bound would be the false positive the incident's own numbers
// rule out (a quiet chain is not a wedged one), and the generic
// IdleReadTimeout remains its (much slower, silent) backstop.
func TestAQuietRelayLinkIsNotPresumedWedged(t *testing.T) {
	logs := captureLog(t)
	const silence = 120 * time.Millisecond

	sink := newRelaySink(t, func(n int, nc net.Conn, done <-chan struct{}) {
		// Live and reading, but it has nobody to forward: it sends nothing.
		_, _ = io.Copy(io.Discard, nc)
	})

	tp, err := New(relayLinkConfig(silence))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	name := RelayPeerName(sink.addr())
	if err := tp.AddRelay(sink.addr()); err != nil {
		t.Fatalf("AddRelay: %v", err)
	}
	waitFor(t, "the relay link to be installed", 5*time.Second, func() bool {
		return relayLinkIsUp(tp, name)
	})
	// The node keeps talking to it; the link is alive in the outbound
	// direction and the socket accepts the writes.
	for i := 0; i < 8; i++ {
		if err := tp.Send(name, []byte("outbound")); err != nil {
			t.Fatalf("Send on a live quiet link: %v", err)
		}
	}

	time.Sleep(6 * silence)
	if got := sink.accepted.Load(); got != 1 {
		t.Fatalf("a quiet-but-live link was torn down and redialled (%d accepts, want 1):\n%s", got, logs.String())
	}
	if !relayLinkIsUp(tp, name) {
		t.Fatalf("a quiet-but-live link disappeared from Peers():\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "presumed wedged") {
		t.Fatalf("a link that never delivered a frame was judged wedged (it may simply have nobody behind it):\n%s", logs.String())
	}
}

// TestRelaySilenceBoundIsFourKeepalivePeriods pins the derivation the brief
// asks for: the node's bound is a multiplier of the RELAY's own keepalive, not
// an independent number that can drift when the relay's default changes. The
// import of internal/relay is deliberate here (and already used elsewhere in
// this package's tests): it is the one place the two constants are compared.
func TestRelaySilenceBoundIsFourKeepalivePeriods(t *testing.T) {
	if got, want := DefaultRelaySilenceTimeout, 4*relay.DefaultKeepAlive; got != want {
		t.Fatalf("DefaultRelaySilenceTimeout = %v, want 4 x relay.DefaultKeepAlive = %v (the node's silence bound must stay derived from the relay's keepalive)", got, want)
	}
	if got := (Options{LocalID: "v0"}).withDefaults().RelaySilenceTimeout; got != DefaultRelaySilenceTimeout {
		t.Fatalf("a zero RelaySilenceTimeout resolved to %v, want the default %v", got, DefaultRelaySilenceTimeout)
	}
	// The bound must stay strictly inside the generic idle deadline, or the
	// silent generic teardown would win and the diagnosis would never print.
	if DefaultRelaySilenceTimeout >= DefaultIdleReadTimeout {
		t.Fatalf("the relay silence bound %v is not inside the idle read deadline %v: the generic silent teardown would fire first", DefaultRelaySilenceTimeout, DefaultIdleReadTimeout)
	}
}
