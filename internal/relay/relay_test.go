// Tests for the relay. Every one of them runs over a real TCP socket on
// 127.0.0.1:0 - the socket path IS the deliverable, because the relay exists
// so that a home Raspberry Pi can reach a public VPS, and a pipe proves
// nothing about sockets.
//
// The properties, in the order the tests pin them:
//
//   - it forwards, both ways, between peers (TestRelayForwardsBetweenTwoPeers);
//   - it never feeds a sender its own frame back (TestRelayDoesNotForwardToTheSender;
//     a validator that receives its own vote again would double-count the one
//     vote per validator the tally relies on);
//   - a peer vanishing mid-frame costs nothing but that peer
//     (TestRelaySurvivesAPeerDisappearing) - no crash, no leaked goroutine,
//     no registry ghost;
//   - it forwards bytes it cannot parse, unchanged
//     (TestRelayForwardsFramesItCannotParse) - the property that keeps the
//     relay dumb, and without this test it would be only a comment;
//   - a peer that stops reading does not stall the relay for everyone else
//     (TestRelayASlowPeerDoesNotStallTheOtherPeers) - the same slow-reader
//     property the transport needed, held at the one hop a stranger owns;
//     and with the write queue actually at its BOUND, forwarding drops
//     instead of blocking (TestRelayAQueueBoundDropsInsteadOfBlocking) - the
//     small-queue variant, because a queue that never fills tests nothing;
//   - a stranger's dials that send only a header and then stall do not hold
//     resources forever: the per-frame read deadline ends them and both the
//     slots and the memory come back (TestRelayStalledHeadersDoNotPinMemoryOrSlots);
//   - accepted connections carry TCP keepalive
//     (TestRelaySetsTCPKeepaliveOnAcceptedConnections), so a half-open
//     connection is reaped by the socket;
//   - a hostile frame length is refused, not allocated and not forwarded
//     (TestRelayRefusesAHostileFrameLength);
//   - connections are bounded (TestRelayRefusesConnectionsBeyondItsBound);
//   - a repeated identical frame is forwarded TWICE - dedup is the receivers'
//     business, spec §6.6 (TestRelayDoesNotDeduplicateARepeatedFrame);
//   - the operator-facing defaults are the documented ones
//     (TestRelayOptionDefaultsPinTheOperatorNumbers);
//   - Close stops every goroutine it started
//     (TestRelayCloseStopsServingAndCleansUp).
package relay

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/wire"
)

// startRelay is spelled out in full in every test rather than in a default
// constructor: knob values in the call site are part of what each test pins.
func startRelay(t *testing.T, opts Options) *Relay {
	t.Helper()
	r := New(opts)
	if err := r.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("relay listen on 127.0.0.1:0: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func writeFrame(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	if err := c.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if err := wire.WriteFrame(c, payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func readFrame(t *testing.T, c net.Conn, max int) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	payload, err := wire.ReadFrame(c, max)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear read deadline: %v", err)
	}
	return payload
}

// waitClosed asserts the relay closed OUR end of the connection: the next
// read fails (EOF or reset) inside the deadline, never delivering data first.
// A test asserting "the relay refused" through a live read would race the
// close; waiting on the read error is the deterministic form. A read that
// merely runs out of its own deadline is NOT a close - that would be a relay
// that did not act, and it fails here instead of passing by accident.
func waitClosed(t *testing.T, c net.Conn, what string) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	for {
		n, err := c.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Fatalf("%s: the relay left the connection open (read timed out instead of closing)", what)
			}
			return // EOF (clean close) or reset: the relay shut the socket
		}
		if n > 0 {
			t.Fatalf("%s: the relay delivered data instead of closing the connection", what)
		}
	}
}

// waitFor polls ok() until it holds, with one generous deadline: tests assert
// outcomes, never sleeps - a poll loop degrades to a timeout failure, not to
// a flake.
func waitFor(t *testing.T, ok func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s (waited 10s)", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitGoroutines is waitFor for goroutine counts.
func waitGoroutines(t *testing.T, want int, what string) {
	t.Helper()
	waitFor(t, func() bool { return runtime.NumGoroutine() <= want }, what)
}

// waitRegistered closes the race this test suite itself exposed: a client's
// dial returns when the KERNEL completes the handshake, but the relay
// registers the connection when its accept loop gets around to Accept - and
// the fan-out set is the registry AT FORWARDING TIME. A frame sent inside
// that window is not delivered to the yet-unregistered peer (message-bus
// semantics; see the package comment). The node layer's handshake is what
// makes that harmless in production; here, Stats().Conns is the observable
// that says "the registry now matches the dials", so every behavioural
// assertion below tests forwarding, not accept-loop scheduling.
func waitRegistered(t *testing.T, r *Relay, want int, what string) {
	t.Helper()
	waitFor(t, func() bool { return r.Stats().Conns == want }, what)
}

// The brief's first test: the relay forwards between two peers, in BOTH
// directions. One direction would be a half relay - and would pass a test
// that only checked a-to-b.
func TestRelayForwardsBetweenTwoPeers(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, WriteQueueSize: 8})
	a := dial(t, r.Addr().String())
	b := dial(t, r.Addr().String())
	waitRegistered(t, r, 2, "a dial completed while its connection sat unregistered")

	writeFrame(t, a, []byte("a1 to b"))
	if got := readFrame(t, b, 4096); string(got) != "a1 to b" {
		t.Fatalf("b read %q, want %q", got, "a1 to b")
	}

	writeFrame(t, b, []byte("b1 to a"))
	if got := readFrame(t, a, 4096); string(got) != "b1 to a" {
		t.Fatalf("a read %q, want %q", got, "b1 to a")
	}
}

// A validator that received its own vote back would double-count the one
// vote per validator the tally relies on - the transport refuses a
// self-connection at its handshake, and the relay must enforce the same
// invariant by construction: forward to every OTHER connection.
//
// The assertion is ordered, not "did anything arrive": after A's send, the
// FIRST frame A reads must be B's reply. If the relay echoed, A would read
// its own frame first and this test says exactly that.
func TestRelayDoesNotForwardToTheSender(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, WriteQueueSize: 8})
	a := dial(t, r.Addr().String())
	b := dial(t, r.Addr().String())
	waitRegistered(t, r, 2, "a dial completed while its connection sat unregistered")

	writeFrame(t, a, []byte("one"))
	if got := readFrame(t, b, 4096); string(got) != "one" {
		t.Fatalf("b read %q, want %q", got, "one")
	}

	writeFrame(t, b, []byte("two"))
	if got := readFrame(t, a, 4096); string(got) != "two" {
		t.Fatalf("a read %q after its own send; want %q - the relay fed the sender its own frame back", got, "two")
	}
}

// A peer vanishing MID-FRAME (a header promising bytes that never come, then
// the socket) must cost the relay nothing but that peer: no crash, no
// goroutine leaked behind the dead connection, no registry ghost, and the
// survivors keep forwarding. This is the relay's everyday weather - a home Pi
// drops its wifi - which is exactly why it must be unremarkable.
func TestRelaySurvivesAPeerDisappearing(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, WriteQueueSize: 8})
	baseline := runtime.NumGoroutine()

	a := dial(t, r.Addr().String())
	b := dial(t, r.Addr().String())
	waitRegistered(t, r, 2, "a dial completed while its connection sat unregistered")

	// Sanity before the death: the pair works.
	writeFrame(t, b, []byte("before"))
	if got := readFrame(t, a, 4096); string(got) != "before" {
		t.Fatalf("a read %q, want %q", got, "before")
	}

	// A dies mid-frame: a header promising 100 payload bytes, then 10, then
	// the socket is gone.
	if err := a.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := a.Write([]byte{0, 0, 0, 100}); err != nil {
		t.Fatalf("write partial frame header: %v", err)
	}
	if _, err := a.Write(make([]byte, 10)); err != nil {
		t.Fatalf("write partial frame payload: %v", err)
	}
	a.Close()

	// The registry drops A (nothing a later sender does can be the cleanup:
	// no frame flows while we check). Then the goroutine count returns to
	// listener + B's reader + B's writer - one each, enumerated, not guessed.
	waitFor(t, func() bool { return r.Stats().Conns == 1 },
		"the relay still lists a peer whose socket died mid-frame")
	waitGoroutines(t, baseline+3,
		"the relay leaked goroutines behind a peer that vanished mid-frame (want accept loop + one live peer's reader+writer)")

	// The survivors are unaffected, both ways.
	c := dial(t, r.Addr().String())
	waitRegistered(t, r, 2, "a dial completed while its connection sat unregistered")
	writeFrame(t, b, []byte("after"))
	if got := readFrame(t, c, 4096); string(got) != "after" {
		t.Fatalf("c read %q, want %q - the relay stopped forwarding after a peer vanished", got, "after")
	}
	writeFrame(t, c, []byte("back"))
	if got := readFrame(t, b, 4096); string(got) != "back" {
		t.Fatalf("b read %q, want %q - the relay stopped forwarding after a peer vanished", got, "back")
	}
}

// THE property that keeps the relay dumb, promoted from comment to test: it
// forwards bytes it cannot parse, unchanged. The payload below is not a
// b10coin message - every decoder in the wire layer refuses it - and the
// relay must neither care nor alter a byte. A relay that "helpfully" dropped
// unparseable frames would be a place where consensus could be interpreted
// and wrongly: signed frames are for the SIGNER's peers to check, never for
// the middlebox.
func TestRelayForwardsFramesItCannotParse(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, WriteQueueSize: 8})
	a := dial(t, r.Addr().String())
	b := dial(t, r.Addr().String())

	// Deterministic bytes (seeded, not crypto-random): a failing assertion
	// must be reproducible. The self-check below refuses to let the test
	// degrade silently if the seed ever produced a decodable message.
	rng := rand.New(rand.NewSource(1))
	payload := make([]byte, 512)
	if _, err := rng.Read(payload); err != nil {
		t.Fatalf("build payload: %v", err)
	}
	waitRegistered(t, r, 2, "a dial completed while its connection sat unregistered")
	if _, err := wire.DecodeHello(payload); err == nil {
		t.Fatalf("test payload decodes as a HELLO - the test's premise is gone; pick another seed")
	}
	if _, err := wire.DecodeBlockSyncReq(payload); err == nil {
		t.Fatalf("test payload decodes as a BLOCK_SYNC request - the test's premise is gone; pick another seed")
	}
	if _, err := wire.DecodeBlockSyncResp(payload); err == nil {
		t.Fatalf("test payload decodes as a BLOCK_SYNC response - the test's premise is gone; pick another seed")
	}

	writeFrame(t, a, payload)
	got := readFrame(t, b, 4096)
	if !bytes.Equal(got, payload) {
		t.Fatalf("relayed frame differs from the bytes sent (got %d bytes, want %d) - the relay interpreted the payload it was supposed to be ignorant of", len(got), len(payload))
	}
}

// One wedged validator must not stall the relay for everyone: the same
// slow-reader property the transport needed, held at the one hop a stranger
// can reach. A stops reading entirely; B floods; C still receives every
// frame, in order. The mechanism is the per-connection bounded write queue:
// forwarding enqueues and never waits, so A's wedge is A's problem alone.
//
// The volume is not decoration: the first version of this test flooded 512 KiB
// and its mutant (a synchronous forward, M3 in the report) SURVIVED - the
// kernel's loopback buffers silently absorbed the entire wedge. 2 MiB of
// undrained data sits above the kill threshold measured on this host,
// between 640 KiB and 768 KiB - a ~3x margin. It is a HOST-DEPENDENT margin:
// a host whose loopback buffers auto-tune larger than 2 MiB could absorb this
// flood too and let a synchronous mutant survive again. The volume was
// chosen against the buffers that exist, and the honest bound of the margin
// is stated rather than claimed away.
func TestRelayASlowPeerDoesNotStallTheOtherPeers(t *testing.T) {
	// The write queue is deliberately deep here (larger than the flood) so
	// that neither A's nor C's queue can ever be the thing tested: the ONLY
	// constrained buffer in this test is A's socket, which nobody drains.
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, WriteQueueSize: 4096})
	a := dial(t, r.Addr().String())
	// Best effort, and the test does not depend on it cooperating: a small
	// receive buffer makes a synchronous-forward mutant block early instead
	// of hiding in loopback's auto-tuned buffers.
	if tc, ok := a.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(2048)
	}
	b := dial(t, r.Addr().String())
	c := dial(t, r.Addr().String())
	waitRegistered(t, r, 3, "a dial completed while its connection sat unregistered")

	const frames = 2048
	const frameSize = 1024

	got := make([]int, 0, frames)
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		deadline := time.Now().Add(15 * time.Second)
		for len(got) < frames {
			if err := c.SetReadDeadline(deadline); err != nil {
				return
			}
			frame, err := wire.ReadFrame(c, 4096)
			if err != nil {
				return
			}
			got = append(got, int(binary.BigEndian.Uint16(frame[:2])))
		}
	}()

	for i := 0; i < frames; i++ {
		frame := make([]byte, frameSize)
		binary.BigEndian.PutUint16(frame[:2], uint16(i))
		writeFrame(t, b, frame)
	}

	<-collected
	if len(got) != frames {
		t.Fatalf("c received %d of %d frames - a wedged peer stalled the relay for its healthy peers", len(got), frames)
	}
	for i, seq := range got {
		if seq != i {
			t.Fatalf("frame %d arrived as %d - the relay reordered or dropped a frame for the healthy peer", i, seq)
		}
	}
}

// The relay is the one component a stranger can reach, so the frame bound is
// its first line of defence: a header declaring more than MaxFrameBytes is
// refused BEFORE allocation (wire.ReadFrame's own discipline), the relay ends
// the connection, and nothing oversize is ever forwarded. A bound that were
// merely a convention would let four hostile bytes allocate a 4 GiB buffer on
// the cheapest machine in the project.
//
// The boundary itself is pinned too: a frame of EXACTLY the bound is not
// hostile and still moves, so the check is "over the bound", not "at it".
func TestRelayRefusesAHostileFrameLength(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 1024, MaxConns: 64, WriteQueueSize: 8})
	a := dial(t, r.Addr().String())
	waitRegistered(t, r, 1, "a dial completed while its connection sat unregistered")

	// Declared length: 0x00000401 = 1025, one byte over the bound. Header
	// only - the hostile header is the whole attack.
	if err := a.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := a.Write([]byte{0, 0, 4, 1}); err != nil {
		t.Fatalf("write hostile header: %v", err)
	}
	waitClosed(t, a, "a frame whose header declares more than the bound")

	// Exactly at the bound is legitimate traffic.
	b := dial(t, r.Addr().String())
	c := dial(t, r.Addr().String())
	waitRegistered(t, r, 2, "a dial completed while its connection sat unregistered")
	frame := make([]byte, 1024)
	for i := range frame {
		frame[i] = byte(i)
	}
	writeFrame(t, b, frame)
	if got := readFrame(t, c, 1024); !bytes.Equal(got, frame) {
		t.Fatalf("a frame exactly at the bound arrived mangled (got %d bytes, want %d)", len(got), len(frame))
	}
}

// Connections are a stranger-controlled resource too: over MaxConns the new
// dial is closed at accept, and the established peers do not notice. Without
// the bound, one stranger with a loop of dials owns the €4 VPS the relay
// runs on - goroutines and buffers per connection are small, but unbounded is
// unbounded.
func TestRelayRefusesConnectionsBeyondItsBound(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 2, WriteQueueSize: 8})
	a := dial(t, r.Addr().String())
	b := dial(t, r.Addr().String())

	waitRegistered(t, r, 2, "a dial completed while its connection sat unregistered")
	extra := dial(t, r.Addr().String())
	waitClosed(t, extra, "a dial beyond the connection bound")

	// The established peers are untouched by the refusal.
	writeFrame(t, a, []byte("still here"))
	if got := readFrame(t, b, 4096); string(got) != "still here" {
		t.Fatalf("b read %q, want %q - refusing an excess dial disturbed the established peers", got, "still here")
	}
}

// Close stops the listener, ends every connection, and leaves no goroutine
// behind - and calling it twice is a no-op, not a panic. The relay is a
// long-lived single process; its shutdown is part of its contract with every
// validator that dials it.
func TestRelayCloseStopsServingAndCleansUp(t *testing.T) {
	baseline := runtime.NumGoroutine()
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, WriteQueueSize: 8})
	addr := r.Addr().String()
	a := dial(t, addr)
	b := dial(t, addr)
	waitRegistered(t, r, 2, "a dial completed while its connection sat unregistered")

	writeFrame(t, a, []byte("before close"))
	if got := readFrame(t, b, 4096); string(got) != "before close" {
		t.Fatalf("b read %q, want %q", got, "before close")
	}

	r.Close()
	r.Close() // idempotent: a second Close is a no-op, never a panic

	// The listener is shut: a fresh dial is refused. (addr was captured
	// before Close: r.Addr() correctly reports nil for a closed relay, and
	// calling a method on a nil interface here would crash the test.)
	if c, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		c.Close()
		t.Fatal("dial after Close succeeded - the relay is still accepting")
	}
	// Connected peers see their connections end.
	waitClosed(t, a, "a connected peer after Close")
	waitClosed(t, b, "a connected peer after Close")
	// Nothing lingers. (One slot of slack for the test binary's own noise; a
	// missed teardown leaves multiples behind.)
	waitGoroutines(t, baseline+1, "the relay left goroutines behind after Close")
}

// THE finding this test exists for (F1, Medium): the relay is the one
// component a stranger can reach, and 100 dials that write only a 4-byte
// header declaring 1 MiB and then SILENCE used to hold 100 reader goroutines,
// 100 one-MiB frame buffers the GC could never reclaim (+100 MiB measured),
// and 100 registry slots forever - at the defaults, one host holding 256
// connections could pin ~256 MiB and every registry slot with 256 four-byte
// writes and zero traffic. The fix is socket-level (the relay kept parsing
// nothing): a per-frame read deadline armed before the header and refreshed
// per frame, so on expiry the connection is ENDED and its slot is RELEASED -
// exactly what this test pins: the connections are reaped, the goroutines
// come back, and the memory is reclaimed.
func TestRelayStalledHeadersDoNotPinMemoryOrSlots(t *testing.T) {
	baseline := runtime.NumGoroutine()
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	r := startRelay(t, Options{
		MaxFrameBytes:  1 << 20, // the reviewer's scenario: frames declared at exactly the default bound
		MaxConns:       256,
		WriteQueueSize: 8,
		ReadTimeout:    3 * time.Second, // the knob under test, shrunk from the 2-minute default for a fast expiry
	})
	addr := r.Addr().String()

	const stalled = 100
	clients := make([]net.Conn, 0, stalled)
	for i := 0; i < stalled; i++ {
		clients = append(clients, dial(t, addr))
	}
	// The whole attack per connection: a 4-byte header declaring exactly 1 MiB
	// - so the frame-size bound PASSES it on - then silence forever.
	hdr := []byte{0, 0x10, 0, 0}
	for i, c := range clients {
		if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("dial %d set write deadline: %v", i, err)
		}
		if _, err := c.Write(hdr); err != nil {
			t.Fatalf("dial %d write stalled header: %v", i, err)
		}
	}
	waitRegistered(t, r, stalled, "the stalled dials did not all reach the registry")

	// Mid-stall: each reader checked its legal 1 MiB length, allocated the
	// payload buffer and now blocks waiting for bytes that never come. The
	// frame bound keeps this at exactly 1 MiB per connection - the point of
	// the test is that it never becomes FOREVER-pinned (that would be the
	// mutant), so the scenario is first REPRODUCED here: ~100 MiB of pinned
	// heap. The pin forms asynchronously (a reader allocates when its header
	// completes), so poll for it rather than racing one reading.
	pin := int64(0)
	pinFormed := time.Now().Add(30 * time.Second)
	for {
		runtime.GC()
		var mid runtime.MemStats
		runtime.ReadMemStats(&mid)
		pin = int64(mid.HeapAlloc) - int64(base.HeapAlloc)
		if pin >= 64<<20 || time.Now().After(pinFormed) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pin < 64<<20 {
		t.Fatalf("mid-stall heap grew only %d MiB (want ≥ 64) - the stalled-header scenario did not reproduce, and this test would then assert nothing", pin>>20)
	}

	// After the deadline: every connection ended, every slot released. On
	// failure the numbers are the before-proof for the report - the same
	// +100 MiB pin the reviewer measured.
	expiry := time.Now().Add(30 * time.Second)
	for r.Stats().Conns != 0 && time.Now().Before(expiry) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := r.Stats(); st.Conns != 0 {
		var pinned runtime.MemStats
		runtime.ReadMemStats(&pinned)
		t.Fatalf("stalled-header connections were never reaped: %d of %d still registered 30s after the deadline, goroutines %d (baseline %d), heap pinned %d MiB (baseline %d MiB) - the read deadline is gone or toothless",
			st.Conns, stalled, runtime.NumGoroutine(), baseline,
			(pinned.HeapAlloc-base.HeapAlloc)>>20, base.HeapAlloc>>20)
	}
	// The client's own end: the relay closed the socket, so a read fails.
	waitClosed(t, clients[0], "a stalled-header connection after its read deadline expired")

	stats := r.Stats()
	if stats.RefusedConns != 0 {
		t.Fatalf("refused %d dials - the scenario must be the read deadline at work, not a connection-bound refusal", stats.RefusedConns)
	}
	if stats.Forwarded != 0 {
		t.Fatalf("forwarded %d frames - a stalled header that never completed must not move anything", stats.Forwarded)
	}
	waitGoroutines(t, baseline+1,
		"goroutines leaked behind the stalled-header connections (want accept loop only)")

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	reclaimed := int64(after.HeapAlloc) - int64(base.HeapAlloc)
	t.Logf("after reaping: conns=%d, goroutines=%d (baseline %d), heap reclaimed to %+d MiB from a mid-stall pin of %d MiB (baseline %d MiB)",
		stats.Conns, runtime.NumGoroutine(), baseline, reclaimed>>20, pin>>20, base.HeapAlloc>>20)
	if reclaimed > 16<<20 {
		t.Fatalf("memory still pinned after the connections were reaped: heap %d MiB above baseline (mid-stall pin was %d MiB) - the frame buffers were not reclaimed",
			reclaimed>>20, pin>>20)
	}
}

// Keepalive, the second half of F1: accepted connections carry TCP keepalive
// so a HALF-OPEN connection - a peer vanished without closing (power cut,
// wifi loss), its socket open but never answering - is reaped by the socket
// itself in minutes, with no code watching and nothing parsed. The wiring is
// pinned at the socket level (SO_KEEPALIVE read back from the accepted socket
// by getsockopt, through sockoptKeepaliveOn): a mutant that disables or drops
// the setting fails here. The reaping itself cannot be raced on a loopback in
// a unit test without kernel manipulation - it is the OS's probe count at
// work - so this test pins the guarantee being set, and its period is a
// documented, operator-visible knob rather than an accident of the toolchain's
// default.
func TestRelaySetsTCPKeepaliveOnAcceptedConnections(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, WriteQueueSize: 8})
	dial(t, r.Addr().String())
	waitRegistered(t, r, 1, "the dial completed while its connection sat unregistered")

	r.mu.Lock()
	conns := make([]*net.TCPConn, 0, 1)
	for c := range r.conns {
		tcp, ok := c.nc.(*net.TCPConn)
		if !ok {
			r.mu.Unlock()
			t.Fatalf("accepted connection is not a TCP connection (%T) - keepalive could not apply", c.nc)
		}
		conns = append(conns, tcp)
	}
	r.mu.Unlock()

	for _, tcp := range conns {
		raw, err := tcp.SyscallConn()
		if err != nil {
			t.Fatalf("get raw fd: %v", err)
		}
		if err := sockoptKeepaliveOn(raw); err != nil {
			t.Fatalf("accepted connection does not carry TCP keepalive: %v", err)
		}
	}
}

// The queue bound must bite as a NON-BLOCKING drop, not as a waiting send.
// The deep-queue slow-reader test above cannot pin that: with the queue (4096)
// larger than the flood (2048) the queue NEVER fills, so a mutant replacing
// the non-blocking enqueue with a BLOCKING send compiles and passes - it
// killed queue-bypass only. This variant makes the queue the thing being
// tested: WriteQueueSize 4, and A deliberately wedged. A's kernel buffers
// absorb roughly 640-768 KiB on this host (measured; see the deep-queue
// test's comment for the same host-dependence), then A's writer wedges, A's
// queue fills at frame 4, and every further frame must be DROPPED - never
// waited on. The flood is PACED so the healthy peer C, whose queue is equally
// small, can always drain it: under a real producer's finite rate the drops
// must land ONLY on the wedged peer, and C still receives every frame in
// sender order. (A fully bursty flood could legitimately drop to C as well;
// burst absorption is the deep queue's property, pinned separately.)
func TestRelayAQueueBoundDropsInsteadOfBlocking(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, WriteQueueSize: 4})
	a := dial(t, r.Addr().String())
	// Best effort, as in the deep-queue test: a small receive buffer makes
	// A's wedge arrive at a predictable frame count instead of hiding in
	// loopback's auto-tuned buffers.
	if tc, ok := a.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(2048)
	}
	b := dial(t, r.Addr().String())
	c := dial(t, r.Addr().String())
	waitRegistered(t, r, 3, "a dial completed while its connection sat unregistered")

	const frames = 2048
	const frameSize = 1024

	got := make([]int, 0, frames)
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		deadline := time.Now().Add(15 * time.Second)
		for len(got) < frames {
			if err := c.SetReadDeadline(deadline); err != nil {
				return
			}
			frame, err := wire.ReadFrame(c, 4096)
			if err != nil {
				return
			}
			got = append(got, int(binary.BigEndian.Uint16(frame[:2])))
		}
	}()

	for i := 0; i < frames; i++ {
		frame := make([]byte, frameSize)
		binary.BigEndian.PutUint16(frame[:2], uint16(i))
		writeFrame(t, b, frame)
		time.Sleep(500 * time.Microsecond) // paced: C must always keep up
	}

	<-collected
	if len(got) != frames {
		t.Fatalf("c received %d of %d frames - the queue bound's drops fell on a healthy peer, not only on the wedged one", len(got), frames)
	}
	for i, seq := range got {
		if seq != i {
			t.Fatalf("frame %d arrived as %d - the relay reordered frames while applying the queue bound", i, seq)
		}
	}
	if st := r.Stats(); st.Dropped == 0 {
		t.Fatalf("Stats().Dropped == 0 with a wedged peer and a 4-frame queue - the bound never bit, so this test pinned nothing about the non-blocking drop")
	}
}

// Dedup is NOT the relay's business (spec §6.6): a repeated identical frame is
// the receivers' decision - a validator may deliberately resend, and a
// middlebox that cannot parse is the last place to guess which repeat is a
// retransmission. No earlier test fed one sender the same payload twice, so a
// mutant that dropped repeats passed the whole suite. The third frame
// distinguishes WHICH copy survived: a dedup that keeps the first (or the
// second) repeats yields [X, Y] and the missing frame's read times out loudly.
func TestRelayDoesNotDeduplicateARepeatedFrame(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, WriteQueueSize: 8})
	a := dial(t, r.Addr().String())
	b := dial(t, r.Addr().String())
	waitRegistered(t, r, 2, "a dial completed while its connection sat unregistered")

	x := []byte("the same frame twice - forwarding is not dedup's business")
	y := []byte("a different frame, to name which copy survived")

	writeFrame(t, a, x)
	writeFrame(t, a, x)
	writeFrame(t, a, y)

	for i, want := range [][]byte{x, x, y} {
		if got := readFrame(t, b, 4096); !bytes.Equal(got, want) {
			t.Fatalf("read %d of 3: b got %q, want %q - the relay deduplicated a repeated frame", i+1, got, want)
		}
	}
}

// The defaults are operator-facing numbers (stated in --help and README), so
// they are pinned exactly, not by accident: changing them should require
// changing this test and the two documents together.
func TestRelayOptionDefaultsPinTheOperatorNumbers(t *testing.T) {
	got := New(Options{}).opts.withDefaults()
	want := Options{
		MaxFrameBytes:  1 << 20,
		MaxConns:       256,
		WriteQueueSize: 64,
		ReadTimeout:    2 * time.Minute,
		KeepAlive:      15 * time.Second,
	}
	if got != want {
		t.Fatalf("relay defaults drifted from the documented operator numbers: got %+v, want %+v", got, want)
	}
}
