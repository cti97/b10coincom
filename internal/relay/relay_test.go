// Tests for the relay. They run over a real TCP socket on 127.0.0.1:0 - the
// socket path IS the deliverable, because the relay exists so that a home
// Raspberry Pi can reach a public VPS, and a pipe proves nothing about
// sockets - with the deliberate exception of the two queue-property tests
// below, which run on hand-built connections with NO socket at all: what
// they pin is language semantics (a send into a full channel with no
// receiver cannot block), and a socket hands that decision to host buffers
// the test process does not control.
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
//     (TestRelayASlowPeerDoesNotStallTheOtherPeers) - asserted for the
//     healthy peer only, every frame in order, because whether the silent
//     peer itself ever wedged is a host property this milestone has stopped
//     trying to pin;
//   - with the write queue actually at its BYTE BOUND, forwarding DROPS
//     instead of blocking (TestRelayAByteBudgetDropsInsteadOfBlocking) -
//     pinned deterministically with NO socket at all, because the previous
//     socket-flood shape of this test left whether the bound bit up to the
//     kernel's loopback buffers and failed a correct relay on the Linux CI;
//   - a sender still makes progress while a peer is genuinely wedged
//     (TestRelayAWedgedPeerDoesNotDelayTheSenders) - forward to a peer whose
//     queue is at its byte budget BY CONSTRUCTION returns promptly and every
//     other peer still receives the payload, on hand-built connections like
//     the budget test: its previous shape provoked the wedge by hammering
//     frames until kernel buffers filled, which the Linux CI absorbed whole;
//   - one sender cannot fill a receiver's whole queue and thereby censor
//     another sender (TestRelayPerSenderShareStopsAFloodFromCensoring):
//     the fair share is constructed full and the honest frame admitted -
//     NO socket, no buffer, no flood to provoke;
//   - a stranger's dials that send only a header and then stall do not hold
//     resources forever: the per-frame read deadline ends them and both the
//     slots and the memory come back (TestRelayStalledHeadersDoNotPinMemoryOrSlots);
//   - a sink that never reads is not pinned forever either, whatever its
//     keepalives say: the per-frame write deadline ends it, the slot and the
//     queued bytes are released, and a fresh dial is admitted
//     (TestRelayAKeepaliveSinkCannotPinASlotOrMemory);
//   - one source IP cannot hold the registry (TestRelayPerSourceIPCapBitesAtAccept);
//   - the documented aggregate memory bound is DERIVED from the option
//     fields, and its default value is pinned
//     (TestRelayDerivesTheDocumentedMemoryPinBound);
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
	"io"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

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
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
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
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
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
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
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
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
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

// One peer that has stopped reading must not stop the relay for the peers
// that keep going - the same slow-reader property the transport needed, held
// at the one hop a stranger can reach. A dials and then reads NOTHING; B
// sends an ordered series of frames; C must receive every one, in sender
// order.
//
// What this test deliberately does NOT contain is the wedge-provocation of
// its own earlier shape: 2048 frames (2 MiB) written for the stated purpose
// of filling A's socket buffers, with a SetReadBuffer to grease it - the
// same buffer-filling defect class that finally failed a correct relay on
// the Linux CI, and which this round deleted from the package at large.
// Nothing here observes A, so no assertion is hostage to whether A's buffers
// filled: C's every-frame-in-order outcome holds for a correct relay at ANY
// volume over ANY buffer, because buffers change only where the queued bytes
// sit in transit, not whether a healthy reader gets them. The kill of a
// blocking-forward mutant moved to the socket-free tests below, where the
// mechanism is language semantics; this test's job is the composed,
// end-to-end fact over a real socket that one reader draining nothing costs
// its peers nothing they can observe.
//
// The shape was ALSO purged of the subtler host dependence its first
// rewrite kept: with a deep queue option under a small frame count, whether
// C's queue ever filled was decided by GOROUTINE SCHEDULING (the collector's
// start beats the fan-out burst or it does not), and the collector then sat
// out its whole deadline waiting for frames that had been dropped. The fix
// is construction again, not tuning: the queue's BYTE budget equals the
// total in-flight volume, so no queue here can ever fill - a budget ≥ the
// in-flight bytes drops nothing BY CONSTRUCTION, on every host and under
// any schedule - and the counters pin that premise at the end.
func TestRelayASlowPeerDoesNotStallTheOtherPeers(t *testing.T) {
	// Both numbers are this test's own constants, coupled on purpose. The
	// volume carries no threshold and no wedge - the frame count is small
	// (32 KiB of traffic in total) and its only job is making sender order
	// through the real reader, queue and writer machinery a meaningful
	// check.
	const (
		frames          = 128
		frameSize       = 256
		queueBytesBound = frames * frameSize // budget ≥ in-flight: no queue can fill here
	)

	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: queueBytesBound})
	// A reads nothing for the whole test. Whether its silent socket ever
	// backs the relay up is a host matter this test does not observe. (The
	// dial's own t.Cleanup closes A's end.)
	dial(t, r.Addr().String())
	b := dial(t, r.Addr().String())
	c := dial(t, r.Addr().String())
	waitRegistered(t, r, 3, "a dial completed while its connection sat unregistered")

	got := make([]int, 0, frames)
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		deadline := time.Now().Add(10 * time.Second)
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
	// When C's collector has read the LAST frame, every earlier frame has
	// already been enqueued on C behind it, so by this point ALL of B's
	// frames exist as enqueues on the two non-senders: the counters below
	// are final and are a premise, not a discovery - with capacity ≥
	// in-flight they cannot read otherwise on any host.
	if st := r.Stats(); st.Forwarded != 2*frames || st.Dropped != 0 {
		t.Fatalf("the test's premise did not hold: Forwarded=%d/Dropped=%d, want %d/0 - every frame must have been enqueued for both non-senders with nothing dropped", st.Forwarded, st.Dropped, 2*frames)
	}
	if len(got) != frames {
		t.Fatalf("c received %d of %d frames while a peer never read - a silent peer stalled the relay for its healthy peers", len(got), frames)
	}
	for i, seq := range got {
		if seq != i {
			t.Fatalf("frame %d arrived as %d - the relay reordered a frame for the healthy peer behind a silent peer", i, seq)
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
	r := startRelay(t, Options{MaxFrameBytes: 1024, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
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
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 2, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
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
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
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
		MaxFrameBytes:   1 << 20, // the reviewer's scenario: frames declared at exactly the default bound
		MaxConns:        256,
		MaxConnsPerIP:   256, // the attack is 100 dials from ONE host: the per-source cap must not pre-empt the read-deadline scenario being tested
		WriteQueueBytes: 4 << 20,
		ReadTimeout:     3 * time.Second, // the knob under test, shrunk from the 2-minute default for a fast expiry
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
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
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

// The queue bound must bite as a NON-BLOCKING drop, not as a waiting send -
// and it must be tested in a way to which NO HOST GETS A VOTE. The previous
// shape of this test wedged peer A over a real socket, flooded it with a fixed
// 2048 frames, and asserted Stats().Dropped > 0 at the end: whether A's
// 4-frame queue ever filled was the KERNEL's decision, the Linux CI's loopback
// buffers absorbed the whole flood, the bound never bit, and the test failed a
// CORRECT relay. That is the sixth time this milestone caught a test whose
// outcome was a host property - a buffer size, a flood size, a queue size, a
// schedule - rather than the code's behaviour, so the old test's two
// conflated properties are now split, each held by the shape that makes it
// host-independent:
//
//   - THE BOUND, in this test: driven directly at the enqueue with no socket
//     at all. This file is in package relay, so the test registers two
//     hand-built connections - no dial, no listener, no kernel buffer - and
//     calls forward() itself. The queue's own state is then the ONLY input
//     the enqueue path has: fill it to its byte budget by construction, and
//     the next enqueue faces an exactly-full byte budget on every host
//     identically. push holds the mutex, runs the two comparisons and
//     returns - no send can block on the refusal path - so the assertions
//     depend on nothing but the sendQ's own semantics. The watchdog exists
//     only to turn a blocking-push mutant into a test failure in seconds
//     instead of a stalled suite; the real call takes microseconds and is
//     logged.
//
//   - THE LIVENESS, in TestRelayAWedgedPeerDoesNotDelayTheSenders: the same
//     construction with NO socket and NO hammer - a queue at its byte budget
//     BY CONSTRUCTION, forward asserted prompt, every other peer asserted
//     served - so nothing about it is left to a host either.
//
// The bound under test is N-2's BYTE budget: payload bytes, any mix of frame
// sizes. The frames here are 100 bytes each against a 300-byte budget, so
// three fit and the fourth cannot - a FRAME-count bound of any size would
// let all four in only by having a budget of >= 4 frames; the byte bound is
// what refuses frame 4, and the assertion names the bytes.
func TestRelayAByteBudgetDropsInsteadOfBlocking(t *testing.T) {
	const (
		frameBytes    = 100
		queueBytes    = 3 * frameBytes // the budget is in BYTES: 3 x 100
		maxFrameBound = 4096           // share = max(queueBytes/2, maxFrame) = 4096: the share never bites here
	)
	r := New(Options{MaxFrameBytes: maxFrameBound, MaxConns: 8, MaxConnsPerIP: 8, WriteQueueBytes: queueBytes})
	// Deliberately never started and never closed: no Listen, so no accept
	// loop and no goroutines; and these connections own no socket, so there
	// is nothing for Close to finish either. The registry below is the only
	// state forward reads.
	sender := &conn{q: newSendQ(queueBytes, maxFrameBound, queueBytes), dead: make(chan struct{})}
	wedged := &conn{q: newSendQ(queueBytes, maxFrameBound, queueBytes), dead: make(chan struct{})}
	r.mu.Lock()
	r.conns[sender] = struct{}{}
	r.conns[wedged] = struct{}{}
	r.mu.Unlock()

	// Fill the wedged peer's queue to its byte budget through the REAL
	// enqueue path. forward targets every connection except the sender, so
	// each call enqueues exactly one 100-byte frame on wedged.q.
	fill := make([]byte, frameBytes)
	for i := 0; i < queueBytes/frameBytes; i++ {
		r.forward(sender, fill)
	}
	if wedged.q.bytes != queueBytes || wedged.q.queued() != 3 {
		t.Fatalf("the byte budget reads %d bytes / %d frames after %d x %d-byte enqueues (want exactly %d bytes / 3 frames) - the queue did not reach its budget, so the test's premise (an exactly-full byte budget) never formed",
			wedged.q.bytes, wedged.q.queued(), queueBytes/frameBytes, frameBytes, queueBytes)
	}
	if st := r.Stats(); st.Forwarded != 3 || st.Dropped != 0 {
		t.Fatalf("at budget the counters read Forwarded=%d/Dropped=%d, want 3/0 - the accounting drifted before a drop was even possible", st.Forwarded, st.Dropped)
	}

	// The overflow enqueue must DROP, not wait. The drop itself is the proof
	// of non-blocking: the refusal is one pair of comparisons behind a mutex,
	// and a push that blocked would never reach the counters below. The
	// watchdog carries the mutant proof: a push replaced by anything
	// blocking fails HERE, within the bound, instead of hanging the suite.
	const nonBlockingBound = 5 * time.Second
	done := make(chan struct{})
	var enqueueDuration time.Duration
	go func() {
		defer close(done)
		start := time.Now()
		r.forward(sender, []byte("overflow"))
		enqueueDuration = time.Since(start)
	}()
	select {
	case <-done:
	case <-time.After(nonBlockingBound):
		t.Fatalf("the enqueue into a FULL %d-byte queue did not return within %v - it blocked instead of dropping", queueBytes, nonBlockingBound)
	}
	t.Logf("the overflow enqueue returned in %s (bound %s)", enqueueDuration, nonBlockingBound)

	if st := r.Stats(); st.Dropped != 1 {
		t.Fatalf("Stats().Dropped == %d after one enqueue over a full budget, want exactly 1 - the drop was never reported", st.Dropped)
	}
	if st := r.Stats(); st.Forwarded != 3 {
		t.Fatalf("Stats().Forwarded == %d after the drop, want 3 - the dropped frame was counted as delivered", st.Forwarded)
	}
	if wedged.q.bytes != queueBytes || wedged.q.queued() != 3 {
		t.Fatalf("the queue holds %d bytes / %d frames after the drop, want %d/3 - the dropped enqueue disturbed the queue", wedged.q.bytes, wedged.q.queued(), queueBytes)
	}
	// And the budget's contents are uncorrupted: three fills, in order.
	for i := 0; i < 3; i++ {
		f, ok := wedged.q.pop()
		if !ok || string(f.b) != string(fill) {
			t.Fatalf("the wedged queue's frame %d is %q (present: %v) - the refusal disturbed the queue's contents", i, f.b, ok)
		}
	}
}

// The other half of the split - the liveness half - and, as of this round,
// held in exactly the shape the bound now uses: with NO socket and NO hammer
// anywhere. The failed history is why. The previous shape exercised "A is
// wedged" as a network EVENT: it dialled a real relay, then hammered up to
// 9000 frames (9 MiB) from B and hoped the host's kernel buffers could not
// absorb the flood before A's 4-slot write queue filled. On the Linux CI the
// kernel absorbed all 9 MiB, A's queue never filled, the wedge never formed,
// and a CORRECT relay failed CI with "the wedge scenario did not reproduce".
// That is the seventh buffer-filling defect this milestone has caught, and
// this round the mechanism is deleted, not tuned: nothing in this file sends
// frames for the purpose of filling a buffer - any buffer - again. "A is
// wedged" is a PRECONDITION here, constructed in the code, so no host gets
// a vote, and the property under test is the code's decision, not the host's.
//
// The property has three assertions, each on hand-built connections:
//
//   - forward targeting a peer whose queue is AT ITS BYTE BUDGET RETURNS
//     PROMPTLY. push's refusal path is two comparisons under a mutex, no
//     send can block on it - so the call that must not wait cannot wait, on
//     every host identically. The watchdog exists only to turn a
//     blocking-push mutant (M1) into a test failure at the bound instead of
//     a hung suite; the real call takes microseconds and is logged.
//
//   - every OTHER peer STILL receives the payload, in sender order - the
//     real property: one stalled peer must not stop delivery to the rest.
//     On hand-built connections a fan-out's receipt IS the enqueue, which is
//     exactly the decision forward owns; a writer's drain of an enqueued
//     frame over a real socket is pinned by the socket tests above.
//
//   - the probe went NOWHERE but the healthy peers: the wedged peer's queue
//     is still at its budget and still holds only the fills that put it
//     there - this is the drop, observable without touching the counter.
//
// The drop COUNTER is asserted nowhere in this test - one fact, one owner:
// the exact accounting at the bound is the deterministic test's property.
func TestRelayAWedgedPeerDoesNotDelayTheSenders(t *testing.T) {
	const (
		fillBytes     = 100
		queueBytes    = 4 * fillBytes // 400 bytes: exactly four fills
		maxFrameBound = 4096          // share = max(queueBytes/2, maxFrame) = 4096: the share never bites here
	)
	r := New(Options{MaxFrameBytes: maxFrameBound, MaxConns: 8, MaxConnsPerIP: 8, WriteQueueBytes: queueBytes})
	// The construction the split partner shares, stated in full as the
	// budget test states it: a relay deliberately never started (no Listen,
	// so no accept loop and no goroutines) carrying HAND-BUILT connections
	// that own no socket, so there is nothing for Close to finish either.
	// The registry below is the only state forward reads, and no writer
	// goroutine exists to drain any queue - the wedged peer's queue, once at
	// its budget, cannot move, on any host.
	sender := &conn{q: newSendQ(queueBytes, maxFrameBound, queueBytes), dead: make(chan struct{})}
	wedged := &conn{q: newSendQ(queueBytes, maxFrameBound, queueBytes), dead: make(chan struct{})}
	healthy := []*conn{
		{q: newSendQ(queueBytes, maxFrameBound, queueBytes), dead: make(chan struct{})},
		{q: newSendQ(queueBytes, maxFrameBound, queueBytes), dead: make(chan struct{})},
	}
	r.mu.Lock()
	r.conns[sender] = struct{}{}
	r.conns[wedged] = struct{}{}
	for _, h := range healthy {
		r.conns[h] = struct{}{}
	}
	r.mu.Unlock()

	// Build the wedge through the REAL enqueue path, exactly as the budget
	// test does. forward targets every connection except the sender, and
	// while the wedge builds, the wedged queue is not yet at its budget, so
	// each of the four 100-byte calls enqueues one frame EVERYWHERE: into
	// wedged.q, bringing it to its 400-byte budget, and into both healthy
	// queues - which is what lets the probe below distinguish "delivered to
	// the others" from "dropped with the wedge".
	const fillBody = "fill"
	const probeBody = "probe"
	fill := append([]byte(fillBody), make([]byte, fillBytes-len(fillBody))...)
	for i := 0; i < queueBytes/fillBytes; i++ {
		r.forward(sender, fill)
	}

	// The wedge, verified, not assumed - and it could not be otherwise:
	// nothing exists here to drain wedged.q.
	if wedged.q.bytes != queueBytes || wedged.q.queued() != 4 {
		t.Fatalf("the wedged peer's queue holds %d bytes / %d frames before the probe (want 400/4) - the test's premise (an exactly-full byte budget built by hand) never formed", wedged.q.bytes, wedged.q.queued())
	}
	// Unlike the wedged peer, the healthy peers' writers KEPT UP (nothing
	// parked them, because nothing is parked at all): the fills are still
	// theirs, and one frame is then drained from each healthy queue - the
	// proof they are still being SERVED - leaving exactly 300 bytes so the
	// probe's 100 fit the budget. At full budget everywhere the probe would
	// drop at every queue and the wedged peer would not be the one thing
	// different about it - the distinction the assertions below rest on.
	wantBytesAfterDrain := queueBytes - fillBytes
	for i, h := range healthy {
		if h.q.bytes != queueBytes || h.q.queued() != 4 {
			t.Fatalf("healthy peer %d's queue holds %d bytes / %d fills after the fill fan-out (want %d/4) - the premise (every fill reached every non-wedged peer) never formed", i, h.q.bytes, h.q.queued(), queueBytes)
		}
		if got, ok := h.q.pop(); !ok || string(got.b[:len(fillBody)]) != fillBody {
			t.Fatalf("healthy peer %d: the drained head of its queue is %q (present %v), want the oldest fill - the fan-out never came to rest in sender order", i, got.b, ok)
		}
		if h.q.bytes != wantBytesAfterDrain || h.q.queued() != 3 {
			t.Fatalf("healthy peer %d's queue holds %d bytes / %d frames after one drain, want %d/3 - the drain did not leave the probe's room", i, h.q.bytes, h.q.queued(), wantBytesAfterDrain)
		}
	}

	// forward INTO the wedge must return promptly. The watchdog carries the
	// M1 proof: forward's enqueue replaced by anything blocking parks this
	// call on the full, receiverless wedged queue, and the test fails AT
	// THE BOUND (a duration failure, never a hung suite). The passing case
	// is one forward over hand-built queues - microseconds.
	const forwardBound = 10 * time.Second
	done := make(chan struct{})
	var forwardDuration time.Duration
	go func() {
		defer close(done)
		start := time.Now()
		r.forward(sender, []byte(probeBody))
		forwardDuration = time.Since(start)
	}()
	select {
	case <-done:
	case <-time.After(forwardBound):
		t.Fatalf("forward with one peer's queue at its byte budget did not return within %v - it blocked on the wedged peer instead of dropping", forwardBound)
	}
	t.Logf("forward with one peer full returned in %s (bound %s)", forwardDuration, forwardBound)

	// THE real property: every other peer still received the payload. The
	// fills came first, so per (sender, receiver) order the probe is each
	// healthy queue's LAST frame (its bytes ride on top of the three fills
	// still queued: wantBytesAfterDrain + len(probeBody)).
	for i, h := range healthy {
		if want := wantBytesAfterDrain + len(probeBody); h.q.bytes != want || h.q.queued() != 4 {
			t.Fatalf("healthy peer %d's queue holds %d bytes / %d frames after a forward with one peer full, want %d/4 - the stalled peer cost it the payload", i, h.q.bytes, h.q.queued(), want)
		}
		for j := 0; j < 3; j++ {
			if got, ok := h.q.pop(); !ok || string(got.b[:len(fillBody)]) != fillBody {
				t.Fatalf("healthy peer %d: queue slot %d holds %q (present %v), want a fill - a stalled peer disturbed an order the relay holds per (sender, receiver)", i, j, got.b, ok)
			}
		}
		if got, ok := h.q.pop(); !ok || string(got.b) != probeBody {
			t.Fatalf("healthy peer %d: the frame behind the fills is %q (present %v), want the probe %q - one stalled peer stopped delivery to the rest", i, got.b, ok, probeBody)
		}
	}

	// The probe went nowhere but the healthy peers: the wedged queue took
	// the drop and kept its contents - the budget held for everyone else
	// while holding the wedge in place.
	if wedged.q.bytes != queueBytes || wedged.q.queued() != 4 {
		t.Fatalf("the wedged peer's queue reads %d bytes / %d frames after the probe forward (want 400/4) - a frame entered a queue that was at its budget", wedged.q.bytes, wedged.q.queued())
	}
	for i := 0; i < 4; i++ {
		if got, ok := wedged.q.pop(); !ok || string(got.b[:len(fillBody)]) != fillBody {
			t.Fatalf("the wedged peer's queue holds %q at slot %d (present %v) - the probe's payload is inside the queue that was already full when it was sent", got.b, i, ok)
		}
	}
}

// One sender cannot occupy a receiver's whole queue and thereby censor
// another sender (audit N-2: per-sender fair share). The construction is
// fully deterministic - NO socket, NO flood, every state built by hand:
//
//   - the receiver's queue has a 300-byte budget and TWO contending sender
//     accounts, so its capacity-relative share is 300/2 = 150 bytes
//     (shareFor(2), MaxFrameBytes set at 32 so the floor is the fraction);
//   - the flooder's first 100-byte frame is ADMITTED (it fits its share);
//     its second is REFUSED at the share (100+100 > 150) - a flooder that is
//     sharing the queue can never fill it, which is the property;
//   - the honest sender's 100-byte frame is then admitted into the space
//     the share guaranteed - under a mutant that drops the share check, the
//     flooder's frames keep flowing until the BUDGET is full, the honest
//     frame drops at the budget, and the test fails on exactly that
//     admission with the counters naming who was refused;
//   - the share refunds on pop: after the flooder's frame is taken out, the
//     flooder can enqueue again - the share caps what a sender HOLDS, not
//     what it has ever sent.
//
// The 2-account contention is supplied explicitly (the pushes below pass the
// divisor the relay's fan-out computes from the registry) because these
// queues are hand-built with no relay fan-out behind them. A single
// UNCONTENDED sender is the other half of the invariant, and it is not
// throttled: TestRelayASingleSenderMayUseTheWholeQueue constructs exactly
// that state, and the socket-level TestRelayASlowPeerDoesNotStallTheOtherPeers
// exercises it through the real reader, queue and writer machinery.
func TestRelayPerSenderShareStopsAFloodFromCensoring(t *testing.T) {
	const (
		frameBytes = 100
		queueBytes = 300
		// senders is the contending-account count the relay would derive for
		// this registry: the flooder and the voter are two distinct accounts.
		senders       = 2
		shareBytes    = queueBytes / senders // shareFor(2) = 150
		maxFrameBound = 32
	)
	r := New(Options{MaxFrameBytes: maxFrameBound, MaxConns: 8, MaxConnsPerIP: 8, WriteQueueBytes: queueBytes})
	flooder := &conn{q: newSendQ(queueBytes, maxFrameBound, queueBytes), dead: make(chan struct{})}
	wedged := &conn{q: newSendQ(queueBytes, maxFrameBound, queueBytes), dead: make(chan struct{})}
	voter := &conn{q: newSendQ(queueBytes, maxFrameBound, queueBytes), dead: make(chan struct{})}
	r.mu.Lock()
	r.conns[flooder] = struct{}{}
	r.conns[wedged] = struct{}{}
	r.conns[voter] = struct{}{}
	r.mu.Unlock()

	frame := make([]byte, frameBytes)
	vote := []byte("the honest vote")
	// The flooder's first frame goes through the REAL fan-out: admitted
	// (100 <= its 150-byte share) into the wedged receiver's queue. Note the
	// voter is ALSO a non-sender of this frame: the flood reaches it too -
	// flooders are not special, the share binds every sender identically.
	r.forward(flooder, frame)
	if st := r.Stats(); st.Forwarded != 2 || st.Dropped != 0 {
		t.Fatalf("after the flooder's first frame the counters read Forwarded=%d/Dropped=%d, want 2/0 - the fan-out path lost an admission", st.Forwarded, st.Dropped)
	}
	if wedged.q.bytes != frameBytes || wedged.q.occupancy(flooder) != frameBytes {
		t.Fatalf("the flooder's occupancy of the wedged queue reads %d/%d - the first admission never landed", wedged.q.bytes, wedged.q.occupancy(flooder))
	}
	// Its second: refused at the SHARE (100+100 > 150) - a flooder sharing the
	// queue can never fill the budget, which is the property this test exists
	// for.
	if wedged.q.push(flooder, frame, senders) {
		t.Fatalf("the flooder's second frame was admitted (queue %d bytes, flooder share %d): the share holds nothing, so the flood's own frames would fill the queue and the honest frame below would drop with them", wedged.q.bytes, wedged.q.occupancy(flooder))
	}
	// THE property: the honest sender's frame is ADMITTED into the space the
	// share guarantees - under a mutant that drops the share check, the
	// flooder's frames flow until the 300-byte BUDGET is full and this push
	// is the one that drops, named by the message.
	if !wedged.q.push(voter, vote, senders) {
		t.Fatalf("the honest sender's frame was refused with the flooder holding only %d of its %d-byte share (queue %d/%d bytes) - one sender's flood censored another sender's frame",
			wedged.q.occupancy(flooder), shareBytes, wedged.q.bytes, queueBytes)
	}
	// Order: flooder's frame first, honest second - FIFO per (sender,
	// receiver); the share is keyed by sender conn, so the pops name them.
	f, ok := wedged.q.pop()
	if !ok || f.sender != flooder {
		t.Fatalf("the first pop is from %p (present %v), want the flooder's conn - FIFO per pair broken", f.sender, ok)
	}
	f, ok = wedged.q.pop()
	if !ok || f.sender != voter || string(f.b) != string(vote) {
		t.Fatalf("the second pop is %q from %p (present %v), want the honest frame - it was admitted into the wrong place or not at all", f.b, f.sender, ok)
	}
	// The refunds: after both pops the budget and the flooder's share are
	// fully free, so the flooder can enqueue again - the share caps what a
	// sender HOLDS, never what it has sent in its life.
	if wedged.q.bytes != 0 || wedged.q.occupancy(flooder) != 0 {
		t.Fatalf("after draining, the queue holds %d bytes and the flooder's occupancy is %d - the pop refund leaked", wedged.q.bytes, wedged.q.occupancy(flooder))
	}
	if !wedged.q.push(flooder, frame, senders) {
		t.Fatalf("the flooder's frame after a full drain was refused - the share did not refund its popped occupancy")
	}
}

// The other half of the fair share, and the invariant two earlier attempts
// broke: a single sender with no competition may use the queue's WHOLE
// capacity. The share is a fraction of the receiver's OWN budget divided
// among the sender accounts contending for it, so with one account the
// fraction is 1/1 and nothing is throttled.
//
// The state is CONSTRUCTED, not provoked through a kernel buffer: a receiver
// whose queue capacity EQUALS the total in-flight bytes, a single sender
// account, and no writer draining it - the exact slow-peer shape
// TestRelayASlowPeerDoesNotStallTheOtherPeers builds over sockets, pinned
// here with no host buffer in the loop. Under the absolute per-sender cap the
// two previous attempts shipped (a share of budget/2), frame 65 of 128 is
// refused and this test names it.
func TestRelayASingleSenderMayUseTheWholeQueue(t *testing.T) {
	const (
		frames    = 128
		frameSize = 256
		limit     = frames * frameSize // capacity == in-flight bytes, by construction
	)
	r := New(Options{MaxFrameBytes: frameSize, MaxConns: 8, MaxConnsPerIP: 8, WriteQueueBytes: limit})
	sender := &conn{q: newSendQ(limit, frameSize, frames), dead: make(chan struct{}), srcGroup: "198.51.100.0/24"}
	wedged := &conn{q: newSendQ(limit, frameSize, frames), dead: make(chan struct{}), srcGroup: "192.0.2.0/24"}
	r.mu.Lock()
	r.conns[sender] = struct{}{}
	r.conns[wedged] = struct{}{}
	r.mu.Unlock()

	// One contending account (the sender's): the receiver is the only member
	// of its own, so the relay counts no second sender.
	if accounts := map[shareAccount]int{
		shareAccountOf(sender): 1,
		shareAccountOf(wedged): 1,
	}; sendersFor(wedged, accounts) != 1 {
		t.Fatalf("sendersFor(wedged) = %d with one sender in the registry, want 1 - the uncontended state never formed", sendersFor(wedged, accounts))
	}
	if got := wedged.q.shareFor(1); got != limit {
		t.Fatalf("shareFor(1) = %d, want the whole queue capacity %d - a single uncontended sender must not be capped below the room it has", got, limit)
	}
	frame := make([]byte, frameSize)
	for i := 0; i < frames; i++ {
		r.forward(sender, frame)
	}
	if got := wedged.q.bytes; got != limit {
		t.Fatalf("after %d frames of %d bytes the queue holds %d of its %d-byte capacity - a healthy sender lost frames while the receiver had room", frames, frameSize, got, limit)
	}
	if st := r.Stats(); st.Forwarded != frames || st.Dropped != 0 {
		t.Fatalf("a single uncontended sender read Forwarded=%d/Dropped=%d, want %d/0 - the share throttled a healthy flow (the defect two earlier attempts shipped)", st.Forwarded, st.Dropped, frames)
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
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
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
// changing this test and the documents together.
func TestRelayOptionDefaultsPinTheOperatorNumbers(t *testing.T) {
	got := New(Options{}).opts
	want := Options{
		MaxFrameBytes:    1 << 20,
		MaxConns:         32,
		MaxConnsPerIP:    8,
		WriteQueueBytes:  2 << 20,
		WriteQueueFrames: 4096,
		WriteTimeout:     30 * time.Second,
		ReadTimeout:      2 * time.Minute,
		KeepAlive:        15 * time.Second,
	}
	if got != want {
		t.Fatalf("relay defaults drifted from the documented operator numbers: got %+v, want %+v", got, want)
	}
	// The AGGREGATE memory bound the documents quote is DERIVED from these
	// fields (Options.MaxPinnedBytes), not asserted beside them: pin the
	// derivation's output at the defaults, so a changed default either moves
	// the documents' number with it or fails here. The derivation includes
	// the per-frame ENTRY ring (audit N-2's re-opened term): 32 x (2 MiB
	// payload + 4096 x 32 B entries + 2 x 1 MiB hands) = 132 MiB.
	wantBound := 32 * (2<<20 + 4096*queuedFrameEntryBytes + 2*(1<<20))
	if bound := got.MaxPinnedBytes(); bound != wantBound {
		t.Fatalf("MaxPinnedBytes() = %d bytes at the defaults, want %d (32 conns x (2 MiB payload + 4096 x 32 B entries + 2 x 1 MiB hands)) - the derived pin the README, --help and the unit's MemoryMax quote has drifted",
			bound, wantBound)
	}
	if wantBound != 132<<20 {
		t.Fatalf("the derived default bound is %d bytes, expected the documented 132 MiB (%d) - the constants and the documents have diverged", wantBound, 132<<20)
	}
	// And the bound is really a derivation: changing one input moves it (a
	// hardcoded constant would silently break the arithmetic).
	custom := got
	custom.MaxConns = 8
	if bound := custom.MaxPinnedBytes(); bound != 8*(2<<20+4096*queuedFrameEntryBytes+2*(1<<20)) {
		t.Fatalf("MaxPinnedBytes() = %d with MaxConns 8, want %d - the bound is not derived from the options", bound, 8*(2<<20+4096*queuedFrameEntryBytes+2*(1<<20)))
	}
	// The entry term is not decorative: dropping the frame cap from the
	// formula moves the number, which is what a byte-budget-only claim did
	// (audit N-2: the same 2 MiB admits ~2M one-byte entries).
	custom = got
	custom.WriteQueueFrames = 1
	if bound := custom.MaxPinnedBytes(); bound >= got.MaxPinnedBytes() {
		t.Fatalf("MaxPinnedBytes() = %d with the frame cap at 1, not below the default %d - the per-frame entry term is not in the derivation", bound, got.MaxPinnedBytes())
	}
}

// A 5-byte keepalive frame can no longer pin a slot indefinitely (audit N-2):
// the pre-fix relay had TWO timers but only the read side was armed on the
// write side's problem. A dialer that NEVER READS backpressures the writer
// into an indefinite block while its queue stays full of pinned bytes - and
// the sink kept its connection, slot and queue alive forever simply by
// WRITING a 5-byte frame every 100 seconds, because every complete frame
// refreshed the READ deadline. This test constructs exactly that sink and
// asserts the two properties the fix owns:
//
//   - the sink is ENDED by the per-frame write deadline (WriteTimeout) even
//     though it never stops sending fresh keepalives - evidenced by its
//     keepalive writes starting to FAIL while the keepalive stream never
//     lapsed, and by the registry draining;
//   - the freed slot is reusable: a fresh dial is admitted immediately
//     after (with MaxConns at 2, a still-pinned sink makes this dial
//     impossible - which is exactly what the mutant does).
//
// The sink's blocking is CONSTRUCTED, not provoked through host buffers:
// the sink sets its own SO_RCVBUF to a near-floor value BEFORE any traffic
// exists, so the relay's writer backpressures within a few kilobytes on any
// host, and the flood that follows is orders of magnitude beyond every
// kernel buffer on the path.
func TestRelayAKeepaliveSinkCannotPinASlotOrMemory(t *testing.T) {
	const (
		frameBytes = 64 << 10 // the flood frame; budget and reader both bound below it
	)
	baseline := runtime.NumGoroutine()
	r := startRelay(t, Options{
		MaxFrameBytes:   1 << 20,
		MaxConns:        2, // the WHOLE point: when the sink is reaped, its slot must be really free
		MaxConnsPerIP:   8, // loopback dials share one IP; the cap must not pre-empt this scenario
		WriteQueueBytes: frameBytes * 4,
		WriteTimeout:    500 * time.Millisecond, // the knob under test, shrunk from the 30s default
		ReadTimeout:     3 * time.Second,
	})
	addr := r.Addr().String()

	// The never-reading sink: buffered to a floor BEFORE any traffic, so the
	// kernel cannot silently absorb the flood for it.
	sink := dial(t, addr)
	stcp, ok := sink.(*net.TCPConn)
	if !ok {
		t.Fatalf("the sink is %T, not a TCP connection - its receive buffer cannot be floored", sink)
	}
	if err := stcp.SetReadBuffer(4096); err != nil {
		t.Fatalf("sink SetReadBuffer: %v", err)
	}
	flooder := dial(t, addr)
	// The flooder DRAINS its own socket throughout: it never reads otherwise,
	// and then the conn that dies of silence is THE FLOODER, not the sink -
	// which would make "the registry drained to one" claim the wrong death.
	// Reading continuously keeps the flooder's own read deadline fed by the
	// sink's keepalives for the test's whole window.
	drainStop := make(chan struct{})
	defer close(drainStop)
	floodErrs := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-drainStop:
				return
			default:
			}
			_ = flooder.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := flooder.Read(buf); err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // a quiet half-second between keepalive frames is not a death
				}
				select {
				case floodErrs <- err:
				default:
				}
				return
			}
		}
	}()
	waitRegistered(t, r, 2, "the sink and flooder dials completed while their connections sat unregistered")

	// The sink's keepalive: one 5-byte frame every 100ms, forever, started
	// BEFORE the traffic arrives (the attack's ordering: the sink is fresh
	// when the frames are forwarded into it). Every failed write is a
	// KEEPALIVE-FAILED event - the proof the sink was closed WHILE its
	// keepalive liveness was still being renewed.
	keepFailed := make(chan error, 1)
	keepStop := make(chan struct{})
	keepStopOpen := true
	defer func() {
		if keepStopOpen {
			close(keepStop)
		}
	}()
	var sent atomic.Uint64
	go func() {
		kb := []byte{1, 2, 3, 4, 5} // exactly the audit's 5-byte keepalive frame
		for {
			select {
			case <-keepStop:
				return
			default:
			}
			if err := sink.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				select {
				case keepFailed <- err:
				default:
				}
				return
			}
			if err := wire.WriteFrame(sink, kb); err != nil {
				select {
				case keepFailed <- err:
				default:
				}
				return // the relay closed the sink: the keepalive could not sustain it
			}
			sent.Add(1)
			select {
			case <-keepStop:
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()

	// The flood: 64 KiB frames, continuously, far beyond the sink's budget
	// and buffers. The relay drains the flooder promptly and (budget, then
	// the sink's wedged writer) drops or backpressures toward the sink -
	// Dropped must rise, proving the queue budget actually bit.
	floodDone := make(chan struct{})
	go func() {
		defer close(floodDone)
		for {
			select {
			case <-keepStop:
				return
			default:
			}
			_ = flooder.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := wire.WriteFrame(flooder, make([]byte, frameBytes)); err != nil {
				select {
				case floodErrs <- err:
				default:
				}
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	// Dropped>0 proves the byte budget actually bit before the reaping is
	// asserted; without this premise the reaping could be ordinary silence.
	waitFor(t, func() bool {
		return r.Stats().Dropped > 0
	}, "the flood dropping against the sink's byte budget")

	// THE reaping: the sink is gone within (backpressure latency +
	// WriteTimeout), its keepalives notwithstanding.
	waitFor(t, func() bool { return r.Stats().Conns == 1 },
		"the never-reading sink being reaped (registry down to the flooder only) within backpressure+write-timeout")
	// The keepalive's own testimony: at least one of the sink's fresh
	// 5-byte keepalives FAILED - the connection was closed by the write
	// deadline while the keepalive stream was live. (Without the keepalive
	// stream, this would be the ordinary read-deadline reaping; the premise
	// that the keepalives were being sent and REJECTED is what makes this
	// the write deadline's work.)
	select {
	case err := <-keepFailed:
		t.Logf("sink keepalive failed as required after %d sent: %v", sent.Load(), err)
	case <-time.After(5 * time.Second):
		t.Fatal("the sink was reaped but none of its keepalive writes ever failed within 5s - it did not keep keepaliving (test premise gone)")
	}
	// The freed slot is genuinely reusable: with MaxConns 2, this dial is
	// exactly the one the pre-fix state could never admit.
	select {
	case <-keepStop:
	default:
		close(keepStop) // stop the flood: the assertions below need a quiet relay
		keepStopOpen = false
	}
	<-floodDone
	// The reaping was SINK-specific: the reading flooder survived it.
	waitRegistered(t, r, 1, "the flood source surviving the sink's reaping")
	fresh := dial(t, addr)
	waitRegistered(t, r, 2, "the fresh dial after the sink was reaped")
	// The flooder keeps working; nothing else was disturbed.
	writeFrame(t, flooder, []byte("still here"))
	if got := readFrame(t, fresh, 4096); string(got) != "still here" {
		t.Fatalf("fresh dial read %q, want %q - reaping disturbed the other peer", got, "still here")
	}
	// The sink's end is dead too - but bytes the relay wrote into the
	// kernel BEFORE the wedge are still deliverable here, so the close-proof
	// for this socket is drain-then-EOF, not "no data may arrive": read
	// until an error, where a TIMEOUT means the socket stayed open.
	_ = sink.SetReadDeadline(time.Now().Add(5 * time.Second))
	drain := make([]byte, 4096)
	for {
		if _, err := sink.Read(drain); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Fatalf("the reaped sink's socket stayed open (read timed out with no further data)")
			}
			break // EOF or reset: the relay's close reached this end
		}
	}
	waitGoroutines(t, baseline+5, "goroutines leaked behind the reaped sink (want accept loop + flooder pair + fresh pair)")
}

// One source PREFIX cannot hold the registry (audit N-2's third attack): the
// cap is enforced at accept, counts against the canonical source prefix
// (connGroup), and frees a slot only when a connection ends. The relay listens
// dual-stack so the test can prove the cap is PER-GROUP and not a second
// global bound: a dial whose prefix differs (::1, i.e. ::/64) is admitted
// while the 127.0.0.0/24 group is at its cap.
func TestRelayPerSourcePrefixCapBitesAtAccept(t *testing.T) {
	r := New(Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 2, WriteQueueBytes: 1 << 16})
	if err := r.Listen("[::]:0"); err != nil { // dual-stack: v4 and v6 sources are separate groups
		t.Fatalf("dual-stack listen: %v", err)
	}
	addr := r.Addr().String()

	a := dialFrom(t, addr, "127.0.0.1")
	b := dialFrom(t, addr, "127.0.0.1")
	waitRegistered(t, r, 2, "the first two loopback dials completed while their connections sat unregistered")

	// The third dial from the SAME prefix: refused at accept.
	third := dialFrom(t, addr, "127.0.0.1")
	waitClosed(t, third, "a third dial from one source prefix past the per-prefix cap")
	waitFor(t, func() bool { return r.Stats().RefusedConns == 1 }, "the per-prefix refusal being counted")

	// A dial from a DIFFERENT prefix: admitted - the cap is per group, and
	// the established peers are untouched.
	v6 := dialFrom(t, addr, "::1")
	waitRegistered(t, r, 3, "the different-prefix dial being admitted")
	writeFrame(t, a, []byte("still here"))
	if got := readFrame(t, b, 4096); string(got) != "still here" {
		t.Fatalf("b read %q, want %q - the per-prefix refusal disturbed the established peers", got, "still here")
	}
	writeFrame(t, v6, []byte("six"))
	if got := readFrame(t, a, 4096); string(got) != "six" {
		t.Fatalf("a read %q, want %q - the sixth-loopback peer was not served", got, "six")
	}
}

// dialFrom dials addr binding the given source IP, so a test can produce two
// distinct source groups over loopback (127.0.0.1 and ::1).
func dialFrom(t *testing.T, addr, sourceIP string) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(sourceIP)}}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s from %s: %v", addr, sourceIP, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// The accept cap's grouping key is a pure function of the ADDRESS - pinned
// on its own so the accept-time rule's input is specified, not incidental:
// IPv4 masks to its /24, IPv6 to its /64 (the audit's bypass was a routed /64
// rotating addresses past a full-address cap), IPv4-mapped IPv6 unmaps to the
// same v4 group as its v4 self, two addresses inside one prefix share a group,
// and a nil address degenerates to a single group.
func TestConnGroupPrefixesTheSource(t *testing.T) {
	cases := []struct {
		ra   net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5}, "127.0.0.0/24"},
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 77), Port: 5}, "127.0.0.0/24"},
		{&net.TCPAddr{IP: net.IPv4(192, 168, 4, 9), Port: 5}, "192.168.4.0/24"},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 5}, "127.0.0.0/24"},
		{&net.TCPAddr{IP: net.ParseIP("::1"), Port: 5}, "::/64"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:3:4:5:6"), Port: 5}, "2001:db8:1:2::/64"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:ffff::1"), Port: 5}, "2001:db8:1:2::/64"},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := connGroup(tc.ra); got != tc.want {
			t.Fatalf("connGroup(%v) = %q, want %q - the accept cap's grouping is not address-prefix-canonical", tc.ra, got, tc.want)
		}
	}
}

// The per-frame entry cost the derivation includes must be the REAL cost of
// the queue's entry type: if sentFrame grows, MaxPinnedBytes silently
// under-counts and the documents' number becomes a lie again (audit N-2's
// re-opened term was exactly a per-frame cost left out). unsafe.Sizeof is the
// only way to pin a constant against a type, and it inspects no data - the
// relay still parses nothing.
func TestRelayQueuedFrameEntryCostMatchesTheType(t *testing.T) {
	if got := int(unsafe.Sizeof(sentFrame{})); got != queuedFrameEntryBytes {
		t.Fatalf("queuedFrameEntryBytes = %d but unsafe.Sizeof(sentFrame{}) = %d - the memory derivation no longer matches the queue's entry type", queuedFrameEntryBytes, got)
	}
}

// The byte budget alone cannot bound the queue's entry memory, because the
// minimum legal frame is one byte (wire.ReadFrame refuses only zero): a 1 MiB
// budget would admit a million one-byte entries. The FRAME cap is the
// structural bound, and this constructs the exact case - a byte budget far
// larger than the frame cap, filled with the smallest frames - so the fifth
// one-byte frame is refused by the COUNT, not the bytes. Fully socket-free
// and deterministic: no flood, no buffer, no schedule. Under the mutant that
// drops the count comparison from push, the fifth entry is admitted and the
// assertions below name the cap that failed to hold.
func TestRelayAFrameCapBoundsTheQueueEntries(t *testing.T) {
	const capFrames = 4
	r := New(Options{MaxFrameBytes: 32, MaxConns: 8, MaxConnsPerIP: 8, WriteQueueBytes: 1 << 20})
	sender := &conn{q: newSendQ(1<<20, 32, capFrames), dead: make(chan struct{})}
	wedged := &conn{q: newSendQ(1<<20, 32, capFrames), dead: make(chan struct{})}
	r.mu.Lock()
	r.conns[sender] = struct{}{}
	r.conns[wedged] = struct{}{}
	r.mu.Unlock()

	for i := 0; i < capFrames; i++ {
		r.forward(sender, []byte{byte(i)})
	}
	if got := wedged.q.queued(); got != capFrames {
		t.Fatalf("the queue holds %d frames after %d one-byte pushes at a %d-frame cap - the entry bound never filled", got, capFrames, capFrames)
	}
	if st := r.Stats(); st.Forwarded != capFrames || st.Dropped != 0 {
		t.Fatalf("at the frame cap the counters read Forwarded=%d/Dropped=%d, want %d/0 - the accounting drifted before the cap could bite", st.Forwarded, st.Dropped, capFrames)
	}
	r.forward(sender, []byte{0xff})
	if got := wedged.q.queued(); got != capFrames {
		t.Fatalf("a frame entered a queue already at its %d-frame cap (%d entries) - only the byte budget bounds the queue, and one-byte frames make that unbounded entry memory", capFrames, got)
	}
	if st := r.Stats(); st.Dropped != 1 {
		t.Fatalf("Stats().Dropped = %d after one push past the frame cap, want exactly 1 - the entry bound did not refuse", st.Dropped)
	}
}

// Two attacker CONNECTIONS from one host must not split a receiver's budget
// between them (audit N-2): the fair share is keyed on the SENDER's source
// group, so the second connection of one host lands in the same account as
// the first and cannot open a fresh share. The construction is fully
// deterministic and socket-free - the sender groups are set on hand-built
// connections - so no host's notion of "same IP" gets a vote. Under the
// mutant that keys the share on the connection, the second attacker frame is
// admitted, the queue reaches the byte budget, and the honest sender's frame
// is refused: the exact censorship the share exists to prevent.
//
// The divisor is not written by hand: it is the SAME sendersFor the relay's
// fan-out calls, applied to this test's registry, so the share is charged
// exactly the contending-account count the real path would derive (the two
// attacker connections are ONE account and the honest sender a second).
func TestRelayTwoConnectionsFromOneHostCannotSplitTheShare(t *testing.T) {
	const (
		frameBytes    = 100
		queueBytes    = 250
		maxFrameBound = 32
	)
	newConn := func(group string) *conn {
		return &conn{q: newSendQ(queueBytes, maxFrameBound, 64), dead: make(chan struct{}), srcGroup: group}
	}
	r := New(Options{MaxFrameBytes: maxFrameBound, MaxConns: 8, MaxConnsPerIP: 8, WriteQueueBytes: queueBytes})
	attacker1 := newConn("198.51.100.0/24")
	attacker2 := newConn("198.51.100.0/24") // same host/prefix, different connection
	honest := newConn("203.0.113.0/24")
	wedged := newConn("192.0.2.0/24") // the receiver whose queue they contend for
	r.mu.Lock()
	accounts := make(map[shareAccount]int, 4)
	for _, c := range []*conn{attacker1, attacker2, honest, wedged} {
		r.conns[c] = struct{}{}
		accounts[shareAccountOf(c)]++
	}
	r.mu.Unlock()
	senders := sendersFor(wedged, accounts) // 2: the attackers' group and the honest sender's
	if senders != 2 {
		t.Fatalf("sendersFor(wedged) = %d for this registry, want 2 - the constructed contention never formed", senders)
	}
	shareBytes := wedged.q.shareFor(senders) // 250/2 = 125

	frame := make([]byte, frameBytes)
	if !wedged.q.push(attacker1, frame, senders) {
		t.Fatalf("the first attacker frame was refused with the queue empty (budget %d, share %d) - the test's premise never formed", queueBytes, shareBytes)
	}
	if wedged.q.push(attacker2, frame, senders) {
		t.Fatalf("a second connection from the SAME host was admitted on its own share (queue %d bytes, attacker1 %d): two attacker connections split a receiver's budget between them", wedged.q.bytes, wedged.q.occupancy(attacker1))
	}
	if !wedged.q.push(honest, frame, senders) {
		t.Fatalf("the honest sender's frame was refused with the attackers holding only %d of %d bytes (share %d) - two connections from one host censored another sender", wedged.q.bytes, queueBytes, shareBytes)
	}
	// The refused connection's account is the SAME account as the first
	// attacker's (one host, one share), and it holds only the first frame:
	// the second was refused cleanly, charged nothing and enqueued nothing.
	if got := wedged.q.occupancy(attacker2); got != frameBytes {
		t.Fatalf("after the refusal the shared sender account holds %d bytes, want only the first attacker's %d - the refused frame was charged anyway", got, frameBytes)
	}
}

// progressConn is a net.Conn for the slow-reading-sink test: every Write
// SUCCEEDS (after writeDelay), so a deadline re-armed per frame at
// now+timeout would never fire - it is a sink that makes progress on every
// frame while never letting the backlog drain. It honours the write deadline
// it is given, and it owns no kernel buffer and no scheduling dependence: the
// delay and the deadline are the test's own values.
type progressConn struct {
	writeDelay time.Duration

	mu       sync.Mutex
	deadline time.Time
	closed   chan struct{}
	once     sync.Once
}

func (p *progressConn) Read([]byte) (int, error) {
	<-p.closed
	return 0, io.EOF
}

func (p *progressConn) Write(b []byte) (int, error) {
	p.mu.Lock()
	deadline := p.deadline
	p.mu.Unlock()
	time.Sleep(p.writeDelay)
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, io.ErrClosedPipe // the deadline the writer armed has passed
	}
	return len(b), nil
}

func (p *progressConn) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *progressConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (p *progressConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (p *progressConn) SetDeadline(time.Time) error {
	return nil
}
func (p *progressConn) SetReadDeadline(time.Time) error {
	return nil
}
func (p *progressConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	return nil
}

// A sink that reads slowly but STEADILY is reaped (audit N-2's second shape):
// the first write-deadline fix armed a fresh now+timeout before each frame, so
// a sink accepting a trickle of every frame made each write "succeed" and its
// full queue stayed pinned past many timeout periods. The fix anchors the
// deadline to the instant the queue became non-empty, so the whole backlog
// must clear within one WriteTimeout whatever the trickle. This test
// CONSTRUCTS that sink (no socket, no kernel buffer): every write takes
// writeDelay and succeeds, the queue is 50 frames deep (1s of steady
// progress), and the 100ms bound must still reap it. Under the pre-fix
// (now+timeout) deadline the queue drains in ~1s and the connection is never
// ended, so the wait below fails.
func TestRelayASlowReadingSinkIsReapedByTheProgressDeadline(t *testing.T) {
	const (
		writeTimeout = 100 * time.Millisecond
		writeDelay   = 20 * time.Millisecond
		queued       = 50
	)
	r := New(Options{
		MaxFrameBytes:    4096,
		MaxConns:         8,
		MaxConnsPerIP:    8,
		WriteQueueBytes:  1 << 20,
		WriteQueueFrames: 64,
		WriteTimeout:     writeTimeout,
	})
	nc := &progressConn{writeDelay: writeDelay, closed: make(chan struct{})}
	c := &conn{
		nc:       nc,
		q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
		dead:     make(chan struct{}),
		srcGroup: "192.0.2.0/24",
	}
	r.mu.Lock()
	r.conns[c] = struct{}{}
	r.perGroup[c.srcGroup]++
	r.mu.Unlock()

	for i := 0; i < queued; i++ {
		// One sender account only, so the capacity-relative share is the whole
		// 1 MiB budget and cannot be what binds - the state under test is the
		// queue's frame count and its age, not a share refusal.
		if !c.q.push(c, []byte{byte(i)}, 1) {
			t.Fatalf("frame %d of %d was refused while the queue was far below its frame cap - the slow-sink state never formed", i, queued)
		}
	}
	if d, ok := c.q.writeDeadline(writeTimeout); !ok || d.IsZero() {
		t.Fatalf("the constructed non-empty queue reports no deadline (ok=%v): the progress scenario never formed", ok)
	}

	r.wg.Add(1)
	go r.writer(c)
	select {
	case <-c.dead:
	case <-time.After(3 * time.Second):
		t.Fatalf("the slow-reading sink was never reaped: its queue stayed non-empty and every write made progress, but the deadline did not account for that - a per-write now+timeout never fires for a trickle (audit N-2)")
	}
	if st := r.Stats(); st.Conns != 0 {
		t.Fatalf("the sink's connection was finished but the registry still counts %d", st.Conns)
	}
}

// THE N-2 memory measurement, made against the DERIVED bound rather than a
// quoted number: MaxConnsPerIP connections from ONE source group - the
// audit's "8 connections from one source IP" shape - each with its queue
// filled to both caps by CONSTRUCTION with the smallest legal frame, which is
// the case a byte budget cannot bound (a 2 MiB budget of one-byte frames is
// ~2 million entries). The whole fan-out goes through the REAL forward path,
// so the payload slices are shared exactly as the relay shares them. The
// assertion is the derived per-group bound, not a hardcoded figure: measured
// heap after GC must sit under it. Pre-fix the entry arrays alone reached
// ~64 MiB per connection; here the frame cap holds them to 128 KiB each.
func TestRelayPinnedHeapStaysWithinTheDerivedBound(t *testing.T) {
	r := New(Options{}) // the shipped defaults
	perConnBound := r.opts.MaxPinnedBytes() / r.opts.MaxConns
	groupBound := perConnBound * r.opts.MaxConnsPerIP

	// Baseline BEFORE the connections exist, so the measurement includes the
	// entry rings each connection allocates at accept - the term the old
	// accounting missed - and not just the frames pushed after.
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	sender := &conn{
		q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
		dead:     make(chan struct{}),
		srcGroup: "198.51.100.0/24",
	}
	r.mu.Lock()
	r.conns[sender] = struct{}{}
	r.mu.Unlock()
	targets := make([]*conn, 0, r.opts.MaxConnsPerIP)
	for i := 0; i < r.opts.MaxConnsPerIP; i++ {
		c := &conn{
			q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
			dead:     make(chan struct{}),
			srcGroup: "198.51.100.0/24",
		}
		r.mu.Lock()
		r.conns[c] = struct{}{}
		r.mu.Unlock()
		targets = append(targets, c)
	}

	// One received frame per iteration, shared across the fan-out exactly as
	// forward shares it; the frame cap is reached at WriteQueueFrames.
	for i := 0; i < r.opts.WriteQueueFrames; i++ {
		r.forward(sender, []byte{byte(i)})
	}
	for i, c := range targets {
		if got := c.q.queued(); got != r.opts.WriteQueueFrames {
			t.Fatalf("target %d holds %d entries, want the full frame cap %d - the constructed worst case never formed", i, got, r.opts.WriteQueueFrames)
		}
		// A further one-byte frame is refused: the byte budget alone would
		// admit millions more, the frame cap is what bounds the entries. The
		// whole registry is one source group, so one sender account contends
		// (shareFor(1) = the whole 2 MiB budget) and the frame count is what
		// refuses.
		if c.q.push(sender, []byte{0}, 1) {
			t.Fatalf("target %d admitted a frame past its %d-entry cap - a one-byte frame flood would pin the entry memory the bound is supposed to cover", i, r.opts.WriteQueueFrames)
		}
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	measured := int64(after.HeapAlloc) - int64(base.HeapAlloc)
	if measured < 0 {
		measured = 0
	}
	t.Logf("MaxConnsPerIP=%d one-byte-frame queues with %d entries each: measured heap +%d bytes (%.2f MiB); derived group bound %d bytes (%.2f MiB)",
		r.opts.MaxConnsPerIP, r.opts.WriteQueueFrames, measured, float64(measured)/(1<<20), groupBound, float64(groupBound)/(1<<20))
	if measured > int64(groupBound) {
		t.Fatalf("the MaxConnsPerIP connections pinned %d bytes of heap, over the derived group bound %d - the documented arithmetic does not cover what the relay can hold", measured, groupBound)
	}
}

// The FULL registry is the other number the audit measured (1025.7 MiB
// pre-fix against a 128 MiB claim): MaxConns connections, one-byte frames,
// every queue filled to its frame cap by construction. Post-fix the entry
// rings are 32 x 128 KiB and the aggregate the documents quote is
// MaxPinnedBytes; the measurement must sit under it. The per-source-prefix
// grouping - the reason one host cannot hold this registry - is pinned as a
// pure function by TestConnGroupPrefixesTheSource above, and the accept cap's
// use of that key over real sockets by
// TestRelayPerSourcePrefixCapBitesAtAccept.
func TestRelayFullRegistryStaysWithinTheDerivedBound(t *testing.T) {
	r := New(Options{}) // the shipped defaults
	bound := int64(r.opts.MaxPinnedBytes())

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	sender := &conn{
		q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
		dead:     make(chan struct{}),
		srcGroup: "198.51.100.0/24",
	}
	r.mu.Lock()
	r.conns[sender] = struct{}{}
	r.mu.Unlock()
	targets := make([]*conn, 0, r.opts.MaxConns)
	for i := 0; i < r.opts.MaxConns; i++ {
		c := &conn{
			q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
			dead:     make(chan struct{}),
			srcGroup: "198.51.100.0/24",
		}
		r.mu.Lock()
		r.conns[c] = struct{}{}
		r.mu.Unlock()
		targets = append(targets, c)
	}
	for i := 0; i < r.opts.WriteQueueFrames; i++ {
		r.forward(sender, []byte{byte(i)})
	}
	for i, c := range targets {
		if got := c.q.queued(); got != r.opts.WriteQueueFrames {
			t.Fatalf("target %d holds %d entries, want %d - the full-registry worst case never formed", i, got, r.opts.WriteQueueFrames)
		}
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	measured := int64(after.HeapAlloc) - int64(base.HeapAlloc)
	if measured < 0 {
		measured = 0
	}
	t.Logf("MaxConns=%d one-byte-frame queues with %d entries each: measured heap +%d bytes (%.2f MiB); derived MaxPinnedBytes %d bytes (%.2f MiB)",
		r.opts.MaxConns, r.opts.WriteQueueFrames, measured, float64(measured)/(1<<20), bound, float64(bound)/(1<<20))
	if measured > bound {
		t.Fatalf("the full registry pinned %d bytes of heap, over the derived MaxPinnedBytes %d - the documented aggregate does not cover what the relay can hold", measured, bound)
	}
}
