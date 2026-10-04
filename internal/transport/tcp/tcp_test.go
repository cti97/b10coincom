package tcp

// The brief's rule, applied to every test here: they run over REAL TCP on
// loopback, never over an in-memory pipe, because the socket path is the
// deliverable. A pipe would prove the framing and nothing else. Listeners
// bind 127.0.0.1:0 and dial back through Addr(), so concurrent test runs get
// free ports instead of fighting over a hardcoded one.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

// recorder collects every message a transport delivers. The callback itself
// runs serialized (dispatch holds its lock across the call), but the test
// goroutine reads the slice between deliveries, so the append is guarded.
type recorder struct {
	mu   sync.Mutex
	msgs []transport.Message
}

func (r *recorder) collect(m transport.Message) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, m)
}

func (r *recorder) snapshot() []transport.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]transport.Message(nil), r.msgs...)
}

func (r *recorder) payloads() []string {
	ms := r.snapshot()
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, string(m.Data))
	}
	return out
}

// waitFor polls cond until it holds or the timeout expires, failing with the
// supplied context. Every "eventually" assertion in this file goes through
// it; nothing sleeps a fixed amount and hopes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", timeout, what)
}

// listen starts a transport bound to a free loopback port and closes it when
// the test ends, so a failing test cannot leave listeners - or goroutines -
// behind for the next test to trip over.
func listen(t *testing.T, opts Options) *TcpTransport {
	t.Helper()
	tp, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := tp.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	return tp
}

// waitPeersIs waits until a transport reports exactly the sorted peer list
// want, which is the handshake having completed from its side.
func waitPeersIs(t *testing.T, tp *TcpTransport, want string) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%s's peers becoming %s", tp.opts.LocalID, want), 5*time.Second, func() bool {
		return fmt.Sprint(tp.Peers()) == want
	})
}

// TestTwoTransportsExchangeAMessage is the brief's smoke test: listen, dial,
// broadcast, receive - with the peer's identity riding the message, because
// From is what the driver keys its tally on.
func TestTwoTransportsExchangeAMessage(t *testing.T) {
	a := listen(t, Options{LocalID: "a"})
	b := listen(t, Options{LocalID: "b"})

	if err := b.Dial(a.Addr().String()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeersIs(t, a, "[b]")
	waitPeersIs(t, b, "[a]")

	gotA, gotB := new(recorder), new(recorder)
	a.OnMessage(gotA.collect)
	b.OnMessage(gotB.collect)

	if err := a.Broadcast([]byte("ping")); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	waitFor(t, "b receiving ping", 5*time.Second, func() bool {
		return len(gotB.payloads()) == 1 && gotB.payloads()[0] == "ping"
	})
	if from := gotB.snapshot()[0].From; from != "a" {
		t.Fatalf("b received a message from %q, want \"a\"", from)
	}

	if err := b.Broadcast([]byte("pong")); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	waitFor(t, "a receiving pong", 5*time.Second, func() bool {
		return len(gotA.payloads()) == 1 && gotA.payloads()[0] == "pong"
	})

	// Peers() is iterated by position in consensus, so it must be sorted and
	// stable call to call - the Transport contract, pinned here too.
	for i := 0; i < 20; i++ {
		if got := a.Peers(); len(got) != 1 || got[0] != "b" {
			t.Fatalf("Peers() = %v, want [b] every call", got)
		}
	}
}

// TestBroadcastSkipsTheSender pins the invariant a validator's tally leans
// on: nobody is ever fed a message through a connection that claims to BE
// the local node. Over TCP the enforcement point is the handshake, not a
// filter inside Broadcast: a connection introducing itself with our own ID is
// refused outright (ErrSelfConnection), so the registry Broadcast iterates
// cannot contain the sender. The test builds exactly that situation with a
// second transport sharing a's ID, and proves nothing comes back through it.
func TestBroadcastSkipsTheSender(t *testing.T) {
	a := listen(t, Options{LocalID: "x"})
	y := listen(t, Options{LocalID: "y"})
	self, err := New(Options{LocalID: "x"}) // the same ID as a: the sender, dialing "itself"
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = self.Close() })

	// Both ends of this socket announce the same ID, so either end may be the
	// first to refuse it; both DO refuse it, so the dial must fail with SOME
	// error - the handshake fails as our own refusal or as the remote's (the
	// socket is closed on us mid-handshake either way). Asserting a specific
	// error here would race the two refusals.
	if err := self.Dial(a.Addr().String()); err == nil {
		t.Fatal("dialing a transport that shares our ID must fail: a validator was about to be fed its own messages back")
	}
	if err := y.Dial(a.Addr().String()); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	waitPeersIs(t, a, "[y]")
	time.Sleep(100 * time.Millisecond) // a grace window: an admitted self connection would surface here
	if got := a.Peers(); fmt.Sprint(got) != "[y]" {
		t.Fatalf("Peers() = %v: the self connection was admitted to the registry", got)
	}

	gotA, gotSelf, gotY := new(recorder), new(recorder), new(recorder)
	a.OnMessage(gotA.collect)
	self.OnMessage(gotSelf.collect)
	y.OnMessage(gotY.collect)

	if err := a.Broadcast([]byte("loop")); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	waitFor(t, "y receiving the broadcast", 5*time.Second, func() bool {
		return len(gotY.payloads()) == 1 && gotY.payloads()[0] == "loop"
	})
	time.Sleep(200 * time.Millisecond) // the control passed; a self-delivery would have arrived within this too
	if got := gotA.snapshot(); len(got) != 0 {
		t.Fatalf("the sender received its own broadcast: %+v", got)
	}
	if got := gotSelf.snapshot(); len(got) != 0 {
		t.Fatalf("the same-ID peer received the broadcast as if from a peer: %+v", got)
	}
}

// TestSendDeliversToExactlyOnePeer pins the unicast the BLOCK_SYNC pair of
// Task 4 travels on: a request/response between two peers, so every OTHER
// peer receives nothing, and an unknown peer errors instead of panicking or
// silently succeeding.
func TestSendDeliversToExactlyOnePeer(t *testing.T) {
	a := listen(t, Options{LocalID: "a"})
	b := listen(t, Options{LocalID: "b"})
	c := listen(t, Options{LocalID: "c"})

	if err := b.Dial(a.Addr().String()); err != nil {
		t.Fatalf("b Dial: %v", err)
	}
	if err := c.Dial(a.Addr().String()); err != nil {
		t.Fatalf("c Dial: %v", err)
	}
	waitPeersIs(t, a, "[b c]")

	gotA, gotB, gotC := new(recorder), new(recorder), new(recorder)
	a.OnMessage(gotA.collect)
	b.OnMessage(gotB.collect)
	c.OnMessage(gotC.collect)

	if err := b.Send("a", []byte("uni")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	waitFor(t, "a receiving the unicast from b", 5*time.Second, func() bool {
		return len(gotA.payloads()) == 1 && gotA.payloads()[0] == "uni"
	})
	if from := gotA.snapshot()[0].From; from != "b" {
		t.Fatalf("unicast arrived from %q, want \"b\"", from)
	}
	if err := a.Send("b", []byte("reply")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	waitFor(t, "b receiving the reply", 5*time.Second, func() bool {
		return len(gotB.payloads()) == 1 && gotB.payloads()[0] == "reply"
	})

	// The peers a unicast must NEVER reach: the bystander, after a grace
	// window far longer than any loopback delivery of a misrouted copy.
	time.Sleep(400 * time.Millisecond)
	if got := gotC.snapshot(); len(got) != 0 {
		t.Fatalf("unicast reached a bystander peer: %+v", got)
	}

	// Unknown peers error; they never panic and never silently succeed.
	if err := a.Send("nobody", []byte("?")); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("Send to unknown peer = %v, want ErrUnknownPeer", err)
	}
	// The sender's own ID is not a peer either: a validator never messages
	// itself over the wire (self connections are refused at the handshake).
	if err := a.Send("a", []byte("?")); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("Send to self = %v, want ErrUnknownPeer", err)
	}
	// b and c share no link: unicast crosses live connections only.
	if err := b.Send("c", []byte("?")); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("Send between unconnected peers = %v, want ErrUnknownPeer", err)
	}
}

// TestASlowReaderDoesNotBlockTheSender is THE property of this task, stated
// in time, not in hope: a peer whose reader is wedged inside a callback must
// not stall the sender's Broadcast past a generous bound.
//
// How it is built: r's dispatch runs its callback on its OWN reader
// goroutine; parking that callback stops r from reading its socket, the
// kernel receive buffer fills, s's writer blocks in Write, and s's bounded
// queue fills - after which every further Broadcast must return while r is
// still not reading. The assertions are: the whole batch returns within 3s
// (measured, not assumed), every single Broadcast within 500ms, and at least
// one enqueue was dropped past the bound - which only a BOUNDED queue can
// produce, so the green path carries its own proof.
func TestASlowReaderDoesNotBlockTheSender(t *testing.T) {
	r := listen(t, Options{LocalID: "r"})
	// The BOUND lives on the sender: it is s's per-connection queue that must
	// fill while r is not reading.
	s := listen(t, Options{LocalID: "s", WriteQueueSize: 8})

	if err := s.Dial(r.Addr().String()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeersIs(t, r, "[s]")

	var delivered atomic.Int64
	block := make(chan struct{}) // closed at the very end: until then r is not reading
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(block) }) }
	defer unblock() // even a failing test leaves no wedged reader behind
	r.OnMessage(func(m transport.Message) {
		delivered.Add(1)
		<-block
	})

	const msgSize = 256 << 10 // 256 KiB: a few messages overflow any loopback socket buffer
	msg := make([]byte, msgSize)

	type timing struct {
		n int
		d time.Duration
	}
	var mu sync.Mutex
	var timings []timing
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 60; i++ { // 15 MiB in flight: far beyond queue + kernel buffers
			start := time.Now()
			_ = s.Broadcast(msg)
			mu.Lock()
			timings = append(timings, timing{i, time.Since(start)})
			mu.Unlock()
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a batch of Broadcasts did not return within 3s while the peer was not reading: the sender was blocked on a slow peer")
	}

	// Exactly one frame was (or is being) processed by r; everything after it
	// piled up in kernel buffers and, past the bound, was dropped.
	waitFor(t, "r wedging in its first callback", 5*time.Second, func() bool {
		return delivered.Load() == 1
	})
	time.Sleep(100 * time.Millisecond) // nothing further may be dispatched after the wedged one
	if got := delivered.Load(); got != 1 {
		t.Fatalf("r processed %d messages while its reader was wedged; want exactly 1", got)
	}

	mu.Lock()
	var total time.Duration
	for _, tm := range timings {
		total += tm.d
		if tm.d > 500*time.Millisecond {
			mu.Unlock()
			t.Fatalf("Broadcast #%d took %v while the peer was not reading (must never block beyond its queue bound)", tm.n, tm.d)
		}
	}
	mu.Unlock()
	if total > 2*time.Second {
		t.Fatalf("the whole broadcast batch took %v against a wedged peer", total)
	}

	dropped := int64(0)
	s.mu.Lock()
	for _, c := range s.conns {
		dropped += int64(c.dropped.Load())
	}
	s.mu.Unlock()
	if dropped == 0 {
		t.Fatal("no enqueue was dropped: the write queue is not bounded (or loopback buffered 15 MiB for a peer that was not reading, which sockets do not do)")
	}
	unblock()
}

// TestARejectedFrameDoesNotKillTheConnection: a peer whose frame exceeds
// MaxFrameBytes has that ONE frame refused - and exactly that frame. Because
// the length prefix declares the frame's exact end, the reader skips those
// bytes and re-synchronises on the next frame, so the connection (and every
// message around the bad one) survives a misconfigured-but-honest peer.
func TestARejectedFrameDoesNotKillTheConnection(t *testing.T) {
	r := listen(t, Options{LocalID: "r", MaxFrameBytes: 512})

	cc, err := net.Dial("tcp", r.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	br := bufio.NewReader(cc)

	// Handshake: read r's ID, present ours.
	cc.SetReadDeadline(time.Now().Add(5 * time.Second))
	theirs, err := wire.ReadFrame(br, 4096)
	cc.SetReadDeadline(time.Time{})
	if err != nil || string(theirs) != "r" {
		t.Fatalf("handshake: got %q, %v", theirs, err)
	}
	if err := wire.WriteFrame(cc, []byte("hostile")); err != nil {
		t.Fatalf("writing handshake: %v", err)
	}

	got := new(recorder)
	r.OnMessage(got.collect)

	// An oversized frame with its FULL payload on the wire, immediately
	// followed by a good frame: the good one must arrive, in order, on the
	// same connection.
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 600) // 600 > the 512-byte bound; its full payload follows
	if _, err := cc.Write(hdr); err != nil {
		t.Fatalf("writing oversized header: %v", err)
	}
	if _, err := cc.Write(make([]byte, 600)); err != nil {
		t.Fatalf("writing oversized payload: %v", err)
	}
	if err := wire.WriteFrame(cc, []byte("good")); err != nil {
		t.Fatalf("writing good frame: %v", err)
	}

	waitFor(t, "the good frame arriving after the rejected one", 5*time.Second, func() bool {
		return len(got.payloads()) == 1 && got.payloads()[0] == "good"
	})
	if n := r.droppedOversized.Load(); n != 1 {
		t.Fatalf("the oversized-skip path ran %d times, want exactly 1", n)
	}

	// And the connection still works in BOTH directions: r's broadcast reaches
	// the hostile client, which is on the far side of the rejection.
	if err := r.Broadcast([]byte("reply")); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	cc.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := wire.ReadFrame(br, 512)
	cc.SetReadDeadline(time.Time{})
	if err != nil || string(reply) != "reply" {
		t.Fatalf("the connection did not deliver r's broadcast after rejecting a frame: got %q, %v", reply, err)
	}
	if msgs := got.snapshot(); len(msgs) != 1 {
		t.Fatalf("the oversized frame was delivered as a message: %+v", msgs)
	}
}

// TestReconnectUsesBackoff connects to a raw listener the test fully
// controls, kills the connection from that side, and watches a real redial
// come back. Then it makes the redials FAIL for a while (listener closed) and
// watches the delay grow across consecutive failed attempts - recorded per
// attempt, so growth is measured, not assumed - and finally reopens the
// listener on the same port to prove the recovery section 6.6 named: the
// relay restarts, every validator redials.
func TestReconnectUsesBackoff(t *testing.T) {
	rl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := rl.Addr().String()
	accepted := make(chan net.Conn, 8)
	// The raw end answers every handshake the moment it is accepted, in the
	// background: it must, or a blocking Dial would deadlock against its own
	// handshake deadline while the test is still inside tp.Dial.
	var trackMu sync.Mutex
	var live []net.Conn // handshake-complete raw sockets, in accept order
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case c := <-accepted:
				if err := rawHandshake(c); err != nil {
					c.Close()
					continue
				}
				trackMu.Lock()
				live = append(live, c)
				trackMu.Unlock()
			case <-done:
				return
			}
		}
	}()
	go acceptAndReadIDs(rl, accepted)
	defer func() { _ = rl.Close() }()

	tp, err := New(Options{
		LocalID:     "t",
		BackoffBase: 20 * time.Millisecond,
		BackoffMax:  500 * time.Millisecond,
		Rand:        rand.New(rand.NewSource(9)),
		DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tp.Close() })

	dropped := func() {
		t.Helper()
		trackMu.Lock()
		defer trackMu.Unlock()
		for _, c := range live {
			_ = c.Close()
		}
		live = nil
	}
	if err := tp.Dial(addr); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// The raw end may not have finished its half of the handshake when Dial
	// returns (Dial waits for tp's OWN half); the registry entry appears once
	// both ends have spoken.
	waitFor(t, "the first raw connection being served", 5*time.Second, func() bool {
		trackMu.Lock()
		defer trackMu.Unlock()
		return len(live) == 1
	})
	waitPeersIs(t, tp, "[srv]")

	// Phase 1: the peer disappears; one real redial restores it. The redial
	// is attempt 1 of the curve (a live connection resets the counter), so
	// its delay must sit in the first-attempt window [base/2, base).
	dropped()
	// After the drop the raw side tracks exactly ONE new socket again: the
	// redial. (live was emptied by dropped(); do not wait for a growing
	// count, wait for the redial to have been served.)
	waitFor(t, "a redialled raw connection being served", 5*time.Second, func() bool {
		trackMu.Lock()
		defer trackMu.Unlock()
		return len(live) == 1
	})
	waitPeersIs(t, tp, "[srv]")
	if d := time.Duration(tp.lastRedialDelay.Load()); d < 10*time.Millisecond || d >= 20*time.Millisecond {
		t.Fatalf("the first redial waited %v; want the attempt-1 window [10ms, 20ms) - a redial that did not consult the backoff", d)
	}

	// Phase 2: make every redial FAIL (no listener; the live socket closed)
	// and watch the recorded delays grow. Successive attempts draw from
	// DISJOINT windows ([10,20), [20,40), [40,80)...), so the distinct
	// sequence observed is strictly increasing by construction; a constant
	// delay - the mutant this guards against - flattens it.
	rl.Close()
	dropped() // the live socket dies too: the maintainer redials against no listener
	var observed []time.Duration
	last := time.Duration(0)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d := time.Duration(tp.lastRedialDelay.Load()); d != last {
			observed = append(observed, d)
			last = d
		}
		if len(observed) >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(observed) < 3 {
		t.Fatalf("only %d distinct redial delays observed (%v): the maintainer is not cycling through the backoff curve", len(observed), observed)
	}
	for i := 1; i < len(observed); i++ {
		if observed[i] <= observed[i-1] {
			t.Fatalf("redial delays did not grow across failed attempts: %v", observed)
		}
	}

	// Phase 3: the listener "restarts" on the SAME port; the next redial
	// finds it and the peer returns - full recovery through the backoff path.
	rl2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("reopening on %s: %v", addr, err)
	}
	defer func() { _ = rl2.Close() }()
	go acceptAndReadIDs(rl2, accepted)
	waitPeersIs(t, tp, "[srv]")
}

// rawHandshake reads the transport's ID frame and answers with "srv",
// completing the handshake from the raw side.
func rawHandshake(c net.Conn) error {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	id, err := wire.ReadFrame(bufio.NewReader(c), 4096)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("reading the dialer's ID: %w", err)
	}
	if string(id) != "t" {
		return fmt.Errorf("unexpected ID %q", id)
	}
	return wire.WriteFrame(c, []byte("srv"))
}

// acceptAndReadIDs is the raw remote end's accept loop; each connection is
// handed to the test, which completes its handshake through serveHandshake
// when (and if) it chooses.
func acceptAndReadIDs(l net.Listener, accepted chan<- net.Conn) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case accepted <- c:
		default:
			c.Close()
		}
	}
}

// TestDeliveryIsSerialized pins the dispatch concurrency contract: however
// many peers send at once, at most ONE OnMessage callback ever runs
// concurrently. Consensus's engine is a single-threaded state machine - the
// property replay is built on - and several reader goroutines feeding it at
// once would corrupt that. Any future parallelism here is a Task-6-breaking
// change and must come with a driver-level lock, not a silent transport one.
func TestDeliveryIsSerialized(t *testing.T) {
	r := listen(t, Options{LocalID: "r"})
	senders := make([]*TcpTransport, 4)
	for i, id := range []transport.PeerID{"s0", "s1", "s2", "s3"} {
		senders[i] = listen(t, Options{LocalID: id})
		if err := senders[i].Dial(r.Addr().String()); err != nil {
			t.Fatalf("%s Dial: %v", id, err)
		}
	}
	waitPeersIs(t, r, "[s0 s1 s2 s3]")

	var cur, maxConcurrent atomic.Int64
	done := make(chan struct{})
	var got atomic.Int64
	r.OnMessage(func(m transport.Message) {
		now := cur.Add(1)
		for {
			old := maxConcurrent.Load()
			if now <= old || maxConcurrent.CompareAndSwap(old, now) {
				break
			}
		}
		got.Add(1)
		cur.Add(-1)
		if got.Load() == 4*100 { // the last message releases the waiter
			close(done)
		}
	})

	for _, s := range senders {
		s := s
		go func() {
			for i := 0; i < 100; i++ {
				_ = s.Broadcast([]byte("x"))
			}
		}()
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("only %d of 400 messages were dispatched", got.Load())
	}
	if m := maxConcurrent.Load(); m != 1 {
		t.Fatalf("OnMessage ran %d-deep concurrently: delivery is not serialized, and the single-threaded engine contract is broken", m)
	}
}

// TestCloseIsIdempotentAndStopsGoroutines runs under -count=20 to show it is
// not a flaky race: Close twice returns cleanly, nothing escapes a closed
// transport, and every goroutine the transport started (accept loop,
// maintainers, tracked inbound handshakes, one reader and one writer per
// connection) is gone afterwards. The leak check is a STACK SCAN, not a count
// against a NumGoroutine baseline: the old baseline+2 allowance could not see
// the exact leaks this test exists to catch (a leaked reader/writer pair lands
// ON a +2 margin, a leaked maintainer on +1/+2), while unrelated runtime
// goroutines (GC workers) made a tighter count noisy. A frame named
// internal/transport/tcp. can belong to nothing but a still-running transport
// goroutine, so ONE leaked goroutine is detected, whatever runs elsewhere.
func TestCloseIsIdempotentAndStopsGoroutines(t *testing.T) {
	a := listen(t, Options{LocalID: "a", BackoffBase: 5 * time.Millisecond, BackoffMax: 20 * time.Millisecond})
	b := listen(t, Options{LocalID: "b"})
	// ONE direction of dialing: a.AddPeer alone connects the pair, because a
	// connection registers at BOTH ends (each side learns the other's ID from
	// the handshake). A second Dial here would hit ErrDuplicatePeer - the
	// registry refusing a second connection to a connected peer - which is
	// correct behavior, just not what this test is about.
	if err := a.AddPeer(b.Addr().String()); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	waitPeersIs(t, a, "[b]")
	waitPeersIs(t, b, "[a]")

	if err := a.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close (must be idempotent): %v", err)
	}
	// The transport is closed: nothing more arrives, nothing new connects.
	got := new(recorder)
	b.OnMessage(got.collect)
	if err := a.Broadcast([]byte("after close")); err != nil {
		t.Fatalf("Broadcast after Close: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if len(got.snapshot()) != 0 {
		t.Fatal("a broadcast escaped a closed transport")
	}
	// Every transport this test made is closed before checking: a's
	// maintainer exited through quit (Close is the only thing that ends a
	// reconnection loop), and the per-connection readers/writers exited
	// through their closed sockets.
	if err := b.Close(); err != nil {
		t.Fatalf("peer transport Close: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		leaked := runningTransportGoroutines()
		if leaked == 0 {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			n := runtime.Stack(buf, true)
			t.Fatalf("%d transport goroutine(s) still running after both transports closed:\n%s", leaked, buf[:n])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// runningTransportGoroutines counts goroutines with a frame inside this
// package - i.e. transport work that is still running. Blocks belonging to the
// CALLING test goroutine report themselves as tcp.Test* frames and are not
// leaks; everything else matching is.
func runningTransportGoroutines() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	count := 0
	for _, block := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(block, "internal/transport/tcp.") && !strings.Contains(block, "tcp.Test") {
			count++
		}
	}
	return count
}

// TestCloseWaitsForInFlightHandshakes pins what Close's doc claims about a
// connection that connected but never finished its handshake: the adopt
// goroutine and its socket are TRACKED, so Close waits for them instead of
// leaving them alive for up to a HandshakeTimeout after close returned. The
// wait is bounded by that same deadline - Close returns within it, and no
// transport goroutine survives the return.
func TestCloseWaitsForInFlightHandshakes(t *testing.T) {
	tp := listen(t, Options{LocalID: "t", HandshakeTimeout: 300 * time.Millisecond})

	raw, err := net.Dial("tcp", tp.Addr().String())
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	// It says NOTHING: once accepted, the inbound adopt goroutine sits in its
	// deadline-bounded handshake read - exactly the goroutine that used to
	// outlive Close untracked. Wait for it to actually BE there (stack scan),
	// so the Close below waits on the tracked goroutine rather than racing
	// the accept loop for a conn still sitting in the backlog.
	waitFor(t, "the inbound adopt goroutine being in its handshake read", 5*time.Second, func() bool {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		return strings.Contains(string(buf[:n]), "tcp.(*TcpTransport).adopt(")
	})

	start := time.Now()
	if err := tp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	elapsed := time.Since(start)
	// Close cannot return before the tracked in-flight handshake ends (its
	// read unblocks at the 300ms deadline), and must not return much later.
	// Untracked, Close returns in microseconds - far below the 100ms floor.
	if elapsed < 100*time.Millisecond {
		t.Fatalf("Close returned after %v, while the inbound handshake was still in flight: the adopt goroutine (and its socket) outlives Close", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Close took %v against a 300ms handshake bound", elapsed)
	}
	if leaked := runningTransportGoroutines(); leaked != 0 {
		t.Fatalf("%d transport goroutine(s) still running after Close waited", leaked)
	}
}

// TestBackoffGrowsExponentiallyWithSeededJitter pins backoff.go with no
// socket involved: one seed, one sequence. Three assertions carry the
// property: the sequence is strictly increasing while the cap is not reached
// (a CONSTANT backoff fails here, which is the mutant this test exists to
// kill), every delay sits in the [d/2, d) jitter window of its
// exponentially-doubling base, and the same seed reproduces itself exactly -
// which is only possible if the jitter genuinely comes from the passed-in
// *rand.Rand and not from a clock-seeded global.
func TestBackoffGrowsExponentiallyWithSeededJitter(t *testing.T) {
	base, max := 10*time.Millisecond, 640*time.Millisecond
	const attempts = 7 // attempts 1..7: 10,20,40,80,160,320,640 ms - all at or below the cap

	run := func() []time.Duration {
		b := NewBackoff(base, max, rand.New(rand.NewSource(42)))
		out := make([]time.Duration, 0, attempts)
		for i := 1; i <= attempts; i++ {
			out = append(out, b.Next(i))
		}
		return out
	}
	delays := run()

	for i := 1; i < len(delays); i++ {
		if delays[i] <= delays[i-1] {
			t.Fatalf("the delay sequence is not strictly increasing: %v", delays)
		}
	}
	want := base
	for i, d := range delays {
		if d < want/2 || d >= want {
			t.Fatalf("attempt %d delay %v outside its [%v, %v) jitter window (full sequence %v)", i+1, d, want/2, want, delays)
		}
		want *= 2
		if want > max {
			want = max // attempt 7 doubles onto the cap and stays flat
		}
	}

	if again := run(); fmt.Sprint(again) != fmt.Sprint(delays) {
		t.Fatalf("the same seed produced a different delay sequence (%v then %v): the jitter is not seeded from the given *rand.Rand", again, delays)
	}
	// A nil rng has nothing to draw from: documented as the no-jitter case.
	if d := NewBackoff(base, max, nil).Next(3); d != 0 {
		t.Fatalf("nil rng delay = %v, want 0 (no jitter without a source)", d)
	}
}

// TestSymmetricBootBothAddPeerLeavesOneConnection is the duplicate-policy
// proof on its realistic trigger: two nodes whose static peer lists name each
// other both AddPeer at boot, so both dial each other - a cross-dial. The old
// duplicate path closed the incumbent AND the newcomer, leaving ZERO
// connections and no maintainer anywhere: a silent permanent partition the
// reviewer reproduced in 2 of 3 runs. The policy (newcomerWins) must converge
// both ends on the SAME surviving socket, so exactly one healthy connection
// exists per side and the link carries traffic both ways. Every run here is
// independent; the check is meaningless green-once, so it repeats itself.
//
// The sends wait for SETTLEMENT before firing. The two ends resolve their
// duplicates independently and microseconds apart; a unicast issued while one
// side's resolution is still in flight can be written into the very socket
// that side's policy is about to discard - the peer's end of it already
// closed - and the frame dies in flight while Send reports success. That was
// the CI failure: a.Send nil, b receiving nothing, both registries
// individually correct. The rank's fixed point is observable
// deterministically, and once it is installed at both ends no further
// registry transition can happen (both entries are unbeatable under
// newcomerWins), so the sends target the settled link and the two waitFors
// are proofs of delivery rather than bets on a scheduling accident. The gate
// does not widen any timeout; it replaces a race the test could only win by
// luck with a state the transport guarantees will arrive.
func TestSymmetricBootBothAddPeerLeavesOneConnection(t *testing.T) {
	for run := 0; run < 30; run++ {
		t.Run(fmt.Sprint(run), func(t *testing.T) {
			a := listen(t, Options{LocalID: "a"})
			b := listen(t, Options{LocalID: "b"})
			recA, recB := new(recorder), new(recorder)
			a.OnMessage(recA.collect)
			b.OnMessage(recB.collect)

			// Boot burst: the two AddPeers race from a barrier, so the
			// maintainers' cross-dials genuinely overlap instead of
			// happening to serialize.
			start := make(chan struct{})
			var spawned sync.WaitGroup
			errs := make(chan error, 2)
			for _, add := range []func() error{
				func() error { return a.AddPeer(b.Addr().String()) },
				func() error { return b.AddPeer(a.Addr().String()) },
			} {
				add := add
				spawned.Add(1)
				go func() {
					defer spawned.Done()
					<-start
					errs <- add()
				}()
			}
			close(start)
			spawned.Wait()
			close(errs)
			for err := range errs {
				if err != nil && !isSocketClosed(err) {
					t.Fatalf("AddPeer: %v", err)
				}
			}

			// Deterministic settlement: exactly one connection each side, and
			// the two entries are the SAME physical link (the smaller end's
			// dial). The failure message names the socket each side kept.
			ca, cb := crossPairSettledConn(t, a, b)
			if ca == nil || cb == nil {
				t.Fatalf("the cross-dial never settled one shared link: a keeps %s, b keeps %s; want the same two sockets, with a keeping its dial and b the accept of it",
					heldConnDesc(a, "b"), heldConnDesc(b, "a"))
			}

			// The survivor is a working link, not a corpse in the registry:
			// unicast must cross it in BOTH directions.
			if err := a.Send("b", []byte("ab")); err != nil {
				t.Fatalf("a Send over the surviving link: %v", err)
			}
			if err := b.Send("a", []byte("ba")); err != nil {
				t.Fatalf("b Send over the surviving link: %v", err)
			}
			waitFor(t, "b receiving a's unicast", 5*time.Second, func() bool {
				pl := recB.payloads()
				return len(pl) == 1 && pl[0] == "ab"
			})
			waitFor(t, "a receiving b's unicast", 5*time.Second, func() bool {
				pl := recA.payloads()
				return len(pl) == 1 && pl[0] == "ba"
			})
		})
	}
}

// crossPairSettledConn waits until a's and b's duplicate resolutions for EACH
// OTHER have both completed, and returns the two entries (a's conn for "b",
// b's conn for "a") whose endpoint addresses name the same two sockets.
//
// Fixed point - all checkable under each transport's mutex:
//   - each registry holds exactly ONE entry for the peer;
//   - the two entries CROSS-MATCH: a.conn's LocalAddr == b.conn's RemoteAddr
//     and a.conn's RemoteAddr == b.conn's LocalAddr, so a and b hold the two
//     ends of one physical TCP connection - the cross-side identity the
//     transport is judged on;
//   - the direction is the rank's: a (the smaller id) keeps the conn it
//     DIALLED, b keeps the accept of a's dial. This signature is what makes
//     the wait HONEST: an intermediate state can already satisfy the
//     count and the cross-match while a supersede is still pending elsewhere
//     (e.g. both ends briefly converged on the pair a has not yet resolved
//     away from), so the direction check separates the fixed point from a
//     snapshot mid-churn. Every later arrival loses the rank against these
//     two, so the pair cannot be unseated after it is observed.
//
// The gate runs in the CI test before any send; it fails (bounded timeout)
// with the sockets each side kept NAMED if the churn ever fails to converge.
func crossPairSettledConn(t *testing.T, a, b *TcpTransport) (cAB, cBA *conn) {
	t.Helper()
	waitFor(t, "the cross-dial settling on one shared link (a keeps its dial, b the accept of it)", 5*time.Second, func() bool {
		ca, ok := crossPairSettled(a, "b", true)
		if !ok {
			return false
		}
		cb, ok := crossPairSettled(b, "a", false)
		if !ok {
			return false
		}
		// The two entries are the two ends of one physical connection:
		// local/remote addresses cross-match.
		if ca.nc.LocalAddr().String() != cb.nc.RemoteAddr().String() ||
			ca.nc.RemoteAddr().String() != cb.nc.LocalAddr().String() {
			return false
		}
		cAB, cBA = ca, cb
		return true
	})
	a.mu.Lock()
	defer a.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	return cAB, cBA
}

// crossPairSettled reads one end of the settled pair under tp.mu: the
// registry names exactly the peer, its single entry is the direction
// wantDial demands (true: this end keeps its own dial; false: it keeps the
// accept of the peer's dial), and its remote address is the peer's listener
// - only the winning dial's socket names the listener; an accepted socket
// dials from an ephemeral port.
func crossPairSettled(tp *TcpTransport, peer transport.PeerID, wantDial bool) (*conn, bool) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	// Exactly one live entry overall: a second conn to ANY peer means the
	// duplicate churn is still mid-flight.
	if len(tp.conns) != 1 {
		return nil, false
	}
	c, ok := tp.conns[peer]
	if !ok {
		return nil, false
	}
	if c.dialled != wantDial {
		return nil, false
	}
	return c, true
}

// heldConnDesc renders the single connection x holds for peer (locked), or a
// summary of a empty registry, for failure messages that name the sockets
// each side kept.
func heldConnDesc(x *TcpTransport, peer transport.PeerID) string {
	x.mu.Lock()
	defer x.mu.Unlock()
	c, ok := x.conns[peer]
	if !ok {
		return fmt.Sprintf("%s: NOTHING (conns=%d)", x.opts.LocalID, len(x.conns))
	}
	return fmt.Sprintf("%s->%s (dialled=%v, superseded=%v)", c.nc.LocalAddr(), c.nc.RemoteAddr(), c.dialled, c.superseded)
}

// TestSendMustNotReportSuccessIntoATornDownConnection pins the Send side of
// the registry's atomicity - the exact mechanism behind the cross-dial CI
// failure's receive half. Its shape there: both registries held one healthy
// looking connection, a's Send returned nil, and b decoded nothing - because
// a's resolution was still in flight, so the unicast was written into the
// socket b's OWN policy had already discarded, a link the two ends held
// DISAGREEING copies of. Deterministically, that state is a connection whose
// teardown has happened while the registry still names it: finish's registry
// exit (the identity-checked delete) now shares one critical section with
// close(dead), so the product cannot serve such a conn to Send; this test
// builds it by hand - running teardown's first half through the same
// sync.Once finish uses, deliberately stopping short of the registry exit -
// and demands Send REFUSE it.
//
// On the pre-fix code (teardown split from the registry exit, Send's lookup
// and enqueue outside the mutex across both) this Send reported nil: the
// frame was accepted into a connection whose writer was already gone and can
// never be written, with no error at any layer - the silent loss the CI run
// hit. Under the fix, Send says so: ErrUnknownPeer, the caller's retry path.
func TestSendMustNotReportSuccessIntoATornDownConnection(t *testing.T) {
	tp := listen(t, Options{LocalID: "a"})

	// A raw remote end announcing "b": a plain inbound connection, the ACCEPT
	// direction, no maintainer anywhere - the shape a duplicate resolution's
	// aftermath leaves behind (the losing directions have no maintainer by
	// design; F2 releases them).
	rc, err := net.Dial("tcp", tp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if err := wire.WriteFrame(rc, []byte("b")); err != nil {
		t.Fatal(err)
	}
	// Both handshake sides write before reading, so the read here is the
	// transport's greeting; the remote idles with its socket open.
	rc.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := wire.ReadFrame(bufio.NewReader(rc), 4096)
	if err != nil || string(got) != "a" {
		t.Fatalf("the handshake was not answered with the transport's identity: got %q, err %v", got, err)
	}
	rc.SetReadDeadline(time.Time{})
	waitPeersIs(t, tp, "[b]")

	// Freeze the mid-teardown state: the dead-close and the socket close go
	// through finish's own once, exactly as finish writes them - but WITHOUT
	// the registry exit - which is the exact interleave the split teardown
	// exposed to Send, held open deterministically instead of for a
	// microsecond race.
	tp.mu.Lock()
	c := tp.conns["b"]
	tp.mu.Unlock()
	if c == nil {
		t.Fatalf("the registry does not hold the peer")
	}
	c.finishOnce.Do(func() {
		close(c.dead)
		_ = c.nc.Close()
		// The registry exit deliberately NOT here.
	})

	// The torn-down conn is still named in the registry. Send must refuse it
	// rather than report success for a frame it can never write.
	if err := tp.Send("b", []byte("probe")); err == nil {
		kept := heldConnDesc(tp, "b")
		t.Fatalf("Send reported success into a connection the transport has torn down (peer's end: closed; ours, still named in the registry: %s): the frame is silently lost with no error at any layer - a keeps believing a dead link is alive while b's side of it is gone: the two ends keep different sockets", kept)
	} else if !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("the torn-down connection was refused with %v, want an ErrUnknownPeer-shaped error the caller can retry against", err)
	}

	// No follow-up assertion about the registry here: the frozen state above
	// is the test's own construction (it fires finish's once by hand), so the
	// registry exit it simulates skipping is the test's, not the product's.
	// The fix's atomic registry exit is what keeps this state UNREACHABLE in
	// the product - see finish's doc; the Send refusal is the gate this test
	// can hold still and read.
}

// isSocketClosed reports whether err is the close noise a connection call can
// return when a racing Close tears the listener down - the only failure a
// boot burst may legitimately produce on this loopback.
func isSocketClosed(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && errors.Is(oe.Err, net.ErrClosed)
}

// TestConcurrentSameIDHandshakesLeaveOneConnection drives the duplicate path
// the way the race detector found it: eight handshakes naming the SAME peer
// id, arriving together on an empty registry. Assertions, all of which the
// pre-fix code fails: exactly one connection survives (not zero), every loser
// socket is closed cleanly (they read EOF, not hangs), the survivor carries
// traffic (Send resolves, the probe is received exactly once) - and under
// -race, no unsynchronised write to a superseded connection's flag anywhere
// in the churn (the pre-fix write sat after t.mu.Unlock; this test is what
// makes the race detector's verdict reproducible).
func TestConcurrentSameIDHandshakesLeaveOneConnection(t *testing.T) {
	for round := 0; round < 3; round++ {
		t.Run(fmt.Sprint(round), func(t *testing.T) {
			r := listen(t, Options{LocalID: "r"})

			const dialers = 8
			type fate struct {
				eof   bool // socket was closed on us: this candidate lost
				probe bool // received r's post-install probe: this one won
			}
			fates := make(chan fate, dialers)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := 0; i < dialers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					nc, err := net.Dial("tcp", r.Addr().String())
					if err != nil {
						return // a failed dial simply never reports a fate; counted below
					}
					defer nc.Close()
					<-start
					if err := wire.WriteFrame(nc, []byte("dup")); err != nil {
						return
					}
					var f fate
					br := bufio.NewReader(nc)
					nc.SetReadDeadline(time.Now().Add(5 * time.Second))
					for {
						frame, err := wire.ReadFrame(br, 4096)
						if err != nil {
							f.eof = true // EOF/reset: r closed this candidate
							fates <- f
							return
						}
						if string(frame) == "probe" {
							f.probe = true // got r's unicast: the surviving one
							fates <- f
							return
						}
						// anything else is r's handshake greeting; keep reading
					}
				}()
			}
			close(start)

			// Exactly one peer, and exactly one connection behind it.
			waitPeersIs(t, r, "[dup]")
			if n := len(r.conns); n != 1 {
				t.Fatalf("registry holds %d connections for a single duplicated id; want exactly 1", n)
			}

			// Probe the survivor: exactly one of the eight sockets is still
			// being served, so exactly one client can ever see this frame.
			if err := r.Send("dup", []byte("probe")); err != nil {
				t.Fatalf("Send to the surviving duplicate peer: %v", err)
			}
			wg.Wait()
			close(fates)
			var got []fate
			for f := range fates {
				got = append(got, f)
			}
			if len(got) != dialers {
				t.Fatalf("only %d of %d candidates reported a fate (dials failed or handshakes stalled)", len(got), dialers)
			}
			wins, eofs := 0, 0
			for _, f := range got {
				if f.probe {
					wins++
				}
				if f.eof {
					eofs++
				}
			}
			if wins != 1 {
				t.Fatalf("%d candidates received the probe; every duplicate but ONE must be closed, one served", wins)
			}
			if eofs != dialers-1 {
				t.Fatalf("%d loser sockets were closed cleanly, want %d", eofs, dialers-1)
			}
		})
	}
}

// TestSupersededMaintainerReleasesItsRegistration pins F2: when a maintainer's
// connection is superseded (here: the transport's own dial loses a duplicate
// race to the peer's incoming dial, which the rank gives to the remote because
// the remote's id is smaller), the maintainer must go dormant AND release its
// address registration. The pre-fix code kept the stale entry, so Dial was
// waved off as idempotent "nil" while nothing redialled - a peer set that
// stayed empty forever. After the release, a fresh Dial must spawn a real
// maintainer and reconnect.
func TestSupersededMaintainerReleasesItsRegistration(t *testing.T) {
	// A raw remote end, fully controlled: answers every handshake as "aaa"
	// and holds its sockets open until closed or abandoned.
	rl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rl.Close() })
	go func() {
		for {
			nc, aerr := rl.Accept()
			if aerr != nil {
				return
			}
			go func(nc net.Conn) {
				defer nc.Close()
				br := bufio.NewReader(nc)
				nc.SetReadDeadline(time.Now().Add(5 * time.Second))
				id, rerr := wire.ReadFrame(br, 4096)
				nc.SetReadDeadline(time.Time{})
				if rerr != nil || string(id) != "zzz" {
					return
				}
				if werr := wire.WriteFrame(nc, []byte("aaa")); werr != nil {
					return
				}
				var sink [16]byte
				for {
					if _, rerr = nc.Read(sink[:]); rerr != nil {
						return
					}
				}
			}(nc)
		}
	}()
	addr := rl.Addr().String()

	// zzz > aaa, so per newcomerWins the peer's dial (the smaller id's dial
	// wins the rank) supersedes this transport's own outbound - the
	// maintainer's connection is the one replaced.
	tp, err := New(Options{LocalID: "zzz"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	// It must also listen: the superseding duplicate arrives as an INBOUND
	// connection on this transport's own listener.
	if err := tp.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tp.Dial(addr); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitPeersIs(t, tp, "[aaa]")

	// The duplicate: an inbound connection announcing the same peer id. It
	// outranks our outbound, so our maintainer's connection is superseded.
	hc, err := net.Dial("tcp", tp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hc.Close() })
	if err := wire.WriteFrame(hc, []byte("aaa")); err != nil {
		t.Fatal(err)
	}
	waitPeersIs(t, tp, "[aaa]") // still exactly one connection - the winner's

	// The registration must be RELEASED (the winner here has no local
	// maintainer - the peer's own dial holds the link from ITS side - so
	// release, not transfer, is what honest bookkeeping looks like). A stale
	// entry here is precisely the lie that made Dial return nil forever.
	waitFor(t, "the superseded maintainer's registration being released", 2*time.Second, func() bool {
		tp.mu.Lock()
		defer tp.mu.Unlock()
		return len(tp.outbounds) == 0
	})

	// Kill the winner from the raw side. Nothing redials - the registration
	// is gone, and pretending otherwise would be the lie above. The peer set
	// drains to empty and STAYS empty until someone dials again.
	hc.Close()
	waitPeersIs(t, tp, "[]")

	// Now Dial must spawn a FRESH maintainer: a maintainer exists again, and
	// the reconnection the transport promises actually happens.
	if err := tp.Dial(addr); err != nil {
		t.Fatalf("Dial after the supersede released the registration: %v", err)
	}
	waitPeersIs(t, tp, "[aaa]")
	if err := tp.Send("aaa", []byte("sync")); err != nil {
		t.Fatalf("Send over the re-established link: %v", err)
	}
}

// TestBackoffClampsAtMax pins the ceiling of the reconnection curve - clamped
// at BackoffMax, including the overshoot: a base/max pair that is not a
// power-of-two apart doubles PAST the max before the clamp pulls it back
// (20ms -> 40ms against a 25ms ceiling), and a base larger than the max must
// be pulled DOWN to it. Before this test existed the clamp was pinned by
// nothing - deleting it left the whole suite green while the curve ignored
// its ceiling.
func TestBackoffClampsAtMax(t *testing.T) {
	const base, max = 20 * time.Millisecond, 25 * time.Millisecond
	b := NewBackoff(base, max, rand.New(rand.NewSource(1)))
	for attempt := 1; attempt <= 50; attempt++ { // far past where the curve stops growing
		d := b.Next(attempt)
		if d >= max {
			t.Fatalf("attempt %d delay %v is at or above the %v ceiling: the clamp is gone", attempt, d, max)
		}
		if attempt >= 2 && d < max/2 {
			t.Fatalf("attempt %d delay %v below the clamped-curve jitter floor %v", attempt, d, max/2)
		}
	}

	// Direct construction with base > max (Options clamps this; Backoff
	// itself must still honour the ceiling, per its own doc).
	b2 := NewBackoff(100*time.Millisecond, 20*time.Millisecond, rand.New(rand.NewSource(1)))
	for attempt := 1; attempt <= 10; attempt++ {
		if d := b2.Next(attempt); d >= 20*time.Millisecond {
			t.Fatalf("attempt %d delay %v with base 100ms > max 20ms: the clamp did not pull the curve down", attempt, d)
		}
	}
}
