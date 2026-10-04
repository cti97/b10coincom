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
// maintainers, one reader and one writer per connection) is gone afterwards.
// The count is taken against a baseline measured before the transports
// existed, with a small margin for unrelated runtime goroutines (GC workers);
// a leaked maintainer or reader/writer pair exceeds it, because this test
// closes EVERY transport it made before counting.
func TestCloseIsIdempotentAndStopsGoroutines(t *testing.T) {
	baseline := runtime.NumGoroutine()

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
	// Every transport this test made is closed before counting: a's
	// maintainer exited through quit (Close is the only thing that ends a
	// reconnection loop), and the per-connection readers/writers exited
	// through their closed sockets.
	if err := b.Close(); err != nil {
		t.Fatalf("peer transport Close: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, true)
	t.Fatalf("goroutines did not return to the baseline (%d -> %d after every transport closed)\n%s",
		baseline, runtime.NumGoroutine(), buf[:n])
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
