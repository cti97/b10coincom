package relay

// Frames that are ADMITTED to a write queue and then abandoned when the
// connection ends used to be counted Forwarded at enqueue and discarded by
// finish with no other counter. That is the 2026-11-15 shape: the relay's line
// read "forwarded climbing, dropped=0" while consensus frames queued for a
// torn-down link were gone. These tests pin the closure: every refusal at the
// door is attributed to the bound that made it, and every frame that never
// reaches the wire is a Dropped frame - so Forwarded = delivered + Dropped.
//
// The two behavioural tests FAIL on origin/main:
//
//   - TestRelayFinishCountsTheFramesItDiscards (Dropped was 0 with 3 queued);
//   - TestRelayAReceiverPauseLeavesNoUncountedFrame (unaccounted > 0).
//
// The attribution tests use the new per-reason fields, so they only compile
// after the fix; they are the evidence that push's refusal paths - which the
// hypothesis blamed - were in fact ALREADY counted, and that a consensus-sized
// frame is never the one they refuse.

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/wire"
)

// relWith builds a socket-free relay whose receiver queue is the given one and
// registers one sender per source group.
func relWith(t *testing.T, q *sendQ, senders int) (*Relay, *conn, []*conn) {
	t.Helper()
	r := New(Options{MaxConns: 16, MaxConnsPerIP: 16})
	// A real (in-memory) socket per connection so finish's closeSocket has
	// something to close; no goroutines are started for these.
	sock := func() net.Conn {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		return a
	}
	recv := &conn{nc: sock(), q: q, dead: make(chan struct{}), srcGroup: "192.0.2.0/24"}
	r.mu.Lock()
	r.conns[recv] = struct{}{}
	out := make([]*conn, 0, senders)
	for i := 0; i < senders; i++ {
		s := &conn{
			nc:       sock(),
			q:        newSendQ(q.limit, 1<<20, 8),
			dead:     make(chan struct{}),
			srcGroup: "198.51.100." + string(rune('1'+i)) + "/24",
		}
		r.conns[s] = struct{}{}
		out = append(out, s)
	}
	r.mu.Unlock()
	return r, recv, out
}

// TestRelayEveryPushRefusalIsCounted drives each bound push applies and asserts
// the refusal is a Dropped frame charged to that reason. On origin/main the
// counters do not exist (and Dropped did move on these paths), so the test is
// the ATTRIBUTION pin rather than the silence pin - the silence was at finish.
func TestRelayEveryPushRefusalIsCounted(t *testing.T) {
	t.Run("byte budget", func(t *testing.T) {
		q := newSendQ(64<<10, 32, 128)
		r, _, senders := relWith(t, q, 1)
		frame := make([]byte, 1024)
		for q.bytes+len(frame) <= q.limit {
			r.forward(senders[0], frame)
		}
		before := r.Stats()
		r.forward(senders[0], frame) // would cross the total budget
		after := r.Stats()
		if got := after.Dropped - before.Dropped; got != 1 {
			t.Fatalf("a frame refused by the byte budget moved Dropped by %d, want 1", got)
		}
		if got := after.DroppedBytes - before.DroppedBytes; got != 1 {
			t.Fatalf("byte-budget refusals moved by %d, want 1", got)
		}
		if q.queued() == 0 || q.bytes > q.limit {
			t.Fatalf("queue state after the refusal: %d frames / %d bytes (limit %d)", q.queued(), q.bytes, q.limit)
		}
	})

	t.Run("frame count", func(t *testing.T) {
		q := newSendQ(1<<20, 64, 2)
		r, _, senders := relWith(t, q, 1)
		r.forward(senders[0], make([]byte, 16))
		r.forward(senders[0], make([]byte, 16))
		before := r.Stats()
		r.forward(senders[0], make([]byte, 16))
		after := r.Stats()
		if got := after.Dropped - before.Dropped; got != 1 {
			t.Fatalf("a frame refused by the entry-ring bound moved Dropped by %d, want 1", got)
		}
		if got := after.DroppedFrames - before.DroppedFrames; got != 1 {
			t.Fatalf("frame-count refusals moved by %d, want 1", got)
		}
	})

	t.Run("per-sender share", func(t *testing.T) {
		q := newSendQ(100, 10, 8) // share = 100/2 = 50 bytes
		r, _, senders := relWith(t, q, 2)
		frame := make([]byte, 10)
		for i := 0; i < 5; i++ { // sender A at its 50-byte share
			r.forward(senders[0], frame)
		}
		r.forward(senders[1], frame) // second account holding bytes: the share is real
		before := r.Stats()
		r.forward(senders[0], frame) // A would cross its share
		after := r.Stats()
		if got := after.Dropped - before.Dropped; got != 1 {
			t.Fatalf("a frame refused by the per-sender share moved Dropped by %d, want 1", got)
		}
		if got := after.DroppedShare - before.DroppedShare; got != 1 {
			t.Fatalf("share refusals moved by %d, want 1", got)
		}
	})

	t.Run("consensus reservation", func(t *testing.T) {
		q := newSendQ(64, 32, 8) // reserve 16, bulk ceiling 48
		q.smallMax = 16          // narrow the threshold so a hand-built queue can reach it
		r, _, senders := relWith(t, q, 1)
		r.forward(senders[0], make([]byte, 17)) // bulk, admitted inside the ceiling
		before := r.Stats()
		r.forward(senders[0], make([]byte, 32)) // bulk; fits the 64-byte budget but crosses 48
		after := r.Stats()
		if got := after.Dropped - before.Dropped; got != 1 {
			t.Fatalf("a bulk frame refused by the reservation moved Dropped by %d, want 1", got)
		}
		if got := after.DroppedLane - before.DroppedLane; got != 1 {
			t.Fatalf("reservation refusals moved by %d, want 1", got)
		}
		if after.DroppedShare != 0 || after.DroppedFrames != 0 {
			t.Fatalf("the lane refusal was charged to another reason: share=%d frames=%d",
				after.DroppedShare, after.DroppedFrames)
		}
	})

	// The reason counters are a partition of Dropped: a refusal has exactly
	// one cause, so their sum can never drift from the total.
	t.Run("reasons sum to dropped", func(t *testing.T) {
		q := newSendQ(64<<10, 32, 128)
		r, _, senders := relWith(t, q, 2)
		frame := make([]byte, 1024)
		for q.bytes+len(frame) <= q.limit {
			r.forward(senders[0], frame)
		}
		for i := 0; i < 3; i++ {
			r.forward(senders[0], frame)
			r.forward(senders[1], frame)
		}
		st := r.Stats()
		sum := st.DroppedBytes + st.DroppedShare + st.DroppedFrames + st.DroppedLane + st.DroppedOnClose + st.DroppedReap + st.DroppedOther
		if st.Dropped == 0 || sum != st.Dropped {
			t.Fatalf("reason counters sum to %d, Dropped is %d: a refusal path is unattributed", sum, st.Dropped)
		}
	})
}

// TestRelayFinishCountsTheFramesItDiscards is the silence pin. Frames already
// in a queue when its connection ends are DISCARDED - the relay cannot write
// them - but they must be Dropped, not left counted Forwarded. It fails on
// origin/main: Dropped stays 0 while Forwarded is 3.
func TestRelayFinishCountsTheFramesItDiscards(t *testing.T) {
	r, recv, senders := relWith(t, newSendQ(64<<10, 32, 64), 1)
	for i := 0; i < 3; i++ {
		r.forward(senders[0], make([]byte, 200))
	}
	before := r.Stats()
	if before.Forwarded != 3 || before.Dropped != 0 {
		t.Fatalf("construction: forwarded=%d dropped=%d, want 3/0", before.Forwarded, before.Dropped)
	}
	r.finish(recv)
	after := r.Stats()
	if after.Dropped != 3 {
		t.Fatalf("finish discarded 3 queued frames but Dropped is %d: the relay counted them forwarded and lost them silently", after.Dropped)
	}
	if after.DroppedOnClose != 3 {
		t.Fatalf("DroppedOnClose is %d, want the 3 frames the queue still held", after.DroppedOnClose)
	}
	if after.Forwarded != 3 {
		t.Fatalf("Forwarded moved on teardown: %d, want the enqueue count 3", after.Forwarded)
	}
	if recv.q.queued() != 0 {
		t.Fatalf("the queue still holds %d frames after finish", recv.q.queued())
	}
}

// deadlineFailConn is a connection whose socket is fine but whose write deadline
// cannot be armed. It makes the writer's SetWriteDeadline exit reachable with no
// race: that is the exit where a popped frame is in the writer's hand, invisible
// to sendQ.abandon, so only the writer can charge it.
type deadlineFailConn struct{ *gateConn }

func (deadlineFailConn) SetWriteDeadline(time.Time) error {
	return errors.New("set write deadline: socket is gone")
}

// timeoutErr is a net.Error whose Timeout is true, the shape a write deadline
// expiring on a stalled receiver produces.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// timeoutWriteConn fails every write with the deadline's own error, so the
// writer takes the reap exit with a frame in its hand.
type timeoutWriteConn struct{ *gateConn }

func (timeoutWriteConn) Write([]byte) (int, error) { return 0, timeoutErr{} }

// writerConn builds a relay with one receiver whose queue holds n frames (all
// admitted through forward, so Forwarded counts them), and the receiver's writer
// not yet started. The socket is the caller's, so each test chooses which exit
// the writer meets.
func writerConn(t *testing.T, n, frameBytes int, nc net.Conn) (*Relay, *conn) {
	t.Helper()
	r := New(Options{
		MaxFrameBytes: 4096, MaxConns: 8, MaxConnsPerIP: 8,
		WriteQueueBytes: 1 << 20, WriteQueueFrames: 64,
		WriteTimeout: 200 * time.Millisecond,
	})
	c := &conn{nc: nc, q: newSendQ(1<<20, 4096, 64), dead: make(chan struct{}), srcGroup: "192.0.2.0/24"}
	sender := &conn{q: newSendQ(1<<20, 4096, 64), dead: make(chan struct{}), srcGroup: "198.51.100.0/24"}
	r.mu.Lock()
	r.conns[c] = struct{}{}
	r.conns[sender] = struct{}{}
	r.perGroup[c.srcGroup]++
	r.perGroup[sender.srcGroup]++
	r.mu.Unlock()
	for i := 0; i < n; i++ {
		r.forward(sender, make([]byte, frameBytes))
	}
	if got := c.q.queued(); got != n {
		t.Fatalf("construction: %d of %d frames queued", got, n)
	}
	return r, c
}

func waitDead(t *testing.T, c *conn, why string) {
	t.Helper()
	select {
	case <-c.dead:
	case <-time.After(5 * time.Second):
		t.Fatal(why)
	}
}

// TestTheWriteDeadlineReapCountsTheBacklogItDiscards pins path 2 on its own: the
// receiver's backlog is CONSTRUCTED as stalled (aged past WriteTimeout and no
// frame admitted within that window), so the writer's very first decision is the
// reap. Every frame the reaper abandons must be Dropped and attributed to the
// reap - on origin/main finish only closed the socket, so the whole queue
// vanished while Forwarded already counted it.
func TestTheWriteDeadlineReapCountsTheBacklogItDiscards(t *testing.T) {
	const queued, frameBytes = 7, 64
	nc := &gateConn{closed: make(chan struct{}), gate: make(chan struct{}), entered: make(chan struct{}), payloadSize: frameBytes}
	r, c := writerConn(t, queued, frameBytes, nc)
	c.q.mu.Lock()
	c.q.oldest = time.Now().Add(-10 * r.opts.WriteTimeout)
	c.q.lastPush = time.Now().Add(-10 * r.opts.WriteTimeout)
	c.q.mu.Unlock()
	if !c.q.receiverStalled(r.opts.WriteTimeout) {
		t.Fatal("the constructed state does not read as a receiver stall")
	}
	r.wg.Add(1)
	go r.writer(c)
	waitDead(t, c, "the writer did not reap a queue that had been stalled past WriteTimeout")
	// dead is closed by the teardown BEFORE the counters are updated (the
	// accounting runs outside the registry lock), so the assertion is on the
	// settled end state, not the instant dead closed.
	waitFor(t, func() bool { return r.Stats().DroppedReap == queued }, "the reap to account the backlog it discarded")
	st := r.Stats()
	if st.Forwarded != queued {
		t.Fatalf("Forwarded is %d, want the %d enqueued frames", st.Forwarded, queued)
	}
	if st.Dropped != queued {
		t.Fatalf("the reap discarded %d queued frames but Dropped is %d: they were forwarded and lost silently", queued, st.Dropped)
	}
	if st.DroppedReap != queued {
		t.Fatalf("the reap's frames were not attributed to it: DroppedReap=%d, want %d", st.DroppedReap, queued)
	}
	if st.DroppedOnClose != 0 {
		t.Fatalf("a reap was charged to an ordinary close: DroppedOnClose=%d", st.DroppedOnClose)
	}
	if c.q.queued() != 0 {
		t.Fatalf("the queue still holds %d frames after the reap", c.q.queued())
	}
}

// TestTheWriterCountsThePoppedFrameWhenTheDeadlineCannotBeArmed pins the exit
// that has no queue to abandon: the writer popped a frame, then could not arm the
// write deadline, and the frame is in its hand. sendQ.abandon cannot see it, so
// only the writer's own charge keeps it from being the one frame this exit loses
// silently.
func TestTheWriterCountsThePoppedFrameWhenTheDeadlineCannotBeArmed(t *testing.T) {
	const queued, frameBytes = 5, 64
	nc := &deadlineFailConn{&gateConn{closed: make(chan struct{}), gate: make(chan struct{}), entered: make(chan struct{}), payloadSize: frameBytes}}
	r, c := writerConn(t, queued, frameBytes, nc)
	r.wg.Add(1)
	go r.writer(c)
	waitDead(t, c, "the writer did not tear down a connection whose write deadline could not be armed")
	waitFor(t, func() bool { return r.Stats().DroppedOnClose == queued }, "the teardown to account the popped frame and its queue")
	st := r.Stats()
	if st.Forwarded != queued {
		t.Fatalf("Forwarded is %d, want the %d enqueued frames", st.Forwarded, queued)
	}
	if st.Dropped != queued {
		t.Fatalf("the teardown discarded %d frames but Dropped is %d: the popped frame was lost silently", queued, st.Dropped)
	}
	if st.DroppedOnClose != queued {
		t.Fatalf("the popped frame and its queue were not attributed to the close: DroppedOnClose=%d, want %d", st.DroppedOnClose, queued)
	}
}

// TestTheWriterCountsThePoppedFrameWhenTheWriteDeadlineExpires pins the other
// in-hand exit: the write deadline expired on a stalled receiver. The popped
// frame is charged to the reap and the rest of the queue is abandoned through
// the same reap teardown, so this exit also counts everything it discards.
func TestTheWriterCountsThePoppedFrameWhenTheWriteDeadlineExpires(t *testing.T) {
	const queued, frameBytes = 5, 64
	nc := &timeoutWriteConn{&gateConn{closed: make(chan struct{}), gate: make(chan struct{}), entered: make(chan struct{}), payloadSize: frameBytes}}
	r, c := writerConn(t, queued, frameBytes, nc)
	r.wg.Add(1)
	go r.writer(c)
	waitDead(t, c, "the writer did not tear down a connection whose write deadline expired")
	waitFor(t, func() bool { return r.Stats().DroppedReap == queued }, "the reaping teardown to account the popped frame and its queue")
	st := r.Stats()
	if st.Forwarded != queued {
		t.Fatalf("Forwarded is %d, want the %d enqueued frames", st.Forwarded, queued)
	}
	if st.Dropped != queued {
		t.Fatalf("the reaping teardown discarded %d frames but Dropped is %d", queued, st.Dropped)
	}
	if st.DroppedReap != queued {
		t.Fatalf("the expired write's frame and its queue were not attributed to the reap: DroppedReap=%d, want %d", st.DroppedReap, queued)
	}
	if st.DroppedOnClose != 0 {
		t.Fatalf("a write-deadline teardown was charged to an ordinary close: DroppedOnClose=%d", st.DroppedOnClose)
	}
}

// TestRelayConsensusFramesAreNotPreferentiallyRejected is audit N-1's property
// restated as an assertion, and the DISPROOF of the hypothesis that the
// reservation makes consensus lose to control traffic: with a target's queue
// as full of bulk as the reservation permits, HELLO-sized and consensus-sized
// frames are offered in the same proportion and BOTH are admitted - while the
// only frame refused is the BULK one that would cross into the reserved bytes.
func TestRelayConsensusFramesAreNotPreferentiallyRejected(t *testing.T) {
	r, recv := laneRelay(t, 3)
	q := recv.q
	senders := sendersOf(t, r, recv)
	if adm := fillBulk(t, r, recv, senders, make([]byte, bulkFrameBytes)); adm == 0 {
		t.Fatal("no bulk frame was admitted: the pressure construction never formed")
	}
	// Top the queue up with the one bulk frame that fits the byte budget but
	// would cross the reservation: it is the frame N-1 reserves against, and
	// it must be the frame the queue refuses.
	rest := q.limit - q.bytes
	if rest <= smallFrameBytes || rest > bulkFrameBytes {
		t.Fatalf("the byte budget's remainder is %d bytes, not one bulk frame (threshold %d, bulk frame %d): the construction does not probe the reservation", rest, smallFrameBytes, bulkFrameBytes)
	}
	beforeBytes := q.bytes
	r.forward(senders[0], make([]byte, rest))
	if q.bytes != beforeBytes {
		t.Fatalf("a %d-byte bulk frame crossed the reservation with %d of %d bytes queued", rest, beforeBytes, q.limit)
	}
	st := r.Stats()
	if st.DroppedLane != 1 {
		t.Fatalf("the bulk top-up was not charged to the reservation: DroppedLane=%d, Dropped=%d", st.DroppedLane, st.Dropped)
	}

	// Now offer HELLO-sized and consensus-sized frames in equal proportion.
	// Every one must be admitted to the target's queue: the reservation shed
	// a BULK frame, never a small one.
	hello := make([]byte, 250) // a HELLO: control traffic
	vote := make([]byte, 1500) // a proposal/prevote: consensus traffic
	const n = 12
	droppedHello, droppedVote := 0, 0
	for i := 0; i < n; i++ {
		before := q.queued()
		r.forward(senders[i%len(senders)], hello)
		if q.queued() == before {
			droppedHello++
		}
		before = q.queued()
		r.forward(senders[i%len(senders)], vote)
		if q.queued() == before {
			droppedVote++
		}
	}
	if droppedHello != 0 || droppedVote != 0 {
		t.Fatalf("with bulk at its ceiling, %d/%d HELLOs and %d/%d consensus frames were refused: consensus loses to bulk, which is the reverse of N-1",
			droppedHello, n, droppedVote, n)
	}
	if q.bytes > q.limit {
		t.Fatalf("the queue holds %d bytes against a %d-byte budget", q.bytes, q.limit)
	}
	t.Logf("bulk at %d bytes (ceiling %d, budget %d); the %d-byte top-up was refused by the reservation; %d HELLOs and %d consensus frames admitted, 0 refused",
		beforeBytes, q.bulkLimit, q.limit, rest, n, n)
}

// shrinkReadBuffer pins the receiver's kernel receive buffer small, so the
// relay's writer blocks after a few frames instead of the host's auto-tuned
// loopback buffer absorbing the whole burst. Without it the test measures the
// kernel, not the relay: a loaded machine can hold megabytes in the socket and
// the relay never reaches its write bound.
func shrinkReadBuffer(t *testing.T, c net.Conn) {
	t.Helper()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("receiver is %T, not a *net.TCPConn", c)
	}
	if err := tc.SetReadBuffer(4096); err != nil {
		t.Fatalf("shrink receiver read buffer: %v", err)
	}
}

// drainFrames reads until the link ends or quiet, returning how many complete
// frames arrived.
func drainFrames(conn net.Conn, max int, wait time.Duration) int {
	got := 0
	for {
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		if _, err := wire.ReadFrame(conn, max); err != nil {
			return got
		}
		got++
	}
}

// TestRelayAReceiverPauseLeavesNoUncountedFrame is the end-to-end shape: a
// real relay and a real sender/receiver pair. The receiver stops reading, the
// relay's write bound expires, and then the receiver resumes. Whatever the
// relay could not deliver must be COUNTED - delivered + Dropped == Forwarded -
// so no consensus frame is silently lost.
//
// It fails on origin/main: the relay reaps the receiver, discards the backlog,
// and leaves it counted Forwarded with Dropped=0 (measured 1132 frames lost,
// dropped=0).
func TestRelayAReceiverPauseLeavesNoUncountedFrame(t *testing.T) {
	t.Run("pause inside the write bound is delivered", func(t *testing.T) {
		opts := Options{WriteTimeout: 2 * time.Second, ReadTimeout: 30 * time.Second}
		r := startRelay(t, opts)
		s := dial(t, r.Addr().String())
		recv := dial(t, r.Addr().String())
		time.Sleep(50 * time.Millisecond)

		const frames, size = 400, 1500
		for i := 0; i < frames; i++ {
			writeFrame(t, s, make([]byte, size))
		}
		time.Sleep(100 * time.Millisecond) // a pause, but well inside WriteTimeout
		got := drainFrames(recv, 1<<20, 2*time.Second)
		st := r.Stats()
		if got != frames {
			t.Fatalf("delivered %d of %d consensus-sized frames after a pause shorter than WriteTimeout (relay forwarded=%d dropped=%d)",
				got, frames, st.Forwarded, st.Dropped)
		}
		if st.Dropped != 0 {
			t.Fatalf("a healthy receiver's backlog was dropped: dropped=%d", st.Dropped)
		}
	})

	t.Run("pause past the bound is counted, never silent", func(t *testing.T) {
		opts := Options{WriteTimeout: 300 * time.Millisecond, ReadTimeout: 30 * time.Second}
		r := startRelay(t, opts)
		s := dial(t, r.Addr().String())
		recv := dial(t, r.Addr().String())
		shrinkReadBuffer(t, recv)
		time.Sleep(50 * time.Millisecond)

		const frames, size = 1200, 1500
		for i := 0; i < frames; i++ {
			writeFrame(t, s, make([]byte, size))
		}
		time.Sleep(700 * time.Millisecond) // past the write bound: the link is reaped
		got := drainFrames(recv, 1<<20, 2*time.Second)

		// End state, after both teardown paths have settled: the invariant is
		// Forwarded = delivered + Dropped, whichever path won. Two outcomes
		// are correct, and which one happens is a real race against the host's
		// socket buffers - when they absorb the whole burst, the burst is
		// delivered even though the pause was longer than WriteTimeout, and
		// Dropped is rightly zero. So the assertions are on the END STATE, not
		// on a mid-flight snapshot that assumes the reap must win:
		//
		//   - the reap won: delivered < forwarded, and every frame that did not
		//     arrive is in Dropped, attributed to the reap (or to the close, if
		//     the reader's deadline won the teardown first) - never left as a
		//     forwarded frame that vanished;
		//   - the drain won: delivered == forwarded and nothing was dropped.
		//
		// What is unacceptable in EITHER outcome is Forwarded > delivered +
		// Dropped: that is a frame the relay admitted and lost.
		deadline := time.Now().Add(2 * time.Second)
		var st Stats
		for {
			st = r.Stats()
			if int(st.Forwarded)-got-int(st.Dropped) == 0 || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if st.Forwarded != frames {
			t.Fatalf("relay forwarded %d frames, sender offered %d", st.Forwarded, frames)
		}
		if unaccounted := int(st.Forwarded) - got - int(st.Dropped); unaccounted != 0 {
			t.Fatalf("%d frames are unaccounted (forwarded %d = delivered %d + dropped %d); delivered+dropped must equal forwarded",
				unaccounted, st.Forwarded, got, st.Dropped)
		}
		if got < frames {
			if st.Dropped == 0 {
				t.Fatalf("the relay discarded the reaped link's backlog but Dropped is 0: %d of %d frames were counted forwarded and lost silently", frames-got, frames)
			}
			if st.DroppedOnClose == 0 && st.DroppedReap == 0 {
				t.Fatalf("the lost frames were not attributed to a teardown: dropped=%d on-close=%d reap=%d", st.Dropped, st.DroppedOnClose, st.DroppedReap)
			}
		}
		t.Logf("delivered %d of %d; relay dropped %d (on-close %d, reap %d) - no frame silently lost",
			got, frames, st.Dropped, st.DroppedOnClose, st.DroppedReap)
	})
}
