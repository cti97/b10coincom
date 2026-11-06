package relay

// N-1 (testrun 2026-11-06, 10 nodes Docker): several validators catching up at
// once halt the healthy quorum for minutes.
//
// THE DEFECT THESE TESTS PIN. Every frame a relay forwards is offered to every
// other connection's write queue, and that queue was a single FIFO bounded in
// bytes and frames but not partitioned by anything. A BLOCK_SYNC response is
// the largest honest frame on the wire (a 64-block window of devnet blocks is
// ~160 KiB, and Answer may serve up to wire.MaxFrameBytes in one frame), while
// a consensus frame is small (a vote is ~150 bytes, a transaction-free proposal
// with its justification ~1.5 KiB). Two such responses fill a 2 MiB queue, so
// while a relay carries catch-up traffic for several peers at once:
//
//   - a consensus frame offered at that moment is REFUSED, and a refusal is a
//     permanent loss (forward counts it in Dropped and never retries), and
//   - a consensus frame offered while the queue still has room is ADMITTED
//     BEHIND the bulk, and the receiver's own relay byte budget (audit PX-4,
//     512 KiB/s) is what paces the drain, so the frame waits
//     queuedBytes/512 KiB/s - seconds, against a 200 ms base round timeout.
//
// Both are liveness failures. The second is why the report's "dropped rose
// 15 -> 1530" cannot be the explanation: what does not fit is the LARGE frame,
// the count is far too small to suppress a quorum, and the votes die of delay.
//
// WHAT THE FIX DOES (and how it is pinned here). Frame size is the one property
// of a frame the relay already reads - the length prefix - so it is the one
// property a parse-free relay may sort by. A queue now keeps its last
// smallFrameReserveBytes free of frames larger than smallFrameBytes, and the
// writer takes consensus-sized frames before bulk. Nothing is added to memory,
// to the byte budget or to the frame bound: the reservation is a SUB-limit on
// bulk, not new capacity.
//
// THE CONSTRUCTION IS BUILT, NOT PROVOKED. No test here starts a socket, waits
// on a clock or loads a host: the queue is filled through the real forward path
// with the exact frame sizes the finding names, and the delay is measured as
// BYTES WRITTEN BEFORE THE VOTE, which is the deterministic form of "the
// receiver had to drain this much first".

import (
	"fmt"
	"testing"
	"time"
)

const (
	// bulkFrameBytes is the on-the-wire size of one BLOCK_SYNC response
	// carrying a full DefaultMaxBlocksPerResponse window: 64 devnet blocks of
	// ~250 bytes plus the ~2.2 KB certificate each (see
	// DefaultMaxBlocksPerResponse's own arithmetic). It is the SHAPE the
	// finding measured, not a worst case - the worst case is
	// wire.MaxFrameBytes, 6.8x this.
	bulkFrameBytes = 160 << 10
	// voteFrameBytes is a prevote/precommit frame: tag, height, round,
	// 32-byte block ID, 32-byte validator key and a 64-byte Ed25519
	// signature, plus varint prefixes and the consensus envelope
	// (consensus.EncodeVote). 150 is that shape; 200 leaves it room.
	voteFrameBytes = 200
	// relayPaceBytesPerSec is the receiving node's own relay-mode inbound
	// budget (tcp.DefaultRelayBytesPerSec) and therefore the rate at which the
	// relay's writer can actually put bytes on that peer's wire. It is what
	// turns a queued byte into a delay.
	relayPaceBytesPerSec = 512 << 10
	// baseRoundTimeout is the shipped ladder's round-0 timeout
	// (internal/devnet's consensusTimeoutBaseMS = 200). It is restated rather
	// than imported because this package must not depend on the node layer,
	// and it is the clock the reservation is sized against.
	baseRoundTimeout = 200 * time.Millisecond
)

// bulkDelay is the time a receiver paced at relayPaceBytesPerSec needs to
// drain n bytes.
func bulkDelay(n int) time.Duration {
	return time.Duration(float64(n) / relayPaceBytesPerSec * float64(time.Second))
}

// laneRelay builds the socket-free relay the queue tests use: a registry of
// hand-built connections, no listener and no goroutines.
func laneRelay(t *testing.T, senders int) (*Relay, *conn) {
	t.Helper()
	r := New(Options{MaxConns: 16, MaxConnsPerIP: 16})
	recv := &conn{
		q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
		dead:     make(chan struct{}),
		srcGroup: "192.0.2.0/24",
	}
	r.mu.Lock()
	r.conns[recv] = struct{}{}
	for i := 0; i < senders; i++ {
		// One source group per sender, so the per-sender share is derived
		// exactly as it is for peers with distinct public addresses.
		s := &conn{
			q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
			dead:     make(chan struct{}),
			srcGroup: fmt.Sprintf("198.51.100.%d/24", i+1),
		}
		r.conns[s] = struct{}{}
	}
	r.mu.Unlock()
	return r, recv
}

// sendersOf snapshots the registered non-receiver connections ONCE, so a
// construction can round-robin over a FIXED sender list.
//
// This is the determinism the loss pin needs, not a convenience. Reading the
// registry map afresh on every offer - `senderOf(..., i%3)` in the first
// version - is not a round-robin: `range r.conns` visits the map in a fresh
// random order on EVERY call, so the same index names a different sender on
// every frame. When the random sequence offered one sender its seventh bulk
// frame before the queue reached its ceiling, that sender's equal share
// (shareFor(3) = limit/3 = 1114112 bytes, six bulk frames) refused it, the
// fill stopped at 7, 9, 10 or 11 frames instead of 12, and the remainder the
// loss pin read off it became whatever the map order produced. The slice's
// order here is still the map's order - the senders are identical in every
// property the queue observes - but it does not change within one
// construction, so the fill's arithmetic is fixed.
func sendersOf(t *testing.T, r *Relay, recv *conn) []*conn {
	t.Helper()
	var senders []*conn
	for c := range r.conns {
		if c != recv {
			senders = append(senders, c)
		}
	}
	if len(senders) == 0 {
		t.Fatal("no sender is registered: the construction never formed")
	}
	return senders
}

// fillBulk offers bulk frames through the real forward path, round-robin over
// the fixed sender list, until the queue refuses one. It returns the number
// admitted.
func fillBulk(t *testing.T, r *Relay, recv *conn, senders []*conn, frame []byte) int {
	t.Helper()
	admitted := 0
	for i := 0; ; i++ {
		before := recv.q.bytes
		r.forward(senders[i%len(senders)], frame)
		if recv.q.bytes == before {
			return admitted
		}
		admitted++
		if admitted > 4096 {
			t.Fatalf("the queue admitted %d bulk frames of %d bytes - the byte budget is not bounding it", admitted, len(frame))
		}
	}
}

// TestRelayBulkTrafficDoesNotDelayConsensusFrames is N-1's DELAY pin: with a
// queue as full of catch-up traffic as bulk may make it, consensus frames must
// not be written behind that traffic.
//
// The measurement is bytes, and it is a duration: queuedBytes / 512 KiB/s.
// Before the reservation every vote sat behind the whole bulk backlog
// (1966080 bytes = 3.75 s against a 200 ms base round timeout); the assertion
// is that it now sits behind no more than the reservation, whose own drain
// (65536 bytes = 125 ms) is inside one base round timeout.
func TestRelayBulkTrafficDoesNotDelayConsensusFrames(t *testing.T) {
	r, recv := laneRelay(t, 3)
	q := recv.q
	senders := sendersOf(t, r, recv)
	adm := fillBulk(t, r, recv, senders, make([]byte, bulkFrameBytes))
	if adm < 3 {
		t.Fatalf("the queue took only %d bulk frames: the catch-up construction never formed", adm)
	}
	if q.bytes > q.bulkLimit {
		t.Fatalf("bulk alone reached %d bytes, past the %d-byte bulk ceiling of a %d-byte budget", q.bytes, q.bulkLimit, q.limit)
	}
	queuedBulk, queuedBytes := q.queued(), q.bytes
	t.Logf("constructed: %d bulk frames, %d bytes queued (bulk ceiling %d, budget %d)", queuedBulk, queuedBytes, q.bulkLimit, q.limit)

	// Ten consensus-sized frames, offered at the instant the queue is as full
	// of bulk as bulk may make it.
	vote := make([]byte, voteFrameBytes)
	lost := 0
	for i := 0; i < 10; i++ {
		before := q.bytes
		r.forward(senders[i%len(senders)], vote)
		if q.bytes == before {
			lost++
		}
	}
	if lost != 0 {
		t.Fatalf("%d of 10 consensus frames were refused with the queue holding %d of its %d bytes - bulk was allowed into the room the reservation exists to keep free", lost, q.bytes, q.limit)
	}
	if q.bytes > q.limit {
		t.Fatalf("the queue holds %d bytes against a %d-byte budget - the reservation added capacity instead of partitioning it", q.bytes, q.limit)
	}

	// Bytes the writer must put on the wire before the first consensus frame:
	// the deterministic stand-in for "how late is the vote".
	ahead, bulkBefore := 0, 0
	for {
		f, ok := q.pop()
		if !ok {
			t.Fatalf("%d frames were consumed without meeting a consensus frame - the 10 votes are not in the queue", bulkBefore)
		}
		if len(f.b) <= smallFrameBytes {
			break
		}
		ahead += len(f.b)
		bulkBefore++
	}
	if ahead > q.reserve {
		t.Fatalf("the first consensus frame was written after %d bulk bytes (%s at %d B/s) - more than the %d-byte reservation, so bulk still delays a vote by %s against a %s base round timeout",
			ahead, bulkDelay(ahead), relayPaceBytesPerSec, q.reserve, bulkDelay(ahead), baseRoundTimeout)
	}
	t.Logf("bulk written ahead of the first consensus frame: %d bytes (%s at %d B/s); reservation %d bytes (%s)",
		ahead, bulkDelay(ahead), relayPaceBytesPerSec, q.reserve, bulkDelay(q.reserve))
}

// TestRelayBulkTrafficDoesNotEvictConsensusFrames is N-1's LOSS pin: the same
// catch-up shape filled to its byte ceiling. Before the reservation the queue
// reaches exactly its limit (the bulk lane and the budget were the same thing),
// and every consensus frame offered behind it is REFUSED - a permanent loss,
// which is the state a stalled quorum cannot recover from. With the
// reservation the frame that would cross the boundary is the BULK one, and the
// consensus frames fit.
//
// THE REMAINDER IS DERIVED, NOT OBSERVED. The first version of this test read
// `rest := limit - q.bytes` after a fill that re-read the registry map on every
// offer, and asserted rest was "the remainder a single bulk frame can top up".
// It was not, sometimes: the map order is random per iteration, so the
// supposedly round-robin fill could refuse one sender's seventh bulk frame
// (its equal share is six) before the queue reached its ceiling. The fill then
// stopped at 7, 9, 10 or 11 frames and rest became 622592, 458752 or 294912
// bytes depending on the run - this test's reported flake. The fill now
// round-robins over a fixed sender list, so the whole-frame count below is a
// property of the queue's arithmetic, and the closure it implies is asserted
// explicitly rather than assumed.
func TestRelayBulkTrafficDoesNotEvictConsensusFrames(t *testing.T) {
	r, recv := laneRelay(t, 3)
	q := recv.q
	senders := sendersOf(t, r, recv)
	adm := fillBulk(t, r, recv, senders, make([]byte, bulkFrameBytes))
	if adm == 0 {
		t.Fatal("no bulk frame was admitted: the construction never formed")
	}

	// BULK SATURATED ITS LANE, and the number is derived from the queue's own
	// bounds: the bulk ceiling holds bulkLimit/bulkFrameBytes WHOLE bulk
	// frames, and the fill must stop exactly there - on the frame that would
	// cross the ceiling. Stopping earlier means the per-sender share refused
	// the fill before the reservation could be observed (the flake);
	// stopping later means bulk is inside the reserved bytes.
	whole := q.bulkLimit / bulkFrameBytes
	if want := whole * bulkFrameBytes; q.bytes != want {
		t.Fatalf("the fill stopped at %d bytes, want the %d whole %d-byte bulk frames the %d-byte ceiling holds (%d bytes): the construction is not the one this test pins", q.bytes, whole, bulkFrameBytes, q.bulkLimit, want)
	}
	// THE CLOSURE. The byte budget's remainder is the frame that would TOP THE
	// QUEUE UP to its limit: it is bulk by size, and at most one bulk frame,
	// so it is exactly the frame the reservation - not the byte budget - must
	// refuse. Asserted rather than assumed, because a remainder that were not
	// bulk could not probe the reservation at all.
	rest := q.limit - q.bytes
	if rest <= smallFrameBytes || rest > bulkFrameBytes {
		t.Fatalf("the byte budget's remainder is %d bytes, which is not one bulk frame (threshold %d, bulk frame %d): the arithmetic no longer closes", rest, smallFrameBytes, bulkFrameBytes)
	}
	bulkAt := q.bytes
	// Before the fix this frame is admitted (it fits the byte budget exactly)
	// and the queue is full; with the fix it is refused, because it is bulk
	// and it would enter the bytes the reservation keeps for consensus.
	r.forward(senders[0], make([]byte, rest))
	full := q.bytes
	if full != bulkAt {
		t.Fatalf("a %d-byte bulk frame was admitted with %d of its %d-byte budget queued, %d bytes of it reserved: bulk crossed the lane", rest, bulkAt, q.limit, q.reserve)
	}

	// THE MEASUREMENT: ten consensus frames offered into whatever is left.
	vote := make([]byte, voteFrameBytes)
	lost := 0
	for i := 0; i < 10; i++ {
		before := q.bytes
		r.forward(senders[i%len(senders)], vote)
		if q.bytes == before {
			lost++
		}
	}
	if lost != 0 {
		t.Fatalf("%d of 10 consensus frames were REFUSED (permanent loss) with the queue at %d of its %d bytes: bulk took the room the reservation exists to keep free, and forward() does not retry a refused frame", lost, full, q.limit)
	}
	if q.bytes > q.limit {
		t.Fatalf("the queue holds %d bytes against a %d-byte budget", q.bytes, q.limit)
	}
	if full > q.bulkLimit {
		t.Fatalf("bulk reached %d bytes, past the %d-byte ceiling of the %d-byte budget: bulk crossed the reservation", full, q.bulkLimit, q.limit)
	}
	if st := r.Stats(); st.Dropped == 0 {
		t.Fatal("nothing was refused at the bulk ceiling: the construction never reached the state it pins")
	}
	t.Logf("bulk stopped at %d bytes (ceiling %d, budget %d, reservation %d); the %d-byte top-up frame was refused; 10 consensus frames admitted, %d refused", bulkAt, q.bulkLimit, q.limit, q.reserve, rest, lost)
}

// TestRelayBulkStillDrainsAndKeepsItsOrder is the no-regression pin for the
// case N-1 records as already working: ONE lagging peer. Bulk must still fill
// the queue to 97% of the budget, arrive in the order it was written, and every
// frame must survive - the reservation defers bulk, it does not drop it. The
// consensus frames must preserve their own arrival order among themselves.
func TestRelayBulkStillDrainsAndKeepsItsOrder(t *testing.T) {
	r, recv := laneRelay(t, 3)
	q := recv.q
	senders := sendersOf(t, r, recv)
	adm := fillBulk(t, r, recv, senders, make([]byte, bulkFrameBytes))
	if adm < 3 {
		t.Fatalf("only %d bulk frames were admitted: a single lagging peer's catch-up must still fill the queue", adm)
	}

	// Votes carry a counter so their own order is checkable: the payload is
	// opaque to the relay, and to this test it is just a byte.
	const votes = 8
	for i := 0; i < votes; i++ {
		v := make([]byte, voteFrameBytes)
		v[0] = byte(i)
		r.forward(senders[i%len(senders)], v)
	}

	for i := 0; i < votes; i++ {
		f, ok := q.pop()
		if !ok {
			t.Fatalf("the queue emptied after %d of %d consensus frames", i, votes)
		}
		if len(f.b) > smallFrameBytes {
			t.Fatalf("frame %d popped is %d bytes - a bulk frame overtook a queued consensus frame", i, len(f.b))
		}
		if f.b[0] != byte(i) {
			t.Fatalf("consensus frame %d popped carries %d: consensus frames left in a different order than they arrived", i, f.b[0])
		}
	}
	for i := 0; i < adm; i++ {
		f, ok := q.pop()
		if !ok {
			t.Fatalf("only %d of %d bulk frames survived the reservation - bulk was dropped, not deferred", i, adm)
		}
		if len(f.b) != bulkFrameBytes {
			t.Fatalf("bulk frame %d is %d bytes, want %d", i, len(f.b), bulkFrameBytes)
		}
	}
	if q.queued() != 0 || q.bytes != 0 || q.smallN != 0 {
		t.Fatalf("queue not empty after draining: %d frames / %d bytes / %d counted small", q.queued(), q.bytes, q.smallN)
	}
}

// TestRelayTheReservationIsASubLimitNotNewCapacity pins the arithmetic the
// reservation must not disturb: the byte budget, the frame bound and the entry
// ring are exactly the options', so Options.MaxPinnedBytes still holds, and the
// reservation's own drain is inside one base round timeout - which is why it is
// this size.
func TestRelayTheReservationIsASubLimitNotNewCapacity(t *testing.T) {
	opts := Options{}.withDefaults()
	q := newSendQ(opts.WriteQueueBytes, opts.MaxFrameBytes, opts.WriteQueueFrames)
	if q.limit != opts.WriteQueueBytes {
		t.Fatalf("queue limit %d != WriteQueueBytes %d", q.limit, opts.WriteQueueBytes)
	}
	if q.maxFrames != opts.WriteQueueFrames {
		t.Fatalf("queue frame bound %d != WriteQueueFrames %d", q.maxFrames, opts.WriteQueueFrames)
	}
	if len(q.ents) != opts.WriteQueueFrames {
		t.Fatalf("entry ring is %d entries for a %d-frame bound - the reservation allocated something", len(q.ents), opts.WriteQueueFrames)
	}
	if q.smallMax != smallFrameBytes {
		t.Fatalf("queue threshold %d != smallFrameBytes %d", q.smallMax, smallFrameBytes)
	}
	if q.reserve <= 0 || q.reserve >= q.limit {
		t.Fatalf("reservation %d is not a proper sub-limit of the %d-byte budget", q.reserve, q.limit)
	}
	if q.bulkLimit != q.limit-q.reserve {
		t.Fatalf("bulk ceiling %d != limit %d - reserve %d", q.bulkLimit, q.limit, q.reserve)
	}
	if q.reserve != smallFrameReserveBytes {
		t.Fatalf("the default reservation is %d bytes, wanted the operator number %d", q.reserve, smallFrameReserveBytes)
	}
	if d := bulkDelay(q.reserve); d >= baseRoundTimeout {
		t.Fatalf("the %d-byte reservation takes %s to drain at %d B/s, at or past the %s base round timeout it is sized against", q.reserve, d, relayPaceBytesPerSec, baseRoundTimeout)
	}
	// A shrunk budget reserves proportionally instead of swallowing itself.
	tiny := newSendQ(4096, 1024, 8)
	if tiny.reserve != 1024 || tiny.bulkLimit != 3072 {
		t.Fatalf("a 4096-byte budget reserved %d bytes (bulk ceiling %d), want a quarter: 1024 / 3072", tiny.reserve, tiny.bulkLimit)
	}

	// The BYTE BUDGET still binds consensus-sized frames: their lane is the
	// whole budget, which is not the same as no budget. Four 16-byte frames
	// from three accounts fill a 64-byte queue exactly; the fifth must be
	// refused even though its sender's share (32 bytes) has room.
	full := newSendQ(64, 32, 8)
	full.smallMax = 16
	senders := make([]*conn, 4)
	for i := range senders {
		senders[i] = &conn{dead: make(chan struct{}), srcGroup: fmt.Sprintf("203.0.113.%d/24", i+1)}
	}
	for i := 0; i < 4; i++ {
		if !full.push(senders[i%3], make([]byte, 16), 3) {
			t.Fatalf("consensus frame %d of 4 was refused with %d of the %d-byte budget queued", i+1, full.bytes, full.limit)
		}
	}
	if full.bytes != full.limit {
		t.Fatalf("four 16-byte consensus frames left the queue at %d bytes, not the %d-byte budget", full.bytes, full.limit)
	}
	if full.push(senders[3], make([]byte, 16), 3) {
		t.Fatalf("a 16-byte consensus frame was admitted into a queue already holding %d of its %d-byte budget - the reservation must not become an exemption from the budget", full.bytes, full.limit)
	}
}

// TestRelayTheReservationBoundaryIsTheFrameSizeItself pins the classification
// comparison at its boundary: a frame of exactly the threshold is
// consensus-sized (so it may use the reserved room), one byte more is bulk (so
// it may not). The threshold is NARROWED here only so the boundary is reachable
// with frames a hand-built queue can hold; the comparison under test is the
// production one (`<=` in sendQ.small), and a `<` there lets one bulk byte buy
// the reserved room.
func TestRelayTheReservationBoundaryIsTheFrameSizeItself(t *testing.T) {
	q := newSendQ(64, 32, 8) // reserve 16 (a quarter), bulk ceiling 48
	q.smallMax = 16
	sender := &conn{dead: make(chan struct{}), srcGroup: "198.51.100.0/24"}

	if !q.push(sender, make([]byte, 17), 1) {
		t.Fatal("the first 17-byte bulk frame was refused at 0 bytes queued")
	}
	if !q.push(sender, make([]byte, 16), 1) {
		t.Fatal("a frame of exactly the threshold was refused room with 33 of 64 bytes queued")
	}
	if q.smallN != 1 {
		t.Fatalf("a frame of exactly the threshold left smallN at %d, want 1", q.smallN)
	}
	before := q.bytes
	if q.push(sender, make([]byte, 17), 1) {
		t.Fatalf("a 17-byte bulk frame was admitted with %d of the 64-byte budget and %d of the 48-byte bulk ceiling queued - one byte over the threshold bought the reserved room", before, before)
	}
	if q.bytes != before || q.smallN != 1 {
		t.Fatalf("the refused push disturbed the queue: %d bytes (was %d), smallN %d (was 1)", q.bytes, before, q.smallN)
	}
	f, ok := q.pop()
	if !ok || len(f.b) != 16 {
		t.Fatalf("the first frame written is %d bytes (present: %v), want the 16-byte consensus frame: the reservation does not drain before bulk", len(f.b), ok)
	}
	if q.smallN != 0 {
		t.Fatalf("smallN is %d after the only consensus frame was written, want 0", q.smallN)
	}
}
