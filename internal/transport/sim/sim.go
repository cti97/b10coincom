// Package sim is a deterministic, virtual-time network. It is what makes the
// spec's verification strategy possible: N validators run in one process over an
// injected-latency, lossy, reordering, partitionable network, all driven by a
// seed, so any failure replays exactly.
//
// Two properties matter more than realism:
//
//   - SINGLE-THREADED. No goroutines, no channels, no sleeps. The driver advances
//     virtual time and the network delivers whatever is now due, in a fixed order.
//     Goroutine scheduling would make runs irreproducible.
//   - THE SEED IS THE ONLY RANDOMNESS. Every jitter, drop and reorder decision comes
//     from one explicitly seeded *rand.Rand stored on the Net.
//
// M4 Task 6 added the one concurrency the simulator has ever needed, without
// surrendering either property: BLOCK_SYNC's pull is a blocking call
// (Syncer.awaitReply waits for the filed response), and a blocking pull must
// not freeze the network it is waiting ON. Net therefore grew a mutex so a
// scenario can advance the network from a second goroutine while one
// validator's pull is parked in its await - the delivery ORDER is still the
// (at, seq) total order, every rng draw still happens in the same place, and
// a single-threaded scenario (the M3 shape) contends on nothing and replays
// byte-identically. The lock is internal discipline, not a delivery policy.
package sim

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
)

// Message aliases transport.Message so code and tests in this package can
// refer to it without the package qualifier.
type Message = transport.Message

// Options configures the simulated network's failure behaviour.
type Options struct {
	Seed    int64         // the only source of randomness
	Latency time.Duration // base one-way delay
	// Jitter is the uniform extra delay in [0, Jitter) added to each
	// delivery. It is also the knob that REORDERS delivery: because each
	// message's delay is an independent draw, arrivals need not match send
	// order whenever Jitter > 0 — there is no separate reorder option.
	Jitter      time.Duration
	DropPercent int // 0..100, applied per delivery
}

// pending is one message waiting for its delivery time.
type pending struct {
	at   time.Duration
	seq  uint64
	to   transport.PeerID
	from transport.PeerID
	data []byte
}

// Net is a deterministic network over virtual time.
type Net struct {
	// mu guards every field of the net and of its endpoints that delivery or
	// sending can touch. The M3 scenarios never contend: one goroutine owns
	// the net, so the lock costs a uncontended acquire per send and changes
	// nothing else. Catch-up (Task 6) is the second owner: a pull goroutine
	// parked in its await while the scenario's drive loop advances.
	mu    sync.Mutex
	opts  Options
	rng   *rand.Rand
	now   time.Duration
	seq   uint64
	peers map[transport.PeerID]*endpoint
	group map[transport.PeerID]int // partition group; equal groups can talk
	queue []pending
}

type endpoint struct {
	id  transport.PeerID
	net *Net
	fn  func(transport.Message)
}

// New creates a network. The seed fixes every subsequent decision.
func New(opts Options) *Net {
	return &Net{
		opts:  opts,
		rng:   rand.New(rand.NewSource(opts.Seed)),
		peers: make(map[transport.PeerID]*endpoint),
		group: make(map[transport.PeerID]int),
	}
}

// Now reports virtual time. It is the ONLY clock the simulator has.
func (n *Net) Now() time.Duration {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.now
}

// AddPeer registers a peer. All peers start in partition group 0.
func (n *Net) AddPeer(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	pid := transport.PeerID(id)
	n.peers[pid] = &endpoint{id: pid, net: n}
	n.group[pid] = 0
}

// TransportFor returns the transport handle for a peer.
func (n *Net) TransportFor(id string) *endpoint {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.peers[transport.PeerID(id)]
}

// Partition puts group A in one partition and group B in another. Messages
// between the groups are dropped; messages within a group still flow.
func (n *Net) Partition(a, b []string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, id := range a {
		n.group[transport.PeerID(id)] = 1
	}
	for _, id := range b {
		n.group[transport.PeerID(id)] = 2
	}
}

// Heal puts every peer back in one partition.
func (n *Net) Heal() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id := range n.group {
		n.group[id] = 0
	}
}

// Advance runs virtual time forward by d, delivering everything that becomes due.
// Deliveries happen in (at, seq) order, so the schedule is a total order and the
// run is reproducible.
//
// The lock is held to pick and to pop a delivery — never across the delivery
// itself. A message's handler may legitimately send (the BLOCK_SYNC server
// answering a request does exactly that), and the send must be able to take
// the lock while the advance loop is mid-flight. Delivering outside the lock
// cannot change the total order: the next pick chooses the minimum (at, seq)
// over the queue as it stands, and a Send that happened during the handler
// competes for the next pick exactly as its at/seq dictate — the same set of
// messages is due, in the same order, as the old single-threaded loop chose.
func (n *Net) Advance(d time.Duration) {
	target := n.now + d
	for {
		n.mu.Lock()
		next := -1
		for i := range n.queue {
			if n.queue[i].at > target {
				continue
			}
			if next < 0 || less(n.queue[i], n.queue[next]) {
				next = i
			}
		}
		if next < 0 {
			n.now = target
			n.mu.Unlock()
			break
		}
		m := n.queue[next]
		n.queue = append(n.queue[:next], n.queue[next+1:]...)
		n.now = m.at
		// The callback is read under the lock; the call happens after it.
		// e.fn is only ever replaced from the scenario goroutine, but the
		// read-then-release shape keeps the race detector silent for the
		// catch-up's second goroutine too.
		var fn func(transport.Message)
		var from transport.PeerID
		var data []byte
		if e := n.peers[m.to]; e != nil && e.fn != nil {
			fn, from, data = e.fn, m.from, m.data
		}
		n.mu.Unlock()
		if fn != nil {
			fn(transport.Message{From: from, Data: data})
		}
	}
}

// less orders deliveries by time, then by send sequence, so ties break the same
// way on every run.
func less(a, b pending) bool {
	if a.at != b.at {
		return a.at < b.at
	}
	return a.seq < b.seq
}

// sortedPeers returns every registered peer ID in sorted order. Broadcast must
// iterate over this, never over the map directly: the number and the order of
// rng draws (drops, jitter) must depend only on the seed, so map iteration
// randomness may not reach an observable decision anywhere.
//
// The caller holds n.mu (Broadcast and Peers are the entire call surface); the
// method deliberately does not take the lock itself.
func (n *Net) sortedPeers() []transport.PeerID {
	ids := make([]transport.PeerID, 0, len(n.peers))
	for id := range n.peers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (e *endpoint) Broadcast(data []byte) error {
	n := e.net
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, id := range n.sortedPeers() {
		if id == e.id {
			continue // a peer never receives its own broadcast
		}
		if n.group[id] != n.group[e.id] {
			continue // partitioned away
		}
		if n.opts.DropPercent > 0 && n.rng.Intn(100) < n.opts.DropPercent {
			continue
		}
		at := n.now + n.opts.Latency
		if n.opts.Jitter > 0 {
			at += time.Duration(n.rng.Int63n(int64(n.opts.Jitter)))
		}
		n.seq++
		n.queue = append(n.queue, pending{
			at: at, seq: n.seq, to: id, from: e.id, data: append([]byte(nil), data...),
		})
	}
	return nil
}

// Send delivers to exactly one peer. It lands in the SAME delivery queue as
// Broadcast, stamped with virtual now and next sequence number, so its
// delivery point is the next Advance and its arrival order is the total
// (at, seq) order — deterministic like everything else here.
//
// The three things Send deliberately does NOT do, and why:
//
//   - no Latency, no Jitter: SYNC is a request/response a validator is
//     already waiting on; a deterministic-uniform added delay would only
//     stretch scenarios without modelling anything Broadcast does not. No
//     rng draw is consumed, so adding Send nowhere changes any existing
//     scenario's rng stream, replay for byte.
//   - no DropPercent roll: the requester retries a lost sync; baking silent
//     loss into unicast would leave the retry untestable at a fixed seed.
//   - no synchronous re-entry: like Broadcast, delivery happens when the
//     network advances, never inside the caller's send — the engine must
//     not be re-entered mid-step regardless of which primitive carried it.
//
// A partitioned peer receives nothing, mirroring Broadcast: a partition is a
// partition for the whole transport surface, not only for gossip.
func (e *endpoint) Send(to transport.PeerID, data []byte) error {
	n := e.net
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.peers[to]; !ok {
		return fmt.Errorf("sim: unknown peer %q", to)
	}
	if to == e.id {
		// Same answer the TCP transport gives (its Send can never find the
		// local ID in its registry because self connections are refused at
		// the handshake): a node is never its own peer, and a validator
		// messaging "itself" over the wire would double-count its own vote.
		// Erroring here keeps the two transports interchangeable for the
		// driver and the Task-4 syncer.
		return fmt.Errorf("sim: %q is the local endpoint, not a peer", to)
	}
	if n.group[to] != n.group[e.id] {
		return fmt.Errorf("sim: peer %q is partitioned away", to)
	}
	n.seq++
	n.queue = append(n.queue, pending{
		at: n.now, seq: n.seq, to: to, from: e.id, data: append([]byte(nil), data...),
	})
	return nil
}

func (e *endpoint) OnMessage(fn func(transport.Message)) {
	n := e.net
	n.mu.Lock()
	defer n.mu.Unlock()
	e.fn = fn
}

func (e *endpoint) Peers() []transport.PeerID {
	n := e.net
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]transport.PeerID, 0, len(n.peers))
	for id := range n.peers {
		if id != e.id {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] }) // deterministic order
	return out
}

func (e *endpoint) Close() error { return nil }
