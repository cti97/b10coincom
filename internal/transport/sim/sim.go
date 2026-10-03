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
package sim

import (
	"math/rand"
	"sort"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
)

// Message aliases transport.Message so code and tests in this package can
// refer to it without the package qualifier.
type Message = transport.Message

// Options configures the simulated network's failure behaviour.
type Options struct {
	Seed        int64         // the only source of randomness
	Latency     time.Duration // base one-way delay
	Jitter      time.Duration // uniform extra delay in [0, Jitter)
	DropPercent int           // 0..100, applied per delivery
	Reorder     bool          // if true, delivery order need not match send order
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
func (n *Net) Now() time.Duration { return n.now }

// AddPeer registers a peer. All peers start in partition group 0.
func (n *Net) AddPeer(id string) {
	pid := transport.PeerID(id)
	n.peers[pid] = &endpoint{id: pid, net: n}
	n.group[pid] = 0
}

// TransportFor returns the transport handle for a peer.
func (n *Net) TransportFor(id string) *endpoint { return n.peers[transport.PeerID(id)] }

// Partition puts group A in one partition and group B in another. Messages
// between the groups are dropped; messages within a group still flow.
func (n *Net) Partition(a, b []string) {
	for _, id := range a {
		n.group[transport.PeerID(id)] = 1
	}
	for _, id := range b {
		n.group[transport.PeerID(id)] = 2
	}
}

// Heal puts every peer back in one partition.
func (n *Net) Heal() {
	for id := range n.group {
		n.group[id] = 0
	}
}

// Advance runs virtual time forward by d, delivering everything that becomes due.
// Deliveries happen in (at, seq) order, so the schedule is a total order and the
// run is reproducible.
func (n *Net) Advance(d time.Duration) {
	target := n.now + d
	for {
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
			break
		}
		m := n.queue[next]
		n.queue = append(n.queue[:next], n.queue[next+1:]...)
		n.now = m.at
		if e := n.peers[m.to]; e != nil && e.fn != nil {
			e.fn(transport.Message{From: m.from, Data: m.data})
		}
	}
	n.now = target
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
func (n *Net) sortedPeers() []transport.PeerID {
	ids := make([]transport.PeerID, 0, len(n.peers))
	for id := range n.peers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (e *endpoint) Broadcast(data []byte) error {
	for _, id := range e.net.sortedPeers() {
		if id == e.id {
			continue // a peer never receives its own broadcast
		}
		if e.net.group[id] != e.net.group[e.id] {
			continue // partitioned away
		}
		if e.net.opts.DropPercent > 0 && e.net.rng.Intn(100) < e.net.opts.DropPercent {
			continue
		}
		at := e.net.now + e.net.opts.Latency
		if e.net.opts.Jitter > 0 {
			at += time.Duration(e.net.rng.Int63n(int64(e.net.opts.Jitter)))
		}
		e.net.seq++
		e.net.queue = append(e.net.queue, pending{
			at: at, seq: e.net.seq, to: id, from: e.id, data: append([]byte(nil), data...),
		})
	}
	if e.net.opts.Reorder {
		// Shuffle the queue deterministically so delivery order need not match
		// send order; ordering is then pinned only by (at, seq) as usual.
		e.net.rng.Shuffle(len(e.net.queue), func(i, j int) {
			e.net.queue[i], e.net.queue[j] = e.net.queue[j], e.net.queue[i]
		})
	}
	return nil
}

func (e *endpoint) OnMessage(fn func(transport.Message)) { e.fn = fn }

func (e *endpoint) Peers() []transport.PeerID {
	out := make([]transport.PeerID, 0, len(e.net.peers))
	for id := range e.net.peers {
		if id != e.id {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] }) // deterministic order
	return out
}

func (e *endpoint) Close() error { return nil }
