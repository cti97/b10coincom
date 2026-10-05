package transport

import "sync"

// VoteKey identifies exactly one consensus message: the tuple
// (validator, height, round, type) that every consensus message carries.
// All four fields participate — a key that ignored any one of them would let
// votes from different validators, heights, rounds or message kinds eat each
// other, and a key that used only some of them would let the same message be
// re-applied under a different name.
type VoteKey struct {
	Validator string
	Height    uint64
	Round     uint32
	Type      uint8
}

// DefaultMaxDedupHeights bounds how many DISTINCT heights the seen-set may
// hold at once. The live window is a handful of heights (the round protocol
// decides one height before moving on), so 64 is far above honest use and
// still a hard ceiling on a peer that announces votes at ever-changing
// heights.
const DefaultMaxDedupHeights = 64

// Dedup is the seen-set for consensus messages, SHARDED BY HEIGHT.
//
// It exists because the star topology of M4 has no loops — a message arrives
// once or not at all — but M5's PEER_EXCHANGE turns the topology into a mesh,
// and in a mesh every gossip message arrives many times. Retrofitting dedup
// into a live protocol is how a network re-applies votes under load, so the
// set is built now, before anything depends on its absence.
//
// Two properties are audit N-7's fix and matter more than the shape:
//
//   - Seen is consulted STRICTLY AFTER signature verification (see
//     MessageRouter.Route). A key is recorded only for a message whose
//     signature already verified, so a stranger cannot pre-seed the key of an
//     honest vote it cannot sign and thereby have that honest vote dropped.
//     Recording before verification would make the dedup set a censorship
//     primitive usable by anyone who can reach the port.
//
//   - The map is sharded by HEIGHT (one bucket per height) and its bucket
//     count is BOUNDED. Forget drops whole height buckets, so it is O(live
//     heights), never an O(entries) scan of every key ever seen; and a peer
//     that keeps announcing new heights cannot grow the map without limit -
//     the lowest bucket is evicted once the ceiling is reached.
//
// All methods are safe for concurrent use: with the one-goroutine-per-
// connection transport, frames arrive on many reader goroutines, and an
// unsynchronised map written from several goroutines is a crash, not a slow
// path.
type Dedup struct {
	mu       sync.Mutex
	byHeight map[uint64]map[VoteKey]struct{}
	// maxHeights is the bucket ceiling. Zero means DefaultMaxDedupHeights.
	maxHeights int
	evicted    uint64
}

// NewDedup returns a height-sharded seen-set holding at most maxHeights
// distinct heights; a non-positive value selects DefaultMaxDedupHeights.
func NewDedup(maxHeights int) *Dedup {
	if maxHeights <= 0 {
		maxHeights = DefaultMaxDedupHeights
	}
	return &Dedup{
		byHeight:   make(map[uint64]map[VoteKey]struct{}),
		maxHeights: maxHeights,
	}
}

// Seen reports whether key has been seen before, and records it as seen on
// this call either way. The first call returns false; every subsequent call
// for the same key returns true. Callers MUST have verified the message's
// signature first.
func (d *Dedup) Seen(key VoteKey) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.byHeight == nil {
		d.byHeight = make(map[uint64]map[VoteKey]struct{})
	}
	if d.maxHeights <= 0 {
		d.maxHeights = DefaultMaxDedupHeights
	}
	bucket := d.byHeight[key.Height]
	if _, ok := bucket[key]; ok {
		return true
	}
	if bucket == nil {
		bucket = make(map[VoteKey]struct{})
		d.byHeight[key.Height] = bucket
		d.evictLowest() // bound the BUCKET count, not only the key count
	}
	bucket[key] = struct{}{}
	return false
}

// evictLowest drops whole height buckets, lowest first, until the ceiling is
// met. Called only after a new bucket was inserted, so at most one step is
// needed in the steady case; the loop covers a caller that lowered the
// ceiling. Caller holds d.mu.
func (d *Dedup) evictLowest() {
	for len(d.byHeight) > d.maxHeights {
		var lowest uint64
		first := true
		for h := range d.byHeight {
			if first || h < lowest {
				lowest, first = h, false
			}
		}
		delete(d.byHeight, lowest)
		d.evicted++
	}
}

// Forget drops every key at heights strictly below the given height. It is
// called as the chain advances so that memory is bounded by the live height
// window rather than by the length of the run. The boundary is exact — a key
// at height == below survives, because the chain advancing past height below
// still needs that height's votes.
//
// It deletes whole height BUCKETS, so its cost is the number of live heights
// (at most the ceiling), not the number of keys ever seen (audit N-7).
//
// The zero-value or empty Dedup is a no-op here, not a panic: the chain can
// advance before the first vote arrives.
func (d *Dedup) Forget(below uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for h := range d.byHeight {
		if h < below {
			delete(d.byHeight, h)
		}
	}
}

// Has reports whether key is currently recorded, WITHOUT recording it. It is
// the read-only companion to Seen, for tests and diagnostics that must ask
// "did this key get recorded?" without changing the answer.
func (d *Dedup) Has(key VoteKey) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.byHeight[key.Height][key]
	return ok
}

// Heights reports how many distinct height buckets are held. It exists for the
// tests that pin the bound and the sharding; production code does not read it.
func (d *Dedup) Heights() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.byHeight)
}

// Evicted reports how many height buckets were dropped by the ceiling. A
// nonzero value means the seen-set was asked to track more heights than its
// bound, which is exactly what the bound exists for.
func (d *Dedup) Evicted() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.evicted
}
