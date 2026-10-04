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

// Dedup is the seen-set for consensus messages.
//
// It exists because the star topology of M4 has no loops — a message arrives
// once or not at all — but M5's PEER_EXCHANGE turns the topology into a mesh,
// and in a mesh every gossip message arrives many times. Retrofitting dedup
// into a live protocol is how a network re-applies votes under load, so the
// set is built now, before anything depends on its absence. It is deliberately
// not wired into the transport yet: the integration belongs with BLOCK_SYNC,
// which needs it first.
//
// Seen is a test-and-set, not a pure query: the first call for a key records
// it and reports false (not seen before), every later call reports true. The
// polarity matters more than anything else in this file — an inverted Seen
// silently drops every vote, a total liveness failure that looks nothing like
// its cause — so the return value is "this key was already known".
//
// All methods are safe for concurrent use: with Task 2's one-goroutine-per-
// connection transport, frames arrive on many reader goroutines, and an
// unsynchronised map written from several goroutines is a crash, not a slow
// path.
type Dedup struct {
	mu   sync.Mutex
	seen map[VoteKey]struct{}
}

// Seen reports whether key has been seen before, and records it as seen on
// this call either way. The first call returns false; every subsequent call
// for the same key returns true.
func (d *Dedup) Seen(key VoteKey) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = make(map[VoteKey]struct{})
	}
	if _, ok := d.seen[key]; ok {
		return true
	}
	d.seen[key] = struct{}{}
	return false
}

// Forget drops every key at heights strictly below the given height. It is
// called as the chain advances so that memory is bounded by the live height
// window rather than by the length of the run: without it, the map grows for
// as long as the node is up. The boundary is exact — a key at height == below
// survives, because the chain advancing past height below still needs that
// height's votes.
//
// The zero-value or empty Dedup is a no-op here, not a panic: the chain can
// advance before the first vote arrives.
func (d *Dedup) Forget(below uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.seen {
		if k.Height < below {
			delete(d.seen, k)
		}
	}
}
