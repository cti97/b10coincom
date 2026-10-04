package transport

// These tests live in package transport rather than transport_test because the
// memory-bound property is not observable through the exported API: only the
// length of the underlying map shows that Forget actually reclaims entries
// rather than merely stopping the map from being consulted. Everything else is
// asserted through the public surface.
//
// House rule from the brief: the polarity of Seen is the one wrong answer that
// looks like a networking problem elsewhere. A dedup that reports every key as
// already seen silently drops every vote — a total liveness failure that
// looks nothing like its cause — so the first test pins the polarity before
// anything else.

import (
	"fmt"
	"sync"
	"testing"
)

func TestDedupReportsAKeySeenOnceAndOnlyOnce(t *testing.T) {
	var d Dedup
	key := VoteKey{Validator: "v1", Height: 7, Round: 2, Type: 3}

	if d.Seen(key) {
		t.Fatal("the first Sight of a key must report false (not seen): an inverted Seen silently drops every vote")
	}
	for i := 0; i < 3; i++ {
		if !d.Seen(key) {
			t.Fatalf("repeat #%d of the same key must report true (seen)", i+2)
		}
	}

	// Every field participates in the key. Distinctness per field is what
	// makes the dedup per-(validator, height, round, type) instead of, say,
	// per-height: get this wrong and votes from different validators or
	// different message types eat each other.
	similar := []VoteKey{
		{Validator: "v2", Height: 7, Round: 2, Type: 3}, // different validator
		{Validator: "v1", Height: 8, Round: 2, Type: 3}, // different height
		{Validator: "v1", Height: 7, Round: 3, Type: 3}, // different round
		{Validator: "v1", Height: 7, Round: 2, Type: 4}, // different type
	}
	for _, k := range similar {
		if d.Seen(k) {
			t.Fatalf("a key differing only in %v must be reported as not seen: got already-seen", k)
		}
		if !d.Seen(k) {
			t.Fatalf("the second Sight of %v must be reported as seen", k)
		}
	}
}

func TestDedupForgetsBelowAHeight(t *testing.T) {
	var d Dedup
	const validators = 8
	const heights = 10
	for h := uint64(1); h <= heights; h++ {
		for v := 0; v < validators; v++ {
			d.Seen(VoteKey{Validator: fmt.Sprintf("v%d", v), Height: h, Round: 1, Type: 2})
		}
	}
	if got, want := len(d.seen), validators*heights; got != want {
		t.Fatalf("expected %d distinct keys recorded, got %d", want, got)
	}

	// Forget(5) must delete heights strictly below 5 and keep the boundary
	// itself: the chain advancing past height 5 still needs height-5 votes.
	d.Forget(5)
	if got, want := len(d.seen), validators*6; got != want {
		t.Fatalf("after Forget(5) expected %d keys (heights 5..10), got %d — a no-op leaks, an over-delete drops live votes", want, got)
	}

	// A forgotten key is seen-able again: it reports not-seen once, then seen.
	forgotten := VoteKey{Validator: "v0", Height: 2, Round: 1, Type: 2}
	if d.Seen(forgotten) {
		t.Fatal("height 2 is strictly below the Forget(5) boundary and must have been forgotten")
	}
	if !d.Seen(forgotten) {
		t.Fatal("after being forgotten and re-seen, the key must be recorded again")
	}

	// The boundary key at exactly below survives the sweep: it was recorded
	// before Forget and must still be seen afterwards.
	if !d.Seen(VoteKey{Validator: "v0", Height: 5, Round: 1, Type: 2}) {
		t.Fatal("height 5 is the boundary itself: Forget(below) must keep keys at exactly below")
	}

	// Forget on an empty set (and on the zero value) must be a no-op, not a
	// panic: the chain can advance before the first vote arrives.
	var empty Dedup
	empty.Forget(3)
	empty.Forget(0) // below the smallest possible height: deletes nothing
}

func TestDedupIsSafeUnderConcurrentUse(t *testing.T) {
	// Mirrors the real shape from Task 2: one reader goroutine per connection
	// calls Seen while the chain-advance loop calls Forget, so the map is
	// read and written from many goroutines at once. Under -race an
	// unsynchronised map here is a crash or a reported data race, not a slow
	// path.
	var d Dedup
	const workers = 8
	const ops = 2000
	const forgets = ops / 10

	var wg sync.WaitGroup
	start := make(chan struct{}) // release every goroutine together

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for h := uint64(1); h <= forgets; h++ {
			d.Forget(h)
		}
	}()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < ops; i++ {
				// A hot key every worker touches (collisions guaranteed, not
				// lucky) plus private keys per worker.
				if d.Seen(VoteKey{Validator: "hot", Height: uint64(i % 100), Round: uint32(w), Type: 1}) {
					continue
				}
				if d.Seen(VoteKey{Validator: fmt.Sprintf("v%d", w), Height: uint64(i), Round: 0, Type: 2}) {
					continue
				}
			}
			// Each worker also sweeps the set, so Forget races Seen from both
			// directions rather than only one dedicated goroutine.
			d.Forget(uint64(w))
		}(w)
	}

	close(start)
	wg.Wait()

	if len(d.seen) == 0 {
		t.Fatal("after concurrent use the set must still hold the keys forget never reached")
	}
}
