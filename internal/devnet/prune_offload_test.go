package devnet

import (
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/consensus"
)

// TestMaybePruneOnlySignalsNeverBlocks pins the other half of the 2026-11-16
// deadlock fix. maybePrune runs on the transport's dispatch goroutine, under
// the transport's dispatch lock; it used to run the prune inline, and the prune
// takes the validator mutex (v.mu), so one commit could park every socket
// reader behind the dispatch lock and stop the node reading frames.
//
// The hook must therefore only leave a coalesced token, whatever state the
// prune goroutine is in - including a full wake channel with nobody draining it
// (the shape a hung or slow prune produces).
func TestMaybePruneOnlySignalsNeverBlocks(t *testing.T) {
	v := &Validator{
		pruner:    &consensus.Pruner{}, // non-nil is all the hook tests
		pruneWake: make(chan struct{}, 1),
	}
	v.pruneWake <- struct{}{} // full: no drainer, the worst case

	done := make(chan struct{})
	go func() {
		v.maybePrune(nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("maybePrune blocked with a full wake channel: the dispatch goroutine can still be parked")
	}
}
