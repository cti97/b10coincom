package devnet

// Deliberate cost benchmark for RT-4, written to keep the corrected claim in
// internal/consensus/diag.go checkable rather than asserted. There are two
// observers on the node's hot path: the per-round ring (Driver.Observe, called
// after every routed frame and every tick, inside the driver mutex) and the
// stall watcher (stallReportOnce, called after every tick and folding the ring
// only when it is about to emit a line). This measures each one at the BOUND:
// the committee is driven to fill the engine's retention window
// (futureVoteRounds + pastVoteRounds + 1 = 9 rounds), four quiet validators have
// their tick and wave loops an hour apart, and two peers are attested so the
// watcher takes its "quorum reachable, same round" early return - the steady
// state a running chain is in.
//
// Run: go test -run '^$' -bench BenchmarkHotPathObservers -benchmem ./internal/devnet
//
// It is a benchmark, not a test: `go test` never executes it.

import (
	"fmt"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
)

func BenchmarkHotPathObservers(b *testing.B) {
	vs := make([]*Validator, 4)
	for i := range vs {
		v, err := StartValidator(ValidatorConfig{
			Dir:        b.TempDir(),
			Index:      i,
			Validators: 4,
			TickEvery:  time.Hour,
			WaveEvery:  time.Hour,
		})
		if err != nil {
			b.Fatalf("starting quiet validator %d: %v", i, err)
		}
		vs[i] = v
	}
	b.Cleanup(func() { closeAll(vs) })
	v := vs[0]
	// Attest the other two live seats exactly as a verified HELLO would, so the
	// watcher sees quorum-reachable and takes its cheap early return.
	for seat := 1; seat < 3; seat++ {
		v.recordHeight(string(vs[seat].pub), transport.PeerID(fmt.Sprintf("v%d", seat)), 0)
	}
	// Fill the retention window: ten rounds of the test's virtual clock, which
	// is what makes diagRetainedRounds walk nine rounds rather than one. No
	// transport exists, so nothing can commit and the height stays 0.
	var now int64
	for i := 0; i < 10; i++ {
		now += 1_000_000
		for _, x := range vs {
			x.mu.Lock()
			x.drv.Tick(now)
			x.drv.Observe()
			x.mu.Unlock()
		}
	}

	// Driver.Observe under the mutex the call sites already hold: this is the
	// whole per-dispatch increment, and one of the two per-tick folds.
	b.Run("observe-full-window", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			v.mu.Lock()
			v.drv.Observe()
			v.mu.Unlock()
		}
	})

	// The stall watcher alone on a healthy tick: the height/round read and the
	// early return, with no ring fold and no quorum-table walk.
	b.Run("stall-watch-healthy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			v.stallReportOnce()
		}
	})

	// The tick path as tickLoop runs it: one Observe plus the watcher.
	b.Run("tick-path-both", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			v.mu.Lock()
			v.drv.Observe()
			v.mu.Unlock()
			v.stallReportOnce()
		}
	})
}
