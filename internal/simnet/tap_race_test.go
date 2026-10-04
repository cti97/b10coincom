package simnet

import (
	"sync"
	"testing"

	"github.com/cti97/b10coincom/internal/transport"
)

// The recording tap's logs (`sent`, `recv`) are appended from at least two
// goroutines on the SAME validator: a catch-up pull runs
// Syncer.PullAndAdopt's Send on its own goroutine while CatchUp's goroutine
// keeps advancing the sim, whose deliveries drive engine Broadcasts and
// inbound OnMessage appends. Before the fix (Task 6 review carry-forward)
// those appends were unlocked — a latent data race, unobserved because a pull
// rarely overlaps an engine broadcast at the right instant.
//
// This test drives the exact racing PAIR of calls — Send and Broadcast (and
// the recv append the delivery callback makes) on the production tap of a
// real two-validator net — from concurrent goroutines, many rounds, so the
// race detector, not scheduling luck, is the evidence. Mutant: remove tap's
// mu (and its locked helpers) — this test fails under -race, repeatably.
func TestTapRecordingLogsAreRaceFreeUnderConcurrentSendAndBroadcast(t *testing.T) {
	n, err := New(2, Options{TempDir: t.TempDir(), Seed: 11})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	// An idle validator: no consensus traffic of its own, so every recorded
	// frame below is the test's own probe. Peers are the endpoint's own
	// list, so the probe peer name is production state, not a guess.
	tp := n.taps[0]
	tp.mu.Lock()
	routerSet := tp.router != nil
	tp.mu.Unlock()
	if !routerSet {
		t.Fatal("the production tap has no router - deliveries would never be recorded")
	}
	p := tp.Peers()
	if len(p) == 0 {
		t.Fatal("validator 0 has no peers to address")
	}

	// The pull side's call shape (the pull goroutine's Send of a request)
	// and the delivery side's call shapes (Advance's delivery of a real frame
	// to OnMessage, whose engine Broadcasts from within the callback). Both go
	// through the tap's own recording paths, exactly as production does.
	probe := transport.Message{From: transport.PeerID("tap-race-probe"), Data: []byte("tap-race-send")}
	const rounds = 400
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(2)
			go func() { defer wg.Done(); _ = tp.Send(p[0], probe.Data) }()
			go func() {
				defer wg.Done()
				_ = tp.Broadcast(probe.Data)
				// The delivery callback records too: inbound frames append
				// to recv through the same lock, so exercise that path from
				// the racing goroutines as well.
				tp.keepRecv(probe.Data)
			}()
		}
		wg.Wait()
	}
	if got := tp.sentCount(); got != rounds*8 {
		t.Fatalf("sent log recorded %d frames, want %d - the recording path lost a payload", got, rounds*8)
	}
	if got := tp.recvCount(); got != rounds*4 {
		t.Fatalf("recv log recorded %d frames, want %d - the receiving path lost a frame", got, rounds*4)
	}
	if got, want := len(tp.sentLog()), tp.sentCount(); got != want {
		t.Fatalf("the snapshot (%d) and the count (%d) disagree - the logs are not one guarded state", got, want)
	}
}
