package simnet

// Audit B-5's deterministic coverage: a round divergence among EXACTLY-quorum
// live seats, with one seat of the committee powered off.
//
// The 4-seat, 3-live rolling-restart stall of the 2026-10-30 Docker re-run is a
// DIFFERENT mechanism from the 3-seat stall `5af2174` fixed. The 3-seat fault was
// a proposal arriving for a round the engine had not entered yet, and it was
// closed by buffering early proposals. This one is round divergence: the live
// seats sit in different rounds, so no round can collect a quorum of votes at
// all. Neither closer available to the protocol can help, and for a structural
// reason:
//
//   - the round-resync jump needs TotalPower-Quorum+1 of the power BEHIND it;
//     with exactly a quorum live (n-1 of n seats for n = 4, 5, 6) ONE live seat
//     in a later round holds 1 of that bar's 2, so the jump never fires;
//   - the timeout ladder is the only closer: the deadline is strictly increasing
//     in the round, so the engine in the SMALLER round fires sooner and gains a
//     round on the others, round after round, until the live seats coincide.
//
// WHAT THIS TEST CONSTRUCTS, AND WHAT IT DOES NOT. It builds the state - one
// seat powered off with exactly-quorum live power, and each live driver
// resuming at a different round - and lets virtual time run. It does NOT
// reproduce the multi-minute wall-clock stall, and it would be wrong to claim
// it does: an in-process restart is instant, and the 2026-10-30 report measured
// the real socket variant (4 to 6.5 minutes). The claim pinned here is the
// MECHANISM and the liveness: with the jump rule structurally unable to fire,
// the ladder still closes a divergence and the height still commits. The
// saturating-ladder mutant (a bounded monotone schedule) makes this test hang
// until its budget expires, which is the absorbing state driver.go describes.

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/store"
)

// runRoundDivergence advances the simulator the way Net.runUntil does, with a
// budget of its own: the generic stall detector allows about two virtual seconds
// without height progress, and a divergence that the ladder has to walk shut is
// exactly a run with no height progress for longer than that. The budget here is
// a bound on the CONSTRUCTION (how far apart the rounds are), not a substitute
// for an assertion: the height must reach the target or the run is called
// stalled.
func runRoundDivergence(n *Net, target uint64, live []int, budget int) error {
	for step := 0; step < budget; step++ {
		n.now += runBlocksStepMS
		for i, d := range n.drv {
			if n.offline[i] {
				continue // a powered-off machine ticks and receives nothing
			}
			d.Tick(n.now)
		}
		n.sim.Advance(ms(runBlocksStepMS))
		done := true
		for _, i := range live {
			if n.ch[i].Height() < target {
				done = false
				break
			}
		}
		if done {
			return nil
		}
	}
	return fmt.Errorf("simnet: the divergence did not close below height %d in %d steps (heights %v, seed %d)",
		target, budget, n.Heights(), n.opts.Seed)
}

// TestARoundDivergenceAmongExactlyQuorumLiveSeatsCloses is the missing
// networked-size coverage B-5 names: 4 to 6 seats with one seat without a node.
func TestARoundDivergenceAmongExactlyQuorumLiveSeatsCloses(t *testing.T) {
	for _, seats := range []int{4, 5, 6} {
		seats := seats
		t.Run(fmt.Sprintf("%d-seats-%d-live", seats, seats-1), func(t *testing.T) {
			n, err := New(seats, Options{
				TempDir:     t.TempDir(),
				Seed:        int64(seats),
				LatencyMS:   1,
				TimeoutBase: 200,
				TimeoutStep: 100,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			if _, err := n.RunBlocks(2); err != nil {
				t.Fatalf("warming the chain: %v", err)
			}

			// One seat without a node. It stays in the committee, so the quorum
			// does not get easier - the opposite of what an outage does.
			live := seats - 1
			victim := seats - 1
			n.TakeOffline(victim)
			head := n.ch[0].Height()

			// FIXTURE: the live power is EXACTLY the quorum, not merely above it.
			// This is the property the whole scenario rests on - with slack, a
			// subset of the live seats could decide without the divergent ones.
			vals, err := n.CommitteeAt(0, head+1)
			if err != nil {
				t.Fatalf("the committee at %d: %v", head+1, err)
			}
			cfg := consensus.Config{Committee: vals}
			total, quorum := cfg.TotalPower(), cfg.Quorum()
			var livePower uint64
			for i := 0; i < live; i++ {
				seat := genesis.SeatOfPubKey(vals, n.keys[i].priv.Public().(ed25519.PublicKey))
				if seat < 0 {
					t.Fatalf("fixture: live validator %d holds no seat at %d", i, head+1)
				}
				livePower += vals[seat].Power
			}
			if livePower != quorum {
				t.Fatalf("fixture: the %d live seats hold %d of %d power; the quorum is %d, so the shape is not exactly-quorum live", live, livePower, total, quorum)
			}
			if livePower == total {
				t.Fatalf("fixture: the powered-off seat carries no power (total %d), so the committee is not short a seat", total)
			}

			// CONSTRUCT THE DIVERGENCE: ONE live seat is ahead, the rest are
			// together at round 0 - the shape the jump rule structurally cannot
			// close. Its bar is TotalPower-Quorum+1 (= 2 here), so a single live
			// seat in a later round can never pull the laggards forward; only the
			// ladder can. The rounds are set through the chain's own durable round
			// record, so the fresh engines restore them through the production
			// path a restarted validator takes.
			ahead := live - 1
			for i := 0; i < live; i++ {
				round := uint32(0)
				if i == ahead {
					round = uint32(live + 1) // for 4 seats: 0, 0, 4
				}
				if err := n.ch[i].PutRound(store.RoundRecord{Height: head + 1, Round: round}); err != nil {
					t.Fatalf("recording validator %d's round: %v", i, err)
				}
				if err := n.rebuildDriver(i); err != nil {
					t.Fatalf("rebuilding validator %d over the recorded round: %v", i, err)
				}
				if got := n.drv[i].Round(); got != round {
					t.Fatalf("fixture: validator %d resumed at round %d, want %d", i, got, round)
				}
			}
			var aheadSeats int
			for i := 0; i < live; i++ {
				if n.drv[i].Round() > 0 {
					aheadSeats++
				}
			}
			if aheadSeats != 1 {
				t.Fatalf("fixture: %d live seats are ahead, want exactly 1: with two ahead the jump rule's bar is met and the ladder is not the closer under test", aheadSeats)
			}
			t.Logf("%d seats, %d live (power %d of %d, quorum %d): one live seat ahead at round %d, the rest at round 0, height %d",
				seats, live, livePower, total, quorum, uint32(live+1), head+1)

			// The ladder is the only closer. Three more heights is enough to
			// prove the committee is finalising again, not merely inching.
			target := head + 3
			if err := runRoundDivergence(n, target, []int{0, 1, 2, 3, 4}[:live], 20000); err != nil {
				t.Fatalf("a round divergence among exactly-quorum live seats did not close: %v", err)
			}
			if err := n.AssertSameChain(); err != nil {
				t.Fatalf("the committee disagreed after the divergence closed: %v", err)
			}
			for _, i := range []int{0, 1, 2, 3, 4}[:live] {
				if got := n.ch[i].Height(); got < target {
					t.Fatalf("validator %d is at height %d, below the target %d", i, got, target)
				}
			}
		})
	}
}
