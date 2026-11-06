package mempool

// Audit S-6 (2026-11-06): Genesis.Validate bounds MaxClaimsPerBlock ABOVE only
// (<= MaxTxsPerBlock), while the pool capped its per-block hand-out at its own
// constant. A legal genesis with a bound below that constant therefore made Take
// hand the producer more claims than state.ApplyBlock accepts: chain.Build
// refuses the block, the batch is re-added, and the proposer never proposes.
//
// The pool's hand-out is now min(MaxFaucetClaimsPerBlock, the head state's
// MaxClaimsPerBlock), read from the HeadView admission already uses under the
// same lock. These tests pin the bound and the ageing consequence of a lower
// bound; node/s6_claim_bound_test.go pins the proposer end to end.

import (
	"testing"

	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// testStateWithClaimBound is testState with the state machine's per-block claim
// bound ENGAGED, which is what a real chain always has (Genesis.Validate refuses
// a genesis that leaves it zero). It exists so the pool can be judged against the
// consensus rule rather than against its own constant.
func testStateWithClaimBound(bound uint64) *state.State {
	return state.NewWithParams(state.Params{
		EpochBlocks:       testEpochBlocks,
		PowArgon2:         testArgon2,
		PowTarget:         testPowTarget(),
		MaxClaimsPerBlock: bound,
	})
}

// TestTakeBoundsFaucetClaimsByTheStateClaimBound is the finding's core: the
// pool must never hand a block more claims than the state machine accepts. Each
// subtest builds a head state whose consensus bound is K, queues far more claims
// than that, and requires Take to hand out exactly min(K, courtesy constant).
func TestTakeBoundsFaucetClaimsByTheStateClaimBound(t *testing.T) {
	const courtesy = uint64(MaxFaucetClaimsPerBlock)
	for _, tc := range []struct {
		name  string
		bound uint64
		want  int
	}{
		{"genesis bound of 1", 1, 1},
		{"genesis bound of 3", 3, 3},
		{"genesis bound one below the courtesy constant", courtesy - 1, int(courtesy - 1)},
		{"genesis bound equal to the courtesy constant", courtesy, int(courtesy)},
		{"genesis bound above the courtesy constant cannot raise the hand-out", courtesy + 5, int(courtesy)},
		{"unengaged legacy zero falls back to the courtesy constant", 0, int(courtesy)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestPool(t, 1000, testStateWithClaimBound(tc.bound), 0)

			const queued = 20
			for i := 0; i < queued; i++ {
				mustAdd(t, m, newTestKey(t).argon2Claim(t, 1))
			}

			got := m.Take(types.MaxTxsPerBlock)
			claims := 0
			for i := range got {
				if got[i].Type == types.TxFaucetClaim {
					claims++
				}
			}
			if claims != tc.want {
				t.Fatalf("Take handed out %d faucet claims at a state bound of %d, want %d: the pool must not hand a block more claims than state.ApplyBlock accepts (audit S-6)", claims, tc.bound, tc.want)
			}
			// The rest stay pending for later blocks; nothing is dropped.
			if want := queued - claims; m.Len() != want {
				t.Fatalf("pool holds %d txs after Take, want the %d claims past the bound to stay pending", m.Len(), want)
			}
			if m.claims != queued-claims {
				t.Fatalf("claim bookkeeping = %d, want %d", m.claims, queued-claims)
			}
		})
	}
}

// TestALowClaimBoundDoesNotAgeOutClaimsWaitingTheirTurn is the ageing half of
// the same fix. MaxClaimAgeBlocks (32) assumed the courtesy hand-out rate; at a
// genesis bound of 1 a full 64-claim sub-pool needs 64 blocks to drain, so a
// fixed 32-skip limit would silently DESTROY half the honest claims the pool
// had already admitted. The age limit follows the rate instead, and this test
// drains a full sub-pool one claim per block and requires every claim to be
// handed out.
func TestALowClaimBoundDoesNotAgeOutClaimsWaitingTheirTurn(t *testing.T) {
	m := newTestPool(t, 1000, testStateWithClaimBound(1), 0)

	for i := 0; i < MaxFaucetClaimsPerPool; i++ {
		mustAdd(t, m, newTestKey(t).argon2Claim(t, 1))
	}
	// One block per Take, draining the sub-pool at the state's rate of 1.
	taken := 0
	for i := 0; i < MaxFaucetClaimsPerPool; i++ {
		got := m.Take(types.MaxTxsPerBlock)
		for j := range got {
			if got[j].Type == types.TxFaucetClaim {
				taken++
			}
		}
	}
	if taken != MaxFaucetClaimsPerPool {
		t.Fatalf("%d of %d admitted claims were handed to a block: %d were aged out while merely waiting behind a bound of 1, which destroys honest claims the pool had already accepted",
			taken, MaxFaucetClaimsPerPool, MaxFaucetClaimsPerPool-taken)
	}
	if m.Len() != 0 || m.claims != 0 {
		t.Fatalf("pool drained to %d txs (%d claims), want 0 after one bound's worth of blocks", m.Len(), m.claims)
	}
}
