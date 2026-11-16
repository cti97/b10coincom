package devnet

import "testing"

// TestTheRoundLadderDefaultsToTheShippedBaseAndStep pins the resolution rule
// behind --timeout-base/--timeout-step: a zero (or absent) setting takes the
// shipped constants, a positive one is used verbatim. The base is the wait a
// round gets before the ladder starts, so its default is the mitigation for
// the round-divergence ratchet (docs/bug-2026-11-16-round-divergence-ratchet.md)
// and must not drift silently.
func TestTheRoundLadderDefaultsToTheShippedBaseAndStep(t *testing.T) {
	cases := []struct {
		name               string
		base, step         int64
		wantBase, wantStep int64
	}{
		{"both absent", 0, 0, consensusTimeoutBaseMS, consensusTimeoutStepMS},
		{"negative is absent", -5, -5, consensusTimeoutBaseMS, consensusTimeoutStepMS},
		{"base set, step absent", 5000, 0, 5000, consensusTimeoutStepMS},
		{"step set, base absent", 0, 250, consensusTimeoutBaseMS, 250},
		{"both set", 5000, 250, 5000, 250},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotBase, gotStep := timeoutsMS(c.base, c.step)
			if gotBase != c.wantBase || gotStep != c.wantStep {
				t.Fatalf("timeoutsMS(%d, %d) = (%d, %d), want (%d, %d)",
					c.base, c.step, gotBase, gotStep, c.wantBase, c.wantStep)
			}
		})
	}
	// The shipped base must stay well above one WAN retransmit (RTO ~230 ms on
	// the measured live path); a regression back to 200 ms would re-open the
	// ratchet this test exists to guard.
	if consensusTimeoutBaseMS < 1000 {
		t.Fatalf("consensusTimeoutBaseMS = %d ms, below the 1 s floor the live WAN needs", consensusTimeoutBaseMS)
	}
}
