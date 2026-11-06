package devnet

// T-1's two properties, pinned on the wait itself rather than on a loaded host
// (testrun 2026-11-06, T-1).
//
// The flake was three rotation tests failing at `heights [0 0 0 0 0]` on a host
// running ~53 containers: their waits were 60 s and 120 s of wall clock, chosen
// as numbers, so a starved scheduler either ran out of them or did not - and a
// longer fixed number would have been the same bug with a bigger multiplier.
// The waits now derive their allowance from the work still missing and the
// cadence a run is actually achieving (`reachByWork` / `reachAllowance`).
//
// Two things must therefore be true, and both are constructed here:
//
//   - the allowance is a FUNCTION of the work and the observed rate, not a
//     constant (so a slow host's budget grows with the slowness); and
//   - a chain that genuinely stops advancing is still reported, inside the
//     product's own stall window, naming the heights - the wait cannot buy
//     patience with a hang.

import (
	"strings"
	"testing"
	"time"
)

func TestReachAllowanceIsDerivedFromWorkAndRate(t *testing.T) {
	const stall = time.Second
	base := reachAllowance(1, 100*time.Millisecond, stall)
	if base != stall+100*time.Millisecond {
		t.Fatalf("allowance for one block at 100ms = %s, want %s: it must be the stall window plus one block", base, stall+100*time.Millisecond)
	}
	// More work still missing => a longer allowance (the wait budgets the
	// blocks it still needs, not a fixed second count).
	if more := reachAllowance(8, 100*time.Millisecond, stall); more <= base {
		t.Fatalf("allowance for 8 blocks (%s) is not above the one-block allowance (%s): the work is not in the derivation", more, base)
	}
	// The SAME work on a slower host => a longer allowance, because perBlock is
	// measured from the run. This is the load-proportionality that the fixed
	// 60 s did not have.
	if slower := reachAllowance(1, 500*time.Millisecond, stall); slower <= base {
		t.Fatalf("allowance at 500ms per block (%s) is not above the 100ms one (%s): the observed rate is not in the derivation", slower, base)
	}
	// And it is never below the stall window: a host cannot talk the wait out
	// of noticing a stall.
	if got := reachAllowance(0, 0, stall); got != stall {
		t.Fatalf("allowance with no work and no rate = %s, want the stall window %s", got, stall)
	}
}

// TestReachByWorkReportsAStallInsteadOfMaskingIt constructs a chain that cannot
// commit - one genesis seat of a committee whose quorum is four - and requires
// the wait to FAIL, quickly and by name. A wait that grew its budget without
// bound (or that returned success on timeout) would pass the rotation tests
// while hiding exactly the stall they exist to catch.
func TestReachByWorkReportsAStallInsteadOfMaskingIt(t *testing.T) {
	g, _ := rotationInGenesis(t)
	// One seat of five genesis seats and a six-seat committee: quorum is four,
	// so this node's rounds climb and its height never moves. The stall is
	// CONSTRUCTED by the committee the test starts, not provoked by timing.
	v := startRotationInValidator(t, g, 0)
	defer v.Close()

	const stall = 300 * time.Millisecond
	start := time.Now()
	err := reachByWork([]*Validator{v}, 2, rotationInTick, stall)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("a validator that never commits was reported as reaching height 2: the wait masks a stall")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the stall took %s to report against a %s window: the allowance is not bounded by the stall window", elapsed, stall)
	}
	for _, want := range []string{"no height advanced", "heights [0]", "target 2", "not making progress"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the stall report does not say %q: %v", want, err)
		}
	}
	t.Logf("stall reported after %s: %v", elapsed, err)
}
