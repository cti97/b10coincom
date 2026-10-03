package faucet

import "testing"

const (
	r0        = 50_000_000 // 0.5 b10 per block, initially
	halv      = 21_000_000 // blocks per halving
	supplyCap = 21_000_000 * 100_000_000
)

func TestRewardHalves(t *testing.T) {
	cases := []struct {
		height uint64
		want   uint64
	}{
		{0, r0}, // the genesis mint
		{1, r0},
		{halv - 1, r0},
		{halv, r0 / 2}, // the first halving
		{2 * halv, r0 / 4},
	}
	for _, c := range cases {
		if got := Reward(c.height, r0, halv); got != c.want {
			t.Errorf("Reward(%d) = %d, want %d", c.height, got, c.want)
		}
	}
}

func TestRewardReachesZeroAndStaysThere(t *testing.T) {
	// R0 has 26 significant bits, so the reward reaches zero at halving 26.
	const endpoint = 26 * halv
	if got := Reward(endpoint, r0, halv); got != 0 {
		t.Fatalf("Reward at the endpoint = %d, want 0", got)
	}
	for _, h := range []uint64{endpoint, endpoint + 1, endpoint + halv, 50 * halv} {
		if got := Reward(h, r0, halv); got != 0 {
			t.Fatalf("Reward(%d) = %d, want 0 after the endpoint", h, got)
		}
	}
}

func TestRewardHandlesDegenerateParameters(t *testing.T) {
	if got := Reward(5, r0, 0); got != 0 {
		t.Fatalf("Reward with a zero halving interval = %d, want 0", got)
	}
}

// The cap is a HARD MAXIMUM. Integer truncation in the shifts means the realized
// series is slightly SHORT of it (2.52 b10 for the specified parameters); it must
// never overshoot.
func TestSeriesTotalNeverExceedsTheCap(t *testing.T) {
	total := SeriesTotal(r0, halv)
	if total > supplyCap {
		t.Fatalf("realized emission %d exceeds the cap %d", total, supplyCap)
	}
	// Pin the exact realized value so a change to the schedule is visible.
	const want = 2_099_999_748_000_000
	if total != want {
		t.Fatalf("realized emission = %d, want %d (short of the cap by %d sparks)",
			total, want, supplyCap-total)
	}
	if short := supplyCap - total; short != 252_000_000 {
		t.Fatalf("shortfall = %d sparks, want 252000000 (2.52 b10)", short)
	}
}

// SeriesTotal must SATURATE on overflow, not wrap: a wrapped total could pass a
// cap check that it should fail. The specified parameters never overflow, so
// this case drives the loop with parameters that do.
func TestSeriesTotalSaturatesRatherThanWraps(t *testing.T) {
	// 2^63 shifted down 64 times sums to 2^64-1, and with an interval of 2 the
	// product overflows uint64. The total must saturate to ^uint64(0), not wrap.
	if got := SeriesTotal(1<<63, 2); got != ^uint64(0) {
		t.Fatalf("SeriesTotal on overflow = %d, want saturation to %d", got, ^uint64(0))
	}
}
