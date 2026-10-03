package faucet

// Emission schedule.
//
// The reward is paid into the protocol-controlled faucet account, which has no
// private key; coins leave it only through the claim rule in the state machine.
//
// Reward is NOT special-cased at height 0. Interval 0 spans heights
// 0..HalvingInterval-1, so the genesis mint the spec calls for falls out of the
// same formula.
//
// The realized series is slightly SHORT of the supply cap because each halving
// truncates: for the specified parameters it totals 2,099,999,748,000,000 sparks
// (20,999,997.48 b10), 252,000,000 sparks (2.52 b10) below the 21,000,000 b10 cap.
// Those sparks are simply never minted. The cap is a maximum, never a target, and
// the series can never overshoot it. Omitting the genesis mint would widen the
// shortfall to 3.02 b10, which is why height 0 is included.
func Reward(height, initialReward, halvingInterval uint64) uint64 {
	if halvingInterval == 0 {
		return 0
	}
	halvings := height / halvingInterval
	if halvings >= 64 {
		return 0
	}
	return initialReward >> halvings
}

// SeriesTotal is the sum of Reward over every height from 0 to the point the
// reward reaches zero. It is used by tests and by the genesis-parameter check to
// prove the schedule cannot exceed the cap.
func SeriesTotal(initialReward, halvingInterval uint64) uint64 {
	if halvingInterval == 0 {
		return 0
	}
	var halved uint64
	for k := uint64(0); k < 64; k++ {
		r := initialReward >> k
		if r == 0 {
			break
		}
		// The accumulator can overflow before the guard below runs (a huge R0
		// makes the sum of halvings wrap into a smaller number), so saturate
		// during accumulation: a wrapped total could pass a cap check.
		if r > ^uint64(0)-halved {
			return ^uint64(0)
		}
		halved += r
	}
	// Each halving interval spans exactly halvingInterval heights, and interval 0
	// starts at height 0, so the whole series is halvingInterval * sum of halvings.
	if halved > ^uint64(0)/halvingInterval {
		return ^uint64(0) // saturate rather than wrap; a wrapped total could pass a cap check
	}
	return halved * halvingInterval
}
