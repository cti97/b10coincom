package devnet

// The Nakamoto coefficient is M5's second acceptance artefact: the smallest
// number of validators whose combined power exceeds the BFT failure threshold.
// It is deliberately computed from COMMITTED STATE - the committee that
// validated a height - and never from a peer or online set: a validator this
// node is connected to is not a validator with a bonded seat, and counting it
// would make the number a property of the observer's view rather than of the
// chain.
//
// THE THRESHOLD IS ONE THIRD, NOT ONE HALF. b10coin is a BFT chain: it loses
// safety when MORE than a third of the committee's power is adversarial, not
// when a majority is. A reader arriving from Bitcoin (where the familiar figure
// is 51%) will otherwise assume the divisor is a bug. The comparison is strict:
// exactly one third is not enough, because a one-third coalition cannot by
// itself finalise a conflicting block. The arithmetic is integer throughout -
// no float is formed from a power sum anywhere in this file.

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"strings"

	"github.com/cti97/b10coincom/internal/genesis"
)

const (
	// nakamotoDenominator is the denominator of the BFT threshold: a chain
	// fails when more than 1/3 of the committee's power is adversarial. It is
	// not 2 (a bare majority) and the comment above says why.
	nakamotoDenominator uint64 = 3

	// sharePercentScale is the integer factor a percentage is formed with.
	// A share is 100*power/total, truncated, never a float.
	sharePercentScale uint64 = 100
)

var (
	// ErrEmptyCommittee reports a height whose committee seats no validator.
	// It is an error in the report rather than a row of zeroes: 0/0 has no
	// coefficient, and printing k=0 would look like a number the chain
	// reported.
	ErrEmptyCommittee = errors.New("devnet: the committee for that height seats no validator")
	// ErrZeroCommitteePower reports a committee whose powers sum to zero. The
	// derivation refuses to emit one (state.ErrZeroPowerSeat), so this is a
	// hand-built input; dividing by it would be a 0/0, not a coefficient.
	ErrZeroCommitteePower = errors.New("devnet: the committee's total power is zero")
	// ErrCommitteePowerOverflow reports a committee whose powers do not fit in
	// a uint64. state.Committee refuses such a state (ErrCommitteePowerOverflow
	// there), so a committed committee cannot carry one; this guards the pure
	// function against a hand-built slice.
	ErrCommitteePowerOverflow = errors.New("devnet: the committee's total power overflows uint64")
	// ErrNoEpochLength reports a report asked to bucket heights by an epoch
	// length of zero. genesis.Validate refuses such a chain, so this is a
	// caller error rather than a reachable chain.
	ErrNoEpochLength = errors.New("devnet: the epoch length is zero")
)

// NakamotoRow is one point of the plotted series: the coefficient of the
// committee that validated Height, and the numbers it was derived from.
//
// Epoch is Height/EpochBlocks (the committee epoch, 0-based - deliberately not
// the 1-based faucet claim epoch). TopPower is the largest single seat's power
// and TotalPower the sum of the seated powers; both are sums of Genesis
// validator Power, in the same unit, never a float. The series carries them so
// a reader can re-derive the coefficient instead of trusting the print.
type NakamotoRow struct {
	Epoch, Height        uint64
	Seats, Nakamoto      int
	TopPower, TotalPower uint64
}

// CommitteeSource is the committed-state seam the report reads. *chain.Chain
// implements it: CommitteeAt(h) is the committee that validated h, derived from
// the state committed at the end of the preceding epoch (or the genesis state
// for epoch 0). Nothing in this file can see Peers(), a transport or the wall
// clock, which is the point.
type CommitteeSource interface {
	CommitteeAt(height uint64) ([]genesis.Validator, error)
}

// Nakamoto is the smallest k whose k largest powers sum to MORE than one third
// of the committee's total power - the BFT threshold (see the file comment).
//
// It is a pure function of the committee it is given: no map is iterated, no
// clock is read and no state is touched. The seats are ordered by power
// descending and, for equal powers, by public-key bytes ascending - the same
// tie-break state.Committee uses when it selects the top CommitteeSize
// candidates - so two nodes summing one committee take the seats in the same
// order. (The COEFFICIENT is in fact invariant to the order of equal powers;
// the ordering is pinned so the derivation is a deterministic function of the
// committee in every observable, not merely in this one.)
//
// 0 is returned for an empty committee (there is nothing to count) and for a
// committee a chain cannot emit (zero total power, or a total that overflows
// uint64). The reporting path does not rely on that sentinel: NakamotoAt
// refuses those inputs with an error, because a printed 0 would read as a
// coefficient.
func Nakamoto(committee []genesis.Validator) int {
	k, _, _, err := nakamotoOf(committee)
	if err != nil {
		return 0
	}
	return k
}

// NakamotoAt is the per-height form: it asks the committed-state source for the
// committee that validated height and returns the coefficient with the numbers
// it came from. It is the function the series is built from.
func NakamotoAt(src CommitteeSource, height, epochBlocks uint64) (NakamotoRow, error) {
	if epochBlocks == 0 {
		return NakamotoRow{}, ErrNoEpochLength
	}
	committee, err := src.CommitteeAt(height)
	if err != nil {
		return NakamotoRow{}, fmt.Errorf("devnet: nakamoto at height %d: %w", height, err)
	}
	k, top, total, err := nakamotoOf(committee)
	if err != nil {
		return NakamotoRow{}, fmt.Errorf("devnet: nakamoto at height %d: %w", height, err)
	}
	return NakamotoRow{
		Epoch:      height / epochBlocks,
		Height:     height,
		Seats:      len(committee),
		Nakamoto:   k,
		TopPower:   top,
		TotalPower: total,
	}, nil
}

// NakamotoRows builds the plotted series for a chain whose head is at `head`:
// one row per epoch boundary (0, E, 2E, ... at or below the head) plus the head
// itself when it is not already a boundary. Rows are monotone in height.
//
// Each row is read at its OWN height from the source. Looking every row up at
// the head would report today's committee for yesterday's block, which is
// exactly the "the set that committed h" property the report exists to show;
// TestNakamotoIsComputedFromTheHeightsCommittee pins it.
func NakamotoRows(src CommitteeSource, head, epochBlocks uint64) ([]NakamotoRow, error) {
	if epochBlocks == 0 {
		return nil, ErrNoEpochLength
	}
	rows := make([]NakamotoRow, 0, head/epochBlocks+2)
	for epoch := uint64(0); epoch <= head/epochBlocks; epoch++ {
		row, err := NakamotoAt(src, epoch*epochBlocks, epochBlocks)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	if head%epochBlocks != 0 {
		row, err := NakamotoAt(src, head, epochBlocks)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// orderedSeats returns a copy of the committee in the greedy accumulation's
// order: power descending, then public-key bytes ascending. The copy is
// returned rather than sorted in place, so the caller's committee - committed
// state, or a copy of it - is never reordered by a report.
func orderedSeats(committee []genesis.Validator) []genesis.Validator {
	ordered := slices.Clone(committee)
	slices.SortFunc(ordered, compareSeats)
	return ordered
}

// nakamotoOf is the one implementation of the coefficient. It returns the
// coefficient and the largest and total powers the threshold was measured
// against, so the report and the function cannot disagree about the sum.
func nakamotoOf(committee []genesis.Validator) (int, uint64, uint64, error) {
	if len(committee) == 0 {
		return 0, 0, 0, ErrEmptyCommittee
	}
	ordered := orderedSeats(committee)

	var top, total uint64
	for _, seat := range ordered {
		if seat.Power > top {
			top = seat.Power
		}
		next, carry := bits.Add64(total, seat.Power, 0)
		if carry != 0 {
			return 0, 0, 0, ErrCommitteePowerOverflow
		}
		total = next
	}
	if total == 0 {
		return 0, 0, 0, ErrZeroCommitteePower
	}
	// The strict threshold. total/3 is integer division; cum > total/3 is
	// exactly equivalent to 3*cum > total without forming the product, so
	// neither a float nor a 3*cum that could overflow is involved. Equality is
	// NOT enough: {3,3,3} has one third in one seat and k = 2, and {4,3,2} is
	// one spark more and k = 1.
	threshold := total / nakamotoDenominator
	var cumulative uint64
	for i, seat := range ordered {
		// cumulative + seat.Power <= total, which the sum above proved fits,
		// so this add cannot wrap.
		cumulative += seat.Power
		if cumulative > threshold {
			return i + 1, top, total, nil
		}
	}
	// total > total/3 for every total >= 1, so the whole committee always
	// clears the threshold and this is unreachable; returning the full slice
	// keeps the function total rather than claiming a coefficient it did not
	// compute.
	return len(ordered), top, total, nil
}

// compareSeats orders one committee for the greedy accumulation: power
// descending, then public-key BYTES ascending. It mirrors state's
// compareCandidates, whose first two keys are exactly these two; the address
// term there is for a map entry identity this slice does not carry.
func compareSeats(x, y genesis.Validator) int {
	switch {
	case x.Power > y.Power:
		return -1
	case x.Power < y.Power:
		return 1
	}
	return bytes.Compare(x.PubKey, y.PubKey)
}

// sharePercent is 100*power/total truncated to an integer. Both operands are
// powers (sparks at genesis, a genesis Power in the fixture); the result is a
// percentage, never a float. The product is formed with bits.Mul64 and divided
// with bits.Div64: 100*power cannot be computed in uint64 for a large
// committee, and a float would introduce exactly the rounding the project bans
// from a power sum.
func sharePercent(power, total uint64) uint64 {
	if total == 0 {
		return 0
	}
	if power > total {
		// Unreachable from a committee: TopPower is a member of TotalPower's
		// sum. Guarded rather than trusted because bits.Div64 panics when the
		// high word is not below the divisor.
		return 0
	}
	hi, lo := bits.Mul64(power, sharePercentScale)
	quotient, _ := bits.Div64(hi, lo, total)
	return quotient
}

// FormatNakamoto renders the series as a terminal table - the acceptance
// artefact. Heights and values are printed; no graphing library is involved.
// The percentage is the truncated integer share, and the header states the
// threshold so the numbers are not read as a Bitcoin 51% figure.
func FormatNakamoto(rows []NakamotoRow) string {
	var b strings.Builder
	b.WriteString("nakamoto coefficient across the run (smallest k whose k seats exceed 1/3 of committee power)\n")
	b.WriteString("  height  epoch  seats  k   top share\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "  %6d  %5d  %5d  %d   %d of %d (%d%%)\n",
			r.Height, r.Epoch, r.Seats, r.Nakamoto,
			r.TopPower, r.TotalPower, sharePercent(r.TopPower, r.TotalPower))
	}
	return b.String()
}
