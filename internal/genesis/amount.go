package genesis

// Exact decimal b10 parsing for the staking verbs (M5 Task 6).
//
// Money is sparks, a uint64, everywhere below the CLI. The one place a human
// writes money is a command line flag, and that is a decimal STRING: "1000" or
// "0.00000001". Parsing it with strconv.ParseFloat would put a binary float in
// the path between the operator's intent and a signed transaction, and floats
// do not represent most decimal fractions exactly. The parser below never
// touches a float: it splits on '.', validates the digits, and does the
// multiply by SparksPerB10 with explicit overflow checks.
//
// The precision point is not theoretical. On this machine
// uint64(ParseFloat("0.29")*1e8) is 28,999,999, one spark short of the 29,000,000
// the operator wrote; "0.1" happens to round-trip, which is why the test table
// pins a value that does not. See TestParseB10IsExact.

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ErrBadAmount reports a string that is not an exact, non-negative b10 amount:
// empty, signed, exponent-bearing, more than one decimal point, more than 8
// decimal places, or too large to express in sparks.
var ErrBadAmount = errors.New("genesis: invalid b10 amount")

// ParseB10 converts an exact decimal b10 string into sparks.
//
// Accepted: an unsigned decimal integer part and an optional fraction of at
// most 8 digits, with a non-empty part on each side of the point when the point
// is present ("1000", "1000.5", "0.00000001"). Rejected with ErrBadAmount:
// empty input, signs ("-1", "+1"), exponents ("1e9"), whitespace (" 1"),
// adjacent points ("1..2"), a trailing point ("1."), a bare fraction (".5"), a
// ninth decimal place ("1.000000001"), and any value whose sparks do not fit in
// a uint64 ("184467440738").
//
// The fractional part is right-padded to 8 digits, so "0.1" is exactly
// 10,000,000 sparks - not the nearest float64 to it.
func ParseB10(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("%w: empty", ErrBadAmount)
	}
	intPart, fracPart := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, fracPart = s[:i], s[i+1:]
		if strings.IndexByte(fracPart, '.') >= 0 {
			return 0, fmt.Errorf("%w: %q has more than one decimal point", ErrBadAmount, s)
		}
		if fracPart == "" {
			return 0, fmt.Errorf("%w: %q has a decimal point but no fraction", ErrBadAmount, s)
		}
	}
	if intPart == "" {
		return 0, fmt.Errorf("%w: %q has no integer part", ErrBadAmount, s)
	}
	if len(fracPart) > 8 {
		return 0, fmt.Errorf("%w: %q has %d decimal places, at most 8 (one spark) are expressible", ErrBadAmount, s, len(fracPart))
	}
	if !allDigits(intPart) || !allDigits(fracPart) {
		return 0, fmt.Errorf("%w: %q must be digits and at most one decimal point (no sign, spaces or exponent)", ErrBadAmount, s)
	}

	// The integer part, built digit by digit with a wrap check. Checking the
	// multiply by SparksPerB10 afterwards would be too late: the integer part
	// itself can overflow uint64 long before the scale does.
	var whole uint64
	for i := 0; i < len(intPart); i++ {
		d := uint64(intPart[i] - '0')
		if whole > (math.MaxUint64-d)/10 {
			return 0, fmt.Errorf("%w: %q is too large for sparks", ErrBadAmount, s)
		}
		whole = whole*10 + d
	}
	if whole > math.MaxUint64/SparksPerB10 {
		return 0, fmt.Errorf("%w: %q b10 is too large for sparks", ErrBadAmount, s)
	}
	sparks := whole * SparksPerB10

	// The fraction is exactly 8 digits after right-padding; building it as a
	// number in [0, 10^8) cannot overflow.
	var frac uint64
	for i := 0; i < 8; i++ {
		frac *= 10
		if i < len(fracPart) {
			frac += uint64(fracPart[i] - '0')
		}
	}
	if sparks > math.MaxUint64-frac {
		return 0, fmt.Errorf("%w: %q b10 is too large for sparks", ErrBadAmount, s)
	}
	return sparks + frac, nil
}

// FormatB10 renders sparks as the exact decimal b10 string ParseB10 accepts
// back. It is the inverse of ParseB10 for every uint64: the fraction is
// trimmed of trailing zeros, and a whole number is printed with no point.
// Integer arithmetic only - no float ever holds the amount.
func FormatB10(sparks uint64) string {
	whole := sparks / SparksPerB10
	frac := sparks % SparksPerB10
	if frac == 0 {
		return strconv.FormatUint(whole, 10)
	}
	f := strconv.FormatUint(frac+100_000_000, 10)[1:] // 8 digits, zero-padded
	return strconv.FormatUint(whole, 10) + "." + strings.TrimRight(f, "0")
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
