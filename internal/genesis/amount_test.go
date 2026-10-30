package genesis

import (
	"errors"
	"math"
	"testing"
)

// TestParseB10IsExact pins the exact decimal conversion the staking verbs put
// between a person's --amount and a signed transaction.
//
// The "0.29" row is the one a float64 cannot pass: uint64(ParseFloat("0.29")*
// 1e8) is 28,999,999, one spark below the written amount. ("0.1" does NOT
// catch a float64 - it happens to convert to exactly 10,000,000 - which is why
// the table carries both a value that survives float conversion and one that
// does not.)
func TestParseB10IsExact(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"1", 100_000_000},
		{"0.1", 10_000_000},
		{"0.29", 29_000_000},
		{"1000", 100_000_000_000}, // MIN_STAKE
		{"1000.00000001", 100_000_000_001},
		{"0.00000001", 1},
		{"0", 0},
		{"0001.5", 150_000_000},
		{"184467440737.09551615", math.MaxUint64},
	}
	for _, tc := range cases {
		got, err := ParseB10(tc.in)
		if err != nil {
			t.Errorf("ParseB10(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseB10(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"", "1.", ".5", "-1", "+1", "1.000000001", "1e9", " 1", "1 ", "1..2",
		"1,5", "0x10", "184467440738", // 184467440738 b10 overflows sparks
		"184467440737.1", // the integer part fits; the sum does not
	}
	for _, in := range bad {
		if got, err := ParseB10(in); !errors.Is(err, ErrBadAmount) {
			t.Errorf("ParseB10(%q) = %d, %v; want ErrBadAmount", in, got, err)
		}
	}
}

// TestFormatB10IsTheInverseOfParseB10 keeps every amount the CLI prints
// re-parseable. A formatter that rounded or truncated would make an operator's
// copied amount a different bond from the one they were shown.
func TestFormatB10IsTheInverseOfParseB10(t *testing.T) {
	values := []uint64{
		0, 1, 7, 10_000_000, 29_000_000, 100_000_000,
		100_000_000_000, 100_000_000_001, math.MaxUint64,
	}
	for _, v := range values {
		s := FormatB10(v)
		got, err := ParseB10(s)
		if err != nil {
			t.Errorf("FormatB10(%d) = %q, which ParseB10 refuses: %v", v, s, err)
			continue
		}
		if got != v {
			t.Errorf("ParseB10(FormatB10(%d)) = %d", v, got)
		}
	}
	if got := FormatB10(100_000_000_000); got != "1000" {
		t.Errorf("FormatB10(10^11) = %q, want %q", got, "1000")
	}
	if got := FormatB10(1); got != "0.00000001" {
		t.Errorf("FormatB10(1) = %q, want %q", got, "0.00000001")
	}
}
