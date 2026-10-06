package chain

import (
	"errors"
	"testing"
)

// S-8: block timestamps were unvalidated beyond > 0. The chain now requires
// strict monotonicity on every path (Append/ValidateNext) and pins the
// consensus path to parent+1 (ValidateConsensusNext). These three tests cover
// the audit's three cases - a timestamp in the future, one not greater than the
// parent's, and a legitimate one - for the rules that apply to each path.

// The general rule every path shares: a block's timestamp must be strictly
// greater than its parent's. Both a timestamp equal to the parent's and one
// behind it are refused, before any state work.
func TestAppendRejectsATimestampNotAfterTheParent(t *testing.T) {
	c, priv := devChain(t)
	parent := c.Head().Header.Timestamp
	for _, ts := range []int64{parent, parent - 1} {
		b, err := c.Build(priv, nil, ts)
		if err != nil {
			t.Fatalf("Build(ts=%d): %v", ts, err)
		}
		if err := c.Append(b); !errors.Is(err, ErrBadTimestamp) {
			t.Fatalf("Append(ts=%d, parent=%d) = %v, want ErrBadTimestamp", ts, parent, err)
		}
		if c.Height() != 0 {
			t.Fatalf("a refused block advanced the chain to height %d", c.Height())
		}
	}
}

// The legitimate case: parent+1 is accepted and advances the chain.
func TestAppendAcceptsATimestampAfterTheParent(t *testing.T) {
	c, priv := devChain(t)
	parent := c.Head().Header.Timestamp
	b, err := c.Build(priv, nil, parent+1)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append(b); err != nil {
		t.Fatalf("Append(parent+1): %v", err)
	}
	if c.Height() != 1 {
		t.Fatalf("height = %d, want 1", c.Height())
	}
}

// The consensus pin: the driver's validation seam requires exactly parent+1.
// A FUTURE timestamp (parent+5) is refused even though it is monotonic, and a
// timestamp not greater than the parent's is refused too; parent+1 is the one
// legitimate value. The same future block passes the chain's weaker global rule
// (ValidateNext / Append), which is the documented division of labour: the
// consensus path is where grinding matters, and the single-node path stamps
// with its wall clock.
func TestConsensusTimestampIsPinnedToParentPlusOne(t *testing.T) {
	c, priv := devChain(t)
	parent := c.Head().Header.Timestamp

	for _, tc := range []struct {
		name string
		ts   int64
		ok   bool
	}{
		{"legitimate parent+1", parent + 1, true},
		{"future parent+5", parent + 5, false},
		{"not after the parent", parent, false},
		{"behind the parent", parent - 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := c.Build(priv, nil, tc.ts)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			err = c.ValidateConsensusNext(b)
			if tc.ok && err != nil {
				t.Fatalf("ValidateConsensusNext(parent+1) = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, ErrBadTimestamp) {
				t.Fatalf("ValidateConsensusNext(ts=%d) = %v, want ErrBadTimestamp", tc.ts, err)
			}
			// The consensus pin is the stricter rule: a monotonic future
			// timestamp the pin refuses is still acceptable to the general
			// chain rule (it just must not be committed by consensus).
			if tc.ts == parent+5 {
				if err := c.ValidateNext(b); err != nil {
					t.Fatalf("ValidateNext(monotonic parent+5) = %v, want nil (the pin lives on the consensus path)", err)
				}
			}
		})
	}
}
