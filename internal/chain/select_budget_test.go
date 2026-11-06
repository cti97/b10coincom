package chain

// The BYTE BUDGET half of audit S-3, at the policy itself. The composition test
// lives in internal/consensus (TestTheBlockFrameWindowTriangle); this one pins
// the contract a caller depends on: what fits is a PREFIX of the candidates,
// what does not fit is returned rather than dropped, and the prefix plus the
// block's fixed overhead is under the block bound.

import (
	"testing"

	"github.com/cti97/b10coincom/internal/types"
)

// TestSelectApplicableStopsAtTheByteBudget: 7,000 applicable transfers are
// 7,000 x 165 + 212 = 1,155,212 bytes, past the 1 MiB block bound but well
// inside the 10,000-transaction count bound - the exact shape of the S-3 bug.
// The filter must select the longest prefix that fits, and hand the rest back.
func TestSelectApplicableStopsAtTheByteBudget(t *testing.T) {
	const candidates = 7_000
	c, txs := selectFixture(t, 16, candidates)

	selected, retry, err := c.SelectApplicable(txs)
	if err != nil {
		t.Fatal(err)
	}
	if len(retry) == 0 {
		t.Fatalf("all %d candidates were selected: the byte budget did not bind", candidates)
	}
	if len(selected) == 0 {
		t.Fatal("the filter selected nothing: a byte budget that admits no transaction at all is not a budget")
	}
	// The split is a PREFIX: what fits comes first, what does not comes after,
	// in the caller's order. A caller re-adds retry and expects the pool's order
	// to survive. This fixture is one sender with strictly increasing nonces, so
	// the per-sender ordering audit S-17 added is the identity here and the
	// prefix property is unaffected.
	for i := range selected {
		if selected[i].ID() != txs[i].ID() {
			t.Fatalf("selected[%d] is not candidates[%d]: the split is not a prefix", i, i)
		}
	}
	for i := range retry {
		if retry[i].ID() != txs[len(selected)+i].ID() {
			t.Fatalf("retry[%d] is not candidates[%d]: the remainder is not the tail", i, len(selected)+i)
		}
	}
	if len(selected)+len(retry) != candidates {
		t.Fatalf("%d selected + %d retried = %d, want all %d candidates accounted for",
			len(selected), len(retry), len(selected)+len(retry), candidates)
	}
	// The selected prefix, encoded the way a block encodes it, fits.
	weight := types.BlockOverheadBytes
	for i := range selected {
		weight += selected[i].FramedSize()
	}
	if weight > types.MaxBlockBytes {
		t.Fatalf("the selected prefix encodes to %d bytes, above the %d-byte block bound", weight, types.MaxBlockBytes)
	}
	// And it is as full as the budget allows: one more transaction would not
	// fit, so the producer is not leaving a block's worth of capacity unused.
	if next := weight + txs[len(selected)].FramedSize(); next <= types.MaxBlockBytes {
		t.Fatalf("the prefix stopped at %d bytes although one more transaction (%d) still fit under %d",
			weight, next, types.MaxBlockBytes)
	}
}
