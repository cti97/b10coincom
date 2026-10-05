package chain

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// selectFixture builds a chain whose head state holds `accounts` inert
// accounts, plus one funded sender, and `candidates` signed transfers from that
// sender with strictly increasing nonces (all of which apply, so the filter
// keeps every one). The large account set is what made the OLD
// per-candidate-clone filter expensive: each candidate copied the whole map.
// The state is constructed directly (the test is in package chain), never
// provoked through a race or a buffer.
func selectFixture(tb testing.TB, accounts, candidates int) (*Chain, []types.Tx) {
	tb.Helper()
	g := genesis.Devnet()
	c, err := Open(g, tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = c.Close() })

	// Clone the genesis state so its params (GenesisHash, MinFee, EpochBlocks)
	// travel, then inflate the account set.
	st := c.State().Clone()
	for i := 0; i < accounts; i++ {
		var a types.Address
		binary.BigEndian.PutUint64(a[12:], uint64(i)+1)
		st.Set(a, state.Account{Balance: 1})
	}
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		tb.Fatal(err)
	}
	sender := types.AddressFromPub(pub)
	var recipient types.Address
	recipient[0] = 0xAB // distinct from every generated account and the sender
	// Each transfer pays amount 1 + the chain's minimum fee; fund for all of
	// them.
	st.Set(sender, state.Account{Balance: uint64(candidates) * 2})
	c.state = st

	txs := make([]types.Tx, candidates)
	for i := 0; i < candidates; i++ {
		tx := &types.Tx{
			Type: types.TxTransfer, From: sender, PubKey: pub,
			Nonce: uint64(i), Fee: g.Params.MinFeeSparks,
			To: recipient, Amount: 1,
		}
		h := tx.SigningHash(g.Hash())
		tx.Sig = crypto.Sign(priv, h[:])
		txs[i] = *tx
	}
	return c, txs
}

// BenchmarkSelectApplicable10000 is the audit S-6 cost measurement at the
// 10,000-candidate (MaxTxsPerBlock) case. Before the fix each candidate ran
// through state.ApplyBlock, which clones the whole account map; after it the
// base is mutated in place by state.ApplyTx, so the map is copied once for the
// whole batch. Run with -benchmem to read the bytes/op.
func BenchmarkSelectApplicable10000(b *testing.B) {
	c, txs := selectFixture(b, 2000, 10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := c.SelectApplicable(txs)
		if err != nil {
			b.Fatal(err)
		}
		if len(valid) != len(txs) {
			b.Fatalf("SelectApplicable kept %d of %d candidates", len(valid), len(txs))
		}
	}
}

// TestSelectApplicableCostDoesNotScaleWithTheAccountCount is the regression
// guard for audit S-6: the filter ran state.ApplyBlock per candidate, and
// ApplyBlock clones the whole account map, so one pass allocated
// O(candidates x accounts). The fix mutates one cloned base in place, so the
// cost is O(accounts + candidates): 16x the accounts at a fixed candidate count
// must not multiply the bytes allocated. This test calibrates itself against
// the fixed cost (signature verification, identical at both account counts)
// instead of pinning an absolute budget, so it is a byte comparison, not a
// stopwatch, and cannot flake on a loaded machine.
func TestSelectApplicableCostDoesNotScaleWithTheAccountCount(t *testing.T) {
	const candidates = 2000
	allocated := func(accounts int) uint64 {
		c, txs := selectFixture(t, accounts, candidates)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		if _, err := c.SelectApplicable(txs); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	small := allocated(1000)
	large := allocated(16000)
	// The fixed code's extra cost is two map clones (a few MB at most); the
	// removed per-candidate clone would make `large` ~16x `small`.
	if large > 2*small {
		t.Fatalf("SelectApplicable allocated %d bytes over 16,000 accounts but %d over 1,000 (%.1fx); "+
			"the cost must not scale with the account count, which is the per-candidate state clone audit S-6 removed",
			large, small, float64(large)/float64(small))
	}
}
