package genesis_test

// This file is in the EXTERNAL test package for one reason: internal/mempool
// imports internal/state, and internal/state imports internal/genesis (the
// committee derivation returns []genesis.Validator). A test file in package
// genesis that imported mempool would therefore close the cycle
// genesis[test] -> mempool -> state -> genesis and the whole test build would
// fail. The external package may import both, so the cross-package pin below
// keeps its value and the cycle is gone.

import (
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
)

// MaxClaimsPerBlock is a consensus parameter: state.ApplyBlock invalidates
// any block carrying more claims than it. This test pins the shipped value
// and its one supporting invariant. The bound must EQUAL internal/mempool's
// MaxFaucetClaimsPerBlock for both chains: the mempool is the LOCAL half of
// the same defence — it stops a node building a block the chain would reject,
// and nothing more — so if the two ever disagree, either the pool offers
// blocks the chain invalidates wholesale, or the chain is stricter than its
// own pool with nobody noticing. The pin is load-bearing in both directions:
// changing either value fails here.
func TestMaxClaimsPerBlockIsPinnedAndMatchesTheMempoolBound(t *testing.T) {
	for _, g := range []*genesis.Genesis{genesis.Devnet(), genesis.Testnet()} {
		if g.Params.MaxClaimsPerBlock != 8 {
			t.Fatalf("%s: MaxClaimsPerBlock = %d, want the derived 8 (see Testnet's tuning comment)",
				g.Params.ChainID, g.Params.MaxClaimsPerBlock)
		}
		if g.Params.MaxClaimsPerBlock != mempool.MaxFaucetClaimsPerBlock {
			t.Fatalf("%s: MaxClaimsPerBlock = %d but the mempool bound is %d - the consensus rule and the local pool courtesy must be derived from the same number",
				g.Params.ChainID, g.Params.MaxClaimsPerBlock, mempool.MaxFaucetClaimsPerBlock)
		}
	}
}
