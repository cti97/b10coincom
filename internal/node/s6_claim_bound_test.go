package node

// Audit S-6 (2026-11-06), end to end. Genesis.Validate bounds
// MaxClaimsPerBlock above only, and the mempool used to cap its per-block
// hand-out at its own constant (8). A legal genesis with a bound below that -
// 1 is the extremal case - made Take hand the producer more claims than
// state.ApplyBlock accepts, so chain.Build refused the block, RunOnce re-added
// the batch, and the proposer NEVER proposed. This is the shipped producer path
// (RunOnce: Take -> SelectApplicable -> Build -> Append), not a hand-built state.

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

// genuineClaims builds n signed faucet claims for epoch 1 from n distinct fresh
// keys, each carrying a real proof of work for the genesis tuning. Distinct keys
// matter: admission allows one pending claim per key, and the genesis claim bound
// must be the only thing limiting the batch.
func genuineClaims(t *testing.T, c *chain.Chain, n int) []types.Tx {
	t.Helper()
	p := c.Genesis().Params
	claims := make([]types.Tx, 0, n)
	for i := 0; i < n; i++ {
		pub, key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		pow, ok := faucet.SolveClaim(pub, 1, p.FaucetPowTarget, p.FaucetPowArgon2, 1<<24)
		if !ok {
			t.Fatalf("claim %d: could not solve the devnet puzzle", i)
		}
		claim := &types.Tx{
			Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
			Nonce: 0, Epoch: 1, PowNonce: pow,
		}
		h := claim.SigningHash(c.Genesis().Hash())
		claim.Sig = crypto.Sign(key, h[:])
		claims = append(claims, *claim)
	}
	return claims
}

// TestAGenesisClaimBoundOfOneStillLetsTheProposerPropose is the finding's
// reproduction and its fix in one test: a genesis the validator ACCEPTS with
// MaxClaimsPerBlock = 1, three claims pending, and the ordinary producer tick.
//
// PRE-FIX it fails at the first RunOnce with state.ErrTooManyClaims: Take handed
// out all three claims (the pool's constant was 8), Build ran the head+1
// transition and refused the count, and the batch went back into the pool - the
// head never moved, and the same three claims would be handed out on every later
// tick, forever. POST-FIX Take hands out one claim, the block builds and appends,
// and the remaining claims follow one per block.
func TestAGenesisClaimBoundOfOneStillLetsTheProposerPropose(t *testing.T) {
	g := *genesis.Devnet()
	g.Params.MaxClaimsPerBlock = 1
	// The claim amount is lowered to 1 spark so the FAUCET is not the limiter.
	// The devnet faucet is funded by emission alone (0.5 b10 per block) and a
	// default 1 b10 claim needs two blocks of emission, which would make every
	// other block carry no claim for a reason that has nothing to do with this
	// finding. The bound under test must be the only reason a block holds one
	// claim.
	g.Params.ClaimAmountSparks = 1
	if err := g.Validate(); err != nil {
		t.Fatalf("fixture: a genesis with MaxClaimsPerBlock = 1 must be LEGAL (that is the finding's premise): %v", err)
	}
	c, err := chain.Open(&g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	claims := genuineClaims(t, c, 3)
	mp := mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)
	for i := range claims {
		if err := mp.Add([]types.Tx{claims[i]})[0]; err != nil {
			t.Fatalf("claim %d was not admitted: %v", i, err)
		}
	}
	if mp.Len() != len(claims) {
		t.Fatalf("fixture: pool holds %d of %d claims", mp.Len(), len(claims))
	}

	n := New(c, priv, mp)
	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		if errors.Is(err, state.ErrTooManyClaims) {
			t.Fatalf("the proposer could not build a block at a genesis claim bound of 1: %v - Take handed out more claims than ApplyBlock accepts, Build refused, the batch was re-added, and the proposer never proposes (audit S-6)", err)
		}
		t.Fatalf("RunOnce: %v", err)
	}
	if c.Height() != 1 {
		t.Fatalf("chain height = %d, want 1: the proposer did not propose", c.Height())
	}
	if len(b.Txs) != 1 || b.Txs[0].Type != types.TxFaucetClaim {
		t.Fatalf("the block carries %d txs, want exactly the genesis bound's 1 claim", len(b.Txs))
	}
	if mp.Len() != len(claims)-1 {
		t.Fatalf("pool holds %d txs after the block, want the %d claims past the bound to stay pending", mp.Len(), len(claims)-1)
	}

	// The rest drain one per block, which is the point of keeping them: a bound
	// of 1 must throttle claim hand-out, not destroy the claims.
	for i := 0; i < len(claims)-1; i++ {
		if _, err := n.RunOnce(1_700_000_101 + int64(i)); err != nil {
			t.Fatalf("block %d: the proposer stalled on a pending claim: %v", i+2, err)
		}
		if got, want := c.Height(), uint64(i+2); got != want {
			t.Fatalf("chain height = %d, want %d", got, want)
		}
	}
	if mp.Len() != 0 {
		t.Fatalf("pool holds %d txs after %d blocks, want 0", mp.Len(), len(claims))
	}
	// Every claim was paid: the bound throttles a block, it does not lose money.
	for i := range claims {
		if got, want := c.State().Get(claims[i].From).Balance, g.Params.ClaimAmountSparks; got != want {
			t.Fatalf("claimant %d balance = %d sparks, want %d", i, got, want)
		}
	}
}
