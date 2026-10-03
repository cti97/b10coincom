// Package devnet runs a self-contained local chain. It is the single
// acceptance check for M0-M1: one call builds a chain, includes a real
// transfer, persists it and reports a reproducible state root. M2 adds the
// faucet: Options.Claims submits puzzle-solved claim attempts after the block
// loop, so one call also exercises the claim path end to end — emission funds
// the faucet, a solved puzzle buys a claim, and the claimant is paid. Each
// PAID claim is immediately followed by a second, solved claim from the same
// key in the same epoch, so one call also proves the anti-farming rule: that
// attempt must be refused, or the run fails.
package devnet

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/node"
	"github.com/cti97/b10coincom/internal/types"
)

var ErrNoBlocks = errors.New("devnet: Blocks must be greater than zero")

// maxPuzzleAttempts bounds one claim's solve. The devnet's easy target needs
// about two attempts, so a failure here means the fixture tuning broke, not
// that mining is slow.
const maxPuzzleAttempts = 1_000_000

// Options configures a devnet run.
type Options struct {
	Dir    string
	Blocks uint64
	// Claims is the number of faucet-claim ATTEMPTS made after the block
	// loop. Each attempt solves the puzzle for a fresh key at the epoch the
	// next block makes current and is submitted in the block that follows;
	// an attempt the probe refuses (an empty faucet) is evicted and its
	// block is simply empty. Only the paid ones count towards
	// Summary.Claimed. Every paid attempt is additionally followed by that
	// same key's same-epoch double claim, which the probe must evict (an
	// applied double claim fails the run) and which takes one further empty
	// block per paid claim.
	Claims uint64
}

// Summary reports what a run produced.
type Summary struct {
	ChainID     string
	Height      uint64
	StateRoot   [32]byte
	TxsIncluded int

	// The faucet's outcome for this run. ClaimAmount is the genesis
	// parameter the claims were paid at. Claimed is the number of claims
	// that were actually PAID (attempts can be refused and evicted instead
	// of failing the run). ClaimedBalance is the balance of the last paid
	// claim's claimant, read from the chain's state. FaucetBalance is the
	// faucet account's final balance; EmittedTotal is every reward the run
	// credited into the faucet, heights 0..Height inclusive — emission is
	// the only thing that funds it, so
	// FaucetBalance == EmittedTotal - Claimed*ClaimAmount exactly.
	//
	// DoubleClaimsRefused counts the same-epoch double-claim attempts the
	// scenario made and the node refused. The run FAILS if any double claim
	// is applied, so in a successful run every paid claim also has its
	// double-claim rejection behind it: DoubleClaimsRefused == Claimed
	// whenever Claims > 0. It is a run-side report, not a replayable one: a
	// stored chain cannot distinguish the empty block a refused double claim
	// left behind from any other empty block.
	DoubleClaimsRefused uint64
	Claimed             uint64
	ClaimAmount         uint64
	ClaimedBalance      uint64
	FaucetBalance       uint64
	EmittedTotal        uint64
}

// Run creates a fresh devnet and drives it to o.Blocks. One transfer is
// seeded before the first block, so the state transition path is exercised
// rather than only empty blocks. After the block loop, o.Claims claim
// attempts are driven the same way (through the node's own RunOnce, probe
// included), so the claim path is exercised end to end rather than by
// hand-applying transactions.
func Run(o Options) (Summary, error) {
	if o.Blocks == 0 {
		return Summary{}, ErrNoBlocks
	}
	g := genesis.Devnet()
	c, err := chain.Open(g, o.Dir)
	if err != nil {
		return Summary{}, err
	}
	defer c.Close()

	_, priv := genesis.DevValidatorKey()
	mp := mempool.New(1000)
	n := node.New(c, priv, mp)

	tx, err := devTransfer(c, 250*genesis.SparksPerB10)
	if err != nil {
		return Summary{}, err
	}
	if err := mp.Add([]types.Tx{*tx})[0]; err != nil {
		return Summary{}, err
	}

	included := 0
	for h := uint64(1); h <= o.Blocks; h++ {
		b, err := n.RunOnce(g0Time + int64(h))
		if err != nil {
			return Summary{}, err
		}
		included += len(b.Txs)
	}

	// The claim attempts. Each attempt is one fresh key, solved at the epoch
	// the block that will apply it makes current; the claim rides the node's
	// own RunOnce, so the probe must mirror the transition for the claim to
	// survive. A refused attempt leaves its block empty and is not counted.
	//
	// After a PAID attempt the scenario proves the anti-farming rule live:
	// the same key immediately attempts a second claim IN THE SAME EPOCH.
	// That double claim is solved and signed just like the first — the
	// puzzle binds only (key, epoch), so the first claim's solution still
	// verifies — which is exactly why only the claim-epoch marker can reject
	// it. The node's probe must evict it, so its block is empty; a block
	// that carries the double claim means the rule is broken and the run
	// fails. Every RunOnce call appends exactly one block, so timestamps and
	// heights both advance once per call: one block per claim attempt, one
	// more per paid claim.
	claimed := uint64(0)
	claimedBalance := uint64(0)
	refusedDoubleClaims := uint64(0)
	ts := g0Time + int64(o.Blocks)
	for attempt := uint64(0); attempt < o.Claims; attempt++ {
		pub, priv := claimantKey(attempt)
		claimant := types.AddressFromPub(pub)
		epoch := (c.Height()+1)/g.Params.EpochBlocks + 1
		pow, ok := faucet.Solve(pub, epoch, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, maxPuzzleAttempts)
		if !ok {
			return Summary{}, fmt.Errorf("devnet: claim attempt %d of %d did not solve the fixture puzzle", attempt+1, o.Claims)
		}
		claim := devClaim(pub, priv, c.State().Get(claimant).Nonce, epoch, pow)
		if err := mp.Add([]types.Tx{*claim})[0]; err != nil {
			return Summary{}, err
		}
		ts++
		b, err := n.RunOnce(ts)
		if err != nil {
			return Summary{}, err
		}
		// TxsIncluded must count what the run's blocks actually carried, claims
		// included, so Replay - which recounts from the stored blocks - reports
		// the same number for this run.
		included += len(b.Txs)
		id := claim.ID()
		var paid bool
		for i := range b.Txs {
			if b.Txs[i].ID() == id {
				paid = true
				claimed++
				// Read the paid balance from the chain itself rather than
				// deriving it, so a claim that moved anything other than the
				// claim amount would show up in the summary instead of being
				// papered over by arithmetic.
				claimedBalance = c.State().Get(claimant).Balance
			}
		}
		if !paid {
			continue
		}

		// The double claim reuses the first claim's solution (the puzzle binds
		// pubkey, epoch and nonce, not the transaction) and spends the account
		// nonce the paid claim just advanced.
		double := devClaim(pub, priv, c.State().Get(claimant).Nonce, epoch, pow)
		if err := mp.Add([]types.Tx{*double})[0]; err != nil {
			return Summary{}, err
		}
		ts++
		bd, err := n.RunOnce(ts)
		if err != nil {
			return Summary{}, err
		}
		// An empty double-claim block is EXPECTED: the probe refused the
		// transaction, so it is evicted, never stored, and the replayed chain
		// cannot even tell it happened. Inclusion is the one outcome this
		// scenario must never accept.
		doubleID := double.ID()
		for i := range bd.Txs {
			if bd.Txs[i].ID() == doubleID {
				return Summary{}, fmt.Errorf("devnet: a second claim from claimant %x in epoch %d was applied; the one-claim-per-epoch rule is broken", claimant, epoch)
			}
		}
		refusedDoubleClaims++
	}

	// Emission is the ONLY thing that funds the faucet: every reward the run
	// credited, heights 0..Height inclusive (Reward(0) is the genesis mint
	// the spec names). Summed from the same formula the transition credits
	// with, so FaucetBalance == EmittedTotal - Claimed*ClaimAmount holds
	// exactly, and a paid-from-nowhere claim or a double debit breaks it.
	var emitted uint64
	for h := uint64(0); h <= c.Height(); h++ {
		emitted += faucet.Reward(h, g.Params.InitialRewardSparks, g.Params.HalvingIntervalBlocks)
	}

	return Summary{
		ChainID:             g.ChainID,
		Height:              c.Height(),
		StateRoot:           c.State().Root(),
		TxsIncluded:         included,
		DoubleClaimsRefused: refusedDoubleClaims,
		Claimed:             claimed,
		ClaimAmount:         g.Params.ClaimAmountSparks,
		ClaimedBalance:      claimedBalance,
		FaucetBalance:       c.State().Get(g.FaucetAddress()).Balance,
		EmittedTotal:        emitted,
	}, nil
}

// Replay reopens an existing devnet directory and reports the replayed
// state. TxsIncluded is recomputed from the stored blocks rather than left
// at zero, because a hard zero would be indistinguishable from a chain that
// genuinely included no transactions; the faucet fields are recomputed the
// same way rather than zeroed, for the same reason. DoubleClaimsRefused is
// the exception: a stored chain carries no trace of a refused double claim
// (its block is empty and indistinguishable from any other empty block), so
// leaving it at zero is the honest reading rather than a guess.
func Replay(dir string) (Summary, error) {
	g := genesis.Devnet()
	c, err := chain.Open(g, dir)
	if err != nil {
		return Summary{}, err
	}
	defer c.Close()

	included := 0
	claimed := uint64(0)
	var lastClaimant types.Address
	for h := uint64(1); h <= c.Height(); h++ {
		b, err := c.BlockAt(h)
		if err != nil {
			return Summary{}, err
		}
		included += len(b.Txs)
		for i := range b.Txs {
			// A stored claim tx was necessarily APPLIED: Append validated the
			// block's root, which only a paid application produces.
			if b.Txs[i].Type == types.TxFaucetClaim {
				claimed++
				lastClaimant = b.Txs[i].From
			}
		}
	}

	var emitted uint64
	for h := uint64(0); h <= c.Height(); h++ {
		emitted += faucet.Reward(h, g.Params.InitialRewardSparks, g.Params.HalvingIntervalBlocks)
	}

	return Summary{
		ChainID:        g.ChainID,
		Height:         c.Height(),
		StateRoot:      c.State().Root(),
		TxsIncluded:    included,
		Claimed:        claimed,
		ClaimAmount:    g.Params.ClaimAmountSparks,
		ClaimedBalance: c.State().Get(lastClaimant).Balance,
		FaucetBalance:  c.State().Get(g.FaucetAddress()).Balance,
		EmittedTotal:   emitted,
	}, nil
}

// devTransfer builds a signed transfer from dev account 0 to dev account 1.
func devTransfer(c *chain.Chain, amount uint64) (*types.Tx, error) {
	fromPub, fromPriv := genesis.DevAccountKey(0)
	toPub, _ := genesis.DevAccountKey(1)
	from := types.AddressFromPub(fromPub)
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  c.State().Get(from).Nonce,
		To:     types.AddressFromPub(toPub),
		Amount: amount,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(fromPriv, sigHash[:])
	return tx, nil
}

// devClaim builds and signs one faucet-claim transaction from pub (its
// solution pow already found for epoch). nonce is the claimant's replay
// counter at application time: zero for a claimant key that has never
// transacted, and the value the paid claim advanced for the same key's
// double claim.
func devClaim(pub ed25519.PublicKey, priv ed25519.PrivateKey, nonce, epoch, pow uint64) *types.Tx {
	tx := &types.Tx{
		Type:     types.TxFaucetClaim,
		From:     types.AddressFromPub(pub),
		PubKey:   pub,
		Nonce:    nonce,
		Epoch:    epoch,
		PowNonce: pow,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return tx
}

// claimantKey derives the deterministic devnet claimant keypair for attempt i.
// The claim scenario must be reproducible like every other part of the
// devnet — the same run must reach the same state root — so claimant keys are
// derived rather than generated, one per attempt: fresh in that no EARLIER
// attempt (or any other account) ever held this key's address. It is NOT
// secret and must never be used outside devnet, exactly like genesis's
// devnet keys.
func claimantKey(i uint64) (ed25519.PublicKey, ed25519.PrivateKey) {
	h := crypto.HashParts([]byte("b10coin-devnet-claimant"), []byte(strconv.FormatUint(i, 10)))
	priv := ed25519.NewKeyFromSeed(h[:])
	return priv.Public().(ed25519.PublicKey), priv
}

// g0Time is the deterministic base timestamp for devnet blocks.
const g0Time = 1_700_000_000
