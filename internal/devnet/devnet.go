// Package devnet runs a self-contained local chain. It is the single
// acceptance check for M0-M1: one call builds a chain, includes a real
// transfer, persists it and reports a reproducible state root. M2 adds the
// faucet: Options.Claims submits puzzle-solved claim attempts after the block
// loop, so one call also exercises the claim path end to end — emission funds
// the faucet, a solved puzzle buys a claim, and the claimant is paid. Each
// PAID claim is immediately followed by a second, solved claim from the same
// key in the same epoch, so one call also proves the anti-farming rule: that
// attempt must be refused, or the run fails. M3 adds RunMulti: a committee of
// consensus validators over the simnet harness, reporting each validator's
// final height and whether the committee holds one history — the acceptance
// check `devnet --validators 4 --blocks 100` the design's section 9 named
// back when a single node could not honour it, because one node needs no
// agreement.
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
	"github.com/cti97/b10coincom/internal/simnet"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrNoBlocks = errors.New("devnet: Blocks must be greater than zero")
	// ErrNoValidators rejects RunMulti(Options{Validators: 0}). RunMulti is
	// the consensus path: a committee of zero has nothing to run, and
	// silently running the single-node loop instead would make --validators
	// a flag that lies.
	ErrNoValidators = errors.New("devnet: RunMulti needs Validators of at least one")
	// ErrClaimsAreMultiUnsupported refuses a RunMulti with claims. The claim
	// scenario solves puzzles and drives transactions through one node's own
	// mempool and RunOnce; the simnet committee's Transport offers only
	// consensus messages, so there is no way to submit a claim to it. A run
	// that dropped o.Claims on the floor would print claims paid = 0 and
	// look like a broken faucet — refuse loudly instead.
	ErrClaimsAreMultiUnsupported = errors.New("devnet: the faucet-claim scenario runs on the single-node path only; a multi-validator run carries no transaction path")
)

// maxPuzzleAttempts bounds one claim's solve. Since audit R-1 the reference
// claimant solves the cheap outer puzzle (16 leading zero bits) as well as the
// devnet's easy Argon2id target, so the expected scan is about 2^17 nonces; a
// failure here means the fixture tuning broke, not that mining is slow.
const maxPuzzleAttempts = 1 << 24

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

	// Validators sizes the committee RunMulti drives. Zero means "not a
	// multi-validator run": the single-node Run/Replay paths ignore it, and
	// RunMulti requires at least one — silently falling back to the
	// single-node loop for zero would make the flag lie. The simnet harness
	// caps committees at 255 and its error propagates for anything larger.
	Validators uint64

	// OfflineValidators names committee indices RunMulti powers off before
	// the run: those validators tick and receive nothing for the whole run,
	// exactly like simnet's TakeOffline — a powered-off machine, not a
	// validator-set change, so they keep their seats and the
	// two-thirds-of-TOTAL-power bar is unmoved. It is the devnet surface's
	// liveness dial: with Validators 4 and one validator offline, the three
	// online validators hold exactly the bar and the chain must still
	// advance. An offline validator has no catch-up path in M3, so its
	// height stays frozen wherever it stood when the run began; its frozen
	// history must remain a strict prefix of the longest chain. Run/Replay
	// ignore it.
	OfflineValidators []int
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

	// The multi-validator run's fields, set by RunMulti and left zero by the
	// single-node Run and Replay.
	//
	// Validators is the committee size requested AND driven: a run whose
	// harness drove a different committee size than the options asked for
	// fails rather than reporting the request.
	//
	// ValidatorHeights is each validator's final chain height by committee
	// index. Height, for a multi run, is the longest of them; StateRoot is
	// zero and means NOT REPORTED, not "empty state" — the harness exposes
	// no state-root reader, and each validator's own chain on disk carries
	// its own root. The same honesty applies to TxsIncluded and every faucet
	// field: RunMulti injects no transaction anywhere (the committee's
	// Transport carries only consensus messages — there is no claim path
	// into it), so there is genuinely nothing to report.
	//
	// Agreed reports whether the validators hold ONE history: every
	// validator's committed blocks, height by height up to its own head, are
	// byte-identical to the longest chain's blocks at the same heights, so
	// shorter validators are strict prefixes of the longest chain and no two
	// validators ever committed conflicting blocks at one height. A run in
	// which the validators disagree FAILS: RunMulti returns an error naming
	// the divergence, and the Summary returned with that error reports
	// Agreed == false. For a committee of one, Agreed is vacuously true —
	// one validator's history trivially is the one history, and the
	// per-validator prefix check degenerates to a self-comparison. That
	// case's overlap with the single-node Run is deliberate, not accidental;
	// see RunMulti.
	Validators       uint64
	ValidatorHeights map[int]uint64
	Agreed           bool
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
	mp := mempool.New(1000, g.Hash(), c.AdmissionHead)
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
		pow, ok := faucet.SolveClaim(pub, epoch, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, maxPuzzleAttempts)
		if !ok {
			return Summary{}, fmt.Errorf("devnet: claim attempt %d of %d did not solve the fixture puzzle", attempt+1, o.Claims)
		}
		claim := devClaim(pub, priv, c.Genesis().Hash(), c.State().Get(claimant).Nonce, epoch, pow)
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
		//
		// Since audit R-1 the mempool enforces the one-claim-per-epoch rule at
		// ADMISSION, so this attempt is normally refused at the door with
		// state.ErrClaimTooSoon rather than admitted and evicted by the block
		// probe. Both are refusals of the same rule and both leave an empty
		// block behind, so the run's block sequence - and its state root - is
		// unchanged; a pool that admitted it is still handled below.
		double := devClaim(pub, priv, c.Genesis().Hash(), c.State().Get(claimant).Nonce, epoch, pow)
		addErr := mp.Add([]types.Tx{*double})[0]
		if addErr != nil && !errors.Is(addErr, state.ErrClaimTooSoon) {
			return Summary{}, fmt.Errorf("devnet: the double claim was neither admitted nor refused for the one-claim-per-epoch rule: %w", addErr)
		}
		ts++
		bd, err := n.RunOnce(ts)
		if err != nil {
			return Summary{}, err
		}
		// An empty double-claim block is EXPECTED: the transaction was refused
		// (at admission, or by the probe if it was admitted), so it is never
		// stored, and the replayed chain cannot even tell it happened.
		// Inclusion is the one outcome this scenario must never accept.
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

// The multi-validator run is a deterministic fixture like every other part of
// the devnet: one fixed seed and one fixed latency, so the same command reaches
// the same committee, the same draws and the same chain on every invocation.
// Seed 1 with 5 ms latency is happy-path scenario 1's shape.
const (
	runMultiSeed      = 1
	runMultiLatencyMS = 5
)

// RunMulti brings up a committee of o.Validators consensus validators over the
// simnet harness — each with its own chain under o.Dir/v<index> — and drives
// every online validator to o.Blocks. It is the multi-validator half of the
// acceptance check: a single node building blocks proves nothing about
// consensus, so the run ends by asking whether the validators hold one history
// (Summary.Agreed) and fails if they do not.
//
// Options.OfflineValidators powers validators off before the run; the online
// rest must still reach o.Blocks whenever they hold two thirds of TOTAL voting
// power or more (three of four is exactly the bar). Offline validators keep
// their committee seats, so the bar never drops.
//
// RunMulti deliberately shares NOTHING with the single-node Run at run time —
// they are different code paths over different genesis. Run drives the devnet
// fixture: one signer, no round protocol, a transaction and claim path.
// RunMulti drives real consensus even for one validator, so a one-validator
// committee is its own chain (b10coin-simnet-1) rather than a fallback that
// would quietly re-enter the single-node loop and make --validators a flag
// that lies. The overlap is the Summary shape and the acceptance-command
// surface, nothing deeper. Claims have no meaning here — the committee's
// Transport carries only consensus messages — and are refused.
//
// A run stops early with the harness's stall error if the online validators
// cannot reach o.Blocks (below two thirds of total power, for instance), and
// with a divergence error if any validator's history is not a prefix of the
// longest chain; both return the Summary of whatever the run did produce,
// heights included, so a failed acceptance check can be diagnosed, not merely
// observed.
func RunMulti(o Options) (Summary, error) {
	if o.Blocks == 0 {
		return Summary{}, ErrNoBlocks
	}
	if o.Validators == 0 {
		return Summary{}, ErrNoValidators
	}
	if o.Claims > 0 {
		return Summary{}, ErrClaimsAreMultiUnsupported
	}
	net, err := simnet.New(int(o.Validators), simnet.Options{
		TempDir:   o.Dir,
		Seed:      runMultiSeed,
		LatencyMS: runMultiLatencyMS,
		// DropPercent stays 0 on purpose: a validator whose quorum-committing
		// proposal is dropped holds no block bytes and parks at that height
		// forever (M3 has no catch-up), so any run asserting "the chain
		// advanced" must be drop-free. Latency alone is the honest fixture.
	})
	if err != nil {
		return Summary{}, err
	}
	defer net.Close()

	for _, i := range o.OfflineValidators {
		if i < 0 || i >= int(o.Validators) {
			return Summary{}, fmt.Errorf("devnet: OfflineValidators names validator %d in a committee of %d", i, o.Validators)
		}
		net.TakeOffline(i)
	}

	return drive(net, o)
}

// multiNet is the part of the harness RunMulti's driver consumes. It is an
// interface for one reason: honest validators never disagree — one history is
// precisely the safety property the protocol guarantees — so a test of the
// disagreement path cannot build the disagreement out of the real harness.
// The disagreement test injects a multiNet backed by genuinely forked chains
// instead, through the same per-validator comparison contract the real Net
// serves.
type multiNet interface {
	RunBlocks(target uint64) (map[uint64]uint64, error)
	AssertPrefix(i int) error
}

// drive runs one committee to o.Blocks and reports the committee's outcome.
// It is the whole of RunMulti minus construction: heights, agreement, and the
// two ways a run can fail without a single line of consensus code being wrong
// on paper — a committee other than the one requested, and validators that do
// not hold one history.
func drive(net multiNet, o Options) (Summary, error) {
	heights, runErr := net.RunBlocks(o.Blocks)

	s := Summary{
		ChainID:          committeeChainID(o.Validators),
		Validators:       o.Validators,
		ValidatorHeights: make(map[int]uint64, len(heights)),
	}
	for i, h := range heights {
		s.ValidatorHeights[int(i)] = h
		if h > s.Height {
			s.Height = h
		}
	}

	// The committee the harness DROVE must be the committee the options
	// requested: RunBlocks' heights carry exactly one entry per validator
	// that was built, so a run that reported the requested size while
	// silently driving fewer (or more) validators — every validator after the
	// missing ones unchecked, the agreement claim quietly covering a smaller
	// committee — would otherwise pass as the requested run. This guard makes
	// "asked for four, ran two, said four" impossible to report as success.
	if uint64(len(s.ValidatorHeights)) != o.Validators {
		return s, fmt.Errorf("devnet: the harness drove %d validators, %d were requested", len(s.ValidatorHeights), o.Validators)
	}

	// Agreement is computed from a real cross-comparison, not asserted:
	// oneHistory walks every validator's full history against the longest
	// chain. A disagreement fails the run and is reported, never papered over.
	agreeErr := oneHistory(net, int(o.Validators))
	s.Agreed = agreeErr == nil

	// The stall is reported first: a run that could not reach o.Blocks is the
	// primary failure, and any divergence is diagnosis on top of it.
	if runErr != nil {
		return s, runErr
	}
	if agreeErr != nil {
		return s, agreeErr
	}
	return s, nil
}

// oneHistory reports whether the committee holds ONE history: every
// validator's committed blocks — height by height, up to its own head — must
// be byte-identical to the network's longest chain, so a shorter validator is
// a strict prefix of the longest chain and two validators can never have
// committed conflicting blocks at one height.
//
// It is computed through the harness's per-validator prefix comparison rather
// than a single sampled head, because heads at different heights say nothing
// about the blocks in between and a fork confined to unshared heights would
// hide behind unequal heads. The comparison is complete: for any two
// validators diverging at a height they both reached, at least one of them
// differs from the longest chain at that height, and its prefix walk fails.
// A committee of one passes vacuously — its history trivially is the one
// history, and the walk degenerates to a self-comparison — which is why
// Agreed's honest reading for Validators: 1 is documented, not derived.
func oneHistory(net multiNet, validators int) error {
	for i := 0; i < validators; i++ {
		if err := net.AssertPrefix(i); err != nil {
			return err
		}
	}
	return nil
}

// committeeChainID mirrors the chain ID the harness derives for its committee
// (simnet's simGenesis: "b10coin-simnet-<n>"). The harness exports no genesis
// accessor, so the driver derives the value the harness mints; the literal is
// pinned by TestRunMultiWithFourValidatorsAgrees asserting the exact string,
// so a format change on either side fails there instead of reporting a stale
// chain ID.
func committeeChainID(validators uint64) string {
	return fmt.Sprintf("b10coin-simnet-%d", validators)
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
		Fee:    c.Genesis().Params.MinFeeSparks,
	}
	sigHash := tx.SigningHash(c.Genesis().Hash())
	tx.Sig = crypto.Sign(fromPriv, sigHash[:])
	return tx, nil
}

// devClaim builds and signs one faucet-claim transaction from pub (its
// solution pow already found for epoch). nonce is the claimant's replay
// counter at application time: zero for a claimant key that has never
// transacted, and the value the paid claim advanced for the same key's
// double claim.
func devClaim(pub ed25519.PublicKey, priv ed25519.PrivateKey, chainHash [32]byte, nonce, epoch, pow uint64) *types.Tx {
	tx := &types.Tx{
		Type:     types.TxFaucetClaim,
		From:     types.AddressFromPub(pub),
		PubKey:   pub,
		Nonce:    nonce,
		Epoch:    epoch,
		PowNonce: pow,
	}
	sigHash := tx.SigningHash(chainHash)
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
