// Package chain owns the canonical block sequence: building candidate
// blocks, validating them against state, appending them durably, and
// rebuilding state by replay on startup.
package chain

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/store"
	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrBadParent       = errors.New("chain: parent hash does not match head")
	ErrBadHeight       = errors.New("chain: height is not head+1")
	ErrBadStateRoot    = errors.New("chain: computed state root does not match header")
	ErrBadProposerSig  = errors.New("chain: proposer signature is missing or invalid")
	ErrNotValidator    = errors.New("chain: proposer is not in the validator set")
	ErrGenesisReplay   = errors.New("chain: replay diverged from stored state root")
	ErrUnknownProposer = errors.New("chain: cannot determine proposer key")
)

// Chain is a validated, durably-stored block sequence. It is safe for
// concurrent use: mu guards state and head, because one process may serve
// the RPC server (reading Height/Head/State/Genesis/BlockAt) while the node
// loop appends. No exported method may be called while its own lock is
// already held — every mutator works on unexported fields directly.
//
// Returning *types.Block and *state.State under a read lock is sound: an
// appended block is never mutated again (see Head), and state.ApplyBlock
// returns a NEW State without touching its receiver, so published states are
// immutable after Open.
type Chain struct {
	mu    sync.RWMutex
	gen   *genesis.Genesis
	store *store.Store
	state *state.State
	head  *types.Block

	// faucet is the protocol-controlled faucet address this chain mints into,
	// derived from the genesis hash (so no private key exists for it). Set
	// once in Open; advanceLocked uses it rather than recomputing per block.
	faucet types.Address
}

// genesisState builds the state that block 1 builds upon. It applies the
// height-0 emission (the genesis mint the spec names: Reward is NOT
// special-cased at height 0, so the mint uses the same formula every later
// block uses) and wires the faucet claim's parameters, without which no
// claim could ever verify. It cannot fail: genesis validation has already
// checked every key length, so the error return is omitted.
func genesisState(g *genesis.Genesis) *state.State {
	st := state.NewWithParams(state.Params{
		FaucetAddress: g.FaucetAddress(),
		ClaimAmount:   g.Params.ClaimAmountSparks,
		EpochBlocks:   g.Params.EpochBlocks,
		PowArgon2:     g.Params.FaucetPowArgon2,
		PowTarget:     g.Params.FaucetPowTarget,
		// The per-block claim bound is consensus state-machine behaviour
		// parameterised by genesis, exactly like the epoch length: without
		// wiring it here the bound would exist only in states that tests
		// construct by hand, and no real chain would enforce it.
		MaxClaimsPerBlock: g.Params.MaxClaimsPerBlock,
	})
	for _, d := range g.DevAccounts {
		addr := types.AddressFromPub(d.PubKey)
		acc := st.Get(addr)
		acc.Balance += d.BalanceSparks
		st.Set(addr, acc)
	}
	// The genesis mint the spec names. Reward is not special-cased at height 0,
	// so this is the same formula every later block uses.
	if r := faucet.Reward(0, g.Params.InitialRewardSparks, g.Params.HalvingIntervalBlocks); r > 0 {
		acc := st.Get(g.FaucetAddress())
		acc.Balance += r
		st.Set(g.FaucetAddress(), acc)
	}
	return st
}

func genesisBlock(g *genesis.Genesis, st *state.State) *types.Block {
	return &types.Block{
		Header: types.Header{
			Height:     0,
			ParentHash: [32]byte{},
			StateRoot:  st.Root(),
			TxRoot:     crypto.MerkleRoot(nil),
			Timestamp:  g.Time,
			Proposer:   nil,
		},
	}
}

// Open loads the chain from dir, replaying every stored block. If the
// directory is empty it initialises the genesis block instead.
func Open(g *genesis.Genesis, dir string) (*Chain, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	st := genesisState(g)
	s, err := store.Open(dir)
	if err != nil {
		return nil, err
	}
	// Close the store on every failure path after this point: returning an
	// open handle with the chain unset would leak the handle. owned records
	// that the handle was successfully handed to a returned Chain; until
	// then the deferred close owns it. Error values are unchanged.
	owned := false
	defer func() {
		if !owned {
			_ = s.Close()
		}
	}()
	c := &Chain{gen: g, store: s, state: st, head: genesisBlock(g, st), faucet: g.FaucetAddress()}

	height, ok := s.Height()
	if !ok {
		owned = true
		return c, nil
	}
	for h := uint64(1); h <= height; h++ {
		raw, err := s.Read(h)
		if err != nil {
			return nil, err
		}
		blk, err := types.DecodeBlock(raw)
		if err != nil {
			return nil, err
		}
		// The store indexes segments by record count, so a lost or rewritten
		// segment would silently renumber every stored block. applyValidated
		// deliberately skips structure, proposer and signature checks, and
		// the state-root check below cannot substitute for these either:
		// blocks that carry no transactions change no state, so a renumbered
		// chain would replay to the very roots the rewritten headers claim.
		// The cheapest authentication of the stored bytes is to require each
		// block to claim the position it sits at and to link exactly the
		// block replayed before it (for replay position h = 1 that
		// predecessor is the synthesized genesis, which lives at height 0).
		if blk.Header.Height != h {
			return nil, fmt.Errorf("%w at height %d: stored block claims height %d", ErrGenesisReplay, h, blk.Header.Height)
		}
		wantParent := c.head.ID()
		if blk.Header.ParentHash != wantParent {
			return nil, fmt.Errorf("%w at height %d: stored block does not link its predecessor (parent %x, expected %x)",
				ErrGenesisReplay, h, blk.Header.ParentHash[:8], wantParent[:8])
		}
		if err := c.applyValidated(blk); err != nil {
			return nil, fmt.Errorf("%w at height %d: %v", ErrGenesisReplay, h, err)
		}
		// The stored header's root must equal what we just recomputed.
		if c.state.Root() != blk.Header.StateRoot {
			return nil, fmt.Errorf("%w at height %d", ErrGenesisReplay, h)
		}
	}
	owned = true
	return c, nil
}

func (c *Chain) Genesis() *genesis.Genesis {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gen
}

func (c *Chain) Height() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.head.Header.Height
}

// Head returns the current head block. Append retains the caller's
// *types.Block as the head and this method hands that same pointer back, so
// a caller must not mutate a block after appending it: doing so silently
// changes Height()/Head().ID() without any store write. Returned blocks are
// therefore immutable by contract.
func (c *Chain) Head() *types.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.head
}

func (c *Chain) State() *state.State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// isValidator reports whether pub is in the genesis validator set.
func (c *Chain) isValidator(pub []byte) bool {
	for _, v := range c.gen.Validators {
		if bytes.Equal(v.PubKey, pub) {
			return true
		}
	}
	return false
}

// creditEmissionLocked pays the block's emission into the faucet account. It
// runs BEFORE the block's transactions, for every height including genesis,
// so a claim in block h may spend block h's emission. Build, Append and
// replay must all call this or their state roots diverge.
//
// Called from advanceLocked only, which always holds c.mu.
func (c *Chain) creditEmissionLocked(st *state.State, height uint64) {
	r := faucet.Reward(height, c.gen.Params.InitialRewardSparks, c.gen.Params.HalvingIntervalBlocks)
	if r == 0 {
		return
	}
	acc := st.Get(c.faucet)
	acc.Balance += r
	st.Set(c.faucet, acc)
}

// advanceLocked applies one block's state transition: emission FIRST, then the
// block's transactions, in that order. Every path that moves the chain forward
// calls this - if any of them applied the transactions first, or skipped the
// emission, its state root would differ from the others and the chain would fork.
//
// It mutates only the clone it returns, never c.state; the caller must hold
// c.mu (reading is enough, which is how Build uses it).
func (c *Chain) advanceLocked(height uint64, txs []types.Tx) (*state.State, error) {
	next := c.state.Clone()
	next.SetHeight(height) // execution context only: the claim rule derives its epoch from it
	c.creditEmissionLocked(next, height)
	return next.ApplyBlock(txs)
}

// Probe reports the state a block at head+1 carrying txs would produce, without
// appending anything. It runs the SAME transition as Append - height set, emission
// credited, transactions applied - because a probe that skipped the emission or used the
// head's height would evict valid faucet claims.
func (c *Chain) Probe(txs []types.Tx) (*state.State, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.advanceLocked(c.head.Header.Height+1, txs)
}

// SelectApplicable filters candidates down to the transactions that apply, in
// order, against the state a block at head+1 would be built on, and returns
// them. This is THE one policy for which transactions a block carries: both
// block producers run through it - node.RunOnce for the single-node path and
// consensus.Driver.build for the consensus path - so what a proposer assembles
// and what every validator's Append must accept are decided by the same code.
// A block assembled one way and judged another is how a chain forks; sharing
// this filter is what makes that impossible by construction rather than by
// two implementations that must be kept in step by hand.
//
// The filter's base is Probe(nil) - the state a block at head+1 with no
// transactions would produce: the SAME transition Build runs, height advanced
// and emission credited. Hand-cloning the head state (the old filter) probed
// a claim against the head's epoch and a pre-emission faucet balance, and
// silently evicted valid claims. Candidates then apply on top of the base
// cumulative - each accepted transaction is inside the running state the next
// probe starts from, so a candidate may chain onto its accepted siblings
// (transfers with nonces 0 and 1 both survive; probing each against the bare
// head state would evict the second). Equivalent-but-quadratic alternative:
// probing every candidate through Probe(accepted... + candidate) re-derives and
// re-verifies the accepted prefix's signatures per candidate, which on a
// full MaxTxsPerBlock mempool is hours of ed25519 per block - a DoS the
// one-base form avoids.
//
// The per-block claim bound is deliberately NOT applied here and its callers
// must not duplicate it: state.ApplyBlock enforces it before any Argon2id
// evaluation, on the block as a whole, which is where the bound is consensus.
// The mempool's local claim courtesy that bounds what each block producer
// TAKES lives in mempool.Take. A filter that re-counted claims here would be
// a second claim rule that could drift from the state machine's; the two
// layers this side of ApplyBlock stay exactly where they are.
//
// A candidate that cannot apply is dropped ALONE: it does not discard its
// valid siblings, and it is gone for good once the caller's Take does not see
// it again - the caller owns what eviction means for its pool. An error
// return means the empty head+1 transition itself failed, so nothing applies
// and every candidate was lost by the caller's bookkeeping; the caller is
// expected to return its candidates to wherever they came from.
func (c *Chain) SelectApplicable(candidates []types.Tx) ([]types.Tx, error) {
	base, err := c.Probe(nil)
	if err != nil {
		return nil, err
	}
	valid := make([]types.Tx, 0, len(candidates))
	for i := range candidates {
		next, err := base.ApplyBlock([]types.Tx{candidates[i]})
		if err != nil {
			continue // evict: it cannot apply at this state
		}
		base = next
		valid = append(valid, candidates[i])
	}
	return valid, nil
}

// Build constructs and signs a candidate block. It does not mutate the
// chain: the caller decides whether to Append.
func (c *Chain) Build(proposer ed25519.PrivateKey, txs []types.Tx, timestamp int64) (*types.Block, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	pub, ok := proposer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrUnknownProposer
	}
	next, err := c.advanceLocked(c.head.Header.Height+1, txs)
	if err != nil {
		return nil, err
	}
	b := &types.Block{
		Header: types.Header{
			Height:     c.head.Header.Height + 1,
			ParentHash: c.head.ID(),
			StateRoot:  next.Root(),
			TxRoot:     types.ComputeTxRoot(txs),
			Timestamp:  timestamp,
			Proposer:   pub,
		},
		Txs: txs,
	}
	if err := b.ValidateStructure(); err != nil {
		return nil, err
	}
	headerHash := b.Header.SigningHash()
	b.Sig = crypto.Sign(proposer, headerHash[:])
	return b, nil
}

// applyValidated applies a block whose structure is already trusted.
// Write-locked; the unlocked body lives in applyValidatedLocked so Append can
// reuse it while holding the lock.
func (c *Chain) applyValidated(b *types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applyValidatedLocked(b)
}

func (c *Chain) applyValidatedLocked(b *types.Block) error {
	next, err := c.advanceLocked(b.Header.Height, b.Txs)
	if err != nil {
		return err
	}
	c.state = next
	c.head = b
	return nil
}

// validateLocked runs every check Append runs for a block over the chain's
// CURRENT head, and returns the state a valid block would produce.
//
// This is the ONE validation policy for what makes a block acceptable at
// head+1: Append (the durable write) and ValidateNext (the consensus engine's
// pre-vote seam) both call it, so a block the engine prevotes is, by
// construction, a block Append would accept - and a proposer's Build (which
// signs exactly the same transition) cannot disagree with either. Two
// validators can only disagree about the chain, never about the rules.
//
// The checks, in Append's order: parent link, head+1 height, block structure
// (types), proposer membership, proposer signature, then the whole state
// transition through advanceLocked - height set, emission credited,
// transactions applied - whose recomputed root must equal the header's claim.
// That last check is the state-root probe: the same Probe-style transition a
// peer who never saw the block would run to judge it.
//
// Read-lock sufficient: nothing here mutates the chain (advanceLocked works
// on a clone). The caller must hold c.mu.
func (c *Chain) validateLocked(b *types.Block) (*state.State, error) {
	if b.Header.ParentHash != c.head.ID() {
		return nil, ErrBadParent
	}
	if b.Header.Height != c.head.Header.Height+1 {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadHeight, b.Header.Height, c.head.Header.Height+1)
	}
	if err := b.ValidateStructure(); err != nil {
		return nil, err
	}
	if !c.isValidator(b.Header.Proposer) {
		return nil, ErrNotValidator
	}
	if b.Sig == nil {
		return nil, ErrBadProposerSig
	}
	headerHash := b.Header.SigningHash()
	if !crypto.Verify(b.Header.Proposer, headerHash[:], b.Sig) {
		return nil, ErrBadProposerSig
	}
	next, err := c.advanceLocked(b.Header.Height, b.Txs)
	if err != nil {
		return nil, err
	}
	if computed := next.Root(); computed != b.Header.StateRoot {
		return nil, fmt.Errorf("%w: computed %x, header claims %x",
			ErrBadStateRoot, computed[:8], b.Header.StateRoot[:8])
	}
	return next, nil
}

// ValidateNext reports whether b is a valid block for head+1, WITHOUT
// appending or mutating anything: it runs exactly the checks Append runs -
// they live in one shared method so the two cannot drift - and returns the
// first failure.
//
// COST, stated where the reviewer will look for it (audit round 3, F4): the
// seam is the whole state transition, not a cheap pre-check. A proposal is
// cloned and applied end to end - emission credited, every transaction
// applied - and a faucet claim's puzzle can only be accepted or rejected by
// evaluating it, so each claim in b costs one FULL Argon2id evaluation here,
// bounded exactly as a genuine block is bounded by MaxClaimsPerBlock and
// MaxTxsPerBlock (ApplyBlock refuses the block above any bound before any
// puzzle runs). All of it runs under this chain's READ lock, so a Byzantine
// proposer can force that work for a block it already knows will fail the
// root comparison at the end - and the work is charged to every validator
// the proposal reaches. The bound is structural: the engine judges at most
// ONE proposal per round (the first stored proposal wins; later ones are
// dropped as duplicates), so the attack is at most one full-transition
// validation per round per validator - the price of the pre-vote probing the
// audit asked for (judging the state root BEFORE a vote can rest on it), and
// work the pre-fix prevote path never did. It is accepted cost, documented
// here so no reviewer has to rediscover it.
//
// This is the audit C-1 seam's chain half: the consensus engine must judge a
// proposal BEFORE prevoting it, and the check it makes must be the one a peer
// (and the chain itself) would make at append time. A validator that lets a
// proposal reach a polka, a lock and a commit before the chain sees it risks
// every node parking on the chain's refusal, with no one able to move on -
// the halt one Byzantine proposer can otherwise inflict with a garbage state
// root.
//
// Like Append, validation is all-or-nothing against the current head: a
// refusal leaves height, state and store untouched.
func (c *Chain) ValidateNext(b *types.Block) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, err := c.validateLocked(b)
	return err
}

// Append validates a block against the current head and state, then stores
// it. Validation happens before any mutation, so a rejected block leaves the
// chain untouched.
//
// Aliasing contract: on success Append retains the caller's *types.Block as
// the chain's head (no defensive copy), and Head() later hands that same
// pointer back. A caller must not mutate a block after appending it:
// mutating the retained block silently changes Height()/Head().ID() with no
// store write, leaving the stored bytes behind the chain's in-memory view.
func (c *Chain) Append(b *types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The full validation runs first (validateLocked), so a rejected block
	// never reaches the store: a refusal leaves the chain byte-identical to
	// what ValidateNext would have observed.
	next, err := c.validateLocked(b)
	if err != nil {
		return err
	}
	if err := c.store.Append(b.Header.Height, b.Encode()); err != nil {
		return err
	}
	c.state = next
	c.head = b
	return nil
}

// BlockAt returns the block stored at height. Only the head is cached, so
// historical reads go to disk. Height 0 is the genesis block, which the
// store deliberately never holds (store heights start at 1): it is
// re-synthesised from the genesis configuration exactly as Open built it.
func (c *Chain) BlockAt(height uint64) (*types.Block, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	headHeight := c.head.Header.Height
	if height > headHeight {
		return nil, fmt.Errorf("%w: %d", store.ErrNotFound, height)
	}
	if height == headHeight {
		return c.head, nil
	}
	if height == 0 {
		st := genesisState(c.gen)
		return genesisBlock(c.gen, st), nil
	}
	raw, err := c.store.Read(height)
	if err != nil {
		return nil, err
	}
	return types.DecodeBlock(raw)
}

// PutLock durably records a validator's lock: that it precommitted
// rec.BlockID at rec.Height in round rec.Round. The chain exposes the
// store's lock log because the lock must survive a restart, and the store is
// only reachable through the chain - it is the same crash-tolerant directory
// the blocks replay from, so the promise is read back in the same Open that
// rebuilds the chain. Write-locked: it mutates the store (append + fsync +
// index update) and must not interleave with readers.
func (c *Chain) PutLock(rec store.LockRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.PutLock(rec)
}

// LockAt returns the newest lock recorded for height, and whether one
// exists. This is how a restarted validator picks its promise back up: the
// replayed blocks say where the chain stands, the lock log says what it
// promised at the height it is about to judge.
func (c *Chain) LockAt(height uint64) (store.LockRecord, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.store.LockAt(height)
}

func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.Close()
}
