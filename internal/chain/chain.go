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
	if b.Header.ParentHash != c.head.ID() {
		return ErrBadParent
	}
	if b.Header.Height != c.head.Header.Height+1 {
		return fmt.Errorf("%w: got %d, want %d", ErrBadHeight, b.Header.Height, c.head.Header.Height+1)
	}
	if err := b.ValidateStructure(); err != nil {
		return err
	}
	if !c.isValidator(b.Header.Proposer) {
		return ErrNotValidator
	}
	if b.Sig == nil {
		return ErrBadProposerSig
	}
	headerHash := b.Header.SigningHash()
	if !crypto.Verify(b.Header.Proposer, headerHash[:], b.Sig) {
		return ErrBadProposerSig
	}

	next, err := c.advanceLocked(b.Header.Height, b.Txs)
	if err != nil {
		return err
	}
	if computed := next.Root(); computed != b.Header.StateRoot {
		return fmt.Errorf("%w: computed %x, header claims %x",
			ErrBadStateRoot, computed[:8], b.Header.StateRoot[:8])
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

func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.Close()
}
