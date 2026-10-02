// Package chain owns the canonical block sequence: building candidate
// blocks, validating them against state, appending them durably, and
// rebuilding state by replay on startup.
package chain

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
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

// Chain is a validated, durably-stored block sequence.
type Chain struct {
	gen   *genesis.Genesis
	store *store.Store
	state *state.State
	head  *types.Block
}

// genesisState builds the state that block 1 builds upon.
func genesisState(g *genesis.Genesis) (*state.State, error) {
	s := state.New()
	for _, d := range g.DevAccounts {
		addr := types.AddressFromPub(d.PubKey)
		acc := s.Get(addr)
		acc.Balance += d.BalanceSparks
		s.Set(addr, acc)
	}
	return s, nil
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
	st, err := genesisState(g)
	if err != nil {
		return nil, err
	}
	s, err := store.Open(dir)
	if err != nil {
		return nil, err
	}
	c := &Chain{gen: g, store: s, state: st, head: genesisBlock(g, st)}

	height, ok := s.Height()
	if !ok {
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
		if err := c.applyValidated(blk); err != nil {
			return nil, fmt.Errorf("%w at height %d: %v", ErrGenesisReplay, h, err)
		}
		// The stored header's root must equal what we just recomputed.
		if c.state.Root() != blk.Header.StateRoot {
			return nil, fmt.Errorf("%w at height %d", ErrGenesisReplay, h)
		}
	}
	return c, nil
}

func (c *Chain) Genesis() *genesis.Genesis { return c.gen }
func (c *Chain) Height() uint64            { return c.head.Header.Height }
func (c *Chain) Head() *types.Block        { return c.head }
func (c *Chain) State() *state.State       { return c.state }

// isValidator reports whether pub is in the genesis validator set.
func (c *Chain) isValidator(pub []byte) bool {
	for _, v := range c.gen.Validators {
		if string(v.PubKey) == string(pub) {
			return true
		}
	}
	return false
}

// Build constructs and signs a candidate block. It does not mutate the
// chain: the caller decides whether to Append.
func (c *Chain) Build(proposer ed25519.PrivateKey, txs []types.Tx, timestamp int64) (*types.Block, error) {
	pub, ok := proposer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrUnknownProposer
	}
	next, err := c.state.ApplyBlock(txs)
	if err != nil {
		return nil, err
	}
	b := &types.Block{
		Header: types.Header{
			Height:     c.Height() + 1,
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
func (c *Chain) applyValidated(b *types.Block) error {
	next, err := c.state.ApplyBlock(b.Txs)
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
func (c *Chain) Append(b *types.Block) error {
	if b.Header.ParentHash != c.head.ID() {
		return ErrBadParent
	}
	if b.Header.Height != c.Height()+1 {
		return fmt.Errorf("%w: got %d, want %d", ErrBadHeight, b.Header.Height, c.Height()+1)
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

	next, err := c.state.ApplyBlock(b.Txs)
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

func (c *Chain) Close() error { return c.store.Close() }
