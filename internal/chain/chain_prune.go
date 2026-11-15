package chain

import (
	"fmt"

	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/store"
	"github.com/cti97/b10coincom/internal/types"
)

// M7's chain-level half of bounded history: resuming a pruned directory from a
// checkpoint, snapshotting the state at a past height (what a checkpoint needs),
// and actually dropping the history below a horizon.
//
// The one rule this file exists to keep: the pruning horizon is an EPOCH
// BOUNDARY, and specifically the last block of the epoch BEFORE the first
// retained one (H = kE-1). That choice is not cosmetic. The committee that
// judges a height is decided by the state committed at the last height before
// its epoch, so a checkpoint at H = kE-1 carries exactly the state that decides
// the first retained epoch - and OpenResume can record that committee from it.
// A checkpoint at H = kE would carry the state that decides epoch k+1 and would
// leave epoch k's committee underivable, which is the rotation-aware gap M7
// explicitly does not solve.

// checkResume validates the internal consistency of a checkpoint hand-off,
// independent of any consensus check the caller already did: the block must sit
// at the height it claims, the height must be the one the directory expects,
// and the state must hash to the root the block commits. The last check is what
// makes the state snapshot tamper-evident WITHOUT trusting the caller: a state
// that does not reproduce the block's root is not the state that block
// committed, whatever the certificate said.
func checkResume(r *ResumeState, wantHeight uint64) error {
	if r == nil {
		return fmt.Errorf("%w: no checkpoint state", ErrCheckpointMismatch)
	}
	if r.Head == nil || r.State == nil {
		return fmt.Errorf("%w: the checkpoint carries no head block or no state", ErrCheckpointMismatch)
	}
	if r.Head.Header.Height != r.Height {
		return fmt.Errorf("%w: the checkpoint's block is at height %d but the checkpoint names height %d", ErrCheckpointMismatch, r.Head.Header.Height, r.Height)
	}
	if r.Height != wantHeight {
		return fmt.Errorf("%w: this directory's retained history builds on height %d, but the checkpoint is at height %d", ErrCheckpointMismatch, wantHeight, r.Height)
	}
	if root := r.State.Root(); root != r.Head.Header.StateRoot {
		return fmt.Errorf("%w: the checkpoint's state hashes to %x, but its block commits %x: the state snapshot is not the state that block committed", ErrCheckpointMismatch, root[:8], r.Head.Header.StateRoot[:8])
	}
	return nil
}

// transition applies one block's state transition to st, returning a NEW state:
// emission first, then the block's transactions, exactly as advanceLocked does
// for the head. It is the shared engine of both paths, so a replayed state and
// a live one can never differ by the order of those two steps.
func (c *Chain) transition(st *state.State, height uint64, txs []types.Tx) (*state.State, error) {
	next := st.Clone()
	next.SetHeight(height) // execution context only: the claim rule derives its epoch from it
	c.creditEmissionLocked(next, height)
	return next.ApplyBlock(txs)
}

// Base returns the height the directory's retained history starts AFTER: 0 for
// a chain that holds genesis, and the checkpoint's height for a pruned one.
// Heights <= Base() are absent by design.
func (c *Chain) Base() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.baseHeight
}

// StateAt returns the committed state at height h: the live state when h is the
// head, and otherwise a replay of the retained blocks from the directory's base
// up to h.
//
// It exists because a checkpoint must carry the state at its horizon, and the
// chain keeps only the head's state. Replaying is the honest way to get it: the
// alternative - keeping a state snapshot per epoch - makes the data directory
// grow again by a term the pruner would have to bound.
//
// COST, stated where a reviewer will look: the replay runs OUTSIDE the chain's
// lock (blocks below the head are immutable), but it is a full state transition
// per block, so a prune of a large window pays for the window it is about to
// keep. It is serialised against PruneHistory by pruneMu, which is what keeps
// the base it replays from from moving underneath it.
func (c *Chain) StateAt(h uint64) (*state.State, error) {
	c.pruneMu.Lock()
	defer c.pruneMu.Unlock()
	c.mu.RLock()
	head := c.head.Header.Height
	base := c.baseHeight
	baseState := c.baseState
	var headState *state.State
	if h == head {
		headState = c.state
	}
	c.mu.RUnlock()
	if h > head {
		return nil, fmt.Errorf("%w: %d", store.ErrNotFound, h)
	}
	if h < base {
		return nil, fmt.Errorf("%w: state at height %d is below the retained history (base %d)", ErrHistoryPruned, h, base)
	}
	if headState != nil {
		return headState, nil
	}
	if baseState == nil {
		return nil, fmt.Errorf("chain: no state at the base height %d to replay from", base)
	}
	st := baseState.Clone()
	for height := base + 1; height <= h; height++ {
		raw, err := c.store.Read(height)
		if err != nil {
			return nil, err
		}
		blk, err := types.DecodeBlock(raw)
		if err != nil {
			return nil, err
		}
		if blk.Header.Height != height {
			return nil, fmt.Errorf("%w at height %d: stored block claims height %d", ErrGenesisReplay, height, blk.Header.Height)
		}
		next, err := c.transition(st, height, blk.Txs)
		if err != nil {
			return nil, fmt.Errorf("%w at height %d: %v", ErrGenesisReplay, height, err)
		}
		if root := next.Root(); root != blk.Header.StateRoot {
			return nil, fmt.Errorf("%w at height %d: replaying to a checkpoint gives root %x, but the stored header commits %x", ErrRuleChange, height, root[:8], blk.Header.StateRoot[:8])
		}
		st = next
	}
	return st, nil
}

// blockAt resolves a height against the head snapshot the caller supplies. It
// takes no lock: BlockAt snapshots the head under a read lock and then reads
// the store WITHOUT the chain lock (audit R-2), and PruneHistory already holds
// the write lock.
func (c *Chain) blockAt(head *types.Block, height uint64) (*types.Block, error) {
	headHeight := head.Header.Height
	if height > headHeight {
		return nil, fmt.Errorf("%w: %d", store.ErrNotFound, height)
	}
	if height == headHeight {
		return head, nil
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

// PruneHistory drops every block and certificate at height <= upTo and makes
// the chain resume from the state at upTo. The caller MUST already have written
// the checkpoint for upTo (consensus.Pruner does): this function deletes the
// only on-disk copy of the history that could rebuild that state.
//
// REFUSALS, each closing a way to lose the chain:
//
//   - upTo must be strictly below the head: the head block - and its
//     certificate - are never pruned (plan §3);
//   - upTo+1 must be an epoch boundary, because the checkpoint's state is what
//     decides the first retained epoch's committee (see this file's header);
//   - st must reproduce the state root stored at upTo. A caller that computed
//     the wrong state (or was handed one) is refused BEFORE anything is
//     deleted, rather than after.
func (c *Chain) PruneHistory(upTo uint64, st *state.State) (store.PruneStats, error) {
	var zero store.PruneStats
	c.pruneMu.Lock()
	defer c.pruneMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()

	blocks := c.gen.Params.EpochBlocks
	if blocks == 0 {
		return zero, fmt.Errorf("chain: cannot prune: EpochBlocks is zero, so there is no epoch boundary to prune at")
	}
	if upTo == 0 {
		return zero, nil // nothing to prune: the genesis block is never stored
	}
	if upTo <= c.baseHeight {
		return zero, nil // already at or below this horizon
	}
	if upTo >= c.head.Header.Height {
		return zero, fmt.Errorf("chain: refusing to prune to height %d: the head is at %d and the head block is never prunable", upTo, c.head.Header.Height)
	}
	if (upTo+1)%blocks != 0 {
		return zero, fmt.Errorf("chain: refusing to prune to height %d: %d is not an epoch boundary (EpochBlocks %d); the state at the horizon must be the one that decides the first retained epoch", upTo, upTo+1, blocks)
	}
	blk, err := c.blockAt(c.head, upTo)
	if err != nil {
		return zero, err
	}
	if st == nil {
		return zero, fmt.Errorf("chain: refusing to prune to height %d without the state at that height", upTo)
	}
	if root := st.Root(); root != blk.Header.StateRoot {
		return zero, fmt.Errorf("chain: refusing to prune to height %d: the supplied state hashes to %x, but that block commits %x", upTo, root[:8], blk.Header.StateRoot[:8])
	}

	bs, err := c.store.PruneBlocks(upTo)
	if err != nil {
		return bs, err
	}
	cs, err := c.store.PruneCerts(upTo)
	if err != nil {
		return bs, err
	}
	bs.CertSegs = cs.CertSegs
	bs.CertBytes = cs.CertBytes
	bs.LegacyCerts = cs.LegacyCerts
	bs.LegacyBytes = cs.LegacyBytes
	bs.FirstHeight = cs.FirstHeight

	c.baseHeight = upTo
	c.baseState = st.Clone()
	// Epoch committees whose whole epoch is below the horizon can never be asked
	// for again (no retained block belongs to them), and keeping one entry per
	// epoch forever is the unbounded memory the committee memo was always going
	// to become. Drop them; the entry the first retained epoch needs was
	// recorded by OpenResume/Apply and is above the horizon.
	for e := range c.committees {
		if e+1 <= upTo/blocks {
			delete(c.committees, e)
		}
	}
	return bs, nil
}
