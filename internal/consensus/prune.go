package consensus

import (
	"fmt"
	"path/filepath"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/store"
)

// The PRUNER (M7 step 3): the component that actually bounds a node's data
// directory, by dropping history below a horizon and leaving a verifiable
// checkpoint at it.
//
// IT IS OPT-IN, AND THE DEFAULT IS "KEEP EVERYTHING". Retain == 0 means no
// pruner is constructed at all; nothing in this file runs. That is what keeps
// every earlier acceptance run byte-identical - a node that was never asked to
// bound its history behaves exactly as it did before M7.
//
// RETENTION IS IN BLOCKS (heights), NOT HOURS (plan §5). A height is exact; a
// duration is not, and the operator can convert.
//
// THE HORIZON IS ONE BLOCK BEFORE AN EPOCH BOUNDARY: H = k*EpochBlocks - 1, so
// the first retained height H+1 is the first block of epoch k. Two properties
// depend on that exact choice:
//
//   - the state at H is the state that DECIDES epoch k's committee, so a node
//     resumed from the checkpoint can record that committee from the snapshot
//     and judge the first retained block (chain.OpenResume);
//   - pruning is a pure function of the head, so two nodes at the same head with
//     the same retention prune to the same horizon and agree on the state there.
//     A horizon in the middle of an epoch would leave the first retained epoch's
//     committee underivable without the state of an earlier epoch.
//
// CHECKPOINTS ARE NOT OPTIONAL (plan §7: "do not make retention the primary
// mechanism for recovery"). This pruner writes the checkpoint BEFORE it deletes
// anything and REFUSES TO PRUNE when it cannot write one - a node with no
// certificate for its horizon (a single-node producer, or a validator whose
// certificate log lacks that height) keeps its history and says why. A pruned
// node that cannot recover is worse than a full disk, because a full disk is
// visible.

// MinRetainEpochs is the smallest retention the pruner accepts, in epochs. It
// is a floor rather than a preference: the checkpoint for the horizon must be
// produced from a height the node still holds, and a window of one or two
// epochs leaves no room for a node to be restarted, catch up and prune again
// between boundaries. Four epochs is small enough to bound a Pi card and large
// enough to be operated.
const MinRetainEpochs = 4

// ValidateRetain checks a retention value against a chain's epoch length.
// retain == 0 means "keep everything" and is always valid.
func ValidateRetain(retain, epochBlocks uint64) error {
	if retain == 0 {
		return nil
	}
	if epochBlocks == 0 {
		return fmt.Errorf("consensus: --retain-blocks needs an epoch length, and this chain's EpochBlocks is 0")
	}
	if min := MinRetainEpochs * epochBlocks; retain < min {
		return fmt.Errorf("consensus: --retain-blocks %d is below the floor of %d blocks (%d epochs of %d blocks): the horizon is only reproducible at an epoch boundary, and a window shorter than a few epochs leaves no room to write and verify the checkpoint that makes the pruned history recoverable", retain, min, MinRetainEpochs, epochBlocks)
	}
	return nil
}

// Pruner bounds one data directory's history. Construct it with NewPruner and
// call MaybePrune after every commit (Driver.HistoryPruner) - it is a no-op
// until the head has moved far enough past the retention window to expose a new
// epoch boundary.
type Pruner struct {
	// Dir is the data directory the checkpoint is written into. It is the same
	// directory the chain stores blocks in, so a restart finds the checkpoint
	// next to the base marker it belongs to.
	Dir string
	// Retain is how many blocks to keep, in heights.
	Retain uint64
	// Log, when set, receives one line per pruning pass and per refusal. It is
	// a hook rather than a print so a library caller (the devnet harness, a
	// test) can observe the decision without scraping stderr.
	Log func(format string, args ...any)
}

// NewPruner returns a pruner keeping retain blocks. retain must be non-zero;
// "keep everything" is the absence of a pruner, not a pruner with a zero
// window (which would prune the chain to its head).
func NewPruner(dir string, retain uint64) (*Pruner, error) {
	if retain == 0 {
		return nil, fmt.Errorf("consensus: a pruner with retain 0 would prune everything; keep the flag unset to keep everything")
	}
	return &Pruner{Dir: dir, Retain: retain}, nil
}

func (p *Pruner) logf(format string, args ...any) {
	if p != nil && p.Log != nil {
		p.Log(format, args...)
	}
}

// MaybePrune prunes when the head has moved far enough past Retain to expose an
// epoch boundary below the window. It returns the stats of what it removed (all
// zero when there was nothing to do).
//
// ERRORS ARE REFUSALS, NOT FAILURES OF THE NODE. Every error path here leaves
// the history INTACT: a checkpoint that cannot be built, written or staged stops
// the pass before a single block is deleted. The caller (the driver) logs it and
// keeps producing blocks; the node's data directory is simply not bounded this
// time, which is the honest outcome.
func (p *Pruner) MaybePrune(c *chain.Chain) (store.PruneStats, error) {
	var zero store.PruneStats
	if p == nil || p.Retain == 0 {
		return zero, nil
	}
	g := c.Genesis()
	blocks := g.Params.EpochBlocks
	if err := ValidateRetain(p.Retain, blocks); err != nil {
		return zero, err
	}
	head := c.Height()
	if head <= p.Retain {
		return zero, nil // the chain is still inside the window
	}
	// The largest epoch boundary (as a PRUNE height, k*E-1) at or below
	// head-Retain. k >= 1 always keeps the genesis block out of it.
	target := head - p.Retain
	k := target / blocks
	if k < 1 {
		return zero, nil
	}
	horizon := k*blocks - 1
	if horizon >= head || horizon <= c.Base() {
		return zero, nil // nothing new to prune
	}

	cp, st, err := exportCheckpointAt(c, horizon, false)
	if err != nil {
		// NO CHECKPOINT, NO PRUNE. This is the refusal that keeps a node from
		// looking healthy while being unable to recover.
		return zero, fmt.Errorf("refusing to prune to height %d: %w", horizon, err)
	}
	// Stage the checkpoint BEFORE deleting anything. A crash after the base
	// marker is written but before this file is renamed still leaves a
	// checkpoint on disk whose height matches the new base, which is what a
	// restart needs (see checkpoint.go's pendingCheckpointName).
	if err := WriteCheckpointFile(filepath.Join(p.Dir, pendingCheckpointName), cp); err != nil {
		return zero, fmt.Errorf("refusing to prune to height %d: cannot stage the checkpoint: %w", horizon, err)
	}
	stats, err := c.PruneHistory(horizon, st)
	if err != nil {
		return stats, err
	}
	// The history below the horizon is gone and the chain resumes from the
	// staged checkpoint; promote it. A failure here is not fatal: the staged
	// file IS a loadable checkpoint (ResumeForDir reads it first), so the next
	// start recovers either way.
	if err := CommitPendingCheckpoint(p.Dir); err != nil {
		return stats, fmt.Errorf("pruned to height %d, but promoting the checkpoint failed (the staged copy remains and is usable): %w", horizon, err)
	}
	p.logf("pruned history below height %d: %d block segments, %d certificate segments (%d bytes total); checkpoint at height %d",
		stats.FirstHeight, stats.Blocks, stats.CertSegs, stats.BlockBytes+stats.CertBytes+stats.LegacyBytes, horizon)
	return stats, nil
}
