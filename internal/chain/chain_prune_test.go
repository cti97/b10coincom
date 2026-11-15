package chain

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/store"
	"github.com/cti97/b10coincom/internal/types"
)

// M7's chain half: StateAt (what a checkpoint needs), PruneHistory (only at an
// epoch boundary, never the head, only with the right state), and reopening a
// pruned directory from a checkpoint.

// pruneChain builds a chain of n empty blocks over a genesis whose epoch is 4,
// so an epoch boundary is cheap to reach. It returns the open chain and its
// genesis.
func pruneChain(tb testing.TB, n int) (*Chain, *genesis.Genesis, string) {
	tb.Helper()
	g := genesis.Devnet()
	g.Params.EpochBlocks = 4
	dir := tb.TempDir()
	c, err := Open(g, dir)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = c.Close() })
	_, priv := devKey()
	for h := 1; h <= n; h++ {
		b, err := c.Build(priv, nil, int64(1_700_000_000+h))
		if err != nil {
			tb.Fatalf("Build(%d): %v", h, err)
		}
		if err := c.Append(b); err != nil {
			tb.Fatalf("Append(%d): %v", h, err)
		}
	}
	return c, g, dir
}

// TestStateAtReproducesEveryStoredRoot pins the replay a checkpoint depends on:
// the state at a past height must hash to that height's committed root, and the
// head must come back as the live state.
func TestStateAtReproducesEveryStoredRoot(t *testing.T) {
	c, _, _ := pruneChain(t, 12)
	for h := uint64(1); h <= 12; h++ {
		st, err := c.StateAt(h)
		if err != nil {
			t.Fatalf("StateAt(%d): %v", h, err)
		}
		blk, err := c.BlockAt(h)
		if err != nil {
			t.Fatalf("BlockAt(%d): %v", h, err)
		}
		if root := st.Root(); root != blk.Header.StateRoot {
			t.Fatalf("StateAt(%d) hashes to %x, but the stored header commits %x", h, root[:8], blk.Header.StateRoot[:8])
		}
	}
	head, err := c.StateAt(12)
	if err != nil {
		t.Fatal(err)
	}
	if head != c.State() {
		t.Fatal("StateAt(head) did not return the live head state")
	}
	if _, err := c.StateAt(13); err == nil {
		t.Fatal("StateAt above the head returned a state")
	}
}

// TestPruneHistoryOnlyAtAnEpochBoundary pins the plan's "prune only at epoch
// boundaries" rule in code: with EpochBlocks 4, the legal prune heights are
// 3, 7, 11, ... (k*4-1, so the first retained height is the first block of an
// epoch) and everything else is refused before a byte is removed.
func TestPruneHistoryOnlyAtAnEpochBoundary(t *testing.T) {
	c, _, _ := pruneChain(t, 12)
	st, err := c.StateAt(4)
	if err != nil {
		t.Fatal(err)
	}
	for _, upTo := range []uint64{1, 2, 4, 5, 6, 9} {
		if _, err := c.PruneHistory(upTo, st); err == nil {
			t.Fatalf("PruneHistory(%d) succeeded; %d is not an epoch boundary (the first retained height must start an epoch)", upTo, upTo+1)
		}
	}
	if c.Base() != 0 {
		t.Fatalf("a refused prune moved the base to %d", c.Base())
	}
	if h := c.Height(); h != 12 {
		t.Fatalf("a refused prune moved the head to %d", h)
	}
}

// TestPruneHistoryRefusesTheHead pins the head's permanence at the chain level.
func TestPruneHistoryRefusesTheHead(t *testing.T) {
	c, _, _ := pruneChain(t, 12)
	// 12 IS the head and 15 is above it: both refuse. 11 (head-1) is legal and
	// keeps block 12 - "the head is never prunable" means the head survives, not
	// that pruning stops a block before it.
	st, err := c.StateAt(11)
	if err != nil {
		t.Fatal(err)
	}
	for _, upTo := range []uint64{12, 15} {
		if _, err := c.PruneHistory(upTo, st); err == nil {
			t.Fatalf("PruneHistory(%d) succeeded; the head block must be kept", upTo)
		}
	}
	// The legal horizon: 7, which leaves 8..12 retained.
	st7, err := c.StateAt(7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PruneHistory(7, st7); err != nil {
		t.Fatalf("PruneHistory(7): %v", err)
	}
	if c.Base() != 7 {
		t.Fatalf("Base after pruning to 7 = %d", c.Base())
	}
	// The horizon's own block is gone from the store - the checkpoint file
	// carries it - and so is everything below it.
	if _, err := c.BlockAt(7); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("BlockAt(7) after pruning = %v, want store.ErrNotFound", err)
	}
	if _, err := c.BlockAt(6); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("BlockAt(6) after pruning = %v, want store.ErrNotFound", err)
	}
	if _, err := c.BlockAt(8); err != nil {
		t.Fatalf("BlockAt(8) after pruning: %v", err)
	}
	// The state at the horizon is still available: it is what the checkpoint
	// was built from and what a resume replays on top of.
	if st, err := c.StateAt(7); err != nil || st.Root() != st7.Root() {
		t.Fatalf("StateAt(7) after pruning = %v, %v; want the checkpoint state", st, err)
	}
	if h := c.Height(); h != 12 {
		t.Fatalf("head moved to %d after pruning", h)
	}
}

// TestPruneHistoryRefusesAStateThatIsNotTheHorizon pins the guard that keeps a
// caller from deleting history and then resuming from the wrong state: the
// supplied state must reproduce the horizon block's committed root, and that is
// checked BEFORE anything is removed.
func TestPruneHistoryRefusesAStateThatIsNotTheHorizon(t *testing.T) {
	c, _, _ := pruneChain(t, 12)
	wrong, err := c.StateAt(3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PruneHistory(7, wrong); err == nil {
		t.Fatal("PruneHistory accepted the state at height 3 as the state at 7")
	}
	if _, err := c.PruneHistory(7, nil); err == nil {
		t.Fatal("PruneHistory accepted a nil state")
	}
	if c.Base() != 0 {
		t.Fatalf("a refused prune moved the base to %d", c.Base())
	}
	if _, err := c.BlockAt(1); err != nil {
		t.Fatalf("a refused prune removed history: BlockAt(1) = %v", err)
	}
}

// TestAPrunedDirectoryNeedsACheckpointAndResumesFromIt is the chain-level
// recovery: after a prune the directory refuses a genesis open, and opening it
// with the verified state at the horizon replays the retained blocks to the very
// same head and root.
func TestAPrunedDirectoryNeedsACheckpointAndResumesFromIt(t *testing.T) {
	c, g, dir := pruneChain(t, 12)
	wantHead, wantRoot := c.Height(), c.State().Root()
	st7, err := c.StateAt(7)
	if err != nil {
		t.Fatal(err)
	}
	blk7, err := c.BlockAt(7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PruneHistory(7, st7); err != nil {
		t.Fatal(err)
	}
	// The live chain keeps working: the head and state are untouched by a prune.
	if c.Height() != wantHead || c.State().Root() != wantRoot {
		t.Fatal("pruning moved the live head or state")
	}
	// A pruned chain can still answer for retained heights, and not for older
	// ones. This is also what a peer it serves would ask.
	if _, err := c.BlockAt(8); err != nil {
		t.Fatalf("BlockAt(8) on the live pruned chain: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// Opening WITHOUT the checkpoint must refuse: replaying the retained blocks
	// from genesis would number them from 1.
	if c2, err := Open(g, dir); err == nil {
		_ = c2.Close()
		t.Fatal("a pruned directory opened from genesis")
	} else if !errors.Is(err, ErrHistoryPruned) {
		t.Fatalf("opening a pruned directory without a checkpoint gave %v, want ErrHistoryPruned", err)
	}

	// Opening WITH the checkpoint at the horizon resumes at H+1 and replays.
	c3, err := OpenResume(g, dir, &ResumeState{Height: 7, Head: blk7, State: st7})
	if err != nil {
		t.Fatalf("OpenResume: %v", err)
	}
	defer func() { _ = c3.Close() }()
	if got := c3.Height(); got != wantHead {
		t.Fatalf("resumed height = %d, want %d", got, wantHead)
	}
	if got := c3.State().Root(); got != wantRoot {
		t.Fatalf("resumed state root = %x, want %x", got[:8], wantRoot[:8])
	}
	// The first retained epoch's committee is derivable from the checkpoint's
	// state: a resumed validator must be able to judge its next height.
	if _, err := c3.CommitteeAt(8); err != nil {
		t.Fatalf("CommitteeAt(8) on the resumed chain: %v (the epoch the checkpoint resumes into)", err)
	}
	// The resumed chain can be extended.
	_, priv := devKey()
	b, err := c3.Build(priv, nil, int64(1_700_000_100))
	if err != nil {
		t.Fatalf("Build on the resumed chain: %v", err)
	}
	if err := c3.Append(b); err != nil {
		t.Fatalf("Append on the resumed chain: %v", err)
	}
}

// TestOpenResumeRefusesAMismatchedCheckpoint pins the three ways a checkpoint
// can disagree with the directory it is handed to. Each is a refusal, never a
// silent genesis start: adopting the wrong starting state is how a node
// "recovers" onto state no quorum committed.
func TestOpenResumeRefusesAMismatchedCheckpoint(t *testing.T) {
	c, g, dir := pruneChain(t, 12)
	st7, err := c.StateAt(7)
	if err != nil {
		t.Fatal(err)
	}
	blk7, err := c.BlockAt(7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PruneHistory(7, st7); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// 1. The wrong height: the marker says the retained history builds on 7.
	if c2, err := OpenResume(g, dir, &ResumeState{Height: 3, Head: blk7, State: st7}); err == nil {
		_ = c2.Close()
		t.Fatal("OpenResume accepted a checkpoint at the wrong height")
	} else if !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("wrong-height checkpoint gave %v, want ErrCheckpointMismatch", err)
	}
	// 2. A state that does not hash to the block's committed root.
	other, err := state.DecodeState(st7.Encode(), GenesisParams(g))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := devKey()
	other.Set(types.AddressFromPub(pub), state.Account{Balance: 12345})
	if _, err := OpenResume(g, dir, &ResumeState{Height: 7, Head: blk7, State: other}); err == nil {
		t.Fatal("OpenResume accepted a state that does not hash to the horizon block's root")
	}
	// 3. No checkpoint at all.
	if _, err := Open(g, dir); !errors.Is(err, ErrHistoryPruned) {
		t.Fatalf("opening without a checkpoint gave %v, want ErrHistoryPruned", err)
	}
	// 4. The IMPORT shape: an empty directory, so there are no retained blocks
	// whose replay could notice a wrong base state. The chain's own root check
	// is the only thing between the operator and a state no quorum committed.
	empty := t.TempDir()
	if c2, err := OpenResume(g, empty, &ResumeState{Height: 7, Head: blk7, State: other}); err == nil {
		_ = c2.Close()
		t.Fatal("OpenResume adopted a state that does not hash to its block's root into an EMPTY directory")
	} else if !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("an empty-directory import with a wrong state gave %v, want ErrCheckpointMismatch", err)
	}
	if base, err := store.BaseOf(empty); err != nil || base != 1 {
		t.Fatalf("a refused import recorded base %d (%v); nothing may be written", base, err)
	}
}
