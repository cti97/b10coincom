package chain

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
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

// certSegsIn returns the certificate segment files a data directory holds,
// sorted. The names are the store's documented on-disk format
// ("certs-NNNNNNNN.cseg", fixed width), which is what lets this test create a
// second, SEALED segment without reaching into the store's internals: the
// L-1 fault has to land on a segment the certificate prune is allowed to
// remove, and audit I-2 makes the ACTIVE one unselectable by construction.
func certSegsIn(t *testing.T, dir string) []string {
	t.Helper()
	segs, err := filepath.Glob(filepath.Join(dir, "certs-*.cseg"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(segs)
	return segs
}

// TestAPruneCertsErrorDoesNotDesynchroniseTheChain is the L-1 fault injection
// (docs/audit-2026-11-15-main.md): PruneHistory's block pass succeeds and its
// certificate pass then fails on an I/O error.
//
// The assertions are about the RUNNING CHAIN's consistency, not about the
// error. Before the fix, PruneBlocks advanced the on-disk base while
// PruneCerts' error returned before the in-memory one moved, so StateAt(h) for
// h in (oldBase, upTo] passed its `h < base` guard, read a DELETED block and
// reported store.ErrNotFound for the life of the process. After the fix the
// same state is reported as PRUNED (a deliberate absence, which a caller can
// act on), the horizon state is still exportable, and the next pass reclaims
// the surplus certificates.
func TestAPruneCertsErrorDoesNotDesynchroniseTheChain(t *testing.T) {
	c, g, dir := pruneChain(t, 12)
	// Certificates below the horizon, so a certificate segment is removable.
	// (The payload is opaque to the chain; only its presence matters here.)
	for h := uint64(1); h <= 3; h++ {
		if err := c.PutCert(h, []byte{byte('0' + h)}); err != nil {
			t.Fatalf("PutCert(%d): %v", h, err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	segs := certSegsIn(t, dir)
	if len(segs) != 1 {
		t.Fatalf("the fixture wrote %d certificate segments, want the one segment its three certificates share: %v", len(segs), segs)
	}
	// Seal segment 0 and give the store a NEW active segment 1 (its header is
	// the segment format itself: the magic and the version, nothing per-file),
	// exactly the shape rotation produces. The pruner may remove segment 0;
	// I-2 forbids it from touching the open segment 1.
	raw, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= store.SegmentHeaderLen {
		t.Fatalf("segment %s is %d bytes, want records after the %d-byte header", segs[0], len(raw), store.SegmentHeaderLen)
	}
	active := filepath.Join(dir, "certs-00000001.cseg")
	if err := os.WriteFile(active, raw[:store.SegmentHeaderLen], 0o644); err != nil {
		t.Fatal(err)
	}
	c2, err := Open(g, dir)
	if err != nil {
		t.Fatalf("reopening the chain with two certificate segments: %v", err)
	}
	defer func() { _ = c2.Close() }()
	// THE FAULT: segment 0's name now belongs to a NON-EMPTY DIRECTORY, so the
	// pruner's os.Remove returns ENOTEMPTY - a real I/O failure on the exact
	// call it makes, with no test seam in the production code.
	if err := os.Remove(segs[0]); err != nil {
		t.Fatalf("replacing %s: %v", segs[0], err)
	}
	if err := os.Mkdir(segs[0], 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(segs[0], "occupied"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	st7, err := c2.StateAt(7)
	if err != nil {
		t.Fatalf("StateAt(7) before the prune: %v", err)
	}
	if _, err := c2.PruneHistory(7, st7); err == nil {
		t.Fatal("PruneHistory(7) reported success although removing a certificate segment must fail")
	}

	// 2. The pruned range reads as PRUNED, not as a missing block - this is
	// the symptom the audit names: pre-fix, StateAt read a DELETED block and
	// reported store.ErrNotFound, which a caller cannot tell from a damaged
	// directory. h=7 is the base itself and is still answerable from baseState.
	for _, h := range []uint64{1, 5} {
		if _, err := c2.StateAt(h); !errors.Is(err, ErrHistoryPruned) {
			t.Fatalf("StateAt(%d) after a certificate-prune error = %v, want ErrHistoryPruned (below the retained history)", h, err)
		}
	}
	// 3. The base advanced anyway: the block base moved on disk, so the
	// in-memory base must move with it.
	if got := c2.Base(); got != 7 {
		t.Fatalf("Base after a certificate-prune error = %d, want 7: the in-memory base must follow the block base, which the successful PruneBlocks already advanced", got)
	}
	if base, err := store.BaseOf(dir); err != nil || base != 8 {
		t.Fatalf("the directory records first block height %d (%v), want 8", base, err)
	}
	if st, err := c2.StateAt(7); err != nil || st.Root() != st7.Root() {
		t.Fatalf("StateAt(7) after the failed pass = %v, %v; want the horizon state (a checkpoint re-export reads exactly this)", st, err)
	}
	// 4. The live chain is untouched and its retained history still replays.
	if got := c2.Height(); got != 12 {
		t.Fatalf("the head moved to %d after a certificate-prune error", got)
	}
	if st, err := c2.StateAt(12); err != nil || st.Root() != c2.State().Root() {
		t.Fatalf("StateAt(head) after the failed pass = %v, %v", st, err)
	}
	// 5. The surplus certificates are reclaimable: repair the injected fault
	// and the NEXT pass completes, on the normal schedule, with no special
	// handling of "a previous pass failed".
	if err := os.RemoveAll(segs[0]); err != nil {
		t.Fatal(err)
	}
	st11, err := c2.StateAt(11)
	if err != nil {
		t.Fatalf("StateAt(11): %v", err)
	}
	if _, err := c2.PruneHistory(11, st11); err != nil {
		t.Fatalf("the next prune must reclaim the surplus certificate segments: %v", err)
	}
	if got := c2.Base(); got != 11 {
		t.Fatalf("Base after the recovering prune = %d, want 11", got)
	}
	if _, err := c2.StateAt(8); !errors.Is(err, ErrHistoryPruned) {
		t.Fatalf("StateAt(8) after pruning to 11 = %v, want ErrHistoryPruned", err)
	}
}
