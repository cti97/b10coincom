package chain

// The round log's chain-level half of the F3 fix (review F3). The round a
// validator had reached is written through Chain.PutRound before it votes, and
// the ONLY height that is ever read back is head+1 (Driver.newEngine). So once
// Append has made head >= h durable, h's round can never be read again - and
// Append must prune it, exactly as it already prunes the lock. Without that
// wiring the store's PruneRounds is never called on the live path and the log
// grows one frame per round entered, forever.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/store"
)

func roundRecAt(h uint64, r uint32) store.RoundRecord {
	return store.RoundRecord{Height: h, Round: r}
}

// Append prunes the rounds of heights the chain has left, while keeping the
// committed head's own round and the head+1 round a restart reads. It is the
// live half of the fix, and the wiring the store-level test cannot reach.
func TestAppendPrunesRoundsBelowTheNewHead(t *testing.T) {
	dir := t.TempDir()
	g := genesis.Devnet()
	_, priv := devKey()
	c, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	appendBlock := func(h uint64) {
		t.Helper()
		b, err := c.Build(priv, nil, 1_700_000_000+int64(h))
		if err != nil {
			t.Fatalf("Build(%d): %v", h, err)
		}
		if err := c.Append(b); err != nil {
			t.Fatalf("Append(%d): %v", h, err)
		}
	}

	appendBlock(1)
	// The round persisted while height 1 was being judged.
	if err := c.PutRound(roundRecAt(1, 1)); err != nil {
		t.Fatal(err)
	}
	appendBlock(2) // committing 2 leaves height 1 behind
	if _, ok := c.RoundAt(1); ok {
		t.Fatal("Append(2) did not prune the round at the height it left (1): the round log has no live prune path")
	}
	if err := c.PutRound(roundRecAt(2, 1)); err != nil {
		t.Fatal(err)
	}
	// The head+1 round, written while height 3 is being judged.
	if err := c.PutRound(roundRecAt(3, 7)); err != nil {
		t.Fatal(err)
	}
	appendBlock(3) // committing 3 must keep 3 and prune 2
	if _, ok := c.RoundAt(2); ok {
		t.Fatal("Append(3) did not prune the round at the height it left (2)")
	}
	if _, ok := c.RoundAt(3); !ok {
		t.Fatal("Append(3) pruned the committed head's own round; the fix keeps it as headroom")
	}
	if got, ok := c.RoundAt(3); !ok || got != 7 {
		t.Fatalf("RoundAt(3) = %d,%v; want the persisted round 7", got, ok)
	}
}

// A long-running validator must not grow rounds.log without limit THROUGH THE
// REAL APPEND PATH (review F3). The store-level long-run test pins PruneRounds
// and its compaction; this one pins that Chain.Append calls them, by measuring
// the file the live path wrote. One frame per round entered would be 2 per
// height - 600 frames for 300 heights - while the pruned, compacted log holds
// only the live rounds plus the compaction threshold.
func TestAppendKeepsTheRoundLogBoundedOverALongRun(t *testing.T) {
	// One frame's on-disk size, measured from a store holding exactly one round,
	// so the bound is expressed in frames without naming the log's internals.
	probeDir := t.TempDir()
	probe, err := store.Open(probeDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.PutRound(store.RoundRecord{Height: 1, Round: 1}); err != nil {
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	probeInfo, err := os.Stat(filepath.Join(probeDir, "rounds.log"))
	if err != nil {
		t.Fatalf("reading the probe store's round log (the name is pinned by internal/store's own round tests): %v", err)
	}
	frameBytes := probeInfo.Size()
	if frameBytes <= 0 {
		t.Fatal("fixture: one round record measured zero on-disk bytes")
	}

	dir := t.TempDir()
	g := genesis.Devnet()
	_, priv := devKey()
	c, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	const heights = 300
	for h := uint64(1); h <= heights; h++ {
		// Two rounds entered while judging height h (head is h-1).
		for r := uint32(1); r <= 2; r++ {
			if err := c.PutRound(roundRecAt(h, r)); err != nil {
				t.Fatal(err)
			}
		}
		b, err := c.Build(priv, nil, 1_700_000_000+int64(h))
		if err != nil {
			t.Fatalf("Build(%d): %v", h, err)
		}
		if err := c.Append(b); err != nil {
			t.Fatalf("Append(%d): %v", h, err)
		}
	}
	// The live map is bounded to head and head+1, not one entry per height.
	if _, ok := c.RoundAt(1); ok {
		t.Fatal("after a long run the round at height 1 is still held: the map grew one entry per height")
	}
	if _, ok := c.RoundAt(heights); !ok {
		t.Fatal("after a long run the committed head's own round is gone")
	}
	// The restart-resume property: the round persisted for head+1 survives the
	// run and a reopen.
	if err := c.PutRound(roundRecAt(heights+1, 9)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "rounds.log"))
	if err != nil {
		t.Fatal(err)
	}
	frames := info.Size() / frameBytes
	t.Logf("%d heights x 2 rounds/height through Chain.Append: rounds.log holds ~%d frames of %d bytes (one frame per round entered would be %d)",
		heights, frames, frameBytes, heights*2)
	// The store's compaction threshold plus the live rounds; generous by a few
	// frames so the assertion is about the BOUND, not an exact frame count.
	if frames > 256+8 {
		t.Fatalf("rounds.log holds ~%d frames after %d heights, want at most ~264 (the compaction threshold plus the live rounds): Append is not pruning the round log", frames, heights)
	}
	if unbounded := int64(heights * 2); frames >= unbounded {
		t.Fatalf("rounds.log holds ~%d frames; one frame per round entered would be %d and the bound must be far below it", frames, unbounded)
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, ok := reopened.RoundAt(heights + 1); !ok || got != 9 {
		t.Fatalf("after reopen the head+1 round is %d,%v, want the persisted 9: the prune must not cost the restart its position", got, ok)
	}
}
