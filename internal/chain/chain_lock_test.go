package chain

import (
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/store"
)

func chainLockID(b byte) [32]byte { var id [32]byte; id[0] = b; return id }

func lockRecAt(h uint64, r uint32, id [32]byte) store.LockRecord {
	return store.LockRecord{Height: h, Round: r, BlockID: id}
}

// The chain exposes the store's lock log because the lock must survive the
// same restart that replays the blocks: a validator that precommitted at
// head+1 and crashed reopens via Open, whose replay rebuilds the chain's
// blocks - and MUST hand the persisted lock back to the consensus driver for
// that same height. This test is the chain-level half of the consensus
// restart test: the record sits at a height the store has NO block for
// (head+1, the height being judged), and it comes back through a full
// close, block replay and reopen.
func TestChainLockSurvivesReplayAndReopen(t *testing.T) {
	dir := t.TempDir()
	g := genesis.Devnet()
	_, priv := devKey()
	c, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	b1, err := c.Build(priv, nil, 1_700_000_100)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := c.Append(b1); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if c.Height() != 1 {
		t.Fatalf("height = %d, want 1", c.Height())
	}

	// Two locks: one at an already-committed height (the height's promise is
	// obsolete once the height commits, but the record may not be corrupted
	// or dropped by the replay), and one at head+1 - the height the
	// restarted validator is about to judge, for which no block exists.
	committed := lockRecAt(1, 5, chainLockID(1))
	pending := lockRecAt(2, 0, chainLockID(2))
	if err := c.PutLock(committed); err != nil {
		t.Fatalf("PutLock at the committed height: %v", err)
	}
	if err := c.PutLock(pending); err != nil {
		t.Fatalf("PutLock at head+1: %v", err)
	}
	rootBefore := c.Head().ID()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	replayed, err := Open(g, dir)
	if err != nil {
		t.Fatalf("Open with a lock log present: %v", err)
	}
	defer replayed.Close()
	// The replay itself was unaffected: same head, one block.
	headAfter := replayed.Head().ID()
	if replayed.Height() != 1 || headAfter != rootBefore {
		t.Fatalf("replay diverged: height %d (want 1), head %x (want %x)",
			replayed.Height(), headAfter[:8], rootBefore[:8])
	}
	if got, _ := replayed.LockAt(2); got != pending {
		t.Fatalf("the lock at head+1 did not survive the replay: got %+v, want %+v", got, pending)
	}
	if got, _ := replayed.LockAt(1); got != committed {
		t.Fatalf("the lock at the committed height did not survive the replay: got %+v, want %+v", got, committed)
	}
	if _, ok := replayed.LockAt(3); ok {
		t.Fatal("a height that was never locked must report no lock after the replay")
	}
}

// Append prunes the locks of heights the chain has left (audit C-13), while
// keeping the head's own record and the head+1 promise. It is the LIVE half of
// the fix: the file and map stop growing one record per height.
func TestAppendPrunesLocksBelowTheNewHead(t *testing.T) {
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
	if err := c.PutLock(lockRecAt(1, 0, chainLockID(1))); err != nil {
		t.Fatal(err)
	}
	appendBlock(2) // committing 2 leaves height 1 behind
	if _, ok := c.LockAt(1); ok {
		t.Fatal("Append(2) did not prune the lock at the height it left (1)")
	}
	if err := c.PutLock(lockRecAt(2, 0, chainLockID(2))); err != nil {
		t.Fatal(err)
	}
	// The head+1 promise, written while height 3 is being judged.
	if err := c.PutLock(lockRecAt(3, 0, chainLockID(3))); err != nil {
		t.Fatal(err)
	}
	appendBlock(3) // committing 3 must keep 3 and prune 2
	if _, ok := c.LockAt(2); ok {
		t.Fatal("Append(3) did not prune the lock at the height it left (2)")
	}
	if _, ok := c.LockAt(3); !ok {
		t.Fatal("Append(3) pruned the committed head's own lock; the fix keeps it")
	}
}
