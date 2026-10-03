package consensus

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

// The persist hook exists so the promise survives a crash BEFORE the precommit
// that records it can leave the process: persisted-then-sent, never
// sent-then-persisted. If the precommit hits the wire first and the write
// lands only after, the crash window between them reproduces the whole defect
// this task closes - a restarted validator that re-enters unlocked while its
// promise is already on the wire.
//
// The engine emits through a queue (emit -> Drain), so "before the precommit
// leaves the engine" is observable: at hook time, no precommit may be sitting
// in the outbox yet.
func TestLockMovePersistsBeforeThePrecommitLeavesTheEngine(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 0, true, parent)
	e := newTestEngine(t, cfg, 0, h, parent)

	var hookCalls int
	var queuedPrecommits, prevoteCountAtHook int
	engineBlockID := e.lk.blockID
	e.persistLock = func(height uint64, round uint32, id [32]byte) {
		hookCalls++
		if height != h || id != engineBlockID() {
			lockedNow := engineBlockID()
			t.Fatalf("the hook saw a lock move it did not take: (h=%d, block %x), engine at (h=%d, block %x)",
				height, id[:8], h, lockedNow[:8])
		}
		for _, o := range e.out {
			if v, err := DecodeVote(o.Data); err == nil {
				switch v.Type {
				case MsgPrecommit:
					queuedPrecommits++
				case MsgPrevote:
					prevoteCountAtHook++
				}
			}
		}
	}

	blkA := testProposer(t, cfg, h, 0, parent)
	deliverProposalAndPrevotes(t, e, cfg, h, blkA)

	if !e.lk.locked() {
		t.Fatal("the engine never locked; the ordering cannot be exercised")
	}
	if hookCalls != 1 {
		t.Fatalf("the persist hook fired %d time(s) for one lock move, want exactly 1", hookCalls)
	}
	if prevoteCountAtHook != 1 {
		t.Fatalf("at hook time %d prevote(s) were queued, want exactly the validator's own prevote", prevoteCountAtHook)
	}
	if queuedPrecommits != 0 {
		t.Fatalf("the precommit was already queued when the lock was persisted: sent-then-persisted reverses the crash-safety order")
	}

	// After Drain, the precommit IS queued - it was not dropped, only ordered
	// behind the persistence.
	precommits := 0
	for _, o := range e.Drain() {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrecommit {
			precommits++
		}
	}
	if precommits != 1 {
		t.Fatalf("%d precommit(s) queued after Drain, want 1: the persist hook must not swallow the vote", precommits)
	}
}

// restoreLock must go through the same forward-only mutator an in-memory lock
// uses, so a restored lock cannot pull the engine backwards. An engine whose
// lock was restored by force (a direct field write) would precommit at an
// earlier round than its promise - but a RESTORED lock must additionally be
// checked for the thing that makes the restore itself safe: restoring into a
// lock that already exists must not LOSE the existing lock.
func TestRestoreLockKeepsTheStrongerPromise(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 0, true, parent)
	e := newTestEngine(t, cfg, 0, h, parent)

	older := testProposer(t, cfg, h, 0, parent)
	newer := conflictingBlock(t, cfg, h, 1, parent, 0xC1)

	// Take a promise at round 1, then "restart" - i.e. restore - a record
	// from an earlier life of this same height that was WEAKER (round 0): the
	// engine must keep the promise it already had, not regress to the
	// restored one.
	e = newTestEngine(t, cfg, 0, h, parent)
	e.restoreLock(1, newer.ID())
	e.restoreLock(0, older.ID()) // an older record arrives late (disk order aside, it happens)
	if got := e.lk.round(); got != 1 {
		t.Fatalf("after restoring an older record the lock regressed to round %d, want the promise at round 1", got)
	}
	lockedBlock := e.lk.blockID()
	newerID := newer.ID()
	if got := e.lk.blockID(); got != newerID {
		t.Fatalf("after restoring an older record the lock block is %x, want the newer promise %x", lockedBlock[:8], newerID[:8])
	}
}
