package consensus

// Audit C-3's own pins: the per-height multi-round vote buffer, the
// commit-from-any-round rule and the persisted (height, round). The already
// shipped halves of C-3 - the capped TimeoutStep ladder and the power-gated,
// stride-bounded round jump - have their existing tests in driver_test.go
// (TestRoundTimeoutsAreCapped, TestTimeoutJumpsOnFutureRoundEvidence,
// TestTimeoutJumpNeedsDistinctMembersNotOneByzantine,
// TestJumpGateCountsPowerNotSeats, TestJumpNeverTravelsFurtherThanABoundedStride)
// and are deliberately untouched here.

import (
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
)

// --- 1. The future-round window and its bound -------------------------------

// TestFutureRoundVotesAreBufferedWithinTheWindowOnly: a vote for a round two
// ahead is retained in that round's own tally and adopted when the engine
// enters it; a vote further ahead than the window is not retained (only its
// round-ladder evidence is). The window, not the run length, decides.
func TestFutureRoundVotesAreBufferedWithinTheWindowOnly(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, false, parent)
	e := newTestEngine(t, cfg, 1, h, parent)
	id := crypto.HashParts([]byte("buffered-block"))

	buffered := e.round + 2 // two rounds ahead: inside futureVoteRounds
	if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, 0, MsgPrevote, h, buffered, id))); err != nil {
		t.Fatal(err)
	}
	s := e.sets[buffered]
	if s == nil {
		t.Fatalf("a prevote %d round(s) ahead was dropped instead of buffered", buffered)
	}
	if got := s.prevotes.PowerFor(id); got != 1 {
		t.Fatalf("the buffered round holds %d prevote power for the block, want 1", got)
	}

	far := e.round + futureVoteRounds + 1 // one past the window
	if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, 1, MsgPrevote, h, far, id))); err != nil {
		t.Fatal(err)
	}
	if e.sets[far] != nil {
		t.Fatalf("a prevote %d rounds ahead was buffered: the future window is unbounded", far)
	}
	if p := e.future[1]; p == nil || p.Round != far {
		t.Fatal("the far-ahead vote was not recorded as round-ladder evidence: the window must bound RETENTION, not observation")
	}

	// Entering the buffered round adopts its tally unchanged.
	e.enterRound(buffered)
	if e.prevotes != e.sets[buffered].prevotes {
		t.Fatal("entering the round did not bind the buffered tally: the vote was re-created instead of adopted")
	}
	if got := e.prevotes.PowerFor(id); got != 1 {
		t.Fatalf("after entering the round the buffered prevote is gone (power %d)", got)
	}
}

// TestRetainedRoundsStayBoundedUnderAVoteFlood constructs the state directly:
// thousands of votes for rounds across the whole uint32 range are fed in, and
// the buffer must stay within (futureVoteRounds + pastVoteRounds + 1) round
// sets and (that x 2 x committee) votes. This is the memory-DoS bound, not a
// timing observation: no round is ever advanced by a race.
func TestRetainedRoundsStayBoundedUnderAVoteFlood(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, false, parent)
	e := newTestEngine(t, cfg, 1, h, parent)
	id := crypto.HashParts([]byte("flood-block"))

	for r := uint32(0); r < 5000; r++ {
		v := voteFrom(t, cfg, int(r)%len(cfg.Committee), MsgPrevote, h, r, id)
		if err := e.OnMessage(EncodeVote(v)); err != nil {
			t.Fatalf("round %d: %v", r, err)
		}
	}
	maxRounds := int(futureVoteRounds + pastVoteRounds + 1)
	if len(e.sets) > maxRounds {
		t.Fatalf("retained %d round sets after a 5000-round flood, want at most %d", len(e.sets), maxRounds)
	}
	maxVotes := maxRounds * 2 * len(cfg.Committee)
	total := 0
	for _, s := range e.sets {
		total += len(s.prevotes.Votes()) + len(s.precommits.Votes())
	}
	if total > maxVotes {
		t.Fatalf("retained %d votes after a 5000-round flood, want at most %d (the stated bound)", total, maxVotes)
	}

	// Advancing far prunes everything outside the new window: the retained set
	// is the window, never the history.
	e.enterRound(4000)
	if len(e.sets) != 1 {
		t.Fatalf("after jumping to round 4000 the engine retains %d round sets, want only the current one", len(e.sets))
	}
}

// TestABufferedPrecommitQuorumCommitsWhenTheRoundIsEntered: a quorum that
// forms for a round the engine has not entered yet is buffered, and the moment
// it reaches quorum it commits (audit C-3's "commit from a precommit quorum in
// any round"): the engine ADOPTS that round, because >2/3 precommitting there
// is where the committee is, so a proposal for the decided round still in
// flight can arrive and be appended. Adopting at formation is also what keeps
// a later round jump from pruning the quorum before it is noticed.
func TestABufferedPrecommitQuorumCommitsAndAdoptsItsRound(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, false, parent)
	e := newTestEngine(t, cfg, 1, h, parent)
	id := crypto.HashParts([]byte("future-quorum-block"))
	target := e.round + 2

	for _, idx := range []int{0, 1, 2} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, idx, MsgPrecommit, h, target, id))); err != nil {
			t.Fatal(err)
		}
	}
	got, ok := e.Committed()
	if !ok || got != id {
		t.Fatalf("a buffered future round's precommit quorum did not commit: got %x,%v want %x", got[:8], ok, id[:8])
	}
	if e.commitRound != target {
		t.Fatalf("commitRound = %d, want the buffered round %d", e.commitRound, target)
	}
	if e.round != target || e.step != StepCommit {
		t.Fatalf("the engine is at (round %d, step %s); a future-round commit must adopt the decided round and stop", e.round, e.step)
	}
	if n := len(e.committedPrecommits()); n != 3 {
		t.Fatalf("the certificate source holds %d precommits, want the quorum's 3", n)
	}
}

// --- 2. Commit from a precommit quorum in any round, and its safety ---------

// TestALatePrecommitQuorumForARoundAlreadyLeftCommits is the audit's named
// case. A validator prevotes and locks at round 0, and the round times out and
// is left BEFORE the remaining precommits arrive. enterRound used to discard
// round 0's precommit set, so the quorum that completes afterwards could never
// commit here. Now the past round's set is retained and maybeCommit scans it:
// the block commits, and the certificate is attributed to round 0.
func TestALatePrecommitQuorumForARoundAlreadyLeftCommits(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, false, parent)
	e := newTestEngine(t, cfg, 1, h, parent)

	blk := testProposer(t, cfg, h, 0, parent)
	id := blk.ID()
	deliverProposalAndPrevotes(t, e, cfg, h, blk)
	if !e.Locked() || e.lk.blockID() != id || e.lk.round() != 0 {
		t.Fatal("fixture: the round-0 polka must have precommitted and locked the engine on the block")
	}
	if got := e.precommits.PowerFor(id); got != 1 {
		t.Fatalf("fixture: %d precommit power before the late votes, want only the engine's own 1", got)
	}
	e.Drain()

	// Round 0 runs out; the engine moves to round 1 and retains round 0's
	// sets. The remaining precommits then arrive LATE.
	e.enterRound(1)
	for _, idx := range []int{0, 2} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, idx, MsgPrecommit, h, 0, id))); err != nil {
			t.Fatal(err)
		}
	}
	got, ok := e.Committed()
	if !ok || got != id {
		t.Fatalf("a late precommit quorum for round 0 did not commit after the engine advanced: got %x,%v want %x", got[:8], ok, id[:8])
	}
	if e.commitRound != 0 {
		t.Fatalf("commitRound = %d, want the round the quorum was cast in (0)", e.commitRound)
	}
	if n := len(e.committedPrecommits()); n != 3 {
		t.Fatalf("the certificate source holds %d precommits, want the quorum's 3", n)
	}
}

// TestTwoBlocksCannotCommitAtOneHeight is the safety pin for C-3's
// commit-from-any-round. Two halves, one per direction of the argument:
//
//   - THE COMMITTED SLOT IS MONOTONE. After the late quorum commits block A,
//     a full, genuinely committee-signed precommit quorum for conflicting
//     block B at a later round cannot displace it: the engine commits once per
//     height, and the lock still names A.
//   - THE HONEST WEIGHT NEVER JOINS B. An honest engine locked on A at round 0
//     refuses to prevote a conflicting proposal at round 1 that carries no
//     valid polka, so it cannot precommit B and cannot be part of B's quorum.
//     (The lock rule itself is pinned by
//     TestLockedValidatorPrevotesOnlyItsBlockOrANewerRound and
//     TestLockRefusalPrevotesNil; this drives the same rule through the full
//     proposal path.)
//
// WHY THE ARGUMENT HOLDS: a commit is >2/3 of power precommitting one block at
// one round; more than 1/3 is honest, and every honest precommit follows a
// prevote for that same block and locks on it. A conflicting quorum needs
// honest validators that were locked on the first block to prevote the second,
// which the lock allows only on a VERIFIED polka from a strictly later round -
// and that polka would itself have needed the locked weight to unlock, which
// cannot happen at the first round a conflicting polka appears. Retaining the
// earlier round and reading it later does not change this: it changes when the
// same evidence is noticed, not what a quorum proves.
func TestTwoBlocksCannotCommitAtOneHeight(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, false, parent)
	e := newTestEngine(t, cfg, 1, h, parent)

	blkA := testProposer(t, cfg, h, 0, parent)
	idA := blkA.ID()
	deliverProposalAndPrevotes(t, e, cfg, h, blkA)
	e.Drain()
	e.enterRound(1)
	for _, idx := range []int{0, 2} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, idx, MsgPrecommit, h, 0, idA))); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := e.Committed(); !ok || got != idA {
		t.Fatal("fixture: the late round-0 quorum did not commit block A")
	}

	blkB := conflictingBlock(t, cfg, h, 1, parent, 0x0B)
	idB := blkB.ID()
	if idB == idA {
		t.Fatal("fixture: the two blocks must differ")
	}
	for _, idx := range []int{0, 2, 3} {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, idx, MsgPrecommit, h, 1, idB))); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := e.Committed(); !ok || got != idA {
		t.Fatalf("a conflicting quorum at a later round displaced the committed block: got %x,%v want %x", got[:8], ok, idA[:8])
	}
	if lockedID := e.lk.blockID(); lockedID != idA {
		t.Fatalf("the lock moved off the committed block to %x", lockedID[:8])
	}

	// The honest-weight half, on a fresh engine locked on A at round 0 and
	// moved to round 1: a conflicting proposal with no polka is prevoted NIL,
	// never precommitted.
	locked := lockedEngineAtRound1(t, cfg, 1, h, parent, idA)
	propB := &Proposal{Height: h, Round: 1, Block: blkB, ValidRound: -1, Validator: cfg.Proposer(h, 1, parent)}
	propB.Sig = signProposal(t, cfg, propB)
	if err := locked.OnMessage(EncodeProposal(propB)); err != nil {
		t.Fatal(err)
	}
	for _, o := range locked.Drain() {
		v, err := DecodeVote(o.Data)
		if err != nil || v.Type != MsgPrecommit {
			continue
		}
		if v.BlockID == idB {
			t.Fatal("the locked engine precommitted the conflicting block: the lock did not gate the conflicting quorum")
		}
	}
}

// --- 3. Persistence of (height, round) --------------------------------------

// TestRestartResumesAtThePersistedRound: the driver persists every round it
// enters through the chain's round log (store.PutRound, framed and fsynced
// like the lock log); a crash, a reopen and a rebuilt driver must resume at
// that round rather than re-entering round 0 for a height already contested.
// The engine is driven to round 5 by real timeout firings, so persistence runs
// through enterRound, the production path.
func TestRestartResumesAtThePersistedRound(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	g := genesis.Devnet()
	g.Validators = cfg.Committee
	g.Params.CommitteeSize = len(cfg.Committee)
	dir := t.TempDir()
	ch, err := chain.Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	d := mustDriver(t, cfg, ch, testCommitteeKey(1), &recordingTransport{Transport: silentInner{}}, nil)
	if d.eng.Round() != 0 {
		t.Fatal("fixture: a fresh engine starts at round 0")
	}

	now := int64(0)
	d.Tick(now) // arms round 0's deadline at TimeoutBase
	for d.eng.Round() < 5 {
		now += 1000
		d.Tick(now)
	}
	if got := d.eng.Round(); got != 5 {
		t.Fatalf("fixture: the engine reached round %d, want 5", got)
	}

	// Crash: the chain closes with the height still undecided.
	if err := ch.Close(); err != nil {
		t.Fatal(err)
	}
	ch2, err := chain.Open(g, dir)
	if err != nil {
		t.Fatalf("reopening the data directory: %v", err)
	}
	defer ch2.Close()
	if got, ok := ch2.RoundAt(ch2.Height() + 1); !ok || got != 5 {
		t.Fatalf("the reopened chain reports round %d,%v for the judged height, want the persisted 5", got, ok)
	}
	d2 := mustDriver(t, cfg, ch2, testCommitteeKey(1), &recordingTransport{Transport: silentInner{}}, nil)
	if got := d2.eng.Round(); got != 5 {
		t.Fatalf("a restarted driver resumed at round %d, want the persisted round 5", got)
	}
}
