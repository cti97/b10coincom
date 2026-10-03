package consensus

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// proposer returns a deterministic block for a height, signed by whoever the
// engine names as proposer. The engine under test never builds blocks itself: it
// is handed a proposer function, so this stays pure and testable.
func testProposer(t *testing.T, cfg Config, height uint64, round uint32, parent [32]byte) types.Block {
	t.Helper()
	pub := cfg.Proposer(height, round, parent)
	b := types.Block{Header: types.Header{
		Height:     height,
		ParentHash: parent,
		StateRoot:  crypto.HashParts([]byte("state"), []byte{byte(height)}),
		TxRoot:     types.ComputeTxRoot(nil),
		Timestamp:  int64(1_700_000_000 + height),
		Proposer:   pub,
	}}
	if err := b.ValidateStructure(); err != nil {
		t.Fatalf("test block is not structurally valid: %v", err)
	}
	return b
}

// conflictingBlock is a structurally valid block for (height, round) whose
// content differs from testProposer's by the salt byte, so its ID is a DIFFERENT
// block at the same height. The justification tests need two blocks competing at
// one height: block A that the validator locked on, and block B that a proposer
// offers afterwards.
func conflictingBlock(t *testing.T, cfg Config, height uint64, round uint32, parent [32]byte, salt byte) types.Block {
	t.Helper()
	pub := cfg.Proposer(height, round, parent)
	b := types.Block{Header: types.Header{
		Height:     height,
		ParentHash: parent,
		StateRoot:  crypto.HashParts([]byte("state"), []byte{byte(height), salt}),
		TxRoot:     types.ComputeTxRoot(nil),
		Timestamp:  int64(1_700_000_000 + height),
		Proposer:   pub,
	}}
	if err := b.ValidateStructure(); err != nil {
		t.Fatalf("test block is not structurally valid: %v", err)
	}
	return b
}

// newTestEngine builds an engine for committee index idx, starting at height 1
// with an all-zero parent and no lock.
func newTestEngine(t *testing.T, cfg Config, idx int, height uint64, parent [32]byte) *Engine {
	t.Helper()
	priv := testCommitteeKey(idx)
	e := NewEngine(cfg, height, parent, priv, func(h uint64, r uint32, p [32]byte) (types.Block, error) {
		return testProposer(t, cfg, h, r, p), nil
	})
	if e.Locked() {
		t.Fatal("a fresh engine must not be locked: the lock's zero value is round 0, which is a real round")
	}
	return e
}

func drainTypes(outs []Outbound) map[MsgType]int {
	m := map[MsgType]int{}
	for _, o := range outs {
		if v, err := DecodeVote(o.Data); err == nil {
			m[v.Type]++
		} else if p, err := DecodeProposal(o.Data); err == nil {
			_ = p
			m[MsgProposal]++
		}
	}
	return m
}

// round0ProposerHeight returns the first height >= 1 at which wantIdx's key is
// the round-0 proposer for parent. Every engine test anchors on a concrete
// (height, proposer) pair, and a fixture that silently landed on the wrong one
// would make onProposal drop the proposal as "not the proposer for this round",
// so the miss is asserted, not assumed.
func round0ProposerHeight(t *testing.T, cfg Config, wantIdx int, match bool, parent [32]byte) uint64 {
	t.Helper()
	for h := uint64(1); h < 100; h++ {
		is := string(cfg.Proposer(h, 0, parent)) == string(cfg.Committee[wantIdx].PubKey)
		if is == match {
			return h
		}
	}
	t.Fatalf("fixture: no height in 1..99 has validator %d proposer=%v at round 0", wantIdx, match)
	return 0 // unreachable
}

// deliverProposalAndPrevotes feeds e a signed proposal for blk plus quorum
// prevotes from committee indexes 0..2, i.e. the full round-0 polka.
func deliverProposalAndPrevotes(t *testing.T, e *Engine, cfg Config, h uint64, blk types.Block) {
	t.Helper()
	prop := &Proposal{
		Height: h, Round: 0, Block: blk, ValidRound: -1,
		Validator: cfg.Proposer(h, 0, e.parent),
	}
	prop.Sig = signProposal(t, cfg, prop)
	if err := e.OnMessage(EncodeProposal(prop)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrevote, h, 0, blk.ID()))); err != nil {
			t.Fatal(err)
		}
	}
}

// lockedEngineAtRound1 leaves e locked on id at round 0 and moved to round 1
// with an empty outbox, ready to judge that round's proposal. The lock must
// survive the round change: that is the premise the justification gate guards
// (Design Decision 11).
//
// enterRound is called directly rather than through OnTimeout because OnTimeout
// collapses "round entered" and "prevote timed out with no proposal" into one
// call, which would nil-prevote in the new round before any proposal of that
// round could arrive - a state the driver only produces after the round's
// propose phase, not at its start.
func lockedEngineAtRound1(t *testing.T, cfg Config, idx int, h uint64, parent, id [32]byte) *Engine {
	t.Helper()
	e := newTestEngine(t, cfg, idx, h, parent)
	blkA := testProposer(t, cfg, h, 0, parent)
	deliverProposalAndPrevotes(t, e, cfg, h, blkA)
	if id != blkA.ID() {
		t.Fatal("fixture: the lock id and the delivered block disagree")
	}
	if !e.Locked() || e.lk.blockID() != id || e.lk.round() != 0 {
		t.Fatalf("fixture: engine must be locked on %x at round 0, got locked=%v round=%d",
			id[:4], e.Locked(), e.lk.round())
	}
	if out := e.Drain(); len(out) == 0 {
		t.Fatal("fixture: locking should have produced output; the outbox must be drained here")
	}
	e.enterRound(1)
	if e.round != 1 || e.step != StepPropose || e.Locked() != true {
		t.Fatal("fixture: the round change lost the locked state or landed in the wrong step")
	}
	return e
}

// The happy path, for one validator: as proposer it proposes, then as a validator
// it prevotes its own proposal once it has seen it.
//
// Two small adaptations from the brief's text, both forced by the engine's own
// contract (recorded in task-6-report.md): the brief fired only OnTimeout and
// expected a proposal, but nothing in that call can produce one - the driver
// calls StartProposing - so the test calls StartProposing first, as the driver's
// Tick does. And StartProposing emits the proposal and the proposer's own
// prevote in the same batch, because a transport never loops a sender's message
// back; so the prevote is asserted in that batch, and the second Drain must be
// EMPTY - which is exactly the brief's "Drain clears the queue" property.
func TestProposerProposesAndPrevotesItsOwnBlock(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	// Find the height/round at which validator 0 is the proposer.
	idx := 0
	h := round0ProposerHeight(t, cfg, idx, true, parent)
	e := newTestEngine(t, cfg, idx, h, parent)

	if err := e.StartProposing(); err != nil {
		t.Fatal(err)
	}
	e.OnTimeout(TimeoutEvent{Height: h, Round: 0, Step: StepPropose})
	outs := e.Drain()

	var gotProposal bool
	for _, o := range outs {
		if p := tryProposal(o.Data); p != nil {
			gotProposal = true
		}
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && !v.IsNil() {
			// The proposer must have prevoted its own block, not nil: prevoting nil
			// would stall the very round it is trying to advance.
			if v.BlockID != e.proposal.ID() {
				t.Fatalf("the proposer prevoted %x, not its own block", v.BlockID[:4])
			}
		}
	}
	if !gotProposal {
		t.Fatal("the proposer produced no proposal")
	}
	if drainTypes(outs)[MsgPrevote] == 0 {
		t.Fatal("the proposer never prevoted for its own proposal")
	}
	if left := e.Drain(); len(left) != 0 {
		t.Fatalf("Drain must clear the queue so the driver owns delivery: %d message(s) left", len(left))
	}
}

// A non-proposer at round 0 must prevote NIL, not stall: without nil votes a round
// whose proposer is offline could never be left behind.
func TestNonProposerEmitsANilPrevoteWhenNoProposalArrives(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, false, parent)
	e := newTestEngine(t, cfg, 1, h, parent)

	e.OnTimeout(TimeoutEvent{Height: h, Round: 0, Step: StepPrevote})
	outs := e.Drain()

	found := false
	for _, o := range outs {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && v.IsNil() {
			found = true
		}
	}
	if !found {
		t.Fatal("a validator with no proposal must emit a nil prevote, or the round can never advance")
	}
}

// Two thirds of prevotes for a block must move the validator to precommit it, and
// that precommit must lock it.
func TestQuorumOfPrevotesLeadsToPrecommitAndLock(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, true, parent)
	e := newTestEngine(t, cfg, 1, h, parent)
	blk := testProposer(t, cfg, h, 0, parent)
	id := blk.ID()

	// Deliver the proposal and three prevotes (the quorum).
	deliverProposalAndPrevotes(t, e, cfg, h, blk)
	outs := e.Drain()
	if drainTypes(outs)[MsgPrecommit] == 0 {
		t.Fatal("a quorum of prevotes produced no precommit")
	}
	if !e.Locked() {
		t.Fatal("precommitting must lock the validator on the block")
	}
	if e.lk.blockID() != id {
		t.Fatal("the lock names the wrong block")
	}
}

// Two thirds of precommits for the same block at the same round must commit it.
func TestQuorumOfPrecommitsCommits(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 2, true, parent)
	e := newTestEngine(t, cfg, 2, h, parent)
	blk := testProposer(t, cfg, h, 0, parent)
	id := blk.ID()

	// Deliver the proposal and three prevotes (the quorum).
	deliverProposalAndPrevotes(t, e, cfg, h, blk)
	e.Drain() // the engine has now precommitted and locked; clear the outbox
	for i := 0; i < 3; i++ {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrecommit, h, 0, id))); err != nil {
			t.Fatal(err)
		}
	}
	got, ok := e.Committed()
	if !ok {
		t.Fatal("a quorum of precommits did not commit")
	}
	if got != id {
		t.Fatal("the committed block is not the one that reached quorum")
	}
}

// A majority for one block must not be mistaken for a majority for another, and a
// sub-quorum must not commit. This is the boundary the whole protocol rests on.
//
// Non-vacuousness is asserted, not assumed: the test checks the tally really is
// 2 of 4 (50%) and that the quorum bar really is 3, so the no-commit verdict
// fails for the reason it names rather than because the precommits were dropped.
func TestSubQuorumDoesNotCommit(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 3, true, parent)
	e := newTestEngine(t, cfg, 3, h, parent)
	blk := testProposer(t, cfg, h, 0, parent)
	id := blk.ID()

	// Deliver the proposal so the tally below is measured with the engine in the
	// state a real validator would be in.
	prop := &Proposal{
		Height: h, Round: 0, Block: blk, ValidRound: -1,
		Validator: cfg.Proposer(h, 0, parent),
	}
	prop.Sig = signProposal(t, cfg, prop)
	if err := e.OnMessage(EncodeProposal(prop)); err != nil {
		t.Fatal(err)
	}
	// Two of four is 50%: below the two-thirds bar. The behavioral verdict is
	// checked first, then the tally and the bar, so the no-commit result is
	// non-vacuous (the precommits really arrived and really total 2 of power
	// against a bar of 3).
	for i := 0; i < 2; i++ {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrecommit, h, 0, id))); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := e.Committed(); ok {
		t.Fatal("a 50% precommit tally committed a block; the bar is two thirds")
	}
	if got := e.precommits.PowerFor(id); got != 2 {
		t.Fatalf("the tally is %d precommit(s) of power, but the test names the 2-of-4 boundary", got)
	}
	if q := e.cfg.Quorum(); q != 3 {
		t.Fatalf("quorum is %d, but for four equal validators the two-thirds bar is 3", q)
	}
}

// A SIMPLE MAJORITY is still not the bar. Four validators cannot tell the two
// rules apart - 3 of 4 is both the simple majority and the two-thirds bar - so
// the only test that kills a "require a bare majority" mutant is a committee of
// five, where 3 of 5 is more than half yet below two thirds. This is the sixth
// test the plan's prose calls for (see task-6-report.md for the discrepancy).
func TestSimpleMajorityDoesNotCommit(t *testing.T) {
	cfg := evenCommittee(t, 5, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 2, true, parent)
	e := newTestEngine(t, cfg, 2, h, parent)
	blk := testProposer(t, cfg, h, 0, parent)
	id := blk.ID()

	deliverProposalAndPrevotes(t, e, cfg, h, blk)
	e.Drain() // the engine has now precommitted and locked; clear the outbox
	for i := 0; i < 3; i++ {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrecommit, h, 0, id))); err != nil {
			t.Fatal(err)
		}
	}
	// The behavioral verdict first, so a lowered bar is caught as a commit, not
	// merely as an unexpected threshold: 3 of 5 is a majority (3 > 2.5) but the
	// two-thirds bar for five equal validators is 4.
	if _, ok := e.Committed(); ok {
		t.Fatal("a 3-of-5 simple majority committed a block; the bar is two thirds")
	}
	// Non-vacuousness: the tally and the bar are asserted, so the no-commit
	// verdict above fails for the named reason.
	if got := e.precommits.PowerFor(id); got != 3 {
		t.Fatalf("the tally is %d, but the test names the 3-of-5 majority boundary", got)
	}
	if q := e.cfg.Quorum(); q != 4 {
		t.Fatalf("quorum is %d, but for five equal validators the two-thirds bar is 4", q)
	}
}

// Design Decision 11's counterexample, pinned at the engine level. A proposal
// whose claimed ValidRound outruns the validator's lock does NOT unlock it
// unless the carried prevotes reach quorum for the proposal's own block at that
// round. A proposer asserting evidence it does not have must not be prevoted at
// all - neither its block nor nil (nil is reserved for a justified proposal the
// LOCK refuses, the path TestLockRefusalPrevotesNil pins).
func TestUnjustifiedProposalIsNotPrevoted(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, true, parent)
	blkA := testProposer(t, cfg, h, 0, parent)
	lockedID := blkA.ID()
	e := lockedEngineAtRound1(t, cfg, 1, h, parent, lockedID)

	// A conflicting block at round 1 claiming a polka at round 1 with NO
	// justification carried: the claim is unverifiable, so the whole proposal is
	// unusable evidence and no vote may rest on it.
	blkB := conflictingBlock(t, cfg, h, 1, parent, 0xB7)
	p1 := cfg.Proposer(h, 1, parent)
	propB := &Proposal{Height: h, Round: 1, Block: blkB, ValidRound: 1, Validator: p1}
	propB.Sig = signProposal(t, cfg, propB)
	if err := e.OnMessage(EncodeProposal(propB)); err != nil {
		t.Fatal(err)
	}

	if left := e.Drain(); len(left) != 0 {
		t.Fatalf("an unjustified proposal must not be prevoted at all, got %d message(s)", len(left))
	}
	if e.Step() != StepPropose {
		t.Fatalf("an unjustified proposal must not move the step, got %s", e.Step())
	}
	if e.lk.blockID() != lockedID {
		t.Fatal("an unjustified proposal must not move the lock")
	}
}

// The positive half of the gate: the SAME validator that refused the unjustified
// proposal above prevotes a conflicting block the moment its justification
// checks out - three quorum prevotes for that block at the claimed round. Unlock
// on evidence is liveness; without this half the gate would be a permanent stop.
func TestJustifiedProposalUnlocksALockedValidator(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, true, parent)
	blkA := testProposer(t, cfg, h, 0, parent)
	lockedID := blkA.ID()
	e := lockedEngineAtRound1(t, cfg, 1, h, parent, lockedID)

	blkB := conflictingBlock(t, cfg, h, 1, parent, 0xB7)
	idB := blkB.ID()
	p1 := cfg.Proposer(h, 1, parent)
	propB := &Proposal{
		Height: h, Round: 1, Block: blkB, ValidRound: 1, Validator: p1,
		Justification: encodeJustification([]*Vote{
			voteFrom(t, cfg, 0, MsgPrevote, h, 1, idB),
			voteFrom(t, cfg, 1, MsgPrevote, h, 1, idB),
			voteFrom(t, cfg, 2, MsgPrevote, h, 1, idB),
		}),
	}
	propB.Sig = signProposal(t, cfg, propB)
	if err := e.OnMessage(EncodeProposal(propB)); err != nil {
		t.Fatal(err)
	}

	outs := e.Drain()
	if drainTypes(outs)[MsgPrevote] == 0 {
		t.Fatal("a justified proposal for a newer polka must unlock the validator and be prevoted")
	}
	for _, o := range outs {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && !v.IsNil() {
			if v.BlockID != idB {
				t.Fatalf("prevoted %x, not the justified block %x", v.BlockID[:4], idB[:4])
			}
		}
	}
	if e.Step() != StepPrevote {
		t.Fatalf("after prevoting a justified proposal the step is %s, want prevote", e.Step())
	}
}

// The nil-prevote half of the lock rule: when the engine HAS a proposal but the
// lock refuses it, it must prevote NIL. Returning silently would leave the
// validator's weight out of the nil tally, so the round could never end - the
// liveness bug the controller found in the Task 5 shape of this code.
//
// The scenario is the Byzantine proposer of Design Decision 11's counterexample:
// the validator is locked on A at round 0, and a proposer offers conflicting B at
// round 1 with a polka for B it says dates from round 0 (same round as the
// lock). The evidence is genuine, so the gate passes it - but valid round 0 does
// not exceed the lock's round 0, so the lock refuses, and the refusal must speak.
func TestLockRefusalPrevotesNil(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, true, parent)
	blkA := testProposer(t, cfg, h, 0, parent)
	lockedID := blkA.ID()
	e := lockedEngineAtRound1(t, cfg, 1, h, parent, lockedID)

	blkB := conflictingBlock(t, cfg, h, 1, parent, 0xB7)
	idB := blkB.ID()
	p1 := cfg.Proposer(h, 1, parent)
	propB := &Proposal{
		Height: h, Round: 1, Block: blkB, ValidRound: 0, Validator: p1,
		// A polka for B at round 0, verified but not newer than the lock.
		Justification: encodeJustification([]*Vote{
			voteFrom(t, cfg, 0, MsgPrevote, h, 0, idB),
			voteFrom(t, cfg, 1, MsgPrevote, h, 0, idB),
			voteFrom(t, cfg, 2, MsgPrevote, h, 0, idB),
		}),
	}
	propB.Sig = signProposal(t, cfg, propB)
	if err := e.OnMessage(EncodeProposal(propB)); err != nil {
		t.Fatal(err)
	}

	outs := e.Drain()
	if got := drainTypes(outs); got[MsgPrevote] != 1 {
		t.Fatalf("a lock-refused proposal must yield exactly one NIL prevote, got %v", got)
	}
	for _, o := range outs {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote {
			if !v.IsNil() {
				t.Fatalf("the lock refused this block, yet the engine prevoted %x", v.BlockID[:4])
			}
		}
	}
	if e.Step() != StepPrevote {
		t.Fatalf("after a nil prevote the step is %s, want prevote", e.Step())
	}
	if e.lk.blockID() != lockedID {
		t.Fatal("a nil prevote must not move the lock")
	}
}
