package consensus

import (
	"errors"
	"math"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
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
//
// Since round 3 (F3), NewEngine installs a refusing default validation seam -
// a driver-less engine never prevotes FOR an unjudged block. The consensus
// tests here model the consensus logic on a block whose chain validity is
// not under test (the chain's seam has its own tests, and the driver wiring
// is exercised by the driver and committee tests), so the fixture DELIBERATELY
// replaces the refusal with an accepting validator - a visible assignment,
// the exact act the F3 design requires, never an absence of wiring. Tests of
// the refusal itself build their engine directly with NewEngine and keep the
// default.
func newTestEngine(t *testing.T, cfg Config, idx int, height uint64, parent [32]byte) *Engine {
	t.Helper()
	priv := testCommitteeKey(idx)
	e := NewEngine(cfg, height, parent, priv, func(h uint64, r uint32, p [32]byte) (types.Block, error) {
		return testProposer(t, cfg, h, r, p), nil
	})
	e.SetValidate(func(*types.Block) error { return nil }) // accept: chain validity is not this file's subject
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
// enterRound is called directly because a timeout cannot express this fixture:
// OnTimeout ends the round the engine is IN, so its event must name the round
// being left and the vote it carries belongs to that round. A real driver
// reaches round 1 by letting round 0's timer run out; the fixture jumps
// straight there so the justification gate is isolated from the timeout logic.
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
// Two adaptations from the brief's text (recorded in task-6-report.md): the
// brief fired only OnTimeout and expected a proposal, but nothing in that call
// can produce one - the driver calls StartProposing - so the test calls
// StartProposing first, as the driver's Tick does. StartProposing emits the
// proposal and the proposer's own prevote in the same batch, because a transport
// never loops a sender's message back.
//
// The proposal's signature is not merely decoded - it is VERIFIED, and the
// emitted bytes are then round-tripped through a second engine's OnMessage, the
// real decode-check-proposer-verify path every peer runs. Decoding alone
// (tryProposal) cannot see a wrong signature: that blind spot is exactly how a
// proposal signed with the header hash instead of the envelope hash once passed
// this suite green while failing at every peer.
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
	outs := e.Drain()

	// The batch must contain exactly one proposal, and it must decode.
	var prop *Proposal
	for _, o := range outs {
		if p := tryProposal(o.Data); p != nil {
			if prop != nil {
				t.Fatal("the proposer emitted more than one proposal")
			}
			prop = p
		}
	}
	if prop == nil {
		t.Fatal("the proposer produced no proposal")
	}
	// The signature must verify against the envelope's own SigningHash() - the
	// hash Proposal.Verify checks on every peer. This is the assertion that
	// kills the header-hash-signature mutant.
	if err := prop.Verify(); err != nil {
		t.Fatalf("the emitted proposal does not carry a verifiable signature: %v", err)
	}
	propID := prop.Block.ID()

	if drainTypes(outs)[MsgPrevote] == 0 {
		t.Fatal("the proposer never prevoted for its own proposal")
	}
	for _, o := range outs {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && !v.IsNil() {
			// The proposer must have prevoted its own block, not nil: prevoting nil
			// would stall the very round it is trying to advance.
			if v.BlockID != propID {
				t.Fatalf("the proposer prevoted %x, not its own block", v.BlockID[:4])
			}
		}
	}
	if left := e.Drain(); len(left) != 0 {
		t.Fatalf("Drain must clear the queue so the driver owns delivery: %d message(s) left", len(left))
	}

	// Round trip: a SECOND engine fed the exact emitted bytes must accept the
	// proposal for this round and prevote the block it carries. onProposal runs
	// DecodeProposal, the proposer check and Verify before it accepts, so an
	// unverifiable proposal is dropped here and this test fails.
	peer := newTestEngine(t, cfg, 1, h, parent)
	for _, o := range outs {
		if err := peer.OnMessage(o.Data); err != nil {
			t.Fatalf("a peer rejected the proposer's emission: %v", err)
		}
	}
	if peer.proposal == nil || peer.proposal.ID() != propID {
		t.Fatal("the peer did not accept the emitted proposal as this round's proposal")
	}
	if peer.proposalEn == nil || peer.proposalEn.Sig == nil {
		t.Fatal("the peer accepted the block without keeping its signed envelope")
	}
	prevoted := false
	for _, o := range peer.Drain() {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && v.BlockID == propID {
			prevoted = true
		}
	}
	if !prevoted {
		t.Fatal("the peer accepted the proposal but did not prevote its block")
	}
}

// A validator's own vote must count toward its own tally. The engine tallies a
// vote when it arrives, and a real network never echoes a sender's own
// broadcast back, so before the self-tally fix (review finding F1) a validator's
// prevote existed only on the wire: its tally ceiling was n-1, not n. With four
// validators and one silent, the three live ones could then gather at most 2 of
// the quorum of 3 and no height ever committed - a committee tolerant of zero
// silent validators.
//
// The scenario below is exactly that boundary, at the engine level: the engine
// emits its own prevote, two peers join, and the third peer's prevote must
// complete a POLKA - possible only if the engine's own vote was tallied.
func TestOwnPrevoteCountsTowardTheTally(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 0, true, parent)
	e := newTestEngine(t, cfg, 0, h, parent)

	if err := e.StartProposing(); err != nil {
		t.Fatal(err)
	}
	var ownPrevote []byte
	for _, o := range e.Drain() {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && string(v.Validator) == string(e.pub) {
			ownPrevote = o.Data
		}
	}
	if ownPrevote == nil {
		t.Fatal("fixture: the proposer emitted no prevote of its own")
	}
	id := e.proposal.ID()
	if got := e.prevotes.PowerFor(id); got != 1 {
		t.Fatalf("the engine's own prevote is missing from its own tally: power %d, want 1 (the self-vote was never tallied)", got)
	}
	// A duplicate of our own vote arriving over the wire must be collapsed by
	// the duplicate rule, not double-counted: the self-delivery in emitVote
	// walks the same received-vote path, so the same one-vote-per-validator
	// rule faces it.
	if err := e.OnMessage(ownPrevote); err != nil {
		t.Fatal(err)
	}
	if got := e.prevotes.PowerFor(id); got != 1 {
		t.Fatalf("a duplicate of the engine's own prevote was counted again: power %d, want 1", got)
	}

	// One peer prevote: 2 of 4, below the bar of 3. No precommit may fire.
	if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, 1, MsgPrevote, h, 0, id))); err != nil {
		t.Fatal(err)
	}
	if e.Step() == StepPrecommit || e.Step() == StepCommit {
		t.Fatal("2 of 4 produced a precommit: the bar moved")
	}
	// The second peer reaches 3 of 4 - the quorum of 3 exists ONLY because the
	// engine's own prevote sits in the tally.
	if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, 2, MsgPrevote, h, 0, id))); err != nil {
		t.Fatal(err)
	}
	if !e.Locked() || e.lk.blockID() != id {
		t.Fatalf("3 of 4 prevotes did not lock the block: the engine's own vote is not counted (locked=%v)", e.Locked())
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

// The round must genuinely advance. Each timeout names the round the engine is
// IN - what the plan's driver Tick passes, and the only event OnTimeout acts
// on - and moves the engine 0 -> 1 -> 2 -> 3 over three firings. A validator
// that never receives a proposal ends each round with exactly one nil prevote
// FOR THE ROUND THAT ENDED, and enters the next round at StepPropose emitting
// nothing: the new round's proposal has not had a chance to arrive yet.
func TestThreeTimeoutsAdvanceTheRoundOneNilPrevoteEach(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	// Validator 1 at a height where it is NOT the round-0 proposer: no proposal
	// will ever arrive, which is precisely the stalled round the timeout exists
	// to rescue.
	h := round0ProposerHeight(t, cfg, 1, false, parent)
	e := newTestEngine(t, cfg, 1, h, parent)

	for ended := uint32(0); ended < 3; ended++ {
		if e.Round() != ended {
			t.Fatalf("fixture: the engine is at round %d, want %d", e.Round(), ended)
		}
		// The driver's shape: fire the timer for the round the engine is in.
		e.OnTimeout(TimeoutEvent{Height: e.Height(), Round: e.Round(), Step: e.Step()})
		outs := e.Drain()
		if len(outs) != 1 {
			t.Fatalf("round %d: the timeout must emit exactly the owed nil prevote, got %d message(s)",
				ended, len(outs))
		}
		v, err := DecodeVote(outs[0].Data)
		if err != nil || v.Type != MsgPrevote || !v.IsNil() {
			t.Fatalf("round %d: expected one nil prevote, got type %d, decode err %v", ended, outs[0].Data[0], err)
		}
		if v.Round != ended {
			t.Fatalf("the nil prevote is for round %d, want the round that ended (%d)", v.Round, ended)
		}
		if e.Round() != ended+1 {
			t.Fatalf("the timeout did not advance the round: at %d, want %d", e.Round(), ended+1)
		}
		if e.Step() != StepPropose {
			t.Fatalf("the next round must start at propose, waiting for its proposal, got %s", e.Step())
		}
	}
	// Three timeouts: round 0 -> 1 -> 2 -> 3.

	// A re-fire for a round already left, an event for a round not yet entered,
	// and an event for another height are all ignored: only the current round
	// can run out of time, and only the driver knows which one that is.
	for _, stale := range []TimeoutEvent{
		{Height: h, Round: 0, Step: StepPrevote},     // a round already left
		{Height: h, Round: 99, Step: StepPropose},    // a round never entered
		{Height: h + 1, Round: 3, Step: StepPropose}, // another height
	} {
		e.OnTimeout(stale)
		if e.Round() != 3 {
			t.Fatalf("event %+v moved the round to %d; only the current round's timer acts", stale, e.Round())
		}
		if left := e.Drain(); len(left) != 0 {
			t.Fatalf("event %+v emitted %d message(s); stale events must be silent", stale, len(left))
		}
	}
}

// A timeout that ends a round must not launder the lock. A validator locked on
// a block at round r that times out into round r+1 is STILL locked on that
// block at round r (the lock survives enterRound, which is where the timeout
// lands). And because it already cast its precommit, the timeout emits nothing.
func TestTimeoutIntoTheNextRoundKeepsTheLock(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, true, parent)
	blk := testProposer(t, cfg, h, 0, parent)
	id := blk.ID()
	e := newTestEngine(t, cfg, 1, h, parent)

	deliverProposalAndPrevotes(t, e, cfg, h, blk)
	if !e.Locked() || e.lk.blockID() != id {
		t.Fatal("fixture: the quorum prevotes should have precommitted and locked")
	}
	e.Drain() // clear the precommit the lock emitted

	e.OnTimeout(TimeoutEvent{Height: e.Height(), Round: e.Round(), Step: e.Step()})

	if e.Round() != 1 {
		t.Fatalf("the timeout did not advance the round, still at %d", e.Round())
	}
	if !e.Locked() || e.lk.blockID() != id || e.lk.round() != 0 {
		t.Fatalf("the timeout moved or dropped the lock: locked=%v id-match=%v round=%d",
			e.Locked(), e.lk.blockID() == id, e.lk.round())
	}
	if left := e.Drain(); len(left) != 0 {
		t.Fatalf("a validator that already cast its vote must emit nothing on the round timeout, got %d message(s)", len(left))
	}
	if e.Step() != StepPropose {
		t.Fatalf("the new round must wait for its proposal at propose, got %s", e.Step())
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

	// The three delivered prevotes sit BELOW the bar of 4 for five validators, so
	// the engine has neither precommitted nor locked: it is unlocked, at
	// StepPrevote, with an empty outbox (the Drain is the fixture's queue-clear
	// before the precommits below arrive).
	deliverProposalAndPrevotes(t, e, cfg, h, blk)
	e.Drain()
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

// The gate's defining property: the justification must prove a polka for the
// PROPOSAL'S OWN block at the claimed round - not merely SOME quorum among the
// carried prevotes. A proposer that attaches a real quorum for block C to a
// proposal of block B has furnished no unlock for B, and the proposal must not
// be prevoted (no vote may rest on evidence for a different block).
//
// This pins the HasQuorum(p.Block.ID()) check specifically: accepting
// "quorum for anything" instead would let exactly this proposal through, and
// the mutant formerly compiled past the entire shipped suite.
func TestJustificationMustProveQuorumForTheProposalsOwnBlock(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, true, parent)
	blkA := testProposer(t, cfg, h, 0, parent)
	lockedID := blkA.ID()
	e := lockedEngineAtRound1(t, cfg, 1, h, parent, lockedID)

	blkB := conflictingBlock(t, cfg, h, 1, parent, 0xB7)
	blkC := conflictingBlock(t, cfg, h, 1, parent, 0xC3) // a third block: C != B != A
	p1 := cfg.Proposer(h, 1, parent)
	propB := &Proposal{
		Height: h, Round: 1, Block: blkB, ValidRound: 1, Validator: p1,
		// A GENUINE quorum of prevotes - for block C. Every vote is correctly
		// signed, from a committee member, at the claimed round 1. Nothing here
		// is evidence for B, which is the point.
		Justification: encodeJustification([]*Vote{
			voteFrom(t, cfg, 0, MsgPrevote, h, 1, blkC.ID()),
			voteFrom(t, cfg, 1, MsgPrevote, h, 1, blkC.ID()),
			voteFrom(t, cfg, 2, MsgPrevote, h, 1, blkC.ID()),
		}),
	}
	propB.Sig = signProposal(t, cfg, propB)
	if err := e.OnMessage(EncodeProposal(propB)); err != nil {
		t.Fatal(err)
	}

	if left := e.Drain(); len(left) != 0 {
		t.Fatalf("an unlock grounded in another block's quorum must not prevote B, got %d message(s)", len(left))
	}
	if e.Step() != StepPropose {
		t.Fatalf("a proposal justified for a different block must not move the step, got %s", e.Step())
	}
	if e.lk.blockID() != lockedID {
		t.Fatal("a proposal justified for a different block must not move the lock")
	}

	// And the failure is really ErrBadJustification, not an accidentally
	// dropped message or a signature problem elsewhere in the envelope.
	if _, err := e.verifyJustification(propB); !errors.Is(err, ErrBadJustification) {
		t.Fatalf("a quorum for C is no evidence for B: want ErrBadJustification, got %v", err)
	}
}

// A ValidRound that does not fit the VoteSet's uint32 round must be REJECTED
// outright, never truncated: uint32(MaxUint32+1) is 0, so a silent truncation
// would tally the carried evidence for round 0 and grant an unlock at a round
// the proposal never claimed. The boundary is pinned from BOTH sides: the
// evidence below is genuine quorum prevotes, so anything other than the range
// guard would let the too-large claim through, while exactly MaxUint32 - where
// no truncation occurs - must still verify.
func TestValidRoundAboveUint32IsRejected(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, false, parent)
	e := newTestEngine(t, cfg, 1, h, parent)
	blk := testProposer(t, cfg, h, 0, parent)
	p0 := cfg.Proposer(h, 0, parent)

	// Genuine quorum prevotes for the proposal's own block at round 0. If the
	// too-large ValidRound were truncated to uint32, this evidence would tally
	// as a polka at round 0 and the proposal would be prevoted.
	just := encodeJustification([]*Vote{
		voteFrom(t, cfg, 0, MsgPrevote, h, 0, blk.ID()),
		voteFrom(t, cfg, 1, MsgPrevote, h, 0, blk.ID()),
		voteFrom(t, cfg, 2, MsgPrevote, h, 0, blk.ID()),
	})

	p := &Proposal{
		Height: h, Round: 0, Block: blk, ValidRound: int64(math.MaxUint32) + 1,
		Justification: just, Validator: p0,
	}
	p.Sig = signProposal(t, cfg, p)
	if _, err := e.verifyJustification(p); !errors.Is(err, ErrBadJustification) {
		t.Fatalf("ValidRound MaxUint32+1 must be rejected with ErrBadJustification, not truncated, got %v", err)
	}
	// And behaviorally: fed through the wire path, the justification check
	// refuses silently - the event is not an error, but no vote rests on it.
	if err := e.OnMessage(EncodeProposal(p)); err != nil {
		t.Fatalf("OnMessage returned %v; want silent refusal", err)
	}
	if left := e.Drain(); len(left) != 0 {
		t.Fatalf("a proposal whose ValidRound cannot fit a uint32 round must not be prevoted, got %d message(s)", len(left))
	}

	// The other side of the boundary: exactly MaxUint32 FITS, so with evidence
	// genuinely from that round the justification verifies.
	justAtMax := encodeJustification([]*Vote{
		voteFrom(t, cfg, 0, MsgPrevote, h, math.MaxUint32, blk.ID()),
		voteFrom(t, cfg, 1, MsgPrevote, h, math.MaxUint32, blk.ID()),
		voteFrom(t, cfg, 2, MsgPrevote, h, math.MaxUint32, blk.ID()),
	})
	pMax := &Proposal{
		Height: h, Round: 0, Block: blk, ValidRound: math.MaxUint32,
		Justification: justAtMax, Validator: p0,
	}
	pMax.Sig = signProposal(t, cfg, pMax)
	got, err := e.verifyJustification(pMax)
	if err != nil || got != math.MaxUint32 {
		t.Fatalf("a ValidRound of exactly MaxUint32 fits a uint32 and must verify, got round %d, err %v", got, err)
	}
}

// The validation seam is ENFORCED, not conventional (round-3 F3). After the
// C-2 fix removed the envelope-vs-header-proposer equality (necessarily: a
// locked re-proposal offers another validator's block), a block's header
// proposer key and signature are checked ONLY by the seam - so a driver-less
// engine built through the EXPORTED NewEngine used to prevote bytes nobody
// ever verified. The constructor now installs a default seam that refuses
// every block, and only a visible replacement (SetValidate, or the driver's
// direct wiring) can enable a FOR prevote - a prevotable engine cannot arise
// from forgetting to wire something.
func TestEngineWithoutAValidationSeamNeverPrevotesForABlockItDidNotJudge(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 0, true, parent)

	// The mechanism, asserted where it lives: the exported constructor's
	// default seam is installed (never nil) and refuses with its named error.
	// Checked AFTER the behavioural verdicts below, so a mutant removing the
	// installation fails on the behaviour the finding is about, not only on
	// the fixture check.
	p0 := NewEngine(cfg, h, parent, testCommitteeKey(0), func(hh uint64, rr uint32, pp [32]byte) (types.Block, error) {
		return testProposer(t, cfg, hh, rr, pp), nil
	})

	// Proposer side: the seam-less engine IS this round's proposer. It still
	// proposes (refusing to propose is not the fix - rounds must stay
	// leavable) but must NIL-prevote its own emission: the block was never
	// judged, and FOR would stake a vote on bytes nobody authenticated.
	if err := p0.StartProposing(); err != nil {
		t.Fatal(err)
	}
	sawProposal, sawFor, sawNil := false, false, false
	for _, o := range p0.Drain() {
		if p := tryProposal(o.Data); p != nil {
			sawProposal = true
		}
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote {
			if v.IsNil() {
				sawNil = true
			} else {
				sawFor = true
			}
		}
	}
	if !sawProposal {
		t.Fatal("fixture: the proposer emitted no proposal; the fixture must exercise the prevote")
	}
	if sawFor {
		t.Fatal("a driver-less engine PREVOTED FOR its own proposal: the header proposer's key and signature were never checked by anyone - the driver-less prevote hole F3 closes")
	}
	if !sawNil {
		t.Fatal("the seam-less engine was silent instead of nil-prevoting: a validator that casts nothing leaves its weight out of the nil tally and stalls the round")
	}

	// Follower side: a perfectly signed, well-formed proposal from the real
	// round proposer arrives at a seam-less engine. Same verdict: the refusal
	// is about the missing judge, not the bytes, so the verdict is nil - once.
	p1 := NewEngine(cfg, h, parent, testCommitteeKey(1), func(hh uint64, rr uint32, pp [32]byte) (types.Block, error) {
		return testProposer(t, cfg, hh, rr, pp), nil
	})
	blk := testProposer(t, cfg, h, 0, parent)
	p := &Proposal{Height: h, Round: 0, Block: blk, ValidRound: -1, Validator: cfg.Proposer(h, 0, parent)}
	p.Sig = signProposal(t, cfg, p)
	if err := p1.OnMessage(EncodeProposal(p)); err != nil {
		t.Fatalf("the seam-less engine must still accept the signed proposal as round data, got %v", err)
	}
	outs := p1.Drain()
	if len(outs) != 1 {
		t.Fatalf("the seam-less follower emitted %d message(s) for one unusable proposal, want exactly the nil prevote", len(outs))
	}
	v, err := DecodeVote(outs[0].Data)
	if err != nil || v.Type != MsgPrevote || !v.IsNil() {
		t.Fatal("the seam-less follower's only emission was not a nil prevote: either it prevoted FOR unjudged bytes or it emitted nothing at all")
	}
	if p1.Locked() {
		t.Fatal("the seam-less engine locked a block its refusal itself named unusable")
	}

	// The mechanism, now that the behaviour is pinned: the exported
	// constructor's default seam is installed (never nil) and refuses with
	// its named error - the detail that makes the refusal hold for every
	// exported construction, not just this fixture's two engines.
	if p0.validate == nil {
		t.Fatal("NewEngine must install a default validation seam; a nil field is the bypass this fix closed")
	}
	if err := p0.validate(nil); !errors.Is(err, errNoValidationSeam) {
		t.Fatalf("NewEngine's default seam returned %v, want the named refusal errNoValidationSeam", err)
	}

	// And the nil-proof wiring: SetValidate(nil) - the assignment that would
	// restore the hole through the exported API - cannot be made at all.
	defer func() {
		if recover() == nil {
			t.Fatal("SetValidate(nil) did not panic: the exported API can silently disable the validation seam again")
		}
	}()
	p1.SetValidate(nil)
}

// A future-round vote is membership-checked BEFORE any signature verification
// (round-3 F2, the audit's C-8 discipline): IndexOf is a linear scan the
// engine pays anyway, an Ed25519 verification is not, and the old order let
// any peer force one verification per frame with a self-signed future-round
// vote. The instrument is crypto.VerifyHook - an observation point that
// counts exactly the Ed25519 evaluations; production never sets it.
func TestAFutureRoundVoteFromANonMemberCostsNoSignatureVerification(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	someID := crypto.HashParts([]byte("some-later-block"))
	h := round0ProposerHeight(t, cfg, 0, false, parent)
	e := newTestEngine(t, cfg, 0, h, parent)

	strangerPub, strangerPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	verifications := 0
	crypto.VerifyHook = func() { verifications++ }
	defer func() { crypto.VerifyHook = nil }()

	// Eight self-signed future-round votes from a key NOT in the committee:
	// per frame, the old order paid one Ed25519 verification (each vote's
	// signature is genuinely valid - the peer is just not a member), the new
	// order pays none. Rounds 1..4 are also inside the C-3 future buffer, so
	// they reach the round's VoteSet and are refused there as ErrNotValidator;
	// rounds 5..8 fall outside it and are refused by the out-of-window path's
	// own membership check. Either way the frame is REFUSED - the error is the
	// engine saying so, not a fatal condition - and neither verification nor
	// evidence may move.
	for r := uint32(1); r <= 8; r++ {
		v := &Vote{Type: MsgPrevote, Height: h, Round: r, BlockID: someID, Validator: strangerPub}
		hash := v.SigningHash()
		v.Sig = crypto.Sign(strangerPriv, hash[:])
		if err := e.OnMessage(EncodeVote(v)); err != nil && !errors.Is(err, ErrNotValidator) {
			t.Fatal(err)
		}
	}
	if verifications != 0 {
		t.Fatalf("%d non-member frame(s) each forced an Ed25519 verification before the membership check: the free check must run first (want 0 verifications)", verifications)
	}
	if len(e.future) != 0 {
		t.Fatalf("non-member future-round votes left %d recorded entr(y/ies): a stranger's vote must also be refused for recording", len(e.future))
	}

	// Non-vacuity control 1: the branch DOES verify a member's vote - exactly
	// one verification for the member's valid future vote, which is then
	// recorded. A hook that never fires cannot pass this test, and the
	// reorder cannot have silenced the evidence path.
	if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, 1, MsgPrevote, h, 5, someID))); err != nil {
		t.Fatal(err)
	}
	if verifications != 1 {
		t.Fatalf("a member's valid future-round vote reached %d verification(s), want exactly 1: the reorder must keep authentication", verifications)
	}
	if p := e.future[1]; p == nil || p.Round != 5 {
		t.Fatal("the member's valid future-round vote was not recorded: the branch under test never ran")
	}

	// Non-vacuity control 2: membership first does not mean trust members -
	// a member's vote with a corrupted signature is verified (the free pass
	// would be the next hole) and recorded nowhere.
	bad := voteFrom(t, cfg, 2, MsgPrevote, h, 7, someID)
	bad.Sig[0] ^= 0xff
	if err := e.OnMessage(EncodeVote(bad)); err != nil {
		t.Fatal(err)
	}
	if verifications != 2 {
		t.Fatalf("a member's corrupted future-round vote reached %d verification(s), want 2: membership first must not skip the member's own verification", verifications)
	}
	if _, seen := e.future[2]; seen {
		t.Fatal("a member's badly signed future-round vote was recorded: the reorder dropped the signature gate")
	}
}

// sealedChainFixture opens a REAL chain under cfg's committee so an engine can
// carry the driver's validation seam: the seam's judgement is the chain's own
// ValidateNext - the same policy Append runs - against a chain whose head the
// engine actually judges. The returned parent is the engine's parent (the
// chain's genesis head) and the height is head+1.
func sealedChainFixture(t *testing.T, cfg Config) (*chain.Chain, uint64, [32]byte) {
	t.Helper()
	g := genesis.Devnet()
	g.Validators = cfg.Committee
	g.Params.CommitteeSize = len(cfg.Committee)
	ch, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	parent := ch.Head().ID()
	return ch, ch.Head().Header.Height + 1, parent
}

// attackProposalForStateRoot builds the audit C-1 attack at (height, round):
// an envelope whose every authenticity check is honest - the real round
// proposer's key signed it, the header height matches the envelope, the
// parent matches the engine's - carrying a block whose StateRoot is garbage.
// The proposer in the attack "builds a normal block, overwrites Header.
// StateRoot with garbage, re-signs": the re-sign means the ENVELOPE'S
// signature is a perfectly valid one. What cannot be honest is the root.
func attackProposalForStateRoot(t *testing.T, cfg Config, height uint64, round uint32, parent [32]byte) (*Proposal, [32]byte) {
	t.Helper()
	pPub := cfg.Proposer(height, round, parent)
	b := types.Block{Header: types.Header{
		Height:     height,
		ParentHash: parent,
		StateRoot:  [32]byte{0xde, 0xad, 0xbe, 0xef},
		TxRoot:     types.ComputeTxRoot(nil),
		Timestamp:  int64(1_700_000_000 + height),
		Proposer:   pPub,
	}}
	if err := b.ValidateStructure(); err != nil {
		t.Fatalf("fixture: the attack block must be structurally valid: %v", err)
	}
	p := &Proposal{Height: height, Round: round, Block: b, ValidRound: -1, Validator: pPub}
	p.Sig = signProposal(t, cfg, p)
	return p, b.ID()
}

// The audit C-1 attack, at the engine level: a fresh validator receives a
// correctly signed proposal from the round's proposer whose block claims a
// garbage state root. Before the seam existed, this proposal was prevoted,
// the polka formed, the lock was taken - and the chain then refused the
// block, parking the node forever. Now the seam judges the block BEFORE any
// vote: the engine prevotes NIL and never locks.
//
// Non-vacuity is structural: maybePrevote only runs when the engine ACCEPTED
// the proposal (stored it), so the emitted nil prevote itself proves the
// attack travelled past the envelope and proposer checks. The refusal is
// therefore attributable to the block content alone.
func TestGarbageStateRootProposalIsNilPrevotedAndNeverLocked(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	ch, height, parent := sealedChainFixture(t, cfg)
	e := newTestEngine(t, cfg, 1, height, parent)
	e.SetValidate(ch.ValidateNext)

	attack, attackID := attackProposalForStateRoot(t, cfg, height, 0, parent)
	if err := e.OnMessage(EncodeProposal(attack)); err != nil {
		t.Fatalf("the attack proposal must pass the envelope checks as protocol data, got %v", err)
	}

	// The refusal must SPEAK: exactly one nil prevote, so the round can end
	// and the committee can move to a later round's honest proposal.
	outs := e.Drain()
	if got := drainTypes(outs); got[MsgPrevote] != 1 {
		t.Fatalf("the garbage-root proposal produced %v prevote emission(s); want exactly one (the nil prevote)", got)
	}
	for _, o := range outs {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote {
			if !v.IsNil() {
				t.Fatalf("the engine prevoted %x for a block whose state root it cannot accept; want nil", v.BlockID[:8])
			}
			if v.Height != height || v.Round != 0 {
				t.Fatalf("the refusal prevote sits at (h=%d, r=%d), want (h=%d, r=0)", v.Height, v.Round, height)
			}
		}
	}
	// And the lock must never have been taken on the garbage block - the
	// persisted promise the old behaviour wrote was what made every restart
	// re-pin the halt.
	if e.Locked() {
		locked := e.lk.blockID()
		if locked == attackID {
			t.Fatalf("the engine locked on %x: a garbage-root proposal must not reach a lock", locked[:8])
		}
		t.Fatalf("the engine locked (on %x) without a usable evidence path", locked[:8])
	}
}

// The positive control over the C-1 seam, from the SAME fixture shape: a
// legitimately valid proposal - block built by the round's proposer through
// the chain's own Build, real state root included - MUST still be prevoted.
// This kills the failure mode where the fix refuses everything: a seam that
// rejects a block Chain.Build signed would show nothing here but a stalled
// committee.
func TestAValidBlockIsStillPrevotedThroughTheSeam(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	ch, height, parent := sealedChainFixture(t, cfg)
	e := newTestEngine(t, cfg, 1, height, parent)
	e.SetValidate(ch.ValidateNext)

	pPub := cfg.Proposer(height, 0, parent)
	b, err := ch.Build(testCommitteeKey(cfg.IndexOf(pPub)), nil, ch.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatalf("fixture: chain.Build must produce the valid proposal block: %v", err)
	}
	p := &Proposal{Height: height, Round: 0, Block: *b, ValidRound: -1, Validator: pPub}
	p.Sig = signProposal(t, cfg, p)
	if err := e.OnMessage(EncodeProposal(p)); err != nil {
		t.Fatal(err)
	}

	outs := e.Drain()
	prevoted := false
	for _, o := range outs {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && v.BlockID == b.ID() {
			prevoted = true
		}
	}
	if !prevoted {
		t.Fatal("a valid proposal was not prevoted through the seam: the engine must not refuse blocks its own chain policy accepts")
	}
	if e.Locked() {
		// Only the engine's own prevote is tallied so far (1 of the quorum
		// of 3): the lock must NOT have formed. This pins that the control
		// case ends in the same mid-round state the attack case refused
		// from, and that prevoting did not itself take a lock.
		locked := e.lk.blockID()
		t.Fatalf("the control engine locked without a polka (on %x): the fixture drifted from one self prevote", locked[:8])
	}
}

// The envelope/header height disagreement is a PROTOCOL ERROR refused at the
// proposal's face (audit C-1): the block a polka would carry must be the
// block at the height being decided. The proposal is not stored, nothing is
// prevoted, and no lock forms.
func TestProposalHeaderHeightMismatchIsAProtocolError(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	h := round0ProposerHeight(t, cfg, 1, true, parent)
	e := newTestEngine(t, cfg, 1, h, parent)

	blk := testProposer(t, cfg, h, 0, parent)
	// The block claims the NEXT height while the envelope names the round's
	// own: exactly the shape a commit-would-fail-forever proposal has if it
	// were allowed past the face checks.
	blk.Header.Height = h + 1
	p := &Proposal{Height: h, Round: 0, Block: blk, ValidRound: -1, Validator: cfg.Proposer(h, 0, parent)}
	p.Sig = signProposal(t, cfg, p)

	err := e.OnMessage(EncodeProposal(p))
	if !errors.Is(err, ErrBadProposalHeight) {
		t.Fatalf("a header-height mismatch must be refused as a protocol error, got %v", err)
	}
	if e.proposal != nil {
		t.Fatal("the mismatched proposal was stored as this round's proposal")
	}
	if left := e.Drain(); len(left) != 0 {
		t.Fatalf("a refused proposal must not be prevoted, got %d message(s)", len(left))
	}
	if e.lk.locked() {
		locked := e.lk.blockID()
		zero := [32]byte{}
		if locked != zero {
			t.Fatal("the lock moved without any evidence")
		}
	}
}

// roundProposerHeight returns the first height in 1..99 at which wantIdx's key
// is the proposer at the given ROUND (round0ProposerHeight is the round-0
// special case).
func roundProposerHeight(t *testing.T, cfg Config, wantIdx int, round uint32, parent [32]byte) uint64 {
	t.Helper()
	for h := uint64(1); h < 100; h++ {
		if string(cfg.Proposer(h, round, parent)) == string(cfg.Committee[wantIdx].PubKey) {
			return h
		}
	}
	t.Fatalf("fixture: no height in 1..99 has validator %d proposer at round %d", wantIdx, round)
	return 0 // unreachable
}

// engineLockedAtRoundN is a proposal-receiving engine (idx idx, NOT the round-0
// proposer at the returned height) locked on blkA.ID() in round 0 - via a
// proposal it received and a quorum of prevotes it tallied - and then parked in
// the round the proposer will be drawn for. The propose function is caller
// supplied so the locked-proposing tests can record whether a fresh block was
// ever built at all.
func engineLockedAtRound0(t *testing.T, cfg Config, idx int, height uint64, parent [32]byte, blkA types.Block, propose ProposeFn) *Engine {
	t.Helper()
	e := NewEngine(cfg, height, parent, testCommitteeKey(idx), propose)
	// The polka below is the fixture's premise, so chain validity is granted
	// explicitly (round 3, F3): NewEngine's default seam refuses every block,
	// and an engine leaving that refusal in place can never be locked by it.
	e.SetValidate(func(*types.Block) error { return nil })
	if e.Locked() {
		t.Fatal("fixture: a fresh engine must not be locked")
	}
	p := &Proposal{Height: height, Round: 0, Block: blkA, ValidRound: -1, Validator: cfg.Proposer(height, 0, parent)}
	p.Sig = signProposal(t, cfg, p)
	if err := e.OnMessage(EncodeProposal(p)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(cfg.Committee) && cfg.Quorum() > uint64(i); i++ {
		if i == idx {
			continue // the engine's own prevote already sits in its tally
		}
		if uint64(i) >= cfg.Quorum() && !e.Locked() {
			break
		}
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrevote, height, 0, blkA.ID()))); err != nil {
			t.Fatal(err)
		}
		if e.Locked() {
			break
		}
	}
	if !e.Locked() || e.lk.round() != 0 || e.lk.blockID() != blkA.ID() {
		t.Fatalf("fixture: the engine must be locked on the polka'd block at round 0 (locked=%v round=%d)",
			e.Locked(), e.lk.round())
	}
	if out := e.Drain(); len(out) == 0 {
		t.Fatal("fixture: locking should have produced output; the outbox must be drained here")
	}
	if e.lockedBlock == nil || e.lockedBlock.ID() != blkA.ID() {
		t.Fatal("fixture: the lock must retain the locked block's bytes for the re-proposal")
	}
	return e
}

// A validator locked on block B and later drawn as proposer must propose B -
// with the polka that locked it as the justification - and must NOT build a
// fresh block (audit C-2). A fresh block would be nil-prevoted by the proposer
// itself, which is exactly why the pre-fix rounds never ended once a third of
// power had locked.
func TestLockedProposerReProposesItsLockedBlock(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	idx := 1
	h := roundProposerHeight(t, cfg, idx, 1, parent)
	blkA := testProposer(t, cfg, h, 0, parent)

	built := false
	propose := func(hh uint64, r uint32, p [32]byte) (types.Block, error) {
		built = true
		return testProposer(t, cfg, hh, r, p), nil
	}
	e := engineLockedAtRound0(t, cfg, idx, h, parent, blkA, propose)
	e.enterRound(1)

	if err := e.StartProposing(); err != nil {
		t.Fatalf("the locked proposer must re-propose, got error: %v", err)
	}
	if built {
		t.Fatal("the locked proposer built a FRESH block: it must re-propose its locked one")
	}

	// Exactly one proposal was emitted (plus the proposer's own prevote of
	// it): scan ONE drained batch - Drain clears, so a second drain here
	// would find nothing that the first one already took.
	var prop *Proposal
	prevoted := false
	for _, o := range e.Drain() {
		if p := tryProposal(o.Data); p != nil {
			if prop != nil {
				t.Fatal("more than one proposal was emitted")
			}
			prop = p
		}
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && !v.IsNil() && v.BlockID == blkA.ID() {
			prevoted = true
		}
	}
	if prop == nil {
		t.Fatal("no proposal was emitted")
	}
	proposedID := prop.Block.ID()
	lockedID := blkA.ID()
	if proposedID != lockedID {
		t.Fatalf("the proposer proposed %x; it is locked on %x and must propose that", proposedID[:8], lockedID[:8])
	}
	if prop.ValidRound != 0 {
		t.Fatalf("the re-proposal claims ValidRound %d; the locked polka was formed at round 0", prop.ValidRound)
	}
	// The carried justification must be the polka itself: a quorum of real
	// prevotes for the locked block at the claimed round, re-tallied through
	// the same gate a peer runs.
	if len(prop.Justification) == 0 {
		t.Fatal("the re-proposal carries no justification - no proof-of-lock")
	}
	vs := NewVoteSet(cfg, h, uint32(prop.ValidRound), MsgPrevote)
	for _, raw := range decodeVotes(prop.Justification) {
		v, err := DecodeVote(raw)
		if err != nil {
			t.Fatalf("the carried justification holds an undecodable vote: %v", err)
		}
		if _, err := vs.Add(v); err != nil {
			t.Fatalf("the carried justification holds a vote that fails verification: %v", err)
		}
	}
	if !vs.HasQuorum(blkA.ID()) {
		t.Fatal("the carried justification does not reach quorum for the locked block")
	}

	// The proposer must also prevote its own re-proposal - nil-prevoting its
	// own proposal was the other half of the C-2 defect.
	if !prevoted {
		t.Fatal("the proposer did not prevote its own re-proposal")
	}

	// And the proof must WORK on a peer: a validator that never saw this
	// proposal before - unlocked, holding nothing - prevotes the locked block
	// on the carried evidence alone. This is the justification doing its job:
	// what the proposer asserts, an honest peer can check.
	// A peer judges the re-proposal in the round it names: like every honest
	// validator it has moved through the timeout into round 1 (the round the
	// re-proposal is proposed in), so the round-match onProposal requires
	// holds.
	peer := newTestEngine(t, cfg, 2, h, parent)
	peer.enterRound(1)
	if err := peer.OnMessage(EncodeProposal(prop)); err != nil {
		t.Fatal(err)
	}
	peerPrevoted := false
	for _, o := range peer.Drain() {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && v.BlockID == blkA.ID() {
			peerPrevoted = true
		}
	}
	if !peerPrevoted {
		t.Fatal("a peer refused the justified re-proposal: the proof-of-lock does not unlock or convince")
	}
	if peer.Locked() {
		t.Fatal("the peer's PREVOTE must not take a lock on its own")
	}
}

// The inverse half of the locked-proposer rule: a locked proposer holding NO
// bytes for its locked ID - the lock restored from the store as an ID alone,
// or taken over prevotes whose proposal never arrived - has nothing to
// re-propose. It falls through to the fresh build, and its own lock then
// judges the result: it must nil-prevote its own fresh proposal (a differing
// block is refused), and the fresh build must go out through the propose seam.
// What it must never do is prevote a block its lock does not name.
func TestLockedProposerWithoutBytesFallsThroughToARefusedFreshBuild(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	idx := 1
	h := round0ProposerHeight(t, cfg, idx, true, parent)

	built := false
	propose := func(hh uint64, r uint32, p [32]byte) (types.Block, error) {
		built = true
		return conflictingBlock(t, cfg, hh, r, p, 0x5E), nil
	}
	e := NewEngine(cfg, h, parent, testCommitteeKey(idx), propose)
	// The restart shape: the promise comes back from the store as (round, ID)
	// alone - no block bytes, no votes.
	e.restoreLock(0, crypto.HashParts([]byte("locked-block-id")))
	if !e.Locked() || e.lockedBlock != nil || len(e.lockedVotes) != 0 {
		t.Fatalf("fixture: the restored lock must exist and carry no bytes")
	}

	if err := e.StartProposing(); err != nil {
		t.Fatalf("a byte-less locked proposer falls through to its fresh build, got error: %v", err)
	}
	if !built {
		t.Fatal("the fresh build never ran through the propose seam")
	}
	// Exactly one proposal; and its own prevote of it MUST BE NIL - the lock
	// refuses a block it does not name, and the proposer is as bound by that
	// as any peer.
	var prop *Proposal
	selfPrevoteNil := false
	for _, o := range e.Drain() {
		if p := tryProposal(o.Data); p != nil {
			if prop != nil {
				t.Fatal("more than one proposal was emitted")
			}
			prop = p
		}
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote {
			if v.IsNil() {
				selfPrevoteNil = true
			} else {
				vID := v.BlockID
				t.Fatalf("the byte-less locked proposer PREVOTED its own fresh block %x: its lock must refuse it", vID[:8])
			}
		}
	}
	if prop == nil {
		t.Fatal("no proposal was emitted")
	}
	if prop.Block.ID() == crypto.HashParts([]byte("locked-block-id")) {
		t.Fatal("the emitted proposal is the locked block: the fixture must hold no bytes for it")
	}
	if !selfPrevoteNil {
		t.Fatal("the proposer did not nil-prevote its own fresh proposal through the lock rule")
	}
	if e.proposalEn == nil || e.proposalEn.ValidRound != -1 {
		t.Fatalf("the fallback fresh proposal must claim no polka, got vr %d", func() int64 {
			if e.proposalEn != nil {
				return e.proposalEn.ValidRound
			}
			return -999
		}())
	}
}
