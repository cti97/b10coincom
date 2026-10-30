package consensus

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

// A PROPOSAL THAT ARRIVES ONE ROUND EARLY.
//
// The 3-seat stall of the M5 network re-run (2026-10-30), captured twice in
// Docker with a debug build: a validator stopped inside the lock window comes
// back, joins every round by a timeout jump, and therefore enters each round
// AFTER the survivors. A round's proposal is broadcast once, the moment its
// proposer enters the round, so it always reached the restarted validator
// while that validator was still in the previous round - and onProposal
// dropped every proposal not for the current round (the capture counted
// foreignprop=20). The survivors were locked on a block whose re-proposal the
// victim never saw; the victim's own fresh proposals were refused by their
// lock; with a three-seat committee no round could gather three prevotes, and
// the chain stood still for minutes until the victim was restarted again.
//
// A proposal for a round inside the retention window ahead is now verified on
// arrival and kept with that round's tallies, and adopted the moment the
// engine enters the round - exactly as a future round's VOTES already are.

// futureProposalHeight finds a height at which validator idx is NOT the
// proposer of round, so a proposal for that round comes from someone else.
func futureProposalHeight(t *testing.T, cfg Config, idx int, round uint32, parent [32]byte) uint64 {
	t.Helper()
	for h := uint64(1); h < 100; h++ {
		if string(cfg.Proposer(h, round, parent)) != string(cfg.Committee[idx].PubKey) {
			return h
		}
	}
	t.Fatalf("fixture: validator %d proposes round %d at every height in 1..99", idx, round)
	return 0
}

// prevoteAt returns the prevote the outbox carries for round, or nil.
func prevoteAt(t *testing.T, outs []Outbound, round uint32) *Vote {
	t.Helper()
	for _, o := range outs {
		if v, err := DecodeVote(o.Data); err == nil && v.Type == MsgPrevote && v.Round == round {
			return v
		}
	}
	return nil
}

// TestAProposalForTheNextRoundIsPrevotedOnEntry: the proposal for round 1
// reaches an engine still in round 0. It casts nothing for it there, and
// prevotes it the moment its own timeout carries it into round 1.
func TestAProposalForTheNextRoundIsPrevotedOnEntry(t *testing.T) {
	cfg := wholeCommittee(t, 3)
	parent := crypto.HashParts([]byte("parent"))
	const idx = 2
	h := futureProposalHeight(t, cfg, idx, 1, parent)
	e := newTestEngine(t, cfg, idx, h, parent)

	blk := testProposer(t, cfg, h, 1, parent)
	p := &Proposal{Height: h, Round: 1, Block: blk, ValidRound: -1, Validator: cfg.Proposer(h, 1, parent)}
	p.Sig = signProposal(t, cfg, p)
	if err := e.OnMessage(EncodeProposal(p)); err != nil {
		t.Fatalf("a valid proposal for the next round was refused: %v", err)
	}
	if v := prevoteAt(t, e.Drain(), 1); v != nil {
		t.Fatal("the engine prevoted round 1 while still in round 0")
	}
	if got := e.diagCounters(); got.EarlyProposals != 1 || got.ForeignProposals != 0 {
		t.Fatalf("the early proposal was counted early=%d foreign=%d, want 1 and 0", got.EarlyProposals, got.ForeignProposals)
	}
	if e.Round() != 0 || e.proposal != nil {
		t.Fatalf("an early proposal moved the engine (round %d, proposal held %v)", e.Round(), e.proposal != nil)
	}

	if err := e.OnTimeout(TimeoutEvent{Height: h, Round: 0}); err != nil {
		t.Fatal(err)
	}
	v := prevoteAt(t, e.Drain(), 1)
	if v == nil {
		t.Fatal("on entering round 1 the engine did not prevote the round-1 proposal it had already received: a validator one step behind never votes for any proposal")
	}
	if v.BlockID != blk.ID() {
		t.Fatalf("the round-1 prevote is for %x, want the early proposal's block %x", v.BlockID[:4], blk.ID())
	}
}

// TestARestartedValidatorPrevotesTheSurvivorsJustifiedReProposalOnEntry is the
// Docker capture itself (the killed-victim variant): the victim's lock was
// restored from the store as an ID alone - no block bytes, no polka - and it
// sits in round 5 when the survivors' re-proposal of the locked block, carrying
// the round-0 polka as its justification, arrives for round 6. On entering
// round 6 it must prevote that block: before the fix it dropped the proposal
// and could only nil-prevote, so the three-seat committee never decided.
func TestARestartedValidatorPrevotesTheSurvivorsJustifiedReProposalOnEntry(t *testing.T) {
	cfg := wholeCommittee(t, 3)
	parent := crypto.HashParts([]byte("parent"))
	const victim, behind, ahead = 1, uint32(5), uint32(6)
	h := futureProposalHeight(t, cfg, victim, ahead, parent)

	blkA := testProposer(t, cfg, h, 0, parent)
	idA := blkA.ID()
	e := newTestEngine(t, cfg, victim, h, parent)
	e.restoreLock(0, idA) // the store's lock record: an ID, nothing else
	e.restoreRound(behind)
	if !e.Locked() || e.lockedBlock != nil || e.Round() != behind {
		t.Fatalf("fixture: want locked by ID alone at round %d (locked=%v bytes=%v round=%d)", behind, e.Locked(), e.lockedBlock != nil, e.Round())
	}

	p := &Proposal{
		Height: h, Round: ahead, Block: blkA, ValidRound: 0, Validator: cfg.Proposer(h, ahead, parent),
		Justification: encodeJustification([]*Vote{
			voteFrom(t, cfg, 0, MsgPrevote, h, 0, idA),
			voteFrom(t, cfg, 1, MsgPrevote, h, 0, idA),
			voteFrom(t, cfg, 2, MsgPrevote, h, 0, idA),
		}),
	}
	p.Sig = signProposal(t, cfg, p)
	if err := e.OnMessage(EncodeProposal(p)); err != nil {
		t.Fatalf("the survivors' re-proposal was refused: %v", err)
	}
	e.Drain()

	if err := e.OnTimeout(TimeoutEvent{Height: h, Round: behind}); err != nil {
		t.Fatal(err)
	}
	v := prevoteAt(t, e.Drain(), ahead)
	if v == nil || v.BlockID != idA {
		t.Fatalf("entering round %d, the restarted validator did not prevote the locked block it had been offered (prevote %v)", ahead, v)
	}
}

// TestAnEarlyProposalFromAnyoneButThatRoundsProposerIsNotKept: the buffer
// checks the signer against the round the proposal NAMES, before any
// signature work, exactly as the current-round path does.
func TestAnEarlyProposalFromAnyoneButThatRoundsProposerIsNotKept(t *testing.T) {
	cfg := wholeCommittee(t, 3)
	parent := crypto.HashParts([]byte("parent"))
	const idx = 2
	h := futureProposalHeight(t, cfg, idx, 1, parent)
	e := newTestEngine(t, cfg, idx, h, parent)

	wrong := -1
	for i := range cfg.Committee {
		if i != idx && string(cfg.Committee[i].PubKey) != string(cfg.Proposer(h, 1, parent)) {
			wrong = i
		}
	}
	if wrong < 0 {
		t.Fatal("fixture: no third validator to sign as the wrong proposer")
	}
	blk := conflictingBlock(t, cfg, h, 1, parent, 0x51)
	blk.Header.Proposer = cfg.Committee[wrong].PubKey
	p := &Proposal{Height: h, Round: 1, Block: blk, ValidRound: -1, Validator: cfg.Committee[wrong].PubKey}
	p.Sig = signProposal(t, cfg, p)
	_ = e.OnMessage(EncodeProposal(p))
	if s := e.sets[1]; s != nil && s.pending != nil {
		t.Fatal("a proposal signed by a validator who is not round 1's proposer was kept")
	}
	if err := e.OnTimeout(TimeoutEvent{Height: h, Round: 0}); err != nil {
		t.Fatal(err)
	}
	if v := prevoteAt(t, e.Drain(), 1); v != nil {
		t.Fatalf("the engine prevoted a wrong-proposer proposal in round 1: %x", v.BlockID[:4])
	}
}

// TestAnEarlyProposalBeyondTheWindowIsDropped: the buffer is the vote
// buffer's window and nothing more, so a proposal for a round past
// futureVoteRounds allocates nothing.
func TestAnEarlyProposalBeyondTheWindowIsDropped(t *testing.T) {
	cfg := wholeCommittee(t, 3)
	parent := crypto.HashParts([]byte("parent"))
	const idx = 2
	far := futureVoteRounds + 1
	h := futureProposalHeight(t, cfg, idx, far, parent)
	e := newTestEngine(t, cfg, idx, h, parent)

	blk := testProposer(t, cfg, h, far, parent)
	p := &Proposal{Height: h, Round: far, Block: blk, ValidRound: -1, Validator: cfg.Proposer(h, far, parent)}
	p.Sig = signProposal(t, cfg, p)
	_ = e.OnMessage(EncodeProposal(p))
	if _, kept := e.sets[far]; kept {
		t.Fatalf("a proposal %d rounds ahead (window %d) allocated that round's sets", far, futureVoteRounds)
	}
}

// TestTheFirstEarlyProposalForARoundWins: an equivocating proposer's second
// proposal for the same future round is ignored, as it is for the current
// round, so the engine never holds two candidates for one round.
func TestTheFirstEarlyProposalForARoundWins(t *testing.T) {
	cfg := wholeCommittee(t, 3)
	parent := crypto.HashParts([]byte("parent"))
	const idx = 2
	h := futureProposalHeight(t, cfg, idx, 1, parent)
	e := newTestEngine(t, cfg, idx, h, parent)

	first := testProposer(t, cfg, h, 1, parent)
	second := conflictingBlock(t, cfg, h, 1, parent, 0x52)
	for i, b := range []*Proposal{
		{Height: h, Round: 1, Block: first, ValidRound: -1, Validator: cfg.Proposer(h, 1, parent)},
		{Height: h, Round: 1, Block: second, ValidRound: -1, Validator: cfg.Proposer(h, 1, parent)},
	} {
		b.Sig = signProposal(t, cfg, b)
		if err := e.OnMessage(EncodeProposal(b)); err != nil {
			t.Fatalf("proposal %d was refused: %v", i, err)
		}
	}
	if err := e.OnTimeout(TimeoutEvent{Height: h, Round: 0}); err != nil {
		t.Fatal(err)
	}
	v := prevoteAt(t, e.Drain(), 1)
	if v == nil || v.BlockID != first.ID() {
		t.Fatalf("entering round 1 the engine prevoted %v, want the FIRST early proposal %x", v, first.ID())
	}
}

// TestAnEarlyProposalSuppliesTheBytesForACommitAheadOfTheEngine: a precommit
// quorum for round 1 arrives while the engine is still in round 0, so commitAt
// adopts round 1 without entering it. The block's bytes are the early proposal
// it already holds, and the driver must be able to append them - otherwise the
// one copy of the proposal sits unused and the engine reports a commit it
// cannot append.
func TestAnEarlyProposalSuppliesTheBytesForACommitAheadOfTheEngine(t *testing.T) {
	cfg := wholeCommittee(t, 3)
	parent := crypto.HashParts([]byte("parent"))
	const idx = 2
	h := futureProposalHeight(t, cfg, idx, 1, parent)
	e := newTestEngine(t, cfg, idx, h, parent)

	blk := testProposer(t, cfg, h, 1, parent)
	p := &Proposal{Height: h, Round: 1, Block: blk, ValidRound: -1, Validator: cfg.Proposer(h, 1, parent)}
	p.Sig = signProposal(t, cfg, p)
	if err := e.OnMessage(EncodeProposal(p)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrecommit, h, 1, blk.ID()))); err != nil {
			t.Fatal(err)
		}
	}
	id, ok := e.Committed()
	if !ok || id != blk.ID() {
		t.Fatalf("a round-1 precommit quorum did not commit the block (committed=%v)", ok)
	}
	if got := e.committedBlock(id); got == nil || got.ID() != id {
		t.Fatal("the engine committed round 1's block but cannot hand over its bytes, though the proposal arrived early")
	}
}

// earlyProposal is round r's proposal from its drawn proposer, signed.
func earlyProposal(t *testing.T, cfg Config, h uint64, r uint32, parent [32]byte) *Proposal {
	t.Helper()
	blk := testProposer(t, cfg, h, r, parent)
	p := &Proposal{Height: h, Round: r, Block: blk, ValidRound: -1, Validator: cfg.Proposer(h, r, parent)}
	p.Sig = signProposal(t, cfg, p)
	return p
}

// A polka buffered for round 1 must lock WITH the early proposal's bytes:
// adopted after the buffered-vote decisions, the lock would hold an ID alone
// and StartProposing could never re-propose it (the proof-of-lock is lost).
func TestAnEarlyProposalIsAdoptedBeforeABufferedPolkaSoTheLockHoldsItsBytes(t *testing.T) {
	cfg := evenCommittee(t, 4, 1)
	parent := crypto.HashParts([]byte("parent"))
	const idx = 3
	h := futureProposalHeight(t, cfg, idx, 1, parent)
	e := newTestEngine(t, cfg, idx, h, parent)
	p := earlyProposal(t, cfg, h, 1, parent)
	if err := e.OnMessage(EncodeProposal(p)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrevote, h, 1, p.Block.ID()))); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.OnTimeout(TimeoutEvent{Height: h, Round: 0}); err != nil {
		t.Fatal(err)
	}
	if e.Round() != 1 || !e.Locked() {
		t.Fatalf("fixture: round %d locked %v", e.Round(), e.Locked())
	}
	if e.lockedBlock == nil || e.lockedBlock.ID() != p.Block.ID() {
		t.Fatal("locked on the round-1 polka without the early proposal's bytes: cannot re-propose")
	}
}

// A forged early proposal is refused and not kept: kept, it would win the
// round's slot (first one wins) and shut out the real proposer's.
func TestAnEarlyProposalWithABadSignatureIsRefusedAndNotKept(t *testing.T) {
	cfg := wholeCommittee(t, 3)
	parent := crypto.HashParts([]byte("parent"))
	const idx = 2
	h := futureProposalHeight(t, cfg, idx, 1, parent)
	e := newTestEngine(t, cfg, idx, h, parent)
	p := earlyProposal(t, cfg, h, 1, parent)
	p.Sig = append([]byte(nil), p.Sig...)
	p.Sig[0] ^= 0xff
	if err := e.OnMessage(EncodeProposal(p)); err == nil {
		t.Fatal("a forged early proposal was accepted")
	}
	if s := e.sets[1]; s != nil && s.pending != nil {
		t.Fatal("a forged early proposal was kept")
	}
}

// The header must name the envelope's height on the early path too (audit C-1).
func TestAnEarlyProposalWhoseHeaderNamesAnotherHeightIsRefused(t *testing.T) {
	cfg := wholeCommittee(t, 3)
	parent := crypto.HashParts([]byte("parent"))
	const idx = 2
	h := futureProposalHeight(t, cfg, idx, 1, parent)
	e := newTestEngine(t, cfg, idx, h, parent)
	blk := testProposer(t, cfg, h, 1, parent)
	blk.Header.Height = h + 1
	p := &Proposal{Height: h, Round: 1, Block: blk, ValidRound: -1, Validator: cfg.Proposer(h, 1, parent)}
	p.Sig = signProposal(t, cfg, p)
	if err := e.OnMessage(EncodeProposal(p)); !errors.Is(err, ErrBadProposalHeight) {
		t.Fatalf("want ErrBadProposalHeight, got %v", err)
	}
	if s := e.sets[1]; s != nil && s.pending != nil {
		t.Fatal("an early proposal whose header names another height was kept")
	}
}

// An adopted early proposal stays retained with its round after the engine
// leaves it, so a precommit quorum that completes late can still be appended.
func TestAnAdoptedEarlyProposalSuppliesTheBytesForALateQuorum(t *testing.T) {
	cfg := wholeCommittee(t, 3)
	parent := crypto.HashParts([]byte("parent"))
	const idx = 2
	h := futureProposalHeight(t, cfg, idx, 1, parent)
	e := newTestEngine(t, cfg, idx, h, parent)
	p := earlyProposal(t, cfg, h, 1, parent)
	if err := e.OnMessage(EncodeProposal(p)); err != nil {
		t.Fatal(err)
	}
	if err := e.OnTimeout(TimeoutEvent{Height: h, Round: 0}); err != nil {
		t.Fatal(err)
	}
	if err := e.OnTimeout(TimeoutEvent{Height: h, Round: 1}); err != nil {
		t.Fatal(err)
	}
	if e.Round() < 2 {
		t.Fatalf("fixture: round %d", e.Round())
	}
	for i := 0; i < 3; i++ {
		if err := e.OnMessage(EncodeVote(voteFrom(t, cfg, i, MsgPrecommit, h, 1, p.Block.ID()))); err != nil {
			t.Fatal(err)
		}
	}
	id, ok := e.Committed()
	if !ok || id != p.Block.ID() {
		t.Fatalf("fixture: committed %v", ok)
	}
	if b := e.committedBlock(id); b == nil {
		t.Fatal("late round-1 quorum committed but the adopted early proposal's bytes are gone")
	}
}
