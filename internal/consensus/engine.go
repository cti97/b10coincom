package consensus

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// Step is where a validator is in a round's four-phase protocol.
type Step uint8

const (
	StepPropose Step = iota
	StepPrevote
	StepPrecommit
	StepCommit
)

func (s Step) String() string {
	switch s {
	case StepPropose:
		return "propose"
	case StepPrevote:
		return "prevote"
	case StepPrecommit:
		return "precommit"
	case StepCommit:
		return "commit"
	}
	return "unknown"
}

// Outbound is a message the engine wants sent. An empty To means broadcast.
type Outbound struct {
	To   string
	Data []byte
}

// TimeoutEvent tells the engine that its round has run out of time. The driver
// owns the clock; the engine never reads one.
type TimeoutEvent struct {
	Height uint64
	Round  uint32
	Step   Step
}

var (
	ErrNoProposer = errors.New("consensus: no proposer for this height and round")
	ErrProposeFn  = errors.New("consensus: the proposer function failed")
)

// ProposeFn builds the block a validator should propose at (height, round). The
// engine does not build blocks: block construction belongs to the caller, which is
// what keeps this type free of chain and mempool concerns.
type ProposeFn func(height uint64, round uint32, parent [32]byte) (types.Block, error)

// Engine is a deterministic BFT state machine for one validator.
//
// It reads no clock, starts no goroutine and performs no I/O. The driver feeds it
// messages and timeout events and carries Drain's output to a Transport. That is
// what makes a failing run reproducible from a seed, and it is why the same type
// will run over real sockets in M4 unchanged.
type Engine struct {
	cfg     Config
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	idx     int
	parent  [32]byte
	propose ProposeFn

	height uint64
	round  uint32
	step   Step

	lk         lock
	proposal   *types.Block // the block this validator is judging this round
	proposalEn *Proposal    // the envelope it arrived in: carries ValidRound/Justification
	prevotes   *VoteSet
	precommits *VoteSet

	committed    [32]byte
	hasCommitted bool
	out          []Outbound
}

// NewEngine creates an engine that will validate height, whose parent is parent,
// signing with priv.
func NewEngine(cfg Config, height uint64, parent [32]byte, priv ed25519.PrivateKey, propose ProposeFn) *Engine {
	pub := priv.Public().(ed25519.PublicKey)
	e := &Engine{
		cfg: cfg, priv: priv, pub: pub,
		idx: cfg.IndexOf(pub), parent: parent, propose: propose,
		height: height,
		// The lock's zero value is round 0, which is a REAL round, so "unlocked"
		// must be set explicitly. Forgetting this makes a fresh validator believe
		// it is locked on the zero block and prevote for nothing.
		lk:         lock{lockedRound: -1},
		step:       StepPropose,
		prevotes:   NewVoteSet(cfg, height, 0, MsgPrevote),
		precommits: NewVoteSet(cfg, height, 0, MsgPrecommit),
	}
	return e
}

func (e *Engine) Height() uint64   { return e.height }
func (e *Engine) Round() uint32    { return e.round }
func (e *Engine) Step() Step       { return e.step }
func (e *Engine) Locked() bool     { return e.lk.locked() }
func (e *Engine) Proposer() []byte { return e.cfg.Proposer(e.height, e.round, e.parent) }
func (e *Engine) IsProposer() bool { return string(e.Proposer()) == string(e.pub) }

// Committed reports the block this engine has committed, if any.
func (e *Engine) Committed() ([32]byte, bool) { return e.committed, e.hasCommitted }

// Drain returns and clears the messages the engine wants sent. The caller owns
// delivery, so the engine never performs I/O.
func (e *Engine) Drain() []Outbound {
	out := e.out
	e.out = nil
	return out
}

func (e *Engine) emit(data []byte) { e.out = append(e.out, Outbound{Data: data}) }

// OnTimeout ends the current round. The event must name the round the engine is
// actually in - the driver owns the clock and fires the timer for the round it
// sees, so it passes Height == e.Height() and Round == e.Round(). A round that
// has already been left is a stale re-fire; a round the engine has not entered
// is not the engine's to judge. Both are ignored, which is why neither the
// driver nor the engine gets a second, divergent notion of "the current round".
//
// Ending a round keeps two concerns apart, in this order:
//
//  1. The round that ran out is CLOSED: the validator casts any vote it still
//     owes it. A validator that never received a usable proposal prevotes NIL
//     exactly once for that round - its weight must leave the round or the
//     round can never be left behind. A validator that already voted this
//     round (prevote via maybePrevote, or precommit after it) casts nothing.
//  2. The NEXT round is ENTERED: enterRound resets the per-round tallies and
//     the proposal slots and parks the validator at StepPropose, waiting for
//     the new round's proposal. Entering a round EMITS NOTHING - in
//     particular no nil prevote for a round nobody has proposed into yet,
//     which is what collapsing these two concerns used to produce.
//
// The lock deliberately survives this transition (it survives enterRound,
// which is where the transition lands): the timeout rescues a stalled round,
// it does not launder a promise.
func (e *Engine) OnTimeout(ev TimeoutEvent) {
	if ev.Height != e.height {
		return // another height: behind us or not reached, not ours to judge
	}
	if ev.Round != e.round {
		return // a stale re-fire for a round already left, or one not yet entered
	}
	if e.step == StepCommit {
		return // the height is decided; the driver moves to the next height
	}
	if e.round == math.MaxUint32 {
		// e.round+1 would wrap to 0 and resurrect a long-settled round's
		// tallies. There is no next round to enter; unreachable under any real
		// timeout schedule, but the wrap must not be silent.
		return
	}
	if e.step == StepPropose && e.proposal == nil {
		// No usable proposal arrived before the round ran out: the one vote
		// this round is owed is NIL. Emitted while e.round is still the round
		// that is ending, so the vote is signed and tallied as that round's.
		e.emitVote(MsgPrevote, [32]byte{})
	}
	// The vote, if any, is cast: StepPrevote and StepPrecommit validators voted
	// earlier through maybePrevote / maybePrecommit, and a validator holding a
	// proposal whose justification failed stays silent by the gate's rule (no
	// vote may rest on evidence that does not exist). Leave the round behind.
	e.enterRound(e.round + 1)
}

// enterRound moves to a later round, resetting the per-round tally. The lock
// deliberately SURVIVES the round change: that is the whole point of it.
func (e *Engine) enterRound(round uint32) {
	e.round = round
	e.step = StepPropose
	e.proposal = nil
	e.proposalEn = nil
	e.prevotes = NewVoteSet(e.cfg, e.height, round, MsgPrevote)
	e.precommits = NewVoteSet(e.cfg, e.height, round, MsgPrecommit)
}

// emitVote signs the vote this validator owes for the current round, queues it
// for broadcast, and delivers it to the engine's own tally through the same
// path a vote received from a peer takes.
//
// The delivery is correctness, not a convenience. A real network never echoes a
// sender's own broadcast back to it, so tallying only what arrives through
// OnMessage leaves a validator's weight out of its own tally: a ceiling of n-1,
// not n. Measured on a four-validator committee with one silent validator, the
// three live validators could then gather at most 2 of the quorum of 3 and
// NEVER committed - a committee that tolerates zero silent validators, which
// defeats the point of BFT. The delivery below runs the full received-vote path
// (decode, signature, duplicate rule, membership check, then the quorum logic),
// so the self-vote is exercised by exactly the rules a peer's vote faces, and a
// stray echo of our own broadcast is still collapsed by the duplicate rule.
//
// Re-entrancy, and why it needs no goroutine, channel or lock: the delivery may
// synchronously run maybePrecommit (the own prevote can complete the polka),
// and from there maybeCommit (the own precommit can complete the commit) while
// the calling frame is still on the stack. That is made safe by ordering, not
// by mutual exclusion: every caller records its step transition BEFORE the
// emission - maybePrevote sets StepPrevote, maybePrecommit sets StepPrecommit
// and locks - so a re-entered guard observes the mid-state the round is really
// in, the deepest transition wins, and no caller writes state after an
// emission. OnTimeout's nil prevote needs no such ordering: a nil vote can
// never complete a non-nil quorum (AnyQuorum skips nil), so nothing it triggers
// can survive the enterRound that immediately follows.
//
// The delivery cannot fail for a correctly constructed engine: the vote is
// signed here, names the engine's own height and round, and its key was admitted
// at construction. A panic on refusal is deliberate - a silent drop would
// quietly reinstate the n-1 bug for a misconfigured committee.
func (e *Engine) emitVote(typ MsgType, id [32]byte) {
	v := &Vote{Type: typ, Height: e.height, Round: e.round, BlockID: id, Validator: e.pub}
	h := v.SigningHash()
	v.Sig = crypto.Sign(e.priv, h[:])
	data := EncodeVote(v)
	e.emit(data)
	if err := e.OnMessage(data); err != nil {
		panic(fmt.Sprintf("consensus: the engine's own vote was refused by its own tally: %v", err))
	}
}

// OnMessage processes one wire message. An error means the message was malformed
// or unusable; the caller may drop it and carry on.
func (e *Engine) OnMessage(data []byte) error {
	if v, err := DecodeVote(data); err == nil {
		return e.onVote(v)
	}
	p, err := DecodeProposal(data)
	if err != nil {
		return fmt.Errorf("%w: not a vote or a proposal", ErrUnknownMsgType)
	}
	return e.onProposal(p)
}

func (e *Engine) onProposal(p *Proposal) error {
	if p.Height != e.height || p.Round != e.round {
		return nil // another height or round: not ours to judge here
	}
	if err := p.Verify(); err != nil {
		return err
	}
	if string(p.Validator) != string(e.Proposer()) {
		return nil // not the proposer for this round; ignore it
	}
	if e.proposal != nil {
		return nil // first proposal wins, so the choice is deterministic
	}
	e.proposal = &p.Block
	e.proposalEn = p
	e.maybePrevote()
	return nil
}

func (e *Engine) onVote(v *Vote) error {
	if v.Height != e.height || v.Round != e.round {
		return nil // not this round
	}
	switch v.Type {
	case MsgPrevote:
		added, err := e.prevotes.Add(v)
		if err != nil {
			return err
		}
		if added {
			e.maybePrecommit()
		}
	case MsgPrecommit:
		added, err := e.precommits.Add(v)
		if err != nil {
			return err
		}
		if added {
			e.maybeCommit()
		}
	}
	return nil
}

// maybePrevote prevotes the current proposal if the lock permits it.
func (e *Engine) maybePrevote() {
	if e.step != StepPropose && e.step != StepPrevote {
		return
	}
	if e.proposal == nil || e.proposalEn == nil {
		return
	}
	id := e.proposal.ID()
	validRound, err := e.verifyJustification(e.proposalEn)
	if err != nil {
		return // an unjustified proposal is not prevoted at all - not even nil: no
		// vote of this validator may rest on evidence that does not exist.
	}
	if !e.lk.canPrevote(e.round, id, validRound) {
		// The lock refuses this block. Prevote NIL rather than staying silent: a
		// validator that emits nothing leaves its weight out of the nil tally, so
		// the round can never end and the chain stalls on exactly the safety path
		// this gate protects.
		//
		// The step is recorded BEFORE the emission: emitVote tallies the engine's
		// own vote, and a late-arriving peer prevote may already sit one vote
		// short of the polka - the self-tally can synchronously re-enter
		// maybePrecommit while this frame is on the stack. Writing the step after
		// the emission would clobber the deeper transition.
		e.step = StepPrevote
		e.emitVote(MsgPrevote, [32]byte{})
		return
	}
	// Same ordering as the nil branch above: the step goes down first, so the
	// re-entrant precommit-or-commit the own prevote may trigger inside
	// emitVote lands on top of a consistent mid-state instead of being
	// overwritten here.
	e.step = StepPrevote
	e.emitVote(MsgPrevote, id)
}

func (e *Engine) maybePrecommit() {
	if e.step == StepPrecommit || e.step == StepCommit {
		return
	}
	id, ok := e.prevotes.AnyQuorum()
	if !ok {
		return
	}
	// The step and the lock are recorded BEFORE the emission. emitVote tallies
	// the engine's own precommit, which may complete the commit and synchronously
	// re-enter maybeCommit while this frame is still on the stack: tallying your
	// own precommit inside emitVote re-enters the commit decision. With the
	// step left until after, maybeCommit's StepCommit would be overwritten here
	// and a timeout would then treat a decided height as undecided. With the
	// step written first, the re-entered maybeCommit observes the true mid-state
	// (precommitted, locked, not yet committed) and its deeper transition
	// survives the unwinding.
	e.step = StepPrecommit
	// Precommitting IS locking: this is the promise the lock records. Doing it
	// anywhere else, or only on commit, would leave the safety rule unenforced
	// for exactly the window it exists to cover.
	e.lk.lockOn(e.round, id)
	e.emitVote(MsgPrecommit, id)
}

func (e *Engine) maybeCommit() {
	if e.hasCommitted {
		return
	}
	id, ok := e.precommits.AnyQuorum()
	if !ok {
		return
	}
	e.committed, e.hasCommitted = id, true
	e.step = StepCommit
}

// StartProposing is called by the driver when this engine is the proposer for the
// current round: it builds and broadcasts a proposal.
func (e *Engine) StartProposing() error {
	if !e.IsProposer() {
		return ErrNoProposer
	}
	if e.proposal != nil {
		return nil
	}
	b, err := e.propose(e.height, e.round, e.parent)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProposeFn, err)
	}
	// ValidRound -1: a fresh block carries no polka yet. It must be SET, not left
	// at the zero value, because 0 CLAIMS a polka at round 0 - which no one has
	// given and this engine could not honestly prove.
	p := &Proposal{
		Height: e.height, Round: e.round, Block: b, ValidRound: -1,
		Validator: e.pub,
	}
	// The signature must cover the envelope's own SigningHash(): that is the
	// exact hash Proposal.Verify checks on every peer, over the envelope fields
	// plus the block header. Signing the bare header hash instead would produce
	// two different domain-separated hashes - a proposal every peer would reject
	// with ErrBadProposalSignature, so no height could ever gather a prevote.
	h := p.SigningHash()
	p.Sig = crypto.Sign(e.priv, h[:])
	e.proposal = &b
	e.proposalEn = p
	e.emit(EncodeProposal(p))
	// The proposer prevotes its own block once it has "received" it, which
	// maybePrevote does for us. A transport never loops a sender's message back,
	// so this is the only chance the proposer gets.
	e.maybePrevote()
	return nil
}

// verifyJustification checks that the proposal's carried prevotes really do prove a
// polka for the proposal's own block at its own ValidRound. It returns the round to
// use for the lock comparison: ValidRound when the evidence checks out, and -1 when
// the proposal carries none, which is the honest case for a fresh block.
//
// Verification is not optional. Trusting the field would let a Byzantine proposer
// claim an unlock that no quorum ever granted, which is precisely the conflicting
// commit the gate exists to prevent.
func (e *Engine) verifyJustification(p *Proposal) (int64, error) {
	if p.ValidRound < 0 {
		if len(p.Justification) > 0 {
			return 0, ErrBadJustification // evidence for a round it does not claim
		}
		return -1, nil
	}
	if p.ValidRound > int64(math.MaxUint32) {
		// VoteSet's round is a uint32; casting a larger claim would silently
		// truncate it, so evidence could be tallied for a DIFFERENT round than
		// the one the proposal asserts and the lock compares against.
		return 0, ErrBadJustification
	}
	vs := NewVoteSet(e.cfg, e.height, uint32(p.ValidRound), MsgPrevote)
	for _, raw := range decodeVotes(p.Justification) { // length-prefixed sequence
		v, err := DecodeVote(raw)
		if err != nil {
			return 0, ErrBadJustification
		}
		if _, err := vs.Add(v); err != nil {
			// Add rejects a wrongly signed vote, a non-member's vote, and - via
			// its height/round guard - any vote carried from another height or
			// claiming another round than the justification asserts.
			return 0, ErrBadJustification
		}
	}
	if !vs.HasQuorum(p.Block.ID()) {
		return 0, ErrBadJustification
	}
	return p.ValidRound, nil
}
