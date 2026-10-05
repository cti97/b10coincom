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

	// validate, when non-nil, is the block-validation seam the DRIVER fills:
	// it reports whether the proposal's block is one this validator may
	// honestly vote for, judged against the chain exactly as the chain's
	// Append will judge it at commit time - structure, height, parent and
	// the state root recomputed through the real transition (audit C-1).
	// It runs in maybePrevote BEFORE the lock check, so an invalid proposal
	// is prevoted NIL and can never gather the polka that would lock every
	// honest validator onto block bytes the chain refuses. Nil (engines built
	// without a driver) means no validation beyond the envelope's own:
	// production engines always carry the seam, because they always carry a
	// chain; a driver-less engine has no chain to disagree with.
	validate func(*types.Block) error

	// lockedBlock retains the bytes of the proposal the lock names, and
	// lockedVotes the prevotes that formed the polka the lock rests on,
	// lockedVoteRound the round those votes were cast in (audit C-2's
	// proof-of-lock). The lock itself records only the block ID and round -
	// enough to REFUSE conflicting proposals, not enough to RE-propose the
	// promised one. A validator that is drawn as proposer while locked must
	// propose its locked block with that polka as its justification - the
	// justification proves to every peer that the block once carried a
	// quorum, which is what lets conflicting locks from strictly earlier
	// rounds unlock and what gives unlocked validators reason to prevote a
	// block they never saw. Proposing a fresh block instead would be
	// nil-prevoted by the proposer itself and every other locked validator,
	// stalling the height for as long as timeouts grow.
	//
	// All three fields are empty/-1 when the engine holds no bytes for its
	// locked ID: a polka can reach quorum over prevotes alone (with the
	// proposal itself lost), and a lock restored from the store after a
	// restart is an ID alone. In that state the engine must not even try -
	// see StartProposing - until a proposal that can rebuild the evidence
	// arrives.
	lockedBlock     *types.Block
	lockedVotes     []*Vote
	lockedVoteRound int64

	// future records, per committee member (index), the HIGHEST round this
	// engine has seen that member sign a vote (prevote or precommit) for at
	// this height, when that round was ahead of the round the engine was in
	// at arrival. The engine drops wrong-round tallies (no multi-round vote
	// sets yet - C-3), but the DISCARDED vote still carries the one piece of information the
	// round ladder needs: the committee has already moved past this round. On
	// timeout the engine JUMPS its round - bounded, evidence-gated resync:
	// strictly more than the Byzantine budget (f+1 members) must have
	// attested a higher round, so at least one honest validator truly was
	// there. A committee whose round counters drift apart (rebuilt engines
	// re-arm their ladders mid-height) resynchronises through this; without
	// it a follower can sit one round behind forever, dropping every proposal
	// as wrong-round while every leader drops its vote back the same way - a
	// fully live committee that never polkas again (observed with the capped
	// round ladder the audit's C-2 asks for).
	//
	// One entry per member, replaced only forward: bounded memory, Byzantine
	// claims contained (f members can attest at most f slots), and the f+1-th
	// largest entry is then always the highest round AN honest member
	// attested. Reset only by a new engine (per height); a round change
	// deliberately keeps it.
	future map[int]*Vote

	// persistLock, when non-nil, is called the instant the lock moves: the
	// driver installs it after construction so the promise is made durable
	// BEFORE the precommit that records it is signed or shipped (a promise
	// broadcast before it can survive a crash is the promise a restart
	// loses). The engine itself performs no I/O - like propose, this is an
	// injected seam, and it stays nil for engines built without a driver,
	// whose lock is in-memory only, exactly as before this field existed.
	persistLock func(height uint64, round uint32, id [32]byte)

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

// restoreLock reinstates a lock taken in the engine's previous life: the
// driver reads the persisted lock for this height out of the store and hands
// it here when a crashed precommit must keep its promise.
//
// A restored lock is not a lesser lock. It goes in through the same
// forward-only mutator an in-memory lock uses, so it survives enterRound and
// refuses a differing block exactly as a promise taken mid-run does - and a
// lock recorded at a round the promise already exceeds cannot pull the
// engine backwards.
func (e *Engine) restoreLock(round uint32, id [32]byte) { e.lk.lockOn(round, id) }

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
	// vote may rest on evidence that does not exist).
	//
	// Jump the ladder on evidence before entering the next round: if f+1
	// committee members signed prevotes at rounds ahead of the one that just
	// ended, the committee IS that far ahead, and stepping +1 would only keep
	// this validator exactly one round behind a committee it can never catch -
	// its own votes and every peer's proposal for the rounds it keeps missing
	// are dropped as wrong-round in BOTH directions, forever. The target is
	// the highest round at least one honest member attested (the f+1-th
	// largest observed member round; f Byzantine slots cannot reach that
	// position). Without evidence the ladder escalates by one, as before.
	if target := e.jumpTarget(); target > e.round {
		e.enterRound(target)
		return
	}
	e.enterRound(e.round + 1)
}

// jumpTarget reports the round the engine should enter on a timeout when its
// future-round evidence says the committee has moved beyond the next round,
// and 0 when there is none (0 is never a valid target: the engine is at round
// >= 0 and only jumps strictly forward).
//
// The criterion is f+1 distinct members' signed votes at rounds ahead of the
// current one - strictly more than the Byzantine budget can supply. Each
// member is counted once, at its highest attested round, and the target is
// the f+1-th LARGEST of those: the highest round the evidence shows bulk at,
// always SOME honest member's own attested round (f Byzantine claims cannot
// reach the f+1-th slot). Jumping to the furthest claim would follow one
// Byzantine member wherever it said; stepping by one would never close a
// drifted round gap under a flat (capped) cadence. One jump moves to the
// evidence's bulk; further evidence, on later timeouts, moves further.
func (e *Engine) jumpTarget() uint32 {
	fplus1 := len(e.cfg.Committee)/3 + 1
	if e.future == nil || len(e.future) < fplus1 {
		return 0
	}
	rounds := make([]uint32, 0, len(e.future))
	for _, v := range e.future {
		rounds = append(rounds, v.Round)
	}
	// Sort descending; index fplus1-1 is the f+1-th largest.
	for i := 1; i < len(rounds); i++ {
		for j := i; j > 0 && rounds[j-1] < rounds[j]; j-- {
			rounds[j-1], rounds[j] = rounds[j], rounds[j-1]
		}
	}
	if int64(rounds[fplus1-1]) <= int64(e.round) {
		return 0
	}
	return rounds[fplus1-1]
}

// enterRound moves to a later round, resetting the per-round tally. The lock
// deliberately SURVIVES the round change: that is the whole point of it. The
// future-round evidence survives too: it is per-HEIGHT observation, and the
// rounds the ladder may still jump to are exactly the ones it records.
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
	// A block whose header claims a height other than the envelope's own is a
	// protocol error, refused here (audit C-1). Appending such a block is
	// impossible (the chain demands head+1), and prevoting it would stake a
	// lock on bytes the chain must refuse - the parked-everyone failure the
	// proposal-validation seam exists to prevent. The check needs no chain
	// state, so it runs on every engine, driverless ones included; the rest
	// of the block's validity is judged by the seam before any prevote.
	if p.Block.Header.Height != p.Height {
		return fmt.Errorf("%w: header claims height %d, envelope names height %d",
			ErrBadProposalHeight, p.Block.Header.Height, p.Height)
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
		// Not this round. A vote from a round AHEAD of ours is still
		// evidence for the ladder jump: record the member's highest attested
		// round (signature and membership verified here, because this path
		// makes a jump decision and must not trust unauthenticated input).
		// Past-round votes need no record: the committee has left them behind
		// and our own ladder never wants to enter one.
		if v.Height == e.height && v.Round > e.round && v.Verify() == nil {
			if idx := e.cfg.IndexOf(v.Validator); idx >= 0 {
				if cur, seen := e.future[idx]; !seen || v.Round > cur.Round {
					if e.future == nil {
						e.future = make(map[int]*Vote)
					}
					e.future[idx] = v
				}
			}
		}
		return nil
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

// maybePrevote prevotes the current proposal if it is valid and the lock permits it.
//
// The proposal is JUDGED before it is voted on, in this order (audit C-1):
//
//  1. verifyJustification: a proposal claiming a polka it does not carry is
//     unusable evidence - not prevoted at all, not even nil: no vote of this
//     validator may rest on evidence that does not exist.
//  2. validate (the driver's seam): the block itself - structure, height,
//     parent, state root through the real transition - exactly what the
//     chain's Append will demand at commit time. A failing block is prevoted
//     NIL, Tendermint's valid(v) rule: the validator will not vote for block
//     bytes it could not accept, and nil, unlike silence, still lets the
//     round end. This check is what closes the halt: with an invalid block
//     prevoted, the polka, the lock, the commit and the append refusal that
//     previously parked every honest node forever can no longer form.
//  3. canPrevote: the lock.
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
	if e.validate != nil {
		if verr := e.validate(e.proposal); verr != nil {
			// The block is not one this validator could accept: prevote NIL.
			// The step is recorded BEFORE the emission, exactly as the lock
			// branch below: emitVote tallies the engine's own vote, and the
			// self-tally may synchronously re-enter maybePrecommit while this
			// frame is on the stack. Writing the step after the emission
			// would clobber the deeper transition.
			e.step = StepPrevote
			e.emitVote(MsgPrevote, [32]byte{})
			return
		}
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
	prev := e.lk
	e.lk.lockOn(e.round, id)
	// The promise is made durable the moment it moves, before the precommit
	// that records it leaves this process. Skipping this hook would leave the
	// lock memory-only, and a restart would re-enter the height unlocked -
	// the exact unsafe re-vote the lock exists to prevent.
	if e.persistLock != nil {
		e.persistLock(e.height, e.round, id)
	}
	// When the lock MOVED, rebind the retained proof-of-lock evidence (audit
	// C-2): the block bytes this validator holds for the locked ID, the
	// prevotes that formed the polka it rests on, and the round those votes
	// were cast in - the round the re-proposal must claim as its ValidRound,
	// because a justification is tallied in its OWN round.
	//
	// The rebinding never leaves an earlier lock's evidence under a new lock
	// (it would name a block other than the promise), and it keeps evidence
	// whose block still matches: a lock that moved to the same ID at a later
	// round keeps the older polka's votes - they are genuine evidence for
	// the promised block, taken in the round the polka actually formed.
	// When the polka's own proposal is in hand this round, the fresher
	// evidence replaces it. A lock whose bytes this engine never held - a
	// polka reached quorum over prevotes alone, or the lock was restored
	// from the store as an ID after a restart - is retained as nothing,
	// which StartProposing treats as "locked, cannot propose".
	//
	// An equal-round relock of the same ID (prev == new) binds nothing: any
	// evidence already retained for that lock still stands, taken in the
	// round the polka was actually formed.
	if e.lk.lockedRound != prev.lockedRound || e.lk.lockedBlock != prev.lockedBlock {
		switch {
		case e.proposal != nil && e.proposal.ID() == id:
			e.lockedBlock = e.proposal
			e.lockedVotes = nil
			for _, v := range e.prevotes.Votes() {
				if v.BlockID == id {
					e.lockedVotes = append(e.lockedVotes, v)
				}
			}
			e.lockedVoteRound = int64(e.round)
		case e.lockedBlock != nil && e.lockedBlock.ID() == e.lk.blockID():
			// keep: the retained block is still the one the lock names
		default:
			e.lockedBlock = nil
			e.lockedVotes = nil
			e.lockedVoteRound = -1
		}
	}
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

// StartProposing is called by the driver when this engine is the proposer for
// the current round: it builds and broadcasts a proposal.
//
// A LOCKED proposer proposes its locked block, not a fresh one (audit C-2).
// Building a fresh block would be protocol self-contradiction: the proposer
// itself is locked on another block, so it would nil-prevote its own
// proposal, and so would every other locked validator - the round dies by
// construction and every further proposer redraw burns another round. The
// locked block is re-proposed with ValidRound set to the round its polka was
// formed in and the polka's prevotes as the justification: the proof-of-lock.
// That evidence is what makes the re-proposal prevotable everywhere - locked
// validators prevote their own promise, and any validator locked on a
// CONFLICTING block from a strictly earlier round unlocks on the verified
// polka and follows the promise.
//
// A locked proposer that holds NO complete proof-of-lock evidence for its
// locked ID - the polka reached this engine over prevotes alone while the
// proposal was lost, or the lock was persisted and restored as an ID alone
// after a restart - cannot construct the re-proposal. It falls through to the
// fresh build: when that rebuild reproduces the locked block byte-for-byte
// (deterministic builds: this validator rebuilding its own earlier proposal,
// and the round-0 draw of a whole-committee restart is exactly that
// validator), the locked peers prevote it by ID-match and the height
// proceeds; when it differs, the lock rule makes the proposer itself
// nil-prevote it, and the round ends inside the capped ladder like any
// undecided round. Recovery in every other case belongs to a locked proposer
// that does hold the evidence.
func (e *Engine) StartProposing() error {
	if !e.IsProposer() {
		return ErrNoProposer
	}
	if e.proposal != nil {
		return nil
	}
	var b types.Block
	var validRound int64
	var justification []byte
	if e.lk.locked() && e.lockedBlock != nil && e.lockedBlock.ID() == e.lk.blockID() && len(e.lockedVotes) > 0 {
		// The lock names a block whose bytes AND polka this engine holds:
		// re-propose THAT block with the polka as its justification (the
		// proof-of-lock). This is the audit C-2 fix proper: a locked proposer
		// proposing anything else would be nil-prevoted by itself - its lock
		// refuses the fresh block - and by every other locked validator, so
		// the round dies by construction while every later redraw burns the
		// same time. The carried justification is what also lets validators
		// locked on a CONFLICTING block from a strictly earlier round unlock
		// and follow the promise.
		b = *e.lockedBlock
		// The ValidRound is the round the retained polka was VOTED in, not the
		// current proposing round and not necessarily the lock's current
		// round: verifyJustification tallies the carried evidence in its own
		// round, so the claim must name the votes' true origin.
		validRound = e.lockedVoteRound
		justification = encodeJustification(e.lockedVotes)
	} else {
		if e.lk.locked() {
			// Locked, but holding no complete proof-of-lock evidence - the
			// lock names a block whose bytes never arrived (a quorum of
			// prevotes reached this engine without the proposal) or were lost
			// in a restart (the store records the lock as an ID alone). No
			// re-proposal is constructible; the honest fallback is the fresh
			// build below, which the proposer's own lock then judges: when
			// the rebuild reproduces the locked block byte-for-byte - the
			// deterministic-build case, and THE round-0 recovery of a
			// whole-committee restart - the locked peers prevote it by
			// ID-match and the height proceeds; when it differs, the lock
			// rule nil-prevotes it (below in maybePrevote), exactly the
			// refused-promise shape the lock exists to enforce. A fresh build
			// that differs from the lock cannot commit anything conflicting:
			// no quorum of locked validators can gather behind it, and this
			// validator itself votes nil.
		}
		nb, err := e.propose(e.height, e.round, e.parent)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrProposeFn, err)
		}
		b = nb
		// ValidRound -1: a fresh block carries no polka yet. It must be SET, not left
		// at the zero value, because 0 CLAIMS a polka at round 0 - which no one has
		// given and this engine could not honestly prove.
		validRound = -1
	}
	p := &Proposal{
		Height: e.height, Round: e.round, Block: b, ValidRound: validRound,
		Justification: justification,
		Validator:     e.pub,
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
