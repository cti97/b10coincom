package consensus

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"math/bits"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// futureVoteRounds bounds the FUTURE window of the per-height vote buffer
// (audit C-3): a vote for a round at most this many ahead of the engine's own
// is retained and tallied as soon as the engine reaches that round, instead of
// being dropped the moment it arrives. A follower that jumped or stepped to
// round r+2 finds that round's prevotes already in hand, so it can precommit -
// and, when the precommits are there too, commit - without waiting for a
// retransmission the protocol never sends.
const futureVoteRounds uint32 = 4

// pastVoteRounds bounds how many rounds BEHIND the engine's own keep their
// tallies (audit C-3). This is the window that makes commit-from-any-round
// real: a precommit quorum that completes for round r after the engine has
// already entered round r+1 still commits, because round r's set was not
// discarded by the round change. Past rounds older than this are pruned; the
// window is what bounds retention, so an unbounded buffer - a memory DoS - is
// impossible.
const pastVoteRounds uint32 = 4

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
//
// It names ONLY (height, round). The step is deliberately not carried (audit
// C-17): OnTimeout already judges the engine's own step - e.step - and a
// caller-supplied step would be a second source of truth about it, exactly the
// duplication the round check avoids. The engine never trusts a caller's echo of
// its own state; it trusts its own.
type TimeoutEvent struct {
	Height uint64
	Round  uint32
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

	// prevotes and precommits are the CURRENT round's tallies; they always
	// point at the entry e.sets[e.round] (see bindRound).
	prevotes   *VoteSet
	precommits *VoteSet

	// sets retains the per-round tallies this engine holds at this HEIGHT
	// (audit C-3), keyed by round. The map is the whole of the multi-round
	// vote buffer: a vote for a future round lands in its own set and is
	// tallied the moment the engine enters that round; a precommit set for a
	// round the engine has already LEFT stays here, so a quorum that
	// completes late still commits (maybeCommit walks every other retained
	// round). Retention is BOUNDED - see withinWindow/pruneRounds:
	// rounds more than futureVoteRounds ahead or pastVoteRounds behind are
	// dropped, and because a VoteSet counts each validator once per round,
	// the whole buffer holds at most
	//
	//	(futureVoteRounds + pastVoteRounds + 1) x 2 x len(Committee)
	//
	// votes - an explicit cap, not a hope about how far rounds drift. A
	// vote outside the window is not retained (it is still counted as
	// round-ladder evidence in future, which is one entry per member).
	sets map[uint32]*roundSets

	// validate, when non-nil, is the block-validation seam the DRIVER fills:
	// it reports whether the proposal's block is one this validator may
	// honestly vote for, judged against the chain exactly as the chain's
	// Append will judge it at commit time - structure, height, parent and
	// the state root recomputed through the real transition (audit C-1).
	// It runs in maybePrevote BEFORE the lock check, so an invalid proposal
	// is prevoted NIL and can never gather the polka that would lock every
	// honest validator onto block bytes the chain refuses.
	//
	// It is never nil for an engine built the exported way: NewEngine
	// installs refuseWithoutSeam, so a driver-less engine - one with no chain
	// behind it - refuses every block and prevotes NIL, never FOR. Before
	// round 3 a nil field meant "no validation beyond the envelope's own",
	// which silently prevoted blocks whose header proposer and signature
	// nobody ever checks (the envelope-proposer equality check was removed
	// for C-2's re-proposals); the driver-less hole is closed by what the
	// CONSTRUCTOR installs rather than by conventions about wiring: a
	// prevotable engine arises only from a visible, deliberate replacement
	// of the refusal through SetValidate (the driver's
	// SetValidate(... chain.ValidateNext)), never from forgetting one.
	// Production engines always carry a chain, so
	// they always replace the refusal with the real seam; a driver-less
	// engine has no chain to agree with, and its honest verdict on any block
	// is refusal.
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
	// at arrival. Since C-3 an in-window future vote is ALSO retained in its
	// round's set; this map is what carries the evidence for rounds OUTSIDE
	// the buffer, and the one piece of information the round ladder needs:
	// the committee has already moved past this round. On
	// timeout the engine JUMPS its round - bounded, evidence-gated resync:
	// strictly more than ONE THIRD OF TOTAL POWER (the same Byzantine budget
	// every power fraction in this package is measured against, and the same
	// TotalPower/quorum arithmetic the committee provides) must have attested
	// a higher round, so the jump cannot be driven by any coalition that does
	// not already exceed the committee's actual fault budget. A committee
	// whose round counters drift apart (rebuilt engines re-arm their ladders
	// mid-height) resynchronises through this; without it a follower can sit
	// one round behind forever, dropping every proposal as wrong-round while
	// every leader drops its vote back the same way - a fully live committee
	// that never polkas again (observed with the capped round ladder the
	// audit's C-2 asks for).
	//
	// One entry per member, replaced only forward: bounded memory. The gate
	// is POWER, not a seat count: committee seats and BFT fault budget are
	// different quantities on a weighted committee, where floor(n/3)+1 seats
	// can hold strictly less than a third of the power and, conversely, far
	// fewer seats than that can hold more than a third. Reset only by a new
	// engine (per height); a round change deliberately keeps it.
	future map[int]*Vote

	// persistLock, when non-nil, is called the instant the lock moves: the
	// driver installs it after construction so the promise is made durable
	// BEFORE the precommit that records it is signed or shipped (a promise
	// broadcast before it can survive a crash is the promise a restart
	// loses). The engine itself performs no I/O - like propose, this is an
	// injected seam, and it stays nil for engines built without a driver,
	// whose lock is in-memory only, exactly as before this field existed.
	persistLock func(height uint64, round uint32, id [32]byte)

	// persistRound, when non-nil, is called the instant the engine ENTERS a
	// later round, before it emits any vote in that round (audit C-3). It is
	// the round-persistence half of the same injected seam: a restart must
	// resume at the round the crashed validator had reached, not re-enter
	// round 0 for a height already contested. Nil for engine-only fixtures,
	// exactly as persistLock is.
	persistRound func(height uint64, round uint32)

	committed    [32]byte
	hasCommitted bool
	// commitRound is the round whose precommit quorum committed committed.
	// With multi-round sets the commit need not be the CURRENT round (a late
	// quorum for a round already left), and the driver's certificate archive
	// needs to know which round's votes are the evidence.
	commitRound uint32
	out         []Outbound
}

// roundSets is one round's two tallies at this engine's height. Keeping them
// together is what lets a round change carry BOTH kinds of vote forward: a
// buffered future round's prevotes and precommits become current the moment
// the engine enters that round, with no re-add and no re-verify.
type roundSets struct {
	prevotes   *VoteSet
	precommits *VoteSet
	// proposal is the block this engine accepted (or built) while it was IN
	// this round, retained for as long as the round's tallies are. It exists
	// because a precommit quorum can complete for a round the engine has
	// already LEFT (audit C-3 keeps those tallies), and a commit needs the
	// block BYTES to append: enterRound clears e.proposal on the round
	// change, so without this copy a late quorum would commit an ID the
	// driver could not append - and, because step becomes StepCommit, one the
	// engine could never recover from. The round window prunes this with the
	// tallies, so retention is bounded by the same pastVoteRounds+1 rounds.
	proposal *types.Block
}

// errNoValidationSeam is what NewEngine's default seam returns. It is the
// failure mode of a driver-less engine, not a judgement about the block:
// without a chain behind it, no engine can honestly judge a block's chain
// validity, and refusing is the only safe verdict (audit round 3, F3).
var errNoValidationSeam = errors.New("consensus: no validation seam wired: an engine without a chain cannot judge block validity and must not prevote it")

// refuseWithoutSeam is the validate seam NewEngine installs by default: it
// refuses every block, so a driver-less engine nil-prevotes instead of
// prevoting for bytes whose header proposer and signature nobody verified.
// The driver replaces it with the chain's ValidateNext in newEngine; tests
// that model an acceptable block replace it with an explicitly accepting
// validator. Both replacements are visible assignments - the refusal cannot
// be bypassed by forgetting to wire something, only by writing code that
// overwrites it.
func refuseWithoutSeam(*types.Block) error { return errNoValidationSeam }

// SetValidate replaces the engine's validation seam - the exported half of the
// F3 enforcement. NewEngine's default refuses every block, so an engine built
// through the exported constructor can never prevote FOR a block nobody judged;
// only a visible call to THIS method, passing a real validator, can change that.
// A nil function is refused with a panic at the assignment site: the one
// assignment that would restore the old driver-less hole (prevote with no
// chain judgement at all) cannot be made accidentally - it crashes the
// constructor-shaped misuse immediately instead of quietly prevoting
// unverified bytes.
func (e *Engine) SetValidate(fn func(*types.Block) error) {
	if fn == nil {
		panic("consensus: a nil validation seam would prevote blocks nobody judged; replace the default refusal with a real validator or leave it in place")
	}
	e.validate = fn
}

// NewEngine creates an engine that will validate height, whose parent is parent,
// signing with priv.
//
// The returned engine carries NO validation seam except the default refusal:
// the caller - the driver, in production - must assign a real validator (the
// chain's ValidateNext) through SetValidate before the engine can prevote FOR
// any block. See the validate field.
func NewEngine(cfg Config, height uint64, parent [32]byte, priv ed25519.PrivateKey, propose ProposeFn) *Engine {
	pub := priv.Public().(ed25519.PublicKey)
	e := &Engine{
		cfg: cfg, priv: priv, pub: pub,
		idx: cfg.IndexOf(pub), parent: parent, propose: propose,
		height:   height,
		validate: refuseWithoutSeam,
		// The lock's zero value is round 0, which is a REAL round, so "unlocked"
		// must be set explicitly. Forgetting this makes a fresh validator believe
		// it is locked on the zero block and prevote for nothing.
		lk:   lock{lockedRound: -1},
		step: StepPropose,
		sets: make(map[uint32]*roundSets),
	}
	// Bind round 0's empty tallies through the same path every later round
	// takes, so prevotes/precommits and sets[e.round] cannot disagree about
	// which VoteSet is current.
	e.bindRound(0)
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
//     exactly once for that round. The nil prevote is the honest RECORD of the
//     round's outcome, not the mechanism that ends the round: with no
//     nil-polka rule in this milestone (audit C-12) the round is left because
//     the timer fired, not because nil weight reached anything - and no
//     decision anywhere reads NilPower. A validator that already voted this
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
//
// The returned error (audit C-11) is the vote this timeout owed being refused -
// a signing key outside the committee, or a self-tally that refused the vote.
// The driver refuses such a key at construction, so the error is unreachable
// for a correctly built driver; returning it keeps the engine from panicking on
// the one shape its exported constructor cannot reject.
func (e *Engine) OnTimeout(ev TimeoutEvent) error {
	if ev.Height != e.height {
		return nil // another height: behind us or not reached, not ours to judge
	}
	if ev.Round != e.round {
		return nil // a stale re-fire for a round already left, or one not yet entered
	}
	if e.step == StepCommit {
		return nil // the height is decided; the driver moves to the next height
	}
	if e.round == math.MaxUint32 {
		// e.round+1 would wrap to 0 and resurrect a long-settled round's
		// tallies. There is no next round to enter; unreachable under any real
		// timeout schedule, but the wrap must not be silent.
		return nil
	}
	if e.step == StepPropose && e.proposal == nil {
		// No usable proposal arrived before the round ran out: the one vote
		// this round is owed is NIL. Emitted while e.round is still the round
		// that is ending, so the vote is signed and tallied as that round's.
		if err := e.emitVote(MsgPrevote, [32]byte{}); err != nil {
			return err
		}
	}
	// The vote, if any, is cast: StepPrevote and StepPrecommit validators voted
	// earlier through maybePrevote / maybePrecommit, and a validator holding a
	// proposal whose justification failed stays silent by the gate's rule (no
	// vote may rest on evidence that does not exist).
	//
	// Jump the ladder on evidence before entering the next round: when
	// committee members holding strictly more than one third of the total
	// power signed prevotes at rounds ahead of the one that just ended, the
	// committee IS that far ahead, and stepping +1 would only keep this
	// validator exactly one round behind a committee it can never catch -
	// its own votes and every peer's proposal for the rounds it keeps missing
	// are dropped as wrong-round in BOTH directions, forever. The target is
	// the highest round at which that much power sits, and it is additionally
	// capped a bounded stride ahead of the current round (see jumpTarget):
	// the evidence can never name a round the engine chases to its own
	// ejection. Without evidence the ladder escalates by one, as before.
	if target := e.jumpTarget(); target > e.round {
		return e.enterRound(target)
	}
	return e.enterRound(e.round + 1)
}

// jumpTarget reports the round the engine should enter on a timeout when its
// future-round evidence says the committee has moved beyond the next round,
// and 0 when there is none (0 is never a valid target: the engine is at round
// >= 0 and only jumps strictly forward).
//
// The criterion is a POWER threshold, not a seat count: the members whose
// combined power can leave the rest of the committee short of quorum must have
// attested a round ahead of the current one. It uses the committee's own
// TotalPower/Quorum arithmetic, so a weighted committee is measured in its real
// currency. A seat count would be wrong twice: on a weighted genesis a
// coalition holding strictly UNDER a third of the power can occupy
// floor(n/3)+1 SEATS (demonstrated on n=7, powers {1,1,1,2,2,2,2}: three
// power-1 seats hold 3/11 ≈ 0.27 of power yet fill the member gate exactly),
// and a coalition holding MORE than a third can do it with fewer seats.
//
// The target is the highest round at which that bulk sits: entries are walked
// from the furthest attested round down, accumulating each member's power
// (one entry per member, highest round only - a member's repeat claims cannot
// multiply its weight), and the target is the FIRST round at which the
// accumulated power reaches the bar. Before that round the accumulated power
// could not block a quorum, so the target is bounded above by some honest
// member's own attested round: a sub-bar coalition cannot pull the target past
// the furthest honest attestation, and - bar the whole-committee case below - a
// single Byzantine validator, whose power the genesis power cap holds under one
// quarter of total, cannot reach the bar at all. One jump moves to the
// evidence's bulk; further evidence, on later timeouts, moves further.
//
// The target is additionally CAPPED at maxRoundEscalation rounds ahead of the
// engine's own round. The gate is correct against the committee's fault
// budget, but "correct" only bounds WHO can name the target, not the number
// they name: a coalition that legitimately exceeds one third can still
// attest an absurd round - and so can one buggy honest validator - and
// jumping to math.MaxUint32 would park the engine in OnTimeout's wrap guard,
// ejecting it from the height silently. One bounded stride per timeout is all
// a resync onto a live committee needs, and the cap keeps round numbers
// reachable only by round COUNTS of timeouts, never by one jump.
//
// The cap is a bound on the JUMP, never on the ladder, and the division of
// labour matters: this gate needs more than a third of the power to attest, so
// it cannot fire at all when the live set is exactly quorum and one live seat
// is ahead (three of four seats: one seat against a bar of two). That shape is
// closed by the DRIVER's timeout ladder instead, which is strictly increasing
// in the round: the engine behind fires sooner and gains a round at a time,
// with no reference to any claim. See Driver.Tick.
func (e *Engine) jumpTarget() uint32 {
	if len(e.future) == 0 {
		return 0
	}
	// The bar: the smallest attested power whose absence leaves the REST of
	// the committee short of quorum, i.e. total - quorum + 1. That is the exact
	// complement of the quorum, and it is what makes a jump a RESYNC rather
	// than a gamble: if that much power sits in a higher round, no round this
	// validator can reach holds a completable quorum, so waiting cannot help.
	// The subtraction cannot underflow - quorumFor(total) <= total for every
	// total - so the bar is always >= 1.
	//
	// It evaluates to ceil(total/3): strictly more than one third when
	// total % 3 != 0, and EXACTLY one third when total % 3 == 0. The previous
	// bar, total/3 + 1, was strictly more than one third in every case, and
	// that single unit was the whole defect at total = 3k. There a
	// quorum-blocking set is exactly total/3, so the smallest set that can
	// stop the rest from reaching quorum could never reach the bar - the bar
	// and the quorum were not complementary. On three equal seats
	// (--validators 3: cap 1/1, quorum 3 = ALL of them) one seat ahead could
	// therefore never trigger the resync while that same one seat's absence
	// blocked every quorum, so a round divergence past the timeout cap left
	// the chains at height 0 with no recovery while an undiverged control on
	// the same fixture committed. Six equal seats had the identical gap
	// (bar 3 against a blocking set of 2); totals 4, 5 and 7 were already
	// complementary.
	//
	// The one-Byzantine property the higher bar existed for is kept wherever
	// it can hold. The genesis power cap is 1/4 of total above the four-seat
	// floor and ceil(total/3) > total/4, so on every committee of four or more
	// no single member reaches the bar. The sole exception is a committee whose
	// quorum is the WHOLE committee (quorum == total, which arithmetic fixes at
	// total <= 3): there one member's absence already blocks every quorum, so
	// that member holds full stall power whatever the bar is, and keeping the
	// bar above it buys no safety - only the unrecoverable stall. The bar drops
	// to a single member there, and that limitation is stated for the three-Pi
	// acceptance shape in scripts/deploy/README.md.
	bar := e.cfg.TotalPower() - e.cfg.Quorum() + 1
	if quorum := e.cfg.Quorum(); quorum == e.cfg.TotalPower() {
		bar = 1
	}

	// Walk the attested members from the furthest round down, accumulating
	// power; stop at the first round whose prefix reaches the bar. The walk
	// is an insertion sort over at most one entry per member, so it costs
	// O(k^2) in attested members on a single timeout decision - a committee
	// member count, not a message count.
	type attestation struct {
		round uint32
		power uint64
	}
	rounds := make([]attestation, 0, len(e.future))
	for idx, v := range e.future {
		rounds = append(rounds, attestation{round: v.Round, power: e.cfg.Committee[idx].Power})
	}
	for i := 1; i < len(rounds); i++ {
		for j := i; j > 0 && rounds[j-1].round < rounds[j].round; j-- {
			rounds[j-1], rounds[j] = rounds[j], rounds[j-1]
		}
	}

	var cum uint64
	for _, a := range rounds {
		var carry uint64
		cum, carry = bits.Add64(cum, a.power, 0)
		if carry != 0 {
			// A wrapped accumulation means unvalidated committee powers; a
			// wrapped comparison would invent or miss a crossing. Refuse to
			// jump rather than act on wrapped arithmetic - the same posture
			// the committee's own overflow guard takes.
			return 0
		}
		if cum < bar {
			continue
		}
		if a.round <= e.round {
			return 0 // the bulk sits behind us: no evidence the committee is ahead
		}
		// The bounded stride: never leave the current round by more than
		// maxRoundEscalation in one jump (see the function comment). The wrap
		// guard below covers e.round close enough to MaxUint32 that the sum
		// would wrap; at e.round == MaxUint32 OnTimeout has already returned.
		limit := e.round + maxRoundEscalation
		if limit < e.round { // wrapped
			limit = math.MaxUint32
		}
		if a.round > limit {
			return limit
		}
		return a.round
	}
	return 0
}

// setsFor returns the vote tallies for round, creating empty ones if this is
// the first time the round is seen. It is total over the rounds the engine may
// retain: callers that must not grow the buffer beyond its window check
// withinWindow first. Every call for a round already in the set hands back the
// SAME VoteSets, so votes buffered while the round was ahead survive the
// engine's arrival in it.
func (e *Engine) setsFor(round uint32) *roundSets {
	s := e.sets[round]
	if s == nil {
		s = &roundSets{
			prevotes:   NewVoteSet(e.cfg, e.height, round, MsgPrevote),
			precommits: NewVoteSet(e.cfg, e.height, round, MsgPrecommit),
		}
		e.sets[round] = s
	}
	return s
}

// bindRound makes round current, pointing prevotes/precommits at its retained
// tallies (creating empty ones on first use). It is the one place e.round and
// the current VoteSets move together, so no caller can leave sets[e.round]
// disagreeing with the fields the rest of the engine reads.
func (e *Engine) bindRound(round uint32) {
	e.round = round
	s := e.setsFor(round)
	e.prevotes = s.prevotes
	e.precommits = s.precommits
}

// withinWindow reports whether a round's tallies are retained: at most
// futureVoteRounds ahead of the engine's own, or pastVoteRounds behind it.
// The two windows are the whole memory bound on the multi-round buffer (see
// the sets field); a vote outside them is dropped rather than accumulated.
func (e *Engine) withinWindow(round uint32) bool {
	if round >= e.round {
		return round-e.round <= futureVoteRounds
	}
	return e.round-round <= pastVoteRounds
}

// pruneRounds deletes the tallies of every round outside the retention
// window. It runs on every round change - the only event that can move the
// window - so the map can never hold a round the engine will not revisit.
// The current round is always inside its own window and is never pruned.
func (e *Engine) pruneRounds() {
	for r := range e.sets {
		if !e.withinWindow(r) {
			delete(e.sets, r)
		}
	}
}

// enterRound moves to a later round, resetting the per-round tally. The lock
// deliberately SURVIVES the round change: that is the whole point of it. The
// future-round evidence survives too: it is per-HEIGHT observation, and the
// rounds the ladder may still jump to are exactly the ones it records.
//
// Entering adopts any votes already buffered for the round (audit C-3): a
// follower that jumped onto a live committee finds the round's prevotes and
// precommits in hand, so the two decisions are re-run against them - a
// buffered polka is precommitted (and locks), and a buffered precommit quorum
// commits, immediately rather than on some further arrival. The round itself
// is made durable BEFORE either emission (persist-before-emit, the same
// ordering as the lock): a vote cast in round r must not outlive a crash that
// forgets the validator ever reached r.
func (e *Engine) enterRound(round uint32) error {
	e.bindRound(round)
	e.step = StepPropose
	e.proposal = nil
	e.proposalEn = nil
	e.pruneRounds()
	if e.persistRound != nil {
		e.persistRound(e.height, round)
	}
	if err := e.maybePrecommit(); err != nil {
		return err
	}
	return e.maybeCommit()
}

// restoreRound reinstates the round a previous life of this engine had
// reached (audit C-3): the driver reads it from the store and hands it here
// when a crashed validator must not re-enter round 0 for a height it had
// already contested.
//
// It is deliberately NOT enterRound: a restore emits nothing, persists
// nothing (the record already exists on disk) and runs no decision - a fresh
// engine holds no votes to decide on. It goes through the same bindRound the
// live path uses, so the restored round's tallies are empty in exactly the
// way a fresh round's are. A persisted lock at a round LATER than the
// persisted round - impossible on a healthy log, because the round is written
// before the precommit that moves the lock, but possible if the round log's
// tail was torn while the lock log's was not - raises the floor: the engine
// never resumes BEHIND its own promise. Safety never depended on the round
// (the lock carries it); this only avoids a needless stall.
func (e *Engine) restoreRound(round uint32) {
	if lr := e.lk.round(); lr >= 0 && int64(round) < lr {
		round = uint32(lr)
	}
	if round == e.round {
		return
	}
	e.bindRound(round)
	e.pruneRounds()
}

// retainedRoundsOther returns every round with retained tallies except the
// engine's own, in ascending order. Ascending is the deterministic choice: if -
// impossibly for an honest committee - two rounds each held a precommit
// quorum, the EARLIER one is the one the committee reached first, and every
// validator reading its own sets in this order agrees on it. Future rounds are
// included: a precommit quorum there is as decisive as one behind us, and
// acting on it at formation is what keeps a later round jump from pruning the
// quorum before it is noticed.
func (e *Engine) retainedRoundsOther() []uint32 {
	rounds := make([]uint32, 0, futureVoteRounds+pastVoteRounds)
	for r := range e.sets {
		if r != e.round {
			rounds = append(rounds, r)
		}
	}
	for i := 1; i < len(rounds); i++ {
		for j := i; j > 0 && rounds[j-1] > rounds[j]; j-- {
			rounds[j-1], rounds[j] = rounds[j], rounds[j-1]
		}
	}
	return rounds
}

// committedPrecommits returns the precommit votes of the round whose quorum
// committed this engine's block, or nil if there is none. It is the
// certificate source the driver archives: with multi-round sets the committing
// round need not be the current one, so reading e.precommits (which points at
// the CURRENT round after a later enterRound) would hand the wrong votes -
// or none - to whoever serves the certificate to a catching-up peer.
func (e *Engine) committedPrecommits() []*Vote {
	if s := e.sets[e.commitRound]; s != nil {
		return s.precommits.Votes()
	}
	return nil
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
// signed here, names the engine's own height and round, and its key is used to
// build the committee membership the engine was constructed with. A key that is
// NOT in the committee is checked FIRST and returned as an error (audit C-11):
// the engine refuses to sign a vote its own tally could never admit, instead of
// emitting one and panicking when the tally refuses it. CheckMembership is the
// same check at construction time, so a driver refuses such a key before it
// ever drives the engine (see NewDriver); this guard is what keeps a
// driver-less engine from panicking.
func (e *Engine) emitVote(typ MsgType, id [32]byte) error {
	if err := e.CheckMembership(); err != nil {
		return err
	}
	v := &Vote{Type: typ, Height: e.height, Round: e.round, BlockID: id, Validator: e.pub}
	h := v.SigningHash()
	v.Sig = crypto.Sign(e.priv, h[:])
	data := EncodeVote(v)
	e.emit(data)
	if err := e.OnMessage(data); err != nil {
		return fmt.Errorf("consensus: the engine's own vote was refused by its own tally: %w", err)
	}
	return nil
}

// CheckMembership reports whether the engine's signing key is one of the
// committee's seats. It is the error the engine's construction cannot return
// (NewEngine keeps its signature): NewDriver calls it and refuses to build a
// driver whose validator holds no seat, and emitVote re-checks it before
// signing anything. The committee index is computed once at construction; this
// is the one place the engine reads it, so a future change to committee
// membership cannot leave it silently unused.
func (e *Engine) CheckMembership() error {
	if e.idx < 0 {
		return fmt.Errorf("%w: the engine's signing key (%x) is not in the committee of %d seats; it cannot sign a vote any member would tally",
			ErrNotValidator, e.pub, len(e.cfg.Committee))
	}
	return nil
}

// OnMessage processes one wire message. An error means the message was malformed
// or unusable; the caller may drop it and carry on.
//
// A nil return deliberately covers two outcomes: a message this engine ACCEPTED
// and a well-formed message that was not for this engine - another height,
// another round, a proposal from someone other than the round's proposer, or a
// duplicate. The distinction is not observable at any caller (audit C-17): the
// router drops an error and keeps a nil-returning message, and in both cases a
// foreign message leaves the engine's state unchanged. Inventing an error for
// "not mine" would report a healthy network's ordinary traffic as malformed,
// the same misreporting ErrWrongHeightRound's comment warns against one level
// down.
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
	// The proposer check runs BEFORE Verify (audit C-8's membership-first
	// discipline, on the engine side): the round's proposer is drawn from the
	// committee, so a key that is not it is not a member either, and an
	// unauthenticated frame must not cost an Ed25519 evaluation just to be
	// discarded for the wrong key. A proposal from the real proposer is still
	// fully verified below - the reorder skips only the frames the very next
	// check would drop anyway.
	if string(p.Validator) != string(e.Proposer()) {
		return nil // not the proposer for this round (and not a member); ignore it
	}
	if err := p.Verify(); err != nil {
		return err
	}
	if e.proposal != nil {
		return nil // first proposal wins, so the choice is deterministic
	}
	e.proposal = &p.Block
	e.proposalEn = p
	// Retain the bytes with this round's tallies (audit C-3's window): a
	// precommit quorum for this round can still complete after enterRound
	// cleared e.proposal on the way to a later round, and the commit then
	// needs these bytes to append. See roundSets.proposal.
	e.setsFor(e.round).proposal = e.proposal
	return e.maybePrevote()
}

// noteFuture records, per member, the highest round at which that member has
// signed a vote at this height, for the round ladder's evidence gate. It is
// only ever reached with a member index an IndexOf already returned.
func (e *Engine) noteFuture(idx int, v *Vote) {
	if idx < 0 {
		return
	}
	if cur, seen := e.future[idx]; !seen || v.Round > cur.Round {
		if e.future == nil {
			e.future = make(map[int]*Vote)
		}
		e.future[idx] = v
	}
}

// onVote tallies one vote, in its own round (audit C-3), when that round is
// within the retention window; a future round's vote is buffered into that
// round's set (and a precommit quorum there commits at once), and a past
// round's precommit set is kept so a late quorum still commits. A vote outside
// the window is dropped, but a FUTURE one is still recorded as round-ladder
// evidence (the jump may name a round the buffer no longer holds).
//
// Membership is checked BEFORE any Ed25519 verification on every path (audit
// C-8): VoteSet.Add is where an in-window vote is verified, and it checks the
// committee first; the out-of-window path below checks IndexOf itself. A
// non-member's frame therefore costs no signature evaluation and reaches no
// tally, whether it names the current round, a buffered one, or one far ahead.
func (e *Engine) onVote(v *Vote) error {
	if v.Height != e.height {
		return nil // another height: behind us or not reached, not ours to judge
	}
	if v.Round > e.round && !e.withinWindow(v.Round) {
		// Outside the buffer, ahead of us: the vote is not retained, but the
		// member's claim is still evidence the committee has moved on.
		// Membership first (audit C-8): a free linear scan against a
		// stranger's frame, an Ed25519 verification only for a member's vote.
		if idx := e.cfg.IndexOf(v.Validator); idx >= 0 && v.Verify() == nil {
			e.noteFuture(idx, v)
		}
		return nil
	}
	if !e.withinWindow(v.Round) {
		return nil // older than the retained window: the committee has left it
	}
	s := e.setsFor(v.Round)
	switch v.Type {
	case MsgPrevote:
		added, err := s.prevotes.Add(v)
		if err != nil {
			return err
		}
		if !added {
			return nil // a duplicate: its weight is already counted
		}
		switch {
		case v.Round > e.round:
			e.noteFuture(e.cfg.IndexOf(v.Validator), v)
		case v.Round == e.round:
			// A polka at the round we are in is what we precommit. Votes
			// buffered for a round we have ALREADY left cannot drive a
			// precommit now; enterRound re-runs this when it adopts them.
			if err := e.maybePrecommit(); err != nil {
				return err
			}
		}
	case MsgPrecommit:
		added, err := s.precommits.Add(v)
		if err != nil {
			return err
		}
		if !added {
			return nil
		}
		switch {
		case v.Round > e.round:
			// Buffered for a round we are not in yet: still ladder evidence,
			// and a precommit quorum among these buffered votes is a commit
			// like any other (audit C-3) - maybeCommit adopts the decided
			// round so a late proposal for it can still be appended.
			e.noteFuture(e.cfg.IndexOf(v.Validator), v)
			return e.maybeCommit()
		default:
			// Current OR past: a quorum here is a commit (audit C-3).
			return e.maybeCommit()
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
func (e *Engine) maybePrevote() error {
	if e.step != StepPropose && e.step != StepPrevote {
		return nil
	}
	if e.proposal == nil || e.proposalEn == nil {
		return nil
	}
	id := e.proposal.ID()
	validRound, err := e.verifyJustification(e.proposalEn)
	if err != nil {
		return nil // an unjustified proposal is not prevoted at all - not even nil: no
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
			return e.emitVote(MsgPrevote, [32]byte{})
		}
	}
	if !e.lk.canPrevote(e.round, id, validRound) {
		// The lock refuses this block. Prevote NIL rather than staying silent:
		// the nil prevote is this validator's honest record that the round
		// produced nothing it could accept, and - once a nil-polka rule exists
		// - it is the weight such a rule would need. In THIS milestone it does
		// not itself end the round (the timeout does; see OnTimeout) and no
		// decision reads NilPower (audit C-12).
		//
		// The step is recorded BEFORE the emission: emitVote tallies the engine's
		// own vote, and a late-arriving peer prevote may already sit one vote
		// short of the polka - the self-tally can synchronously re-enter
		// maybePrecommit while this frame is on the stack. Writing the step after
		// the emission would clobber the deeper transition.
		e.step = StepPrevote
		return e.emitVote(MsgPrevote, [32]byte{})
	}
	// Same ordering as the nil branch above: the step goes down first, so the
	// re-entrant precommit-or-commit the own prevote may trigger inside
	// emitVote lands on top of a consistent mid-state instead of being
	// overwritten here.
	e.step = StepPrevote
	return e.emitVote(MsgPrevote, id)
}

func (e *Engine) maybePrecommit() error {
	if e.step == StepPrecommit || e.step == StepCommit {
		return nil
	}
	id, ok := e.prevotes.AnyQuorum()
	if !ok {
		return nil
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
	return e.emitVote(MsgPrecommit, id)
}

// maybeCommit commits the first block with a precommit quorum, in the current
// round or in ANY other retained round - earlier or buffered ahead (audit
// C-3). Committing from an earlier round is the whole point of keeping past
// precommit sets: a quorum can complete after the engine has already moved on
// - enterRound no longer discards it - and a commit is a commit whether it is
// noticed in round r or in round r+1. Committing from a buffered FUTURE round
// is the same evidence seen from the other side: >2/3 precommitted there, so
// the height is decided and the engine adopts that round (commitAt) rather
// than waiting to be stepped into it - which also means a later jump can never
// prune a decisive quorum before it is acted on.
//
// SAFETY: a commit is a quorum (>2/3 of power) of precommits for one block at
// one round. Retaining other rounds and reading them here does not weaken
// that: it changes WHEN the same evidence is noticed, not what it proves.
// More than one third of the power is honest, so a quorum at any round means
// more than one third of the power both prevoted and precommitted that exact
// block at that round (maybePrecommit precommits only a block with a prevote
// polka, and locks on it). A quorum for a CONFLICTING block must therefore
// contain more than one third of the power that never joined the first, and
// every honest validator it needs was locked on the first block and can
// prevote the conflicting one only on a VERIFIED polka from a strictly later
// round; that polka in turn needs the honest locked weight to have unlocked,
// which is impossible for the first round at which a conflicting polka
// appears. The engine-level pin is TestTwoBlocksCannotCommitAtOneHeight and
// the lock rule itself is TestLockedValidatorPrevotesOnlyItsBlockOrANewerRound.
//
// The current round is checked first, then the others ascending: the order is
// only for determinism, since two honest quorums for two different blocks at
// one height cannot exist.
func (e *Engine) maybeCommit() error {
	if e.hasCommitted {
		return nil
	}
	if id, ok := e.precommits.AnyQuorum(); ok {
		return e.commitAt(id, e.round)
	}
	for _, r := range e.retainedRoundsOther() {
		s := e.sets[r]
		if s == nil {
			continue
		}
		if id, ok := s.precommits.AnyQuorum(); ok {
			return e.commitAt(id, r)
		}
	}
	return nil
}

// commitAt records the commit of id and the round whose precommit quorum
// supplied it. The round is remembered because the commit certificate the
// driver archives is that round's precommit votes - see committedPrecommits.
//
// When the quorum sits in a round AHEAD of the engine's own, the engine ADOPTS
// that round: >2/3 of the power precommitted there, so that is where the
// committee is, and adopting it lets a proposal for the decided round - which
// may still be in flight and would otherwise be refused as the wrong round -
// arrive and be appended. The adopted round is persisted like any other round
// entry, before the commit is recorded. The step is set last, so nothing the
// adoption touches can be overwritten by a post-commit transition; once
// committed the engine emits no further vote for this height.
func (e *Engine) commitAt(id [32]byte, round uint32) error {
	if round > e.round {
		e.bindRound(round)
		e.pruneRounds()
		// The adopted round is not the round e.proposal came from: holding a
		// stale proposal would make onProposal refuse the adopted round's own
		// proposal ("first proposal wins") and strand the height with a
		// committed ID and no bytes. Keep it only when it IS the committed
		// block, where it is exactly the bytes the driver must append.
		if e.proposal != nil && e.proposal.ID() != id {
			e.proposal = nil
			e.proposalEn = nil
		}
		if e.persistRound != nil {
			e.persistRound(e.height, round)
		}
	}
	e.committed, e.hasCommitted = id, true
	e.commitRound = round
	e.step = StepCommit
	return nil
}

// committedBlock returns the block bytes for a committed ID this engine still
// holds, or nil when it holds none. Committing an ID is a safety decision the
// engine takes on the precommit evidence alone (a quorum can complete for a
// round whose proposal this engine never received, or has already left and
// cleared), but appending the block is a separate step the DRIVER owns - and
// it must not depend on e.proposal, which enterRound clears on every round
// change. The bytes can survive in three places, all already bounded:
//
//   - e.proposal, when the commit is in the round the engine is in;
//   - e.sets[e.commitRound].proposal, the round's retained copy (audit C-3's
//     window), which is what makes a LATE quorum for a round the engine has
//     left appendable;
//   - e.lockedBlock, the proof-of-lock bytes C-2 retains for a locked block.
//
// The caller still runs Append, which re-validates the block against the
// chain - so a wrong or stale copy cannot enter the chain; this only decides
// whether there is something to offer. Nil means the bytes are genuinely
// absent; the driver parks and the catch-up path (a peer that did append)
// is what recovers it.
func (e *Engine) committedBlock(id [32]byte) *types.Block {
	if e.proposal != nil && e.proposal.ID() == id {
		return e.proposal
	}
	if s := e.sets[e.commitRound]; s != nil && s.proposal != nil && s.proposal.ID() == id {
		return s.proposal
	}
	if e.lockedBlock != nil && e.lockedBlock.ID() == id {
		return e.lockedBlock
	}
	return nil
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
	// Retain the bytes with this round's tallies (audit C-3's window), so a
	// quorum that completes after the engine has left the round can still be
	// appended - see roundSets.proposal.
	e.setsFor(e.round).proposal = e.proposal
	e.emit(EncodeProposal(p))
	// The proposer prevotes its own block once it has "received" it, which
	// maybePrevote does for us. A transport never loops a sender's message back,
	// so this is the only chance the proposer gets.
	return e.maybePrevote()
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
	// A proposal is re-proposed FROM a later round than the polka it carries:
	// its ValidRound must be STRICTLY earlier than the round it is offered in
	// (audit C-9). Tendermint's validValue rule is validRound < round, and the
	// bound is free to enforce: no honest proposer can offer a block whose
	// polka is dated to the round the block is being proposed in. A proposer
	// that did would be claiming a quorum that could not have formed before
	// its own proposal went out - a round's polka is formed by the prevotes
	// that proposal provokes - so accepting it would let a Byzantine proposer
	// dress a bare round number as evidence. Rejecting it changes no honest
	// behaviour: every fresh proposal claims -1 and every re-proposal names
	// the earlier round its polka formed in.
	if p.ValidRound >= int64(p.Round) {
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
