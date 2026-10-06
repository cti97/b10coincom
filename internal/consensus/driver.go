package consensus

import (
	"crypto/ed25519"
	"fmt"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/store"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/types"
)

// Driver connects one engine to a Transport and to chain persistence.
//
// It owns the two things the engine refuses to own (Design Decision 1): the
// clock, which Tick advances and turns into TimeoutEvents, and the outgoing
// queue, which carries Drain's messages to the transport. It owns the commit
// as well (Design Decision 8): committing is the ONLY place consensus mutates
// the chain. The engine never speculatively applies a block, so a stalled
// height leaves the chain untouched and a node that disagrees with a proposal
// simply reports a lower height than the peers that accepted it.
//
// When the driver is given a mempool it is also the transaction source for its
// own proposals: it takes from the pool the way node.RunOnce does and filters
// the batch through the SAME chain policy (Chain.SelectApplicable), so there
// is one policy for which transactions a block carries across both block
// producers. A nil pool is a node with no transaction path - it proposes
// empty blocks, which is what the M3 simnet validators did and what a
// validator running before its RPC or relay attaches a pool continues to do.
type Driver struct {
	cfg  Config
	ch   *chain.Chain
	pool *mempool.Mempool
	priv ed25519.PrivateKey
	tp   transport.Transport
	eng  *Engine

	// CommitWitness, when set, is called the moment a block is committed AND
	// appended, with the precommit votes that committed it: the certificate a
	// catch-up server serves to catching-up peers. It carries exactly the
	// evidence the live commit used (`precommits.AnyQuorum()`), so the served
	// certificate and the commit decision can never disagree. Nil is the
	// unwired default: nothing else changes, the commit path is byte-identical
	// with the witness absent. Like persistLock this is an injected seam -
	// whoever builds the driver and knows the syncer to serve from wires it;
	// the engine performs no I/O and reads no other component.
	CommitWitness func(height uint64, round uint32, votes []*Vote)

	// pending holds the transactions this driver has TAKEN from its mempool
	// for the proposal at the current undecided height and that no committed
	// block has carried yet. Take removes what it returns, so without this
	// record the batch would evaporate the first time a proposal's round
	// timed out: the pool no longer holds the transactions and nothing else
	// does - they existed only inside an unsigned block nobody agreed on.
	// reclaimPending puts an uncommitted batch back before the next build
	// (this height's or the first build after a foreign commit), and flush
	// clears it only when the block that appends is the very block pending
	// was built into, so a batch is always findable until it lands: in the
	// pool, in pending, or committed. Nil-pool drivers never set it.
	pending []types.Tx

	// pendingID is the ID of the block pending was built into. flush clears
	// the batch only when the block that appends IS this one: a peer's
	// proposal reaching quorum instead - this node's proposal timed out or
	// was lost and a foreign one succeeded - must leave the batch pending,
	// or Take's removal would have lost it from both the pool and the
	// committed block. The next height's first build reclaims it, and
	// SelectApplicable there evicts whichever of its transactions the
	// foreign block already applied.
	pendingID [32]byte

	// now is the driver's clock reading in virtual milliseconds: the last
	// value Tick was called with. The engine reads no clock; this one field
	// is the only time the driver measures, which is what keeps a failing run
	// replayable from its seed.
	now int64
	// timeoutAt is the reading at which the engine's current round expires.
	timeoutAt int64
	// appendRefused records that the chain REFUSED this engine's committed
	// block, so flush never offers it again. The refusal is deterministic and
	// permanent while the engine stays: this driver is M3's only chain writer,
	// the chain head therefore never moves on its own, and Append re-validates
	// against that head - the same block offered again fails for the identical
	// reason. Retrying it on every flush would take the chain's write lock
	// forever for no possible effect, so the retry stops instead; the node
	// stays parked at the undecided height (Design Decision 8: a refused block
	// is never silently skipped, because advancing past it would diverge this
	// node from every peer that accepted it). A future milestone that gives a
	// node a way to adopt a peer's block must clear this flag when it does.
	appendRefused bool
}

// maxRoundEscalation caps the timeout ladder (audit C-2): a round's deadline
// is TimeoutBase + min(round, maxRoundEscalation)*TimeoutStep from the clock
// reading, so an undecided height settles into a FIXED round cadence instead
// of growing its timeouts without bound. The escalation exists to let slow
// committees converge; past this many rounds it has done all the good it can
// and only makes recovery after a stall linearly slower. With the shipped
// defaults (200ms base, 100ms step) rounds top out at 1.8s; a testnet keeps
// proposing steadily instead of crawling to multi-second rounds.
const maxRoundEscalation = uint32(16)

// NewDriver starts a driver that will extend ch from its current head.
//
// pool is the driver's transaction source and may be nil: a validator with no
// attached pool proposes empty blocks, exactly the M3 behaviour. A non-nil
// pool is taken from at proposal time and nothing else in the driver writes
// to it - transactions enter through the process's own submission paths, the
// same pool an RPC server would fill.
//
// The engine begins at head+1 with the head as its parent, and its round 0 is
// armed at the FIRST Tick with a full TimeoutBase before any timeout can end
// it (see timeoutArmed below).
//
// The engine is not necessarily unlocked, even at round 0: if this validator
// precommitted at head+1 and crashed before the height was decided, the lock
// it persisted is restored here (newEngine) - a restart may not re-enter a
// height the validator has already promised about.
//
// A signing key that is not one of the committee's seats is REFUSED with an
// error (audit C-11): the engine cannot tally its own vote, so driving it would
// only reach emitVote's refusal on the first timeout. Returning the error at
// construction is the loud, non-panicking form of that refusal; the production
// node already checks the same key against the genesis committee before it gets
// here, and this makes the consensus layer enforce it for every caller.
func NewDriver(cfg Config, ch *chain.Chain, priv ed25519.PrivateKey, tp transport.Transport, pool *mempool.Mempool) (*Driver, error) {
	d := &Driver{cfg: cfg, ch: ch, pool: pool, priv: priv, tp: tp}
	d.eng = d.newEngine(ch.Height()+1, ch.Head().ID())
	// The membership gate (audit C-11): the engine computed its committee
	// index at construction but never used it, so a key outside the committee
	// reached emitVote and panicked there. Refuse it before the transport is
	// wired, so a misconfigured validator fails to start instead of failing to
	// vote.
	if err := d.eng.CheckMembership(); err != nil {
		return nil, err
	}
	// timeoutAt is ARMED ON THE FIRST TICK, not at construction (the sentinel
	// below). Anchoring it at construction means assuming the caller's clock
	// starts at zero - true for a fresh simnet run, FALSE for every rebuild
	// over a clock already running: Task 6's catch-up rebuild and the
	// networked node's rebuildDriver re-create drivers mid-run, and an
	// absolute TimeoutBase against a now of tens of thousands would fire an
	// instant timeout on the rebuilt engine's first tick - emit a NIL prevote
	// for round 0 - and the round the committee's actual proposal travels in
	// is then already burned for this validator (its one prevote per round is
	// spent): it parks at that height forever while the committee races on.
	// Arming at the first real reading gives the fresh engine exactly the
	// TimeoutBase window the fresh-run path always had; a fresh run's clock
	// merely shifts its ladder by the first step's offset, and every
	// scenario's assertions are property assertions, not schedule assertions.
	d.timeoutAt = -1
	tp.OnMessage(d.OnMessage)
	return d, nil
}

// newEngine builds the engine for (height, parent) and connects it to the
// store through the chain: the persistLock hook makes every future lock move
// durable the moment it happens, and any lock previously persisted for THIS
// height - the height the engine is about to judge - is restored into it.
//
// Restoring is not optional and not best-effort cosmetic: the locking rule's
// safety argument assumes a locked validator STAYS locked, and a validator
// that precommitted and then restarted re-enters this height with no
// in-memory state at all. Without the restore the fresh engine would be
// unlocked, prevote a conflicting block, and reproduce exactly the
// counterexample the lock exists to prevent.
//
// The restore target is lockOn itself, the same forward-only mutator an
// in-memory lock uses, so a restored lock is not a second class of lock: it
// survives enterRound and it refuses a differing block until a verified
// justification exceeds its round.
func (d *Driver) newEngine(height uint64, parent [32]byte) *Engine {
	eng := NewEngine(d.cfg, height, parent, d.priv, d.build)
	eng.persistLock = d.persistLock
	eng.persistRound = d.persistRound
	// The validation seam (audit C-1): every engine the driver builds judges
	// proposals through ValidateNext - the chain's own pre-vote check, the
	// same method Append's shared validation runs. A proposer's Build and a
	// validator's seam and the final Append all run one policy, so a block
	// this engine would prevote is a block the chain must accept: the case
	// where they could disagree (a garbage state root carrying a polka to a
	// commit and then refusing at Append, parking the whole committee) is
	// closed before any vote is cast.
	//
	// The seam's COST is deliberate and bounded: it runs the full head+1
	// state transition (including any Argon2id claim verification, the block's
	// own bounds applying) under the chain's read lock on each judged proposal,
	// at most once per round - a Byzantine proposer can therefore force that
	// one transition per round for a block it knows fails the root compare.
	// The cost statement lives with the seam itself: chain.ValidateNext's doc,
	// "COST" paragraph (audit round 3, F4).
	//
	// ValidateConsensusNext, not bare ValidateNext: the consensus path also
	// pins the block timestamp to parent+1 (audit S-8), so a proposal carrying
	// any other timestamp is nil-prevoted here rather than merely being
	// monotonic. Every honest driver builds parent+1, so the pin never binds
	// an honest proposer.
	eng.SetValidate(func(b *types.Block) error { return d.ch.ValidateConsensusNext(b) })
	if rec, ok := d.ch.LockAt(height); ok {
		eng.restoreLock(rec.Round, rec.BlockID)
	}
	// The round a previous life of this height had reached (audit C-3):
	// restored AFTER the lock, because restoreRound floors itself at the
	// lock's round - a torn round log must not resume the engine behind its
	// own promise. Absence is round 0, the legitimate fresh-start value.
	if r, ok := d.ch.RoundAt(height); ok {
		eng.restoreRound(r)
	}
	return eng
}

// persistRound is the hook the engine calls the moment it enters a later
// round, before it emits any vote in that round (audit C-3): the round must
// be durable first, or a crash between the write and the vote leaves a
// restarted validator re-entering round 0 for a height the committee has
// already carried into round 3 - every proposal and vote wrong-round in both
// directions until it times out its way back.
//
// A persistence failure PANICS deliberately, exactly as persistLock's does:
// the engine is about to cast a vote in a round a restart could not
// remember, and a node that cannot keep its position durable must stop rather
// than vote from a state it cannot reproduce.
//
// PREVOTES ARE DELIBERATELY NOT PERSISTED (audit C-10). Only the lock and the
// round are durable; the signed prevote a validator cast at (height, round) is
// not written anywhere. A validator that prevotes and crashes before its round
// advances therefore comes back with its round (restoreRound) and its lock
// (restoreLock) restored but with NO memory of the prevote, and may honestly
// cast a second prevote at that same round: a proposal re-delivered for the
// round makes it prevote the same block again, and - the realistic case, since
// this protocol does not retransmit proposals - its timeout makes it prevote
// NIL, so the two signed prevotes at one (height, round) need not agree.
//
// This does not weaken commit safety, and the argument is why the omission is
// acceptable rather than deferred: two conflicting commits at one height need
// two quorums of more than two thirds of the power, whose intersection is more
// than one third, so two conflicting quorums require more than one third of the
// power to have double-voted. One validator's weight is capped below a quarter
// of the total, so a single restarted validator can never supply that
// intersection; and every honest validator in a quorum also precommitted, and
// the lock IS persisted before that precommit is signed. What the omission
// produces is therefore EVIDENCE, not an unsafe commit: the two signed prevotes
// are exactly the equivocation M5 slashing must punish. M5 therefore either
// persists the prevote before it is emitted (the same persist-before-emit
// ordering the lock uses) or defines its evidence to include a re-cast prevote;
// until slashing exists, this behaviour is documented here rather than assumed
// away, and TestARestartDoesNotRememberAPrevote pins it.
func (d *Driver) persistRound(height uint64, round uint32) {
	rec := store.RoundRecord{Height: height, Round: round}
	if err := d.ch.PutRound(rec); err != nil {
		panic(fmt.Sprintf("consensus: the round reached at height %d round %d could not be made durable: %v", height, round, err))
	}
}

// persistLock is the hook the engine calls the moment its lock moves, before
// the precommit that records it is signed or shipped: the promise must be
// durable first, or the crash window leaves a promise on the wire that no
// restart can remember (and that a restarted validator would then vote
// against - the exact unsafe direction).
//
// A persistence failure PANICS deliberately. Broadcasting the precommit
// would keep the engine running on a promise it could not make durable - the
// validator would behave as locked and come back unlocked after a crash,
// which is precisely the defect this hook closes; a node that cannot keep
// its promise durable must stop instead of voting. A panic does not corrupt
// anything: the store's writes are atomic per record (append + fsync, torn
// writes truncated at Open), so the promise before this one still stands.
func (d *Driver) persistLock(height uint64, round uint32, id [32]byte) {
	rec := store.LockRecord{Height: height, Round: round, BlockID: id}
	if err := d.ch.PutLock(rec); err != nil {
		panic(fmt.Sprintf("consensus: the lock taken at height %d round %d could not be made durable: %v", height, round, err))
	}
}

// build constructs the block this node would propose at the height it is asked
// to judge. The chain's own Build does the work, so proposal construction and
// chain validation cannot disagree about what a valid block is: whatever Build
// signs, Append will accept.
//
// The block carries the mempool's transactions, selected by Chain.SelectApplicable
// - the ONE policy node.RunOnce runs. Every peer will run the whole block back
// through state.ApplyBlock at Append, all-or-nothing, so the filter is not a
// convenience: a transaction that fails to apply anywhere in the committee
// would otherwise ride a proposal to a quorum that cannot append it, and this
// node would park at the undecided height forever (M3 has no adoption path),
// or the committee's own Append refusals would strand every honest validator
// behind a commit nobody can apply. One inapplicable transaction is evicted
// ALONE - it must not discard its valid siblings (the same tolerance RunOnce
// has) and it must not fail the proposal.
//
// The timestamp is the parent's plus one: deterministic (re-playable runs must
// not vary by wall-clock) and always positive, which ValidateStructure
// requires - a zero timestamp would fail chain.Build outright and no height
// could ever propose.
func (d *Driver) build(height uint64, round uint32, parent [32]byte) (types.Block, error) {
	head := d.ch.Head()
	headID := head.ID()
	if headID != parent || head.Header.Height+1 != height {
		return types.Block{}, fmt.Errorf("consensus: refusing to propose: the engine judges (height %d, parent %x) but the chain head is (height %d, id %x)",
			height, parent[:8], head.Header.Height, headID[:8])
	}
	txs := []types.Tx(nil)
	if d.pool != nil {
		// A batch left over from an earlier proposal goes back into the
		// pool before this round's batch is taken: it is uncommitted -
		// its proposal was abandoned (a timed-out round here, or this
		// very height decided on a peer's block that did not carry the
		// batch), and Take removed it. Proposing it again is sound - and
		// if another validator's block for this or an earlier height
		// carried any of it, SelectApplicable evicts it below against
		// the state the chain already moved to.
		d.reclaimPending()
		candidates := d.pool.Take(types.MaxTxsPerBlock)
		valid, err := d.ch.SelectApplicable(candidates)
		if err != nil {
			// The head+1 transition itself failed, so nothing applies:
			// park the candidates back rather than lose them, and refuse
			// to propose.
			return types.Block{}, d.reAdd(candidates, err)
		}
		txs = valid
	}
	b, err := d.ch.Build(d.priv, txs, head.Header.Timestamp+1)
	if err != nil {
		// The block was never built, so the batch it would have carried is
		// uncommitted: put it back. (The empty batch is a no-op.)
		if len(txs) > 0 {
			return types.Block{}, d.reAdd(txs, err)
		}
		return types.Block{}, err
	}
	// The batch now lives in the built proposal: it is either committed with
	// it (flush clears pending only when THAT block - identified by
	// pendingID - is the one that appends) or reclaimed by the next build at
	// this height or the first build after a foreign commit, whichever
	// comes first.
	d.pending = txs
	d.pendingID = b.ID()
	return *b, nil
}

// reclaimPending puts this driver's uncommitted proposal batch back into its
// mempool, at the start of a later build at the same height or the same
// driver's first build at a later height. The pool is the only place a
// transaction can wait for a future block, so the reclaim is what keeps a
// timed-out round from evaporating transactions Take already removed.
//
// The re-add's errors are deliberately unchecked. A duplicate is the normal
// benign outcome - the batch often re-enters the pool right before the Take
// below collects it again, and a client resubmission between the two is
// another route to the same already-present verdict. A non-duplicate failure
// (a pool flooded to capacity in the window between Take and this re-add)
// strands at most the batch already in hand; node's reAdd reports that case
// because RunOnce returns an error to a caller, while this runs inside build,
// whose only signal to the engine is the block itself - a stranded batch here
// would surface as a transaction that never lands, never as a silent state
// divergence, and the report notes it as a known exposure of this path.
func (d *Driver) reclaimPending() {
	if d.pool == nil || len(d.pending) == 0 {
		return
	}
	_ = d.pool.Add(d.pending)
	d.pending = nil
	d.pendingID = [32]byte{}
}

// reAdd puts transactions back into the driver's mempool after a failed
// proposal attempt and returns the cause unchanged: the engine wraps build's
// error into ErrProposeFn and the driver's Tick discards that, so there is no
// reader for the stranded-count wrapping node's reAdd carries - the value of
// this helper is the re-add itself, and a stranded transaction's failure mode
// is a transaction that never lands, not a divergent chain.
func (d *Driver) reAdd(txs []types.Tx, cause error) error {
	if d.pool != nil {
		_ = d.pool.Add(txs)
	}
	return cause
}

// Height reports the chain height this driver has committed to. An undecided
// height reports the previous one, which is how a stalled validator looks to
// the rest of the network: merely behind.
func (d *Driver) Height() uint64 { return d.ch.Height() }

// Round reports the round the driver's current engine is in. Together with
// AppendRefused it is the pair a stalled node needs to be diagnosable from
// outside: "the height is not moving" has two entirely different causes, and
// the committed height cannot tell them apart.
//
// A node whose engine has committed but whose Append was REFUSED reports
// AppendRefused true and a round that has stopped advancing (the engine is at
// StepCommit; see flush). A node churning its round ladder - the shape a
// scheduler-skewed run produces, where one engine's rounds run ahead of the
// committee's and neither side's votes are any longer tallied at the other's
// round - reports AppendRefused false and a round that keeps climbing. It is
// the round number, not the height, that says which one this is.
func (d *Driver) Round() uint32 { return d.eng.Round() }

// AppendRefused reports whether flush has STOPPED offering this height's
// committed block because the chain refused it: the park described on the
// field itself and by Design Decision 8. It is true only after a refused
// Append, and it clears when a fresh engine replaces the refused one.
func (d *Driver) AppendRefused() bool { return d.appendRefused }

// Tick advances the driver's clock to nowMillis and drives three things in a
// fixed order: proposing (a proposer must not sit silently in its own round),
// the round timeout of the round the engine is IN, and the flush that delivers
// drained messages and performs the commit.
func (d *Driver) Tick(nowMillis int64) {
	d.now = nowMillis
	// Propose before the timeout check: if this validator is the current
	// round's proposer and holds no proposal yet, it starts proposing now,
	// not at whichever later tick gets around to it first.
	if e := d.eng; e.IsProposer() && e.proposal == nil && e.step == StepPropose {
		_ = e.StartProposing()
	}
	// The CURRENT height and round are passed - never pre-incremented.
	// OnTimeout's contract is "the round you are in ran out of time", and the
	// engine advances the round itself. A pre-incremented round would be read
	// as a stale re-fire for a round the engine has not entered, be ignored,
	// and no round would ever be left behind: the exact defect Task 6's
	// review removed from the engine's caller. The test
	// TestDriverEndsTheRoundItIsInOnTimeout pins it here.
	if d.timeoutAt < 0 {
		// First Tick (or first Tick of a rebuilt driver): arm the round-0
		// deadline a full TimeoutBase from THIS reading, so a driver built
		// over a clock that is already running gets the same window a fresh
		// one does (see NewDriver).
		d.timeoutAt = nowMillis + d.cfg.TimeoutBase
	} else if d.now >= d.timeoutAt {
		// The returned error (audit C-11) is discarded for the same reason
		// StartProposing's is: NewDriver refused a signing key outside the
		// committee, so the only emission this can refuse is a vote the
		// engine's own tally would not admit - unreachable for a driver that
		// was constructed at all. The driver has no error channel here (Tick
		// is the clock's callback), and a key that cannot vote must fail at
		// construction, which is where CheckMembership now puts it.
		_ = d.eng.OnTimeout(TimeoutEvent{Height: d.eng.Height(), Round: d.eng.Round()})
		// The round the engine is in NOW, after OnTimeout advanced it, gets
		// the base timeout plus its own step - CAPPED at maxRoundEscalation
		// steps (audit C-2): each round therefore runs longer than the one
		// before it until the cap, after which every round runs the same
		// fixed cadence. A height that cannot decide must not grow its
		// timeouts without bound: unbounded growth made every later round
		// linearly slower forever, so a committee that recovered late would
		// still crawl. A new round's propose phase still runs before the
		// next timer can fire: the deadline is at least TimeoutBase from a
		// clock reading taken this tick.
		escalation := d.eng.Round()
		if escalation > maxRoundEscalation {
			escalation = maxRoundEscalation
		}
		d.timeoutAt = d.now + d.cfg.TimeoutBase + int64(escalation)*d.cfg.TimeoutStep
	}
	d.flush()
}

// OnMessage feeds one wire message into the engine and flushes whatever it
// produced. Malformed or foreign messages error back and are dropped - a
// driver that crashed on garbage input would be a remote kill switch.
func (d *Driver) OnMessage(m transport.Message) {
	_ = d.eng.OnMessage(m.Data)
	d.flush()
}

// flush delivers the engine's outbound messages and, if it has committed,
// appends the committed block to the chain EXACTLY ONCE.
//
// Exactly once is structural, not a flag: a successful Append is followed
// immediately below by replacing the engine with one for the next height, and
// a fresh engine has committed nothing. A REJECTED Append swaps nothing, so
// the driver stays at the undecided height - the chain refused the block, and
// silently advancing past a refused block is how one node diverges from every
// peer that accepted it. The refusal is also the LAST offer: appendRefused
// makes the driver stop retrying, because the same block re-offered against a
// head that cannot move fails identically forever (see the field comment).
func (d *Driver) flush() {
	for _, o := range d.eng.Drain() {
		// An empty To is a broadcast; a non-empty To is a unicast, which the
		// Transport interface grew in M4. The M3 engine emits only
		// broadcasts - emit() never sets To - but the seam now ROUTES rather
		// than drops a To the engine ever does emit. An error (say a Send to
		// a peer that disconnected mid-round) is dropped exactly as M3
		// deliberately dropped everything non-empty: the engine's retransmit
		// behaviour on the next tick, not the transport, owns recovery.
		if o.To == "" {
			_ = d.tp.Broadcast(o.Data)
		} else {
			_ = d.tp.Send(transport.PeerID(o.To), o.Data)
		}
	}
	id, ok := d.eng.Committed()
	if !ok || d.appendRefused {
		return
	}
	// The committed block is the proposal this engine accepted: the driver can
	// only append bytes it actually holds. A quorum CAN precommit a block
	// whose proposal this engine never received, or one it received and then
	// cleared when the round changed (audit C-3 commits from ANY retained
	// round, so the committing round need not be the current one): the engine
	// has legitimately judged that ID on its precommit evidence, and the bytes
	// may still be retained with the committing round's tallies or as the
	// proof-of-lock copy. committedBlock is where those copies are collected;
	// a node that holds none appends nothing and stays at the undecided
	// height - reporting a lower height than the peers that did receive the
	// proposal, never a fabricated one - and catch-up from a peer that DID
	// append is its recovery.
	blk := d.eng.committedBlock(id)
	if blk == nil {
		return
	}
	// Append re-validates the block against the chain - parent link, height,
	// proposer signature and state root - so a bug above this line cannot
	// inject an invalid block: it fails here and the chain stays untouched.
	// The failure is recorded so no later flush re-offers the same refused
	// block to the chain's write lock.
	if err := d.ch.Append(blk); err != nil {
		d.appendRefused = true
		return
	}
	// The commit certificate. The witness (if wired) receives the precommit
	// votes THAT committed this very block: the engine tallied them through
	// the ordinary VoteSet, so the certificate is the commit's own evidence,
	// handed over at the only moment it is known complete. Votes for anything
	// else (nil votes, a Byzantine validator's conflicting precommit) are not
	// evidence for this block and do not travel.
	if w := d.CommitWitness; w != nil {
		id, _ := d.eng.Committed()
		round := d.eng.commitRound
		cert := make([]*Vote, 0, len(d.eng.committedPrecommits()))
		for _, v := range d.eng.committedPrecommits() {
			if v.BlockID == id {
				cert = append(cert, v)
			}
		}
		w(d.ch.Height(), round, cert)
	}
	// The batch is committed only when the block that just committed is the
	// very block pending was built into. A PEER's proposal can reach quorum
	// at this height while this driver's own batch is still uncommitted (the
	// ordinary M4 case: this node's proposal timed out or was lost, a later
	// round's foreign proposal succeeded): that block need not carry the
	// batch, so clearing pending here would orphan it - gone from the pool
	// (Take removed it) and absent from the committed block. It stays
	// pending instead, and the next height's first build reclaims it into
	// the pool before that batch is taken; SelectApplicable there evicts
	// whichever of its transactions the foreign block already applied, so
	// the reclaim never puts an applied transaction up for a second ride.
	// (A batch taken for a proposal that FAILED here belongs to the parked
	// height; it is reclaimed by no build because this driver stops offering,
	// which is the M3 refusal contract, and the report records the exposure.)
	if d.pendingID == id {
		d.pending = nil
		d.pendingID = [32]byte{}
	}
	// The height is decided. Replace the engine: the next height starts the
	// same way a fresh node would (its lock state is per-height, and any
	// previously persisted lock for THIS height is restored - the restart
	// guarantee is a per-creation guarantee, not a start-of-process one),
	// judging head+1 over the block just committed. Its round 0 gets
	// TimeoutBase from the driver's current reading, so its propose phase
	// runs before its timer can fire. The refusal flag belonged to the
	// replaced engine's commit and starts over with the fresh one.
	d.eng = d.newEngine(d.ch.Height()+1, d.ch.Head().ID())
	d.appendRefused = false
	d.timeoutAt = d.now + d.cfg.TimeoutBase
}
