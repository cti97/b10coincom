package consensus

import (
	"crypto/ed25519"
	"fmt"

	"github.com/cti97/b10coincom/internal/chain"
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
type Driver struct {
	cfg  Config
	ch   *chain.Chain
	priv ed25519.PrivateKey
	tp   transport.Transport
	eng  *Engine

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

// NewDriver starts a driver that will extend ch from its current head.
//
// The engine begins at head+1 with the head as its parent, and its round 0 is
// armed with exactly TimeoutBase: the first round a validator is in gets the
// full configured window before any timeout can end it.
//
// The engine is not necessarily unlocked, even at round 0: if this validator
// precommitted at head+1 and crashed before the height was decided, the lock
// it persisted is restored here (newEngine) - a restart may not re-enter a
// height the validator has already promised about.
func NewDriver(cfg Config, ch *chain.Chain, priv ed25519.PrivateKey, tp transport.Transport) *Driver {
	d := &Driver{cfg: cfg, ch: ch, priv: priv, tp: tp}
	d.eng = d.newEngine(ch.Height()+1, ch.Head().ID())
	d.timeoutAt = d.cfg.TimeoutBase
	tp.OnMessage(d.OnMessage)
	return d
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
	if rec, ok := d.ch.LockAt(height); ok {
		eng.restoreLock(rec.Round, rec.BlockID)
	}
	return eng
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
	b, err := d.ch.Build(d.priv, nil, head.Header.Timestamp+1)
	if err != nil {
		return types.Block{}, err
	}
	return *b, nil
}

// Height reports the chain height this driver has committed to. An undecided
// height reports the previous one, which is how a stalled validator looks to
// the rest of the network: merely behind.
func (d *Driver) Height() uint64 { return d.ch.Height() }

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
	if d.now >= d.timeoutAt {
		d.eng.OnTimeout(TimeoutEvent{Height: d.eng.Height(), Round: d.eng.Round(), Step: d.eng.Step()})
		// The round the engine is in NOW, after OnTimeout advanced it, gets
		// the base timeout plus its own step. Each round therefore runs
		// longer than the one before it, and a new round's propose phase
		// runs before the next timer can fire: the deadline is at least
		// TimeoutBase from a clock reading taken this tick.
		d.timeoutAt = d.now + d.cfg.TimeoutBase + int64(d.eng.Round())*d.cfg.TimeoutStep
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
		// An empty To is a broadcast, and the Transport interface has no
		// unicast method. The M3 engine emits only broadcasts; anything else
		// has no way out and is dropped deliberately until the interface
		// gains one.
		if o.To == "" {
			_ = d.tp.Broadcast(o.Data)
		}
	}
	id, ok := d.eng.Committed()
	if !ok || d.appendRefused {
		return
	}
	// The committed block is the proposal this engine accepted: the driver can
	// only append bytes it actually holds, and only the proposal it judged
	// carries them. A quorum CAN precommit a block whose proposal this engine
	// never received (the proposal is lost while the precommits it caused
	// still arrive): the engine has legitimately judged that ID on its
	// precommit evidence, but this node holds no block bytes to append and
	// must not guess or reconstruct any. It appends nothing and stays at the
	// undecided height - reporting a lower height than the peers that did
	// receive the proposal, never a fabricated one.
	if d.eng.proposal == nil || d.eng.proposal.ID() != id {
		return
	}
	// Append re-validates the block against the chain - parent link, height,
	// proposer signature and state root - so a bug above this line cannot
	// inject an invalid block: it fails here and the chain stays untouched.
	// The failure is recorded so no later flush re-offers the same refused
	// block to the chain's write lock.
	if err := d.ch.Append(d.eng.proposal); err != nil {
		d.appendRefused = true
		return
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
