package consensus

// Diagnostic observability for a stalled run.
//
// THE GAP THIS CLOSES. A networked validator can sit at one height for a
// minute while every observable the harness had - committed height, round,
// AppendRefused, sync drops, adopted count, peers - is identical to a merely
// slow run. The CI failure this exists for printed `heights [0 0 0]` and
// `round 108` for three of four seats and left the next reader to guess
// between "frames never arrived", "votes arrived but stayed short of quorum",
// "no proposal was ever made" and "the absent seat proposed everything". Those
// are four different faults and no report could tell them apart.
//
// WHAT IS OBSERVED, AND WHY IT CANNOT CHANGE A DECISION. Everything here is a
// READ of state the engine already keeps: its per-round VoteSets, its retained
// proposal, its step, its committee's proposer draw. The one addition on the
// engine's own paths is a set of integer counters incremented in the DROP
// branches (a vote for another height, a vote outside the round window, a
// foreign or duplicate proposal) - no branch, no ordering and no state the
// engine acts on is touched, and the counters are never read by a decision.
// The per-round history itself is accumulated by Driver.Observe. The NODE calls
// it too: after every routed consensus frame (tcpnode.go route) and after every
// tick (tcpnode.go tickLoop), inside the driver mutex. An earlier revision of
// this header said "the consensus paths do not call it, so production runs pay
// nothing for the ring"; that was false (RT-4) and is corrected here rather
// than gated away, because the ring is what the stall line reads and the stall
// line is an operator's only signal during a multi-minute stall (stall.go).
// Both call sites already hold the mutex, so the ring buys no extra lock - only
// a longer hold on the dispatch and tick paths. Its bounded cost is stated
// beside Observe below.
//
// BOUNDED. Engine retention is already bounded (futureVoteRounds +
// pastVoteRounds + 1 rounds). The driver keeps the most recent diagRingRounds
// (height, round) entries; each entry holds a fixed number of block IDs per
// vote type. Nothing grows with the length of a run.

// diagMaxBlockIDs bounds how many distinct block IDs one round's tally
// snapshot keeps, per vote type. A four-seat committee produces at most five
// (four votes plus nil); a larger one truncates, reporting how many were
// omitted and keeping the total power exact.
const diagMaxBlockIDs = 8

// DiagBlockTally is one block ID's share of a round's votes: how many
// validators the engine counted for it and the power they carry.
type DiagBlockTally struct {
	BlockID [32]byte
	Votes   int
	Power   uint64
}

// DiagTally is a bounded, read-only snapshot of one VoteSet (the prevotes or
// precommits of one round).
type DiagTally struct {
	Type  MsgType
	Votes int    // validators counted (one per validator, at most)
	Total uint64 // power summed over every block ID, truncated or not
	N     int    // block IDs in IDs
	IDs   [diagMaxBlockIDs]DiagBlockTally
	More  int // block IDs omitted from IDs because the array was full
	// OwnCast reports whether THIS engine's validator voted in this set, and
	// OwnID carries the block it voted for (the zero ID is a nil vote).
	// It is how the report says "the engine prevoted NIL" rather than merely
	// "nil weight exists", which are different facts.
	OwnCast bool
	OwnID   [32]byte
}

// DiagRound is one (height, round)'s last observed state: the proposer the
// committee drew, whether a proposal reached this engine, what the engine
// prevoted, the two tallies, and the furthest step observed while in it.
type DiagRound struct {
	Height uint64
	Round  uint32

	// Step is the engine's step in this round as last observed while the
	// engine was IN it (or the floor implied by this validator's own vote).
	Step Step

	// Proposer is the committee seat drawn for this round, or -1 when the
	// committee cannot be resolved. The draw is a pure function of the
	// committee, the parent block and (height, round), so it is exactly what
	// every honest validator computed; printing it is what makes "the absent
	// seat proposed every round" checkable without re-deriving it by hand.
	Proposer int

	// HasProposal reports whether THIS engine accepted a proposal for the
	// round (a proposal it never received, or one from the wrong proposer,
	// leaves it false). ProposalID is that block's ID.
	HasProposal bool
	ProposalID  [32]byte

	Prevote   DiagTally
	Precommit DiagTally
}

// DiagCounters counts the frames the engine DROPPED on its own paths. They are
// the engine-side half of "frames lost in delivery": the router counters say
// what never reached the engine, these say what reached it and could not be
// judged. All are per-engine (per height) and observation-only.
type DiagCounters struct {
	// OtherHeightVotes is votes for a height other than the engine's.
	OtherHeightVotes uint64
	// EarlyVotes is votes ahead of the retention window (still recorded as
	// round-ladder evidence, but not tallied).
	EarlyVotes uint64
	// LateVotes is votes older than the retention window.
	LateVotes uint64
	// ForeignProposals is proposals for another height or round.
	ForeignProposals uint64
	// WrongProposerProposals is proposals that named a signer who is not the
	// round's drawn proposer.
	WrongProposerProposals uint64
	// DuplicateProposals is proposals for the round this engine had already
	// accepted one for (first proposal wins).
	DuplicateProposals uint64
	// DuplicateVotes is votes already counted once in their round's set.
	DuplicateVotes uint64
}

// diagFill writes a snapshot of vs into d. own is the engine's own public key,
// used to record which block (if any) this validator voted for. It allocates
// nothing: the tally is copied into d's fixed arrays.
func (vs *VoteSet) diagFill(d *DiagTally, own []byte) {
	*d = DiagTally{Type: vs.typ, Votes: len(vs.votes)}
	for _, p := range vs.power {
		d.Total += p
	}
	for _, id := range vs.order {
		if d.N == diagMaxBlockIDs {
			d.More++
			continue
		}
		d.IDs[d.N].BlockID = id
		d.IDs[d.N].Power = vs.power[id]
		d.N++
	}
	for _, v := range vs.votes {
		for i := 0; i < d.N; i++ {
			if d.IDs[i].BlockID == v.BlockID {
				d.IDs[i].Votes++
				break
			}
		}
	}
	if own == nil {
		return
	}
	for _, v := range vs.votes {
		if string(v.Validator) == string(own) {
			d.OwnCast = true
			d.OwnID = v.BlockID
			return
		}
	}
}

// diagRetainedRounds returns the rounds whose tallies the engine still holds,
// ascending, current round included, appended to dst. Callers pass a stack
// buffer (the retention window bounds the count), so Observe allocates nothing.
func (e *Engine) diagRetainedRounds(dst []uint32) []uint32 {
	rounds := dst
	for r := range e.sets {
		rounds = append(rounds, r)
	}
	found := false
	for _, r := range rounds {
		if r == e.round {
			found = true
			break
		}
	}
	if !found {
		rounds = append(rounds, e.round)
	}
	for i := 1; i < len(rounds); i++ {
		for j := i; j > 0 && rounds[j-1] > rounds[j]; j-- {
			rounds[j-1], rounds[j] = rounds[j], rounds[j-1]
		}
	}
	return rounds
}

// diagProposerSeat is the committee seat drawn at round, or -1 when the key is
// not in the engine's committee (impossible for a running engine, which
// refuses a non-member key at construction, but never index -1).
func (e *Engine) diagProposerSeat(round uint32) int {
	return e.cfg.IndexOf(e.cfg.Proposer(e.height, round, e.parent))
}

// diagFillRound snapshots what the engine still holds for round into d. It
// leaves d.Proposer alone: the draw is computed once, when the round's entry
// is created, and does not change while the (height, parent) does not.
func (e *Engine) diagFillRound(round uint32, d *DiagRound) {
	s := e.sets[round]
	if s == nil {
		return
	}
	d.Height = e.height
	d.Round = round
	if round == e.round {
		d.Step = e.step
	}
	d.HasProposal = s.proposal != nil
	switch {
	case s.proposal == nil:
		d.ProposalID = [32]byte{}
	case d.ProposalID == ([32]byte{}):
		// Hash the round's block ONCE per ring entry, not once per Observe. A
		// round's proposal is immutable - the engine keeps the first one and
		// counts the rest as duplicates - so the ID cannot change while this
		// entry exists, and re-deriving it hashed a block header (Blake3 plus
		// two encoder allocations) for every retained round on every routed
		// frame. That was the real hot-path cost RT-4 found, and what made
		// Observe's "allocates nothing on the steady path" false; the ring
		// already carries the answer.
		d.ProposalID = s.proposal.ID()
	}
	s.prevotes.diagFill(&d.Prevote, e.pub)
	s.precommits.diagFill(&d.Precommit, e.pub)
	// A round the engine has already left no longer reports the step it
	// reached (e.step belongs to the current round), but this validator's own
	// vote in its tally proves the floor: it cannot have prevoted without
	// reaching StepPrevote, nor precommitted without StepPrecommit.
	if d.Prevote.OwnCast && d.Step < StepPrevote {
		d.Step = StepPrevote
	}
	if d.Precommit.OwnCast && d.Step < StepPrecommit {
		d.Step = StepPrecommit
	}
}

// diagCounters snapshots the engine's drop counters.
func (e *Engine) diagCounters() DiagCounters {
	return DiagCounters{
		OtherHeightVotes:       e.diag.otherHeight,
		EarlyVotes:             e.diag.early,
		LateVotes:              e.diag.late,
		ForeignProposals:       e.diag.foreignProposal,
		WrongProposerProposals: e.diag.wrongProposer,
		DuplicateProposals:     e.diag.duplicateProposal,
		DuplicateVotes:         e.diag.duplicateVote,
	}
}

// diagRingRounds bounds the driver's recent-round history. A stalled height
// at round 108 shows its last 24 rounds (85..108), which is more than the
// retention window (9) and enough to see a proposer draw rotating, a tally
// that never reaches quorum, and a run of absent proposals. It does not grow
// with the length of a run, and it is small enough that Observe is cheap.
const diagRingRounds = 24

// Observe records a bounded snapshot of every round the engine currently
// retains into the driver's recent-round ring, updating existing entries in
// place. The devnet harness calls it after each driver operation (inside the
// same lock the driver itself takes), so a poll on a timeout can read a
// history the engine has since pruned.
//
// It allocates nothing on the steady path. That was false before RT-4: the
// round's block ID was re-hashed on every call (Blake3 plus two encoder
// allocations per retained round with a proposal). A proposal is immutable once
// accepted - the engine keeps the first and counts the rest as duplicates - so
// the ID is now derived once per ring entry and reused. The round scratch stays
// a stack array, and the only other allocation is one-off growth of the ring
// slice up to diagRingRounds. It changes no consensus state.
//
// IT IS ON THE PRODUCTION HOT PATH (RT-4). The node calls it after every routed
// consensus frame and after every tick, under the driver mutex; the devnet
// harness calls it after each driver operation; the stall watcher folds once
// more, but only when it is about to emit a line (see stallReportOnce). The
// cost per call is bounded by the retention window: a map iteration and
// scratch sort over at most futureVoteRounds + pastVoteRounds + 1 rounds, a
// linear search of the diagRingRounds ring per round, and a fixed-array tally
// copy per round (two DiagTally snapshots of at most diagMaxBlockIDs entries,
// plus a linear scan of that round's votes). A proposer draw and the proposal's
// block hash are paid only when a round first enters the ring. Nothing it
// records is secret and no decision reads it; this is what the stall line
// costs. BenchmarkHotPathObservers (internal/devnet) measures it.
func (d *Driver) Observe() {
	var scratch [futureVoteRounds + pastVoteRounds + 2]uint32
	for _, round := range d.eng.diagRetainedRounds(scratch[:0]) {
		at := -1
		for i := range d.diagRounds {
			if d.diagRounds[i].Height == d.eng.Height() && d.diagRounds[i].Round == round {
				at = i
				break
			}
		}
		if at < 0 {
			if len(d.diagRounds) == diagRingRounds {
				copy(d.diagRounds, d.diagRounds[1:])
				d.diagRounds = d.diagRounds[:diagRingRounds-1]
			}
			d.diagRounds = append(d.diagRounds, DiagRound{
				Height:   d.eng.Height(),
				Round:    round,
				Proposer: d.eng.diagProposerSeat(round),
			})
			at = len(d.diagRounds) - 1
		}
		d.eng.diagFillRound(round, &d.diagRounds[at])
	}
}

// DiagRounds returns a copy of the recent-round history, oldest first. The
// copy is what makes a poller safe: the driver may append another entry while
// the report is being formatted, and the formatter must see one coherent ring.
func (d *Driver) DiagRounds() []DiagRound {
	return append([]DiagRound(nil), d.diagRounds...)
}

// DiagCounters reports the engine's frame-drop counters.
func (d *Driver) DiagCounters() DiagCounters { return d.eng.diagCounters() }

// DiagStep reports the engine's current step.
func (d *Driver) DiagStep() Step { return d.eng.Step() }

// DiagQuorum reports the quorum threshold at the height the engine judges.
func (d *Driver) DiagQuorum() uint64 { return d.eng.cfg.Quorum() }

// DiagTotalPower reports the total voting power at the height the engine
// judges. Printed beside the quorum so "2 of 3" means something.
func (d *Driver) DiagTotalPower() uint64 { return d.eng.cfg.TotalPower() }
