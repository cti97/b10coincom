package consensus

// lock is a validator's promise about a height: it has precommitted a block, and
// it will not help commit anything conflicting at that height unless the network
// moves to a strictly newer round.
//
// This is the safety-critical rule of the whole protocol. Without it two
// conflicting blocks can each collect two thirds of precommits at one height,
// because validators' precommits at different rounds are not mutually exclusive.
// With it, a quorum for two different blocks at one height would require more than
// a third of the power to have broken its promise.
//
// "Not locked" is the -1 sentinel, not the zero value. lockedRound is an int64
// rather than a uint32 precisely so that -1 is representable, but an int64
// field's zero value is 0 - a real round. So a freshly declared lock CLAIMS to
// be locked at round 0 on the zero block and refuses to prevote any real
// proposal at round 0. That trap is pinned, not fixed, by
// TestZeroValueLockIsNotUsableWithoutInitialization; every constructor that
// makes a lock must set the sentinel explicitly (Task 6's NewEngine does
// `lk: lock{lockedRound: -1}`).
type lock struct {
	lockedRound int64
	lockedBlock [32]byte
}

// lockOn records a precommit of id at round.
//
// It only ever moves FORWARD. Relocking backwards would let a validator prevote a
// conflicting block at a round it had already promised not to - which is the very
// failure this type exists to prevent - so a lower round is ignored rather than
// honoured.
//
// The condition accepts an EQUAL round, not only a greater one. That is load
// bearing: a first lock at round 0 from an uninitialized lock (whose lockedRound
// is 0) must be recorded, and re-recording the precommit a validator just made is
// idempotent, not a backwards move.
func (l *lock) lockOn(round uint32, id [32]byte) {
	if int64(round) >= l.lockedRound {
		l.lockedRound = int64(round)
		l.lockedBlock = id
	}
}

// canPrevote reports whether the validator may prevote id at round while holding
// this lock. The rule, verbatim from the spec: a locked validator prevotes its
// locked block, or a block whose proposal carries a VERIFIED polka
// (two-thirds of prevotes) from a round strictly greater than the one it is
// locked on. Anything else is refused.
//
// The third argument is the proposal's VERIFIED ValidRound, not its proposing
// round: the locking rule implemented literally - unlock on a newer proposing
// round - does not prevent conflicting commits, because a malicious proposer can
// offer a conflicting block at round r+1 with no polka behind it and every locked
// validator would prevote it. Design Decision 11 holds the counterexample.
func (l *lock) canPrevote(round uint32, id [32]byte, validRound int64) bool {
	if l.lockedRound < 0 {
		return true // not locked: anything goes
	}
	if id == l.lockedBlock {
		return true // its own promise, at any round
	}
	// Unlock ONLY on evidence: the proposal must carry a polka for id from a
	// round strictly greater than this validator's lock. A bare round number is
	// not evidence - see Design Decision 11 in
	// docs/plans/2026-10-03-m3-bft-consensus.md for the counterexample.
	return validRound > l.lockedRound
}

func (l *lock) locked() bool      { return l.lockedRound >= 0 }
func (l *lock) round() int64      { return l.lockedRound }
func (l *lock) blockID() [32]byte { return l.lockedBlock }
