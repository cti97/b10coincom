package consensus

import "testing"

func bid(n byte) [32]byte {
	var id [32]byte
	id[0] = n
	return id
}

// Deviation from the brief (deliberate; see task-5-report.md): the brief wrote
// this test with `var l lock` and expected it "to report unlocked". It cannot:
// lockedRound is an int64 whose zero value is 0, and 0 is a real round, so the
// zero value of lock CLAIMS to be locked at round 0 on the zero block. The
// brief itself says the zero value must be initialized by the Engine (Task 6's
// NewEngine does exactly that), so the unlocked state can only be constructed
// with the -1 sentinel - the same literal the constructor uses. The raw zero
// value's behaviour is pinned, not fixed, by
// TestZeroValueLockIsNotUsableWithoutInitialization below.
func TestUnlockedValidatorMayPrevoteAnything(t *testing.T) {
	l := lock{lockedRound: -1}
	if l.locked() {
		t.Fatal("an initialized unlocked lock must report unlocked")
	}
	for _, r := range []uint32{0, 1, 7} {
		if !l.canPrevote(r, bid(1)) {
			t.Fatalf("an unlocked validator refused to prevote at round %d", r)
		}
	}
}

// The rule the spec names: after locking (r, B), a later round may prevote B, or a
// proposal STRICTLY NEWER than r. Nothing else.
func TestLockedValidatorPrevotesOnlyItsBlockOrANewerRound(t *testing.T) {
	var l lock
	l.lockOn(3, bid(1))

	if !l.canPrevote(3, bid(1)) {
		t.Fatal("a locked validator must still prevote its own locked block at the same round")
	}
	if !l.canPrevote(4, bid(1)) {
		t.Fatal("a locked validator must prevote its own locked block in a later round")
	}
	if !l.canPrevote(4, bid(2)) {
		t.Fatal("a locked validator must prevote a DIFFERENT block proposed at a strictly newer round")
	}
	if l.canPrevote(2, bid(2)) {
		t.Fatal("a locked validator must not prevote an OLDER round's different block")
	}
	if l.canPrevote(3, bid(2)) {
		t.Fatal("a locked validator must not prevote a different block at the SAME round it is locked on")
	}
}

// Relocking must only ever move forward. A validator that could relock on an
// earlier round would be able to prevote two conflicting blocks at one height -
// exactly the failure the rule exists to prevent.
func TestRelockingNeverMovesBackwards(t *testing.T) {
	var l lock
	l.lockOn(5, bid(1))
	l.lockOn(3, bid(2)) // an attempt to go back
	if l.round() != 5 || l.blockID() != bid(1) {
		t.Fatalf("relock moved backwards: round=%d block=%v", l.round(), l.blockID()[0])
	}
	l.lockOn(6, bid(2)) // forward is allowed
	if l.round() != 6 || l.blockID() != bid(2) {
		t.Fatalf("relock forward failed: round=%d block=%v", l.round(), l.blockID()[0])
	}
}

// The adversarial property, stated as the safety condition it protects: once a
// validator has locked at round r, it is impossible for it to prevote two
// different blocks in any round <= r.
func TestLockedValidatorCannotPrevoteTwoBlocksInOneRound(t *testing.T) {
	for _, lockedRound := range []uint32{0, 1, 4} {
		var l lock
		l.lockOn(lockedRound, bid(1))

		// At every round up to and including the locked round, only the locked
		// block is prevotable.
		for r := uint32(0); r <= lockedRound; r++ {
			if l.canPrevote(r, bid(2)) {
				t.Fatalf("locked at round %d: prevoted a conflicting block at round %d", lockedRound, r)
			}
		}
		// At every round after it, a conflict is permitted - that is what lets an
		// honest validator follow a newer proposal and make progress.
		if !l.canPrevote(lockedRound+1, bid(2)) {
			t.Fatalf("locked at round %d: refused a conflicting block at round %d, which would stall the chain",
				lockedRound, lockedRound+1)
		}
	}
}

// TestZeroValueLockIsNotUsableWithoutInitialization pins the zero value's
// behaviour EXACTLY, because that zero value is a HAZARD, not an accident.
// lockedRound is an int64 so "not locked" can be the -1 sentinel, but a struct
// field's zero value is 0, and 0 is a real round. So a freshly declared lock
// claims to be locked at round 0 on the zero block: it reports itself locked,
// names a promise (the zero block) it never made, and refuses to prevote ANY
// real proposal at round 0 - the round every height starts at.
//
// lock.go cannot repair this (a zero value of a struct field is what it is);
// Task 6's NewEngine must initialize lockedRound to -1 explicitly, which is why
// TestUnlockedValidatorMayPrevoteAnything constructs its unlocked lock the same
// way. This test exists so that the trap cannot be changed SILENTLY: if anyone
// later "simplifies" lock to a uint32 (making -1 unrepresentable - that also
// breaks the sentinel-initializing test and constructor at compile time), or
// drops the sentinel by special-casing the zero block into an always-unlocked
// state, this test's assertions stop holding and the change to the
// safety-critical type's zero value is loud rather than silent.
func TestZeroValueLockIsNotUsableWithoutInitialization(t *testing.T) {
	var l lock // deliberately NOT initialized: this pins the raw zero value
	if !l.locked() {
		t.Fatal("the zero value of lock claims to be locked - that is the pinned trap, not a desired property")
	}
	if l.round() != 0 {
		t.Fatalf("the zero value claims round %d, want 0: a real round, not the -1 sentinel", l.round())
	}
	if l.blockID() != bid(0) {
		t.Fatal("the zero value claims to be locked on a block it never precommitted (the zero block)")
	}
	// Its phantom round is 0, so it refuses every real proposal at round 0 -
	// which is where every height starts - and would prevote a real block only
	// from round 1 up (1 > 0). The damage is confined to round 0, but round 0
	// is the round consensus starts in.
	if l.canPrevote(0, bid(1)) {
		t.Fatal("the zero value, a phantom round-0 lock, must refuse a real proposal at round 0")
	}
	if !l.canPrevote(1, bid(1)) {
		t.Fatal("the zero value's phantom lock permits prevotes only at rounds strictly above 0")
	}
}

// A lock at round 0 is a REAL lock - it is what a validator holds after
// precommitting in the very first round, which is the common case. locked()
// must report it, and lockOn must RECORD a round-0 lock even from a lock that
// was never initialized: the zero value's lockedRound is 0, so the forward-only
// condition must accept an EQUAL round (>=), not only a greater one (>), or the
// first round's precommit would be silently dropped and the validator would be
// left holding the zero block as its promise.
func TestALockAtRoundZeroIsARealLock(t *testing.T) {
	// From the initialized unlocked state, the way Task 6's constructor makes it:
	l := lock{lockedRound: -1}
	l.lockOn(0, bid(1))
	if !l.locked() {
		t.Fatal("a validator that precommitted at round 0 must report locked: round 0 is a real lock")
	}
	if l.round() != 0 || l.blockID() != bid(1) {
		id := l.blockID() // an array return value cannot be sliced in place
		t.Fatalf("the round-0 lock recorded the wrong promise: round=%d block=%x", l.round(), id[:1])
	}
	if !l.canPrevote(0, bid(1)) {
		t.Fatal("a validator locked at round 0 must still prevote its locked block at round 0")
	}
	if l.canPrevote(0, bid(2)) {
		t.Fatal("a validator locked at round 0 must not prevote a conflicting block at round 0")
	}
	if !l.canPrevote(1, bid(2)) {
		t.Fatal("a validator locked at round 0 must follow a conflicting block at a strictly newer round")
	}

	// From the raw zero value: lockOn(0, ...) must still take effect. The
	// condition accepts an equal round (0 >= 0) exactly so a first lock at
	// round 0 is honoured; with > as the condition this lockOn would be
	// silently ignored and the validator would keep the zero block.
	var z lock
	z.lockOn(0, bid(1))
	if z.round() != 0 || z.blockID() != bid(1) {
		zid := z.blockID() // an array return value cannot be sliced in place
		t.Fatalf("lockOn dropped a round-0 lock from the zero value: round=%d block=%x", z.round(), zid[:1])
	}
	if !z.locked() {
		t.Fatal("lockOn must turn the zero value into a real lock at round 0")
	}
}
