package faucet

import "testing"

// The cheap outer digest must be deterministic and bind the same
// (pubkey, epoch, nonce) triple as the real puzzle, so a solution cannot be
// traded between keys or epochs.
func TestPreDigestBindsKeyEpochAndNonce(t *testing.T) {
	pub := []byte("a-32-byte-public-key-padded-here!")
	other := []byte("a-different-public-key-padded-000!")
	base := PreDigest(pub, 7, 42)

	if base != PreDigest(pub, 7, 42) {
		t.Fatal("PreDigest is not deterministic")
	}
	if base == PreDigest(other, 7, 42) {
		t.Fatal("the outer digest ignored the public key")
	}
	if base == PreDigest(pub, 8, 42) {
		t.Fatal("the outer digest ignored the epoch")
	}
	if base == PreDigest(pub, 7, 43) {
		t.Fatal("the outer digest ignored the nonce")
	}
	// Domain separation: the cheap outer digest must not be the Argon2id one.
	if base == PowDigest(pub, 7, 42, fastParams) {
		t.Fatal("the outer digest is the Argon2id digest under a different name")
	}
}

func TestTargetWithLeadingZeroBits(t *testing.T) {
	// 16 bits: exactly the first two bytes are zero.
	tgt := TargetWithLeadingZeroBits(16)
	if tgt[0] != 0 || tgt[1] != 0 || tgt[2] != 0xFF {
		t.Fatalf("TargetWithLeadingZeroBits(16) = %x..., want 0000ffff...", tgt[:4])
	}
	var d [32]byte
	for i := range d {
		d[i] = 0xFF
	}
	d[0], d[1], d[2] = 0, 0, 0x7F // top 16 bits zero
	if !MeetsTarget(d, tgt) {
		t.Fatal("a digest with its leading 16 bits zero must meet the 16-bit target")
	}
	d[1] = 1 // a one inside the leading 16 bits
	if MeetsTarget(d, tgt) {
		t.Fatal("a digest with a one in its leading 16 bits must not meet the 16-bit target")
	}
	// Degenerate ends.
	if TargetWithLeadingZeroBits(0) != [32]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	} {
		t.Fatal("0 bits must be the all-ones target (everything passes)")
	}
	if TargetWithLeadingZeroBits(256) != ([32]byte{}) {
		t.Fatal("256 bits must be the all-zero (unsatisfiable) target")
	}
}

// The shipped cheap target is 16 leading zero bits.
func TestPreTargetBitsIsPinned(t *testing.T) {
	if PreTargetBits != 16 {
		t.Fatalf("PreTargetBits = %d, want 16: the admission cost in the R-1 report is derived from this value", PreTargetBits)
	}
	if PreTarget() != TargetWithLeadingZeroBits(PreTargetBits) {
		t.Fatal("PreTarget does not match PreTargetBits")
	}
}

// The claimant's one solver must satisfy BOTH puzzles, which is what a node's
// mempool requires before it will admit the claim.
func TestSolveClaimSatisfiesBothPuzzles(t *testing.T) {
	pub := []byte("a-32-byte-public-key-padded-here!")
	target := easyTarget()
	nonce, ok := SolveClaim(pub, 3, target, fastParams, 1<<24)
	if !ok {
		t.Fatal("SolveClaim failed to find a solution it should have found")
	}
	if !MeetsPreTarget(PreDigest(pub, 3, nonce)) {
		t.Fatalf("the nonce SolveClaim returned (%d) does not solve the cheap outer puzzle", nonce)
	}
	if !MeetsTarget(PowDigest(pub, 3, nonce, fastParams), target) {
		t.Fatalf("the nonce SolveClaim returned (%d) does not solve the Argon2id puzzle", nonce)
	}
}

// SolveClaim must still give up rather than loop forever on an unsatisfiable
// target (the outer puzzle may be solvable while the inner one is not).
func TestSolveClaimGivesUpWhenUnsatisfiable(t *testing.T) {
	pub := []byte("a-32-byte-public-key-padded-here!")
	var impossible [32]byte
	if n, ok := SolveClaim(pub, 1, impossible, fastParams, 1024); ok {
		t.Fatalf("SolveClaim succeeded against an impossible Argon2id target with nonce %d", n)
	}
}
