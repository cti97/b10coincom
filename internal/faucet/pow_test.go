package faucet

import (
	"encoding/hex"
	"testing"
)

// fastParams are deliberately trivial so the suite stays quick. The testnet
// parameters are the spec's ~3s ones; a 3s puzzle would make this file unusable.
var fastParams = Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1}

// easyTarget is every bit set except the top one, so roughly half of all
// digests satisfy it and a solve takes a couple of attempts.
func easyTarget() [32]byte {
	var t [32]byte
	for i := range t {
		t[i] = 0xFF
	}
	t[0] = 0x7F
	return t
}

func TestPowDigestIsDeterministic(t *testing.T) {
	pub := []byte("a-32-byte-public-key-padded-here!")
	a := PowDigest(pub, 7, 42, fastParams)
	b := PowDigest(pub, 7, 42, fastParams)
	if a != b {
		t.Fatal("PowDigest is not deterministic")
	}
}

// The puzzle must bind the key AND the epoch: a solution for one is worthless
// for another, which is what stops solutions being traded or replayed.
func TestPowDigestIsBoundToKeyAndEpoch(t *testing.T) {
	pub := []byte("a-32-byte-public-key-padded-here!")
	other := []byte("a-different-public-key-padded-000!")
	base := PowDigest(pub, 7, 42, fastParams)

	if base == PowDigest(other, 7, 42, fastParams) {
		t.Fatal("digest ignored the public key")
	}
	if base == PowDigest(pub, 8, 42, fastParams) {
		t.Fatal("digest ignored the epoch")
	}
	if base == PowDigest(pub, 7, 43, fastParams) {
		t.Fatal("digest ignored the nonce")
	}
}

func TestMeetsTarget(t *testing.T) {
	var zero, big [32]byte
	for i := range big {
		big[i] = 0xFF
	}
	if !MeetsTarget(zero, big) {
		t.Fatal("the smallest digest must meet the largest target")
	}
	if MeetsTarget(big, big) {
		t.Fatal("the comparison must be STRICTLY below the target")
	}
	if MeetsTarget(big, zero) {
		t.Fatal("the largest digest must not meet a zero target")
	}
}

// A target of zero is unsatisfiable, so Solve must exhaust its attempts and
// report failure rather than looping forever.
func TestSolveGivesUpWhenUnsatisfiable(t *testing.T) {
	pub := []byte("a-32-byte-public-key-padded-here!")
	var impossible [32]byte
	if n, ok := Solve(pub, 1, impossible, fastParams, 4); ok {
		t.Fatalf("Solve succeeded against an impossible target with nonce %d", n)
	}
}

// The round trip that matters: what Solve finds, verification accepts.
func TestSolveThenVerify(t *testing.T) {
	pub := []byte("a-32-byte-public-key-padded-here!")
	target := easyTarget()
	nonce, ok := Solve(pub, 3, target, fastParams, 1_000)
	if !ok {
		t.Fatal("Solve failed to find a solution it should have found")
	}
	if !MeetsTarget(PowDigest(pub, 3, nonce, fastParams), target) {
		t.Fatalf("the nonce Solve returned (%d) does not verify", nonce)
	}
}

// TestPowDigestKnownAnswer pins the exact preimage layout and salt. Neither
// travels in genesis, so without this a change to either is invisible to every
// other test while silently invalidating solutions across builds.
//
// GOLDEN VECTOR. Captured once from the initial implementation. Do NOT
// re-capture this value from a fresh run to make a failure go away: if this
// test fails, the digest changed and cross-build verification broke. Fix the
// code or change the pinned value only as a deliberate, documented decision,
// never because the run produced something different.
func TestPowDigestKnownAnswer(t *testing.T) {
	pub := make([]byte, 32) // all-zero pubkey keeps the vector readable
	// Epoch and nonce are deliberately NON-zero: a zero encodes to eight 0x00
	// bytes under either endianness, so a 0/0 vector is blind to a switch of the
	// nonce encoding between big- and little-endian.
	// PowDigest(32 zero bytes, epoch=1, nonce=1, {MemoryKiB: 64, Iterations: 1, Parallelism: 1})
	const digest = "ae1e9529f230f3b44759b4c0689af2626b77f6dab609d3a172b41bbe6e9d6815"
	var want [32]byte
	if _, err := hex.Decode(want[:], []byte(digest)); err != nil {
		t.Fatalf("bad golden vector literal: %v", err)
	}
	if got := PowDigest(pub, 1, 1, Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1}); got != want {
		t.Fatalf("puzzle digest changed:\n got %x\nwant %x", got, want)
	}
}
