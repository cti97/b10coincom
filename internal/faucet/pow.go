// Package faucet implements b10coin's issuance faucet: the proof-of-work puzzle
// that rate-limits claims, and the emission schedule that funds them.
//
// PoW here is NOT consensus. It is a rate limiter on a faucet. The difficulty is
// calibrated so a Raspberry Pi completes a puzzle in seconds, and at that
// difficulty ASICs confer no meaningful advantage. The chain's security comes
// from the validator set (M3), not from this.
package faucet

import (
	"encoding/binary"
	"math/big"

	"golang.org/x/crypto/argon2"
	"lukechampine.com/blake3"
)

// powSalt domain-separates the faucet puzzle from any other use of Argon2id.
var powSalt = []byte("b10coin-faucet-pow")

// preSalt domain-separates the cheap outer puzzle from both Argon2id and every
// other BLAKE3 use in the codebase.
var preSalt = []byte("b10coin-faucet-pre-pow")

// PreTargetBits is the difficulty of the cheap OUTER puzzle: the number of
// leading zero bits an outer digest must carry. The outer puzzle exists to make
// admission of a faucet claim cost a hash rather than an Argon2id evaluation
// (audit R-1/S-4). A claimant must satisfy BOTH the outer puzzle and the
// Argon2id target; a verifier checks the outer puzzle with ONE BLAKE3 hash and
// only pays for Argon2id when the outer digest passes.
//
// The value is a judgment call and a LOCAL MEMPOOL POLICY, not consensus and
// not a genesis parameter: changing it changes no transaction byte, no account
// and no state root. At 16 bits a random "garbage" nonce is rejected after one
// hash (the audit's flood shape), while producing a passing nonce costs the
// submitter ~2^16 BLAKE3 evaluations. That puts the submitter's per-claim
// admission cost within an order of magnitude of the node's per-claim Argon2id
// verification at the testnet tuning (8 MiB x 1 pass, ~0.125 s on the Pi-4
// estimate in genesis.Testnet). Like every Pi-4 figure in this codebase it is
// an estimate and must be re-measured with the rest of the faucet tuning.
const PreTargetBits = 16

// preTarget is the 256-bit target with PreTargetBits leading zero bits.
var preTarget = TargetWithLeadingZeroBits(PreTargetBits)

// TargetWithLeadingZeroBits returns a 256-bit big-endian target whose first
// `bits` bits are zero and every remaining bit is one. A digest is strictly
// below it exactly when those leading bits are zero, so the acceptance
// probability is 2^-bits.
func TargetWithLeadingZeroBits(bits int) [32]byte {
	var t [32]byte
	for i := range t {
		t[i] = 0xFF
	}
	if bits <= 0 {
		return t
	}
	if bits > 256 {
		return [32]byte{} // unsatisfiable
	}
	for i := 0; i < bits/8; i++ {
		t[i] = 0
	}
	if rem := uint(bits % 8); rem != 0 {
		t[bits/8] = 0xFF >> rem
	}
	return t
}

// PreTarget returns the cheap outer puzzle's target.
func PreTarget() [32]byte { return preTarget }

// Argon2Params configures the puzzle. Argon2id is memory-hard, so the cost of a
// guess is dominated by memory bandwidth rather than raw compute — which is
// exactly why ASICs do not help at this difficulty.
type Argon2Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

// PowDigest computes the puzzle digest for a claimant key, an epoch and a nonce.
//
// The claimant's public key and the epoch are both inside the hashed preimage,
// so a solution is worthless for any other key or any other epoch: solutions
// cannot be traded between claimants or replayed in a later epoch.
func PowDigest(pubkey []byte, epoch, nonce uint64, p Argon2Params) [32]byte {
	pre := make([]byte, 0, len(pubkey)+16)
	pre = append(pre, pubkey...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], epoch)
	pre = append(pre, b[:]...)
	binary.BigEndian.PutUint64(b[:], nonce)
	pre = append(pre, b[:]...)

	out := argon2.IDKey(pre, powSalt, p.Iterations, p.MemoryKiB, p.Parallelism, 32)
	var d [32]byte
	copy(d[:], out)
	return d
}

// PreDigest computes the cheap outer puzzle's digest for a claimant key, an
// epoch and a nonce. It is BLAKE3, not Argon2id: one evaluation is orders of
// magnitude cheaper than the real puzzle, which is the entire point - a
// verifier can reject a nonce that did not solve it without paying Argon2id.
// The preimage is the same (pubkey, epoch, nonce) triple the real puzzle binds,
// so an outer solution is worthless for another key or epoch too.
func PreDigest(pubkey []byte, epoch, nonce uint64) [32]byte {
	pre := make([]byte, 0, len(pubkey)+16)
	pre = append(pre, pubkey...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], epoch)
	pre = append(pre, b[:]...)
	binary.BigEndian.PutUint64(b[:], nonce)
	pre = append(pre, b[:]...)

	h := blake3.New(32, nil)
	// The domain tag is a fixed prefix, so preSalt||pre is unambiguous for any
	// pubkey length (a constant prefix is injective on its suffix).
	h.Write(preSalt)
	h.Write(pre)
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// MeetsPreTarget reports whether an outer digest solves the cheap puzzle.
func MeetsPreTarget(digest [32]byte) bool { return MeetsTarget(digest, preTarget) }

// MeetsTarget reports whether digest is STRICTLY below target, both read as
// big-endian 256-bit unsigned integers. A smaller target is a harder puzzle.
func MeetsTarget(digest, target [32]byte) bool {
	return new(big.Int).SetBytes(digest[:]).Cmp(new(big.Int).SetBytes(target[:])) < 0
}

// Solve searches nonces from 0 upward for one whose digest meets target, giving
// up after maxAttempts. The upward scan is deterministic and therefore testable;
// a real claimant should start from a random nonce, which is strictly better but
// is not required for correctness. It solves the Argon2id puzzle only; a
// claimant submitting through a node's mempool must also satisfy the cheap
// outer puzzle, so use SolveClaim for that (audit R-1).
func Solve(pubkey []byte, epoch uint64, target [32]byte, p Argon2Params, maxAttempts uint64) (uint64, bool) {
	for n := uint64(0); n < maxAttempts; n++ {
		if MeetsTarget(PowDigest(pubkey, epoch, n, p), target) {
			return n, true
		}
	}
	return 0, false
}

// SolveClaim finds a nonce that satisfies BOTH the cheap outer puzzle and the
// real Argon2id target: the shape a transaction needs to be admitted by a node
// whose mempool enforces the outer puzzle (audit R-1) and then to be applied by
// the state machine. The outer digest is checked first, so the Argon2id
// evaluation runs only for candidates that already clear the cheap filter -
// the claimant pays the same number of Argon2id evaluations as Solve (the extra
// work is BLAKE3), while a verifier never reaches Argon2id for a nonce that did
// not solve the outer puzzle.
func SolveClaim(pubkey []byte, epoch uint64, target [32]byte, p Argon2Params, maxAttempts uint64) (uint64, bool) {
	for n := uint64(0); n < maxAttempts; n++ {
		if !MeetsPreTarget(PreDigest(pubkey, epoch, n)) {
			continue
		}
		if MeetsTarget(PowDigest(pubkey, epoch, n, p), target) {
			return n, true
		}
	}
	return 0, false
}
