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
)

// powSalt domain-separates the faucet puzzle from any other use of Argon2id.
var powSalt = []byte("b10coin-faucet-pow")

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

// MeetsTarget reports whether digest is STRICTLY below target, both read as
// big-endian 256-bit unsigned integers. A smaller target is a harder puzzle.
func MeetsTarget(digest, target [32]byte) bool {
	return new(big.Int).SetBytes(digest[:]).Cmp(new(big.Int).SetBytes(target[:])) < 0
}

// Solve searches nonces from 0 upward for one whose digest meets target, giving
// up after maxAttempts. The upward scan is deterministic and therefore testable;
// a real claimant should start from a random nonce, which is strictly better but
// is not required for correctness.
func Solve(pubkey []byte, epoch uint64, target [32]byte, p Argon2Params, maxAttempts uint64) (uint64, bool) {
	for n := uint64(0); n < maxAttempts; n++ {
		if MeetsTarget(PowDigest(pubkey, epoch, n, p), target) {
			return n, true
		}
	}
	return 0, false
}
