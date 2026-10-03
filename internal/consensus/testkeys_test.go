package consensus

import (
	"crypto/ed25519"

	"github.com/cti97/b10coincom/internal/crypto"
)

type (
	ed25519PrivateKey = ed25519.PrivateKey
	ed25519PublicKey  = ed25519.PublicKey
)

func ed25519NewKeyFromSeed(seed []byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }

// testCommitteeKey is the single source of the committee fixture key
// derivation, shared across tasks: every fixture that needs validator idx's
// test key must go through it (or through testValidator, which it is pinned
// to). A task that re-derives the key with a drifted literal would fail tally
// signatures that have nothing wrong with them; TestFixtureKeyDerivation-
// MatchesSharedHelper makes any such divergence fail immediately instead.
func testCommitteeKey(idx int) ed25519PrivateKey {
	h := crypto.HashParts([]byte("b10coin-test-validator"), []byte{byte(idx)})
	return ed25519NewKeyFromSeed(h[:])
}
