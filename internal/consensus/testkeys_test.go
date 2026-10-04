package consensus

import (
	"crypto/ed25519"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

type (
	ed25519PrivateKey = ed25519.PrivateKey
	ed25519PublicKey  = ed25519.PublicKey
)

// ed25519Sign: the brief's "ed25519.Sign in the alias block", spelled as a var
// because a func value cannot sit in a type-alias block.
var ed25519Sign = ed25519.Sign

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

// testSign signs h with validator idx's committee key, through the shared
// derivation, so tally signatures fail only when the code is wrong.
func testSign(t *testing.T, idx int, h [32]byte) []byte {
	t.Helper()
	return testSignRaw(t, testCommitteeKey(idx), h)
}

// testSignRaw signs h with an arbitrary private key (e.g. a stranger's key from
// testKey) so the tally's non-member path can be exercised genuinely.
func testSignRaw(t *testing.T, priv ed25519PrivateKey, h [32]byte) []byte {
	t.Helper()
	return ed25519Sign(priv, h[:])
}

// signProposal signs a proposal with its named validator's committee key.
func signProposal(t *testing.T, cfg Config, p *Proposal) []byte {
	t.Helper()
	idx := cfg.IndexOf(p.Validator)
	if idx < 0 {
		t.Fatal("signProposal: proposer is not in the committee")
	}
	// SigningHash returns an array BY VALUE, which cannot be sliced in place; bind it first.
	h := p.SigningHash()
	return ed25519Sign(testCommitteeKey(idx), h[:])
}

// tryProposal decodes a proposal, or returns nil if the message is not one.
func tryProposal(b []byte) *Proposal {
	p, err := DecodeProposal(b)
	if err != nil {
		return nil
	}
	return p
}
