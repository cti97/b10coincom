package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
)

// GenerateKey returns a fresh Ed25519 keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign returns a detached Ed25519 signature over msg.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Verify reports whether sig is a valid Ed25519 signature by pub over msg.
// Lengths are checked explicitly because ed25519.Verify panics on
// wrongly-sized keys, and this function parses untrusted network input.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}
