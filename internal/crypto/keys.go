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

// VerifyHook, when non-nil, is invoked immediately before every Ed25519
// verification this package performs. It is an observation point for tests,
// not a production feature: the audit's C-8 amplification findings are claims
// about WHERE signature-verification work is spent on unauthenticated input
// (which peer can force an Ed25519 evaluation at which gate, or - the round-3
// F2 fix - that a membership check the engine can do for free now runs first),
// and the only way to pin such a claim is to count the expensive calls.
// Production code never sets it; when it is unset, Verify costs one nil
// comparison more and nothing else, and the hook never alters any verdict.
var VerifyHook func()

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
	if VerifyHook != nil {
		VerifyHook()
	}
	return ed25519.Verify(pub, msg, sig)
}
