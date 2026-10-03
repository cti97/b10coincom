package consensus

import "crypto/ed25519"

type (
	ed25519PrivateKey = ed25519.PrivateKey
	ed25519PublicKey  = ed25519.PublicKey
)

func ed25519NewKeyFromSeed(seed []byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }
