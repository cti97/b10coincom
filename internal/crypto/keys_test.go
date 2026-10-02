package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestVerifyRejectsWrongLengths(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("b10coin")
	sig := Sign(priv, msg)

	longPub := make([]byte, ed25519.PublicKeySize+1)
	copy(longPub, pub)
	longSig := make([]byte, ed25519.SignatureSize+1)
	copy(longSig, sig)

	cases := []struct {
		name string
		pub  ed25519.PublicKey
		sig  []byte
	}{
		{"public key too short", pub[:ed25519.PublicKeySize-1], sig},
		{"public key too long", ed25519.PublicKey(longPub), sig},
		{"signature too short", pub, sig[:ed25519.SignatureSize-1]},
		{"signature too long", pub, longSig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// These inputs model untrusted network data. Verify must reject
			// them on length before ed25519.Verify runs; a panic here (which
			// fails this test) means the length guard is gone.
			if Verify(tc.pub, msg, tc.sig) {
				t.Fatalf("Verify accepted %s", tc.name)
			}
		})
	}
}

func TestVerifyGenuineSignature(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("b10coin")
	sig := Sign(priv, msg)

	if !Verify(pub, msg, sig) {
		t.Fatal("Verify rejected a genuine signature over the same message")
	}
	if Verify(pub, []byte("b10coin-tampered"), sig) {
		t.Fatal("Verify accepted a genuine signature over a different message")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("b10coin")
	sig := Sign(priv, msg)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("Sign produced %d-byte signature, want %d", len(sig), ed25519.SignatureSize)
	}
	if !Verify(pub, msg, sig) {
		t.Fatal("Sign/Verify round trip failed")
	}
}
