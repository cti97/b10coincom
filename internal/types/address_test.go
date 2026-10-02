package types

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func randomPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestAddressStringRoundTrip(t *testing.T) {
	addr := AddressFromPub(randomPub(t))
	got, err := ParseAddress(addr.String())
	if err != nil {
		t.Fatalf("ParseAddress(%q) failed: %v", addr.String(), err)
	}
	if got != addr {
		t.Fatalf("round trip mismatch: %v != %v", got, addr)
	}
}

func TestAddressHasPrefixAndIsLowercase(t *testing.T) {
	s := AddressFromPub(randomPub(t)).String()
	if !strings.HasPrefix(s, AddressPrefix) {
		t.Fatalf("address %q lacks prefix %q", s, AddressPrefix)
	}
	if s != strings.ToLower(s) {
		t.Fatalf("address %q is not lowercase", s)
	}
}

func TestAddressIsDeterministic(t *testing.T) {
	pub := randomPub(t)
	if AddressFromPub(pub) != AddressFromPub(pub) {
		t.Fatal("AddressFromPub is not deterministic")
	}
}

func TestAddressDiffersForDifferentKeys(t *testing.T) {
	if AddressFromPub(randomPub(t)) == AddressFromPub(randomPub(t)) {
		t.Fatal("two distinct keys produced the same address")
	}
}

func TestParseAddressRejectsTamperedChecksum(t *testing.T) {
	s := AddressFromPub(randomPub(t)).String()

	// Tamper the FIRST body character, not the last. A 24-byte payload
	// encodes to 39 base32 characters and only the final character carries
	// padding bits (2 data bits + 3 zero padding bits): flipping its low
	// padding bit, as the original version of this test did, produces a
	// string that decodes to the byte-identical payload, the checksum
	// legitimately matches, and for addresses whose last character happens
	// to be 'a' the test failed spuriously. Every other character in the
	// body carries five data bits, so replacing the first body character
	// with any different base32 symbol always changes the decoded payload
	// and the stored checksum can no longer match.
	first := s[len(AddressPrefix)]
	repl := byte('a')
	if first == 'a' {
		repl = 'b'
	}
	tampered := s[:len(AddressPrefix)] + string(repl) + s[len(AddressPrefix)+1:]

	if _, err := ParseAddress(tampered); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("expected ErrBadAddress for tampered checksum, got %v", err)
	}
}

func TestParseAddressRejectsBadInput(t *testing.T) {
	// A 20-byte body is valid base32 and decodes cleanly, so this is the one
	// current input that reaches the decoded-length check; every other input
	// below is rejected earlier, at the prefix check or the base32 decode.
	wrongLength := AddressPrefix + strings.ToLower(b32.EncodeToString(make([]byte, 20)))
	for _, in := range []string{"", "xyz", "b10", "b10!!!!", strings.ToUpper(AddressFromPub(randomPub(t)).String()), wrongLength} {
		if _, err := ParseAddress(in); !errors.Is(err, ErrBadAddress) {
			t.Fatalf("ParseAddress(%q): expected ErrBadAddress, got %v", in, err)
		}
	}
}
