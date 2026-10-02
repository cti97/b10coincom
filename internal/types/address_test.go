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
	// Flip the final character to a different valid base32 symbol.
	last := s[len(s)-1]
	repl := byte('a')
	if last == 'a' {
		repl = 'b'
	}
	tampered := s[:len(s)-1] + string(repl)

	if _, err := ParseAddress(tampered); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("expected ErrBadAddress for tampered checksum, got %v", err)
	}
}

func TestParseAddressRejectsBadInput(t *testing.T) {
	for _, in := range []string{"", "xyz", "b10", "b10!!!!", strings.ToUpper(AddressFromPub(randomPub(t)).String())} {
		if _, err := ParseAddress(in); !errors.Is(err, ErrBadAddress) {
			t.Fatalf("ParseAddress(%q): expected ErrBadAddress, got %v", in, err)
		}
	}
}
