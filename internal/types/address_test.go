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
	a, b := AddressFromPub(pub), AddressFromPub(pub)
	if a != b {
		t.Fatal("AddressFromPub is not deterministic")
	}
}

func TestAddressDiffersForDifferentKeys(t *testing.T) {
	a, b := AddressFromPub(randomPub(t)), AddressFromPub(randomPub(t))
	if a == b {
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

// addressAlphabet is the lowercase base32 alphabet String() renders, in
// symbol-index order. It is duplicated in the test so a change to the
// production alphabet cannot silently make these cases vacuous.
const addressAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// TestParseAddressAcceptsOnlyTheCanonicalSpelling (audit S-11) pins the two
// classes of non-canonical spelling the decoder used to accept. Both decode
// to the SAME [20]byte address as the canonical string - that is the point -
// so only the a.String() == s check can refuse them.
func TestParseAddressAcceptsOnlyTheCanonicalSpelling(t *testing.T) {
	a := AddressFromPub(randomPub(t))
	canonical := a.String()
	got, err := ParseAddress(canonical)
	if err != nil {
		t.Fatalf("the canonical spelling %q must parse: %v", canonical, err)
	}
	if got != a {
		t.Fatalf("canonical spelling parsed to %v, want %v", got, a)
	}

	// Mixed case in the BODY only: the prefix stays lowercase, so the refusal
	// is the canonical check, not the case-sensitive prefix check.
	body := canonical[len(AddressPrefix):]
	upperBody := strings.ToUpper(body)
	if upperBody == body {
		t.Fatalf("test address body %q has no letters to change case", body)
	}
	mixed := AddressPrefix + upperBody
	if _, err := ParseAddress(mixed); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("ParseAddress(%q) = %v, want ErrBadAddress (non-canonical mixed case)", mixed, err)
	}

	// A different final character with the SAME top two data bits: only the
	// three padding bits differ, so it decodes to the same 24-byte payload and
	// the same checksum. Before the fix it parsed to a identical.
	last := body[len(body)-1]
	idx := strings.IndexByte(addressAlphabet, last)
	if idx < 0 {
		t.Fatalf("last body character %q is not in the base32 alphabet", last)
	}
	alt := byte(addressAlphabet[(idx&0b11000)|((idx+1)&0b111)])
	padded := AddressPrefix + body[:len(body)-1] + string(alt)
	if padded == canonical {
		t.Fatal("constructed padding variant equals the canonical spelling")
	}
	if _, err := ParseAddress(padded); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("ParseAddress(%q) = %v, want ErrBadAddress (padding-bit variant)", padded, err)
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
