package types

import (
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/cti97/b10coincom/internal/crypto"
)

const (
	// AddressPrefix is the human-readable prefix of every address.
	AddressPrefix = "b10"
	// AddressSize is the length of the address payload in bytes.
	AddressSize = 20
	// addressChecksumSize is the number of trailing bytes that make a
	// transcription typo detectable.
	addressChecksumSize = 4
)

var (
	// ErrBadAddress is returned for any malformed or mistyped address.
	ErrBadAddress = errors.New("types: invalid address")
	// b32 is RFC 4648 base32 without padding, used case-insensitively.
	b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// Address identifies an account: BLAKE3("b10coin-address" || pubkey)[:20].
type Address [AddressSize]byte

// AddressFromPub derives the address for an Ed25519 public key.
func AddressFromPub(pub []byte) Address {
	h := crypto.HashParts([]byte("b10coin-address"), pub)
	var a Address
	copy(a[:], h[:AddressSize])
	return a
}

// String renders the address as b10 + lowercase base32(payload || checksum).
func (a Address) String() string {
	sum := crypto.HashParts([]byte("b10coin-checksum"), a[:])
	payload := make([]byte, 0, AddressSize+addressChecksumSize)
	payload = append(payload, a[:]...)
	payload = append(payload, sum[:addressChecksumSize]...)
	return AddressPrefix + strings.ToLower(b32.EncodeToString(payload))
}

// ParseAddress validates the prefix, base32 body and checksum of s, and
// accepts ONE canonical spelling of each address only (audit S-11).
//
// Case policy: the "b10" PREFIX check is case-sensitive, so "B10…" is
// rejected, and the base32 BODY is upper-cased before decoding. Decoding is
// therefore case-insensitive, which by itself would accept 2^39 spellings of
// one address, and the 24-byte payload's final base32 character carries three
// padding bits, multiplying that by 8 more. Every one of them denotes the
// same account (an Address compares as its raw [20]byte value), so this was
// never a consensus or signature risk - but it IS an interop hazard: two
// nodes, an explorer and a wallet can disagree on whether two spellings name
// the same account, and a copy-pasted address that a peer re-renders
// differently looks like a different account.
//
// The decoder still upper-cases (so the base32 alphabet is decoded in one
// place), but the result is accepted ONLY when it re-renders to the input:
// a.String() == s. Because String() is the single canonical form, a caller
// that stored or displayed an address's String() can always parse it back,
// and any other spelling is refused with ErrBadAddress.
func ParseAddress(s string) (Address, error) {
	var a Address
	if !strings.HasPrefix(s, AddressPrefix) {
		return a, fmt.Errorf("%w: missing %q prefix", ErrBadAddress, AddressPrefix)
	}
	body := strings.TrimPrefix(s, AddressPrefix)
	if body == "" {
		return a, fmt.Errorf("%w: empty body", ErrBadAddress)
	}
	raw, err := b32.DecodeString(strings.ToUpper(body))
	if err != nil {
		return a, fmt.Errorf("%w: %v", ErrBadAddress, err)
	}
	if len(raw) != AddressSize+addressChecksumSize {
		return a, fmt.Errorf("%w: decoded length %d, want %d", ErrBadAddress, len(raw), AddressSize+addressChecksumSize)
	}
	copy(a[:], raw[:AddressSize])
	sum := crypto.HashParts([]byte("b10coin-checksum"), a[:])
	if !bytes.Equal(sum[:addressChecksumSize], raw[AddressSize:]) {
		return a, fmt.Errorf("%w: checksum mismatch", ErrBadAddress)
	}
	if canonical := a.String(); canonical != s {
		return a, fmt.Errorf("%w: non-canonical spelling (want %q)", ErrBadAddress, canonical)
	}
	return a, nil
}
