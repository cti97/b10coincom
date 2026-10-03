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

// ParseAddress validates the prefix, base32 body and checksum of s.
//
// Case policy is deliberate: the "b10" PREFIX check is case-sensitive, so
// "B10…" is rejected, while the base32 BODY is upper-cased before decoding,
// so a lowercase body is accepted. This asymmetry is not a malleability
// risk: an Address compares as its raw [20]byte value and String() always
// re-renders it in lowercase, so every accepted spelling of an address
// denotes exactly the same account.
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
	return a, nil
}
