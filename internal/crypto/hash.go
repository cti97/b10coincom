// Package crypto provides b10coin's hashing, Merkle commitment and
// signature primitives.
package crypto

import (
	"encoding/binary"

	"lukechampine.com/blake3"
)

// HashParts hashes a sequence of byte slices unambiguously. Each part is
// length-prefixed before hashing, so HashParts(a, b) differs from
// HashParts(a||b) even when the concatenation is identical. Using this
// instead of concatenating prevents a whole class of collision attacks.
func HashParts(parts ...[]byte) [32]byte {
	h := blake3.New(32, nil)
	var lenbuf [binary.MaxVarintLen64]byte
	for _, p := range parts {
		n := binary.PutUvarint(lenbuf[:], uint64(len(p)))
		h.Write(lenbuf[:n])
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}
