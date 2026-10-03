package crypto

import (
	"testing"
)

func TestHashPartsIsUnambiguous(t *testing.T) {
	// Splitting the input differently must not collide: this is why every
	// part is length-prefixed rather than concatenated.
	a := HashParts([]byte("ab"), []byte("c"))
	b := HashParts([]byte("a"), []byte("bc"))
	if a == b {
		t.Fatal("HashParts collided across different part boundaries")
	}
}

func TestHashPartsIsDeterministic(t *testing.T) {
	a := HashParts([]byte("x"), []byte("y"))
	b := HashParts([]byte("x"), []byte("y"))
	if a != b {
		t.Fatal("HashParts is not deterministic")
	}
}

func TestMerkleRootEmptyIsZero(t *testing.T) {
	if got := MerkleRoot(nil); got != ([32]byte{}) {
		t.Fatalf("empty Merkle root = %x, want all zeros", got)
	}
}

func TestMerkleRootSingleLeaf(t *testing.T) {
	leaf := HashParts([]byte("leaf"))
	if got := MerkleRoot([][32]byte{leaf}); got == ([32]byte{}) {
		t.Fatal("single-leaf root must not be the empty root")
	}
}

// Order must matter: a state root that ignores ordering would let two
// different account sets share a root.
func TestMerkleRootIsOrderSensitive(t *testing.T) {
	a := HashParts([]byte("a"))
	b := HashParts([]byte("b"))
	if MerkleRoot([][32]byte{a, b}) == MerkleRoot([][32]byte{b, a}) {
		t.Fatal("Merkle root must depend on leaf order")
	}
}

func TestMerkleRootDetectsTampering(t *testing.T) {
	leaves := [][32]byte{HashParts([]byte("1")), HashParts([]byte("2")), HashParts([]byte("3"))}
	before := MerkleRoot(leaves)

	tampered := make([][32]byte, len(leaves))
	copy(tampered, leaves)
	tampered[1] = HashParts([]byte("2-modified"))

	if MerkleRoot(tampered) == before {
		t.Fatal("Merkle root failed to detect a modified leaf")
	}
}

// TestMerkleRootHandlesOddLeafCounts asserts the odd-promotion CONSTRUCTION
// it names, not merely a non-zero, stable output. Each expected root is
// derived by hand from the rule documented on MerkleRoot — leaf =
// HashParts(0x00, data), internal = HashParts(0x01, left, right), and an odd
// node at any level hashed with itself — written out longhand per level, so a
// changed promotion rule (different padding hash, un-promoted odd node, a
// different pairing order) fails here even though the result would still be
// deterministic and non-zero.
func TestMerkleRootHandlesOddLeafCounts(t *testing.T) {
	// MerkleRoot consumes leaf DATA and applies the leaf rule itself, so the
	// inputs below are raw data blobs and every expectation starts by hashing
	// the data with the 0x00 leaf domain.
	data := func(b byte) [32]byte {
		var v [32]byte
		v[0] = b
		return v
	}
	leaf := func(b byte) [32]byte { // the documented leaf hash
		v := data(b)
		return HashParts([]byte{0x00}, v[:])
	}
	pair := func(l, r [32]byte) [32]byte { // the documented internal hash
		return HashParts([]byte{0x01}, l[:], r[:])
	}

	t.Run("n=1", func(t *testing.T) {
		// A single leaf IS the root: there is no level above it, so it is
		// not promoted a second time.
		want := leaf(0)
		if got := MerkleRoot([][32]byte{data(0)}); got != want {
			t.Fatalf("n=1 root changed:\n got %x\nwant %x", got, want)
		}
	})

	t.Run("n=3", func(t *testing.T) {
		// Level 1: the pair, and the odd third leaf hashed with itself.
		left := pair(leaf(0), leaf(1))
		promoted := pair(leaf(2), leaf(2))
		// Level 2: the two odd-level nodes pair into the root.
		want := pair(left, promoted)
		if got := MerkleRoot([][32]byte{data(0), data(1), data(2)}); got != want {
			t.Fatalf("n=3 root changed:\n got %x\nwant %x", got, want)
		}
	})

	t.Run("n=5", func(t *testing.T) {
		// Level 1: two pairs and the odd fifth leaf hashed with itself.
		a := pair(leaf(0), leaf(1))
		b := pair(leaf(2), leaf(3))
		c := pair(leaf(4), leaf(4))
		// Level 2: ODD AGAIN — the promoted c is hashed with itself once more.
		want := pair(pair(a, b), pair(c, c))
		got := MerkleRoot([][32]byte{data(0), data(1), data(2), data(3), data(4)})
		if got != want {
			t.Fatalf("n=5 root changed:\n got %x\nwant %x", got, want)
		}
	})
}
