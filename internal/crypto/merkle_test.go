package crypto

import (
	"bytes"
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

func TestMerkleRootHandlesOddLeafCounts(t *testing.T) {
	// 1, 3 and 5 leaves exercise the odd-promotion path.
	for _, n := range []int{1, 3, 5} {
		leaves := make([][32]byte, n)
		for i := range leaves {
			leaves[i] = HashParts([]byte{byte(i)})
		}
		got := MerkleRoot(leaves)
		// MerkleRoot's result is an unaddressable array, so it cannot be
		// sliced in place; bind it to a variable before the comparison.
		again := MerkleRoot(leaves)
		if got == ([32]byte{}) {
			t.Fatalf("n=%d produced the empty root", n)
		}
		if !bytes.Equal(got[:], again[:]) {
			t.Fatalf("n=%d is not deterministic", n)
		}
	}
}
