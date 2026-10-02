package crypto

// MerkleRoot computes a binary Merkle root over leaves, preserving order.
//
// Domain separation prevents a second-preimage attack in which an internal
// node is presented as a leaf:
//
//	leaf     = H(0x00 || data)
//	internal = H(0x01 || left || right)
//
// An odd node at any level is hashed with itself to produce the next level.
//
// Known limitation: this construction is vulnerable to the classic
// duplicate-last-leaf ambiguity, where two different leaf lists can produce
// the same root. It is not exploitable for b10coin's state root, because
// leaves are derived from a sorted, deduplicated set of addresses. It MUST
// be revisited before any inclusion or exclusion proof is added — proofs are
// an explicit non-goal of the current spec.
func MerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	level := make([][32]byte, len(leaves))
	for i, l := range leaves {
		level[i] = HashParts([]byte{0x00}, l[:])
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, HashParts([]byte{0x01}, left[:], right[:]))
		}
		level = next
	}
	return level[0]
}
