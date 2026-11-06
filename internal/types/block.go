package types

import (
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
)

const (
	// MaxTxsPerBlock bounds block size so a Raspberry Pi can always
	// process a block within one block interval. It is a COUNT ceiling and it
	// is deliberately LOOSER than the byte budget can fill at a transaction's
	// minimum size (see MaxTxsByBytes): a block must satisfy BOTH bounds, and
	// the producer's byte budget is what actually sizes a full block (audit
	// S-3).
	MaxTxsPerBlock = 10_000
	// MaxBlockBytes bounds the canonical encoding of a block.
	MaxBlockBytes = 1 << 20

	// headerBytes is the canonical encoding of the header of a block a
	// validator will accept: five fixed fields (8+32+32+32+8) plus the
	// varint-prefixed 32-byte proposer key.
	headerBytes = 112 + 1 + ed25519PublicKeySize

	// BlockOverheadBytes is what a signed block costs before its first
	// transaction: the header, the transaction-count varint (two bytes for any
	// block holding at least 128 transactions, the only size this bound is
	// used at), the one-byte signature-length prefix and the 64-byte
	// signature. It is what chain.SelectApplicable charges before it starts
	// accumulating transaction sizes, so a block it assembles can never exceed
	// MaxBlockBytes.
	//
	// THE SIGNATURE IS COUNTED HERE AND NOT BY ValidateStructure: that runs
	// before a block is signed, so it measures a block whose Sig is empty and
	// undercounts the bytes that go on the wire by 65. A block measured there
	// at more than MaxBlockBytes-65 would be accepted locally and then refused
	// by DecodeBlock at every peer (which enforces MaxBlockBytes on the
	// SIGNED bytes). The producer's budget closes that gap; the validity rule
	// is left alone, because tightening it is a consensus change.
	BlockOverheadBytes = headerBytes + 2 + 1 + 64

	// MinTxBytes is the smallest canonical encoding a valid transaction can
	// take once the block frames it: a withdraw's 135 bytes plus its two-byte
	// length prefix. Every other type is larger (a faucet claim is 151 bytes, a
	// bond or unbond 143, a transfer 163), so this is the floor the byte budget
	// can ever be asked to hold.
	MinTxBytes = 135 + 2

	// MaxTxsByBytes is how many minimum-size transactions one block can carry
	// once BlockOverheadBytes is paid. It is the count the BYTE bound implies,
	// derived here so the two ceilings cannot be compared by hand.
	MaxTxsByBytes = (MaxBlockBytes - BlockOverheadBytes) / MinTxBytes
)

// init asserts that the two block ceilings COMPOSE - the check audit S-3 asked
// for, in the one form that is true of these constants.
//
// The literal inequality the audit prescribed - MaxTxsPerBlock <=
// (MaxBlockBytes-BlockOverheadBytes)/MinTxBytes - is FALSE here and must be:
// 10,000 x 165 + 212 = 1,650,212, which is the very arithmetic the finding is
// made of, so an init assertion of that shape would panic every node at
// startup. Making it true means lowering MaxTxsPerBlock to the byte-implied
// count, and that is a CONSENSUS change (ValidateStructure's count check is
// what a validator enforces), so it belongs with the next versioned fork - not
// in a producer fix. What the code depends on instead is that the byte budget
// can hold at least one transaction at the minimum size, or the producer would
// be unable to put anything in a block at all.
func init() {
	if MaxBlockBytes <= BlockOverheadBytes+MinTxBytes {
		panic(fmt.Sprintf("types: MaxBlockBytes %d cannot hold the %d-byte block overhead plus one %d-byte transaction: every block would be empty",
			MaxBlockBytes, BlockOverheadBytes, MinTxBytes))
	}
	if MaxTxsByBytes < 1 {
		panic(fmt.Sprintf("types: the byte budget admits %d transactions, want at least 1", MaxTxsByBytes))
	}
}

var (
	ErrBadProposer    = errors.New("types: proposer must be a valid Ed25519 public key")
	ErrTxRootMismatch = errors.New("types: transaction root does not match header")
	ErrDuplicateTx    = errors.New("types: block contains a duplicate transaction")
	ErrBlockTooLarge  = errors.New("types: block exceeds size limits")
	ErrBadTimestamp   = errors.New("types: timestamp must be positive")
)

// Header is the signed commitment for a block. A block's identity is its
// header hash; the body is carried separately.
type Header struct {
	Height     uint64
	ParentHash [32]byte
	StateRoot  [32]byte
	TxRoot     [32]byte
	Timestamp  int64
	Proposer   []byte // Ed25519 public key
}

// Block is a header plus its transactions. Sig is the proposer's Ed25519
// signature over Header.SigningHash(); it is deliberately outside the header
// so that signing does not change the block's identity.
type Block struct {
	Header Header
	Txs    []Tx
	Sig    []byte
}

// ComputeTxRoot commits to the ordered list of transaction IDs.
//
// COUPLING (audit S-12): crypto.MerkleRoot duplicates an odd final node, so
// [a,b,c] and [a,b,c,c] share a root. That ambiguity is closed here ONLY by
// ValidateStructure refusing a block with a duplicate transaction, and by
// nothing else. A caller that trusts a TxRoot WITHOUT running
// ValidateStructure (or an inclusion proof added later) reopens it: the root
// alone cannot distinguish the two lists. Keep the duplicate check in
// ValidateStructure; if TxRoot is ever consumed on a path that skips it,
// either run ValidateStructure there or add the missing leaf count to what
// the header commits. See crypto.MerkleRoot's own known-limitation note.
func ComputeTxRoot(txs []Tx) [32]byte {
	leaves := make([][32]byte, len(txs))
	for i := range txs {
		leaves[i] = txs[i].ID()
	}
	return crypto.MerkleRoot(leaves)
}

func (h *Header) Encode() []byte {
	e := NewEncoder()
	e.U64(h.Height)
	e.Fixed32(h.ParentHash)
	e.Fixed32(h.StateRoot)
	e.Fixed32(h.TxRoot)
	e.I64(h.Timestamp)
	e.VarBytes(h.Proposer)
	return e.Bytes()
}

// SigningHash is the digest a proposer signs.
func (h *Header) SigningHash() [32]byte {
	return crypto.HashParts([]byte("b10coin-header"), h.Encode())
}

// ID returns the block identifier: the hash of the header alone.
func (b *Block) ID() [32]byte {
	return crypto.HashParts([]byte("b10coin-block"), b.Header.Encode())
}

func (b *Block) Encode() []byte {
	e := NewEncoder()
	e.Raw(b.Header.Encode())
	e.Len(len(b.Txs))
	for i := range b.Txs {
		// VarBytes, not Raw: DecodeBlock frames each transaction by its
		// varint length, so a tx must not be written bare.
		e.VarBytes(b.Txs[i].Encode())
	}
	e.VarBytes(b.Sig)
	return e.Bytes()
}

func (b *Block) ValidateStructure() error {
	if len(b.Header.Proposer) != ed25519PublicKeySize {
		return fmt.Errorf("%w: got %d bytes", ErrBadProposer, len(b.Header.Proposer))
	}
	if b.Header.Timestamp <= 0 {
		return ErrBadTimestamp
	}
	if len(b.Txs) > MaxTxsPerBlock {
		return fmt.Errorf("%w: %d transactions", ErrBlockTooLarge, len(b.Txs))
	}
	if ComputeTxRoot(b.Txs) != b.Header.TxRoot {
		return ErrTxRootMismatch
	}
	seen := make(map[[32]byte]struct{}, len(b.Txs))
	for i := range b.Txs {
		id := b.Txs[i].ID()
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: %x", ErrDuplicateTx, id[:8])
		}
		seen[id] = struct{}{}
	}
	if size := len(b.Encode()); size > MaxBlockBytes {
		return fmt.Errorf("%w: %d bytes", ErrBlockTooLarge, size)
	}
	return nil
}

func DecodeBlock(b []byte) (*Block, error) {
	// Refuse anything already larger than a legal block BEFORE decoding any
	// of it (audit S-17). Without this an attacker-sized input is parsed
	// element by element and only rejected at the end by ValidateStructure,
	// if at all - the decoder allocates the transaction slice and every
	// transaction along the way. A valid block's Encode() is at most
	// MaxBlockBytes by ValidateStructure, so every legal encoding still
	// decodes to exactly the same bytes.
	if len(b) > MaxBlockBytes {
		return nil, fmt.Errorf("%w: %d bytes, above the %d-byte block bound", ErrBlockTooLarge, len(b), MaxBlockBytes)
	}
	d := NewDecoder(b)
	out := &Block{}
	var err error
	if out.Header.Height, err = d.U64(); err != nil {
		return nil, err
	}
	if out.Header.ParentHash, err = d.Fixed32(); err != nil {
		return nil, err
	}
	if out.Header.StateRoot, err = d.Fixed32(); err != nil {
		return nil, err
	}
	if out.Header.TxRoot, err = d.Fixed32(); err != nil {
		return nil, err
	}
	if out.Header.Timestamp, err = d.I64(); err != nil {
		return nil, err
	}
	if out.Header.Proposer, err = d.VarBytes(); err != nil {
		return nil, err
	}
	n, err := d.Len()
	if err != nil {
		return nil, err
	}
	if n > MaxTxsPerBlock {
		return nil, fmt.Errorf("%w: %d transactions", ErrBlockTooLarge, n)
	}
	out.Txs = make([]Tx, 0, n)
	for i := 0; i < n; i++ {
		raw, err := d.VarBytes()
		if err != nil {
			return nil, err
		}
		tx, err := DecodeTx(raw)
		if err != nil {
			return nil, err
		}
		out.Txs = append(out.Txs, *tx)
	}
	if out.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return out, nil
}
