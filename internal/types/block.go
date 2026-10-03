package types

import (
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
)

const (
	// MaxTxsPerBlock bounds block size so a Raspberry Pi can always
	// process a block within one block interval.
	MaxTxsPerBlock = 10_000
	// MaxBlockBytes bounds the canonical encoding of a block.
	MaxBlockBytes = 1 << 20
)

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
