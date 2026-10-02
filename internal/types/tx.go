package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
)

var (
	ErrUnsupportedTxType = errors.New("types: unsupported transaction type")
	ErrBadSignature      = errors.New("types: bad signature")
	ErrAddressMismatch   = errors.New("types: pubkey does not match sender address")
)

// TxType discriminates the transaction union. Only TxTransfer is
// implemented in M1; the rest are reserved so the encoding is stable.
type TxType uint8

const (
	TxTransfer    TxType = 1
	TxFaucetClaim TxType = 2
	TxBond        TxType = 3
	TxUnbond      TxType = 4
	TxWithdraw    TxType = 5
)

// Tx is a signed state transition.
//
// The sender's public key travels with the transaction because an address is
// only a hash of that key: the key cannot be recovered from the address, so
// signature verification needs it supplied explicitly.
type Tx struct {
	Type   TxType
	From   Address
	PubKey []byte
	Nonce  uint64

	// TxTransfer only.
	To     Address
	Amount uint64

	// Sig is the Ed25519 signature over SigningHash().
	Sig []byte
}

// encodeBody renders every field the signature covers.
func (tx *Tx) encodeBody() []byte {
	e := NewEncoder()
	e.U8(uint8(tx.Type))
	e.Raw(tx.From[:])
	e.VarBytes(tx.PubKey)
	e.U64(tx.Nonce)
	if tx.Type == TxTransfer {
		e.Raw(tx.To[:])
		e.U64(tx.Amount)
	}
	return e.Bytes()
}

// SigningHash is the digest that must be signed. It deliberately excludes
// Sig, so signing is not recursive.
func (tx *Tx) SigningHash() [32]byte {
	return crypto.HashParts([]byte("b10coin-tx"), tx.encodeBody())
}

// ID is the transaction identifier used for deduplication and indexing.
func (tx *Tx) ID() [32]byte {
	return crypto.HashParts([]byte("b10coin-txid"), tx.Encode())
}

// Encode returns the canonical wire encoding, signature included.
func (tx *Tx) Encode() []byte {
	e := NewEncoder()
	e.Raw(tx.encodeBody())
	e.VarBytes(tx.Sig)
	return e.Bytes()
}

// VerifySignature checks that PubKey matches From and that Sig is valid.
func (tx *Tx) VerifySignature() error {
	if len(tx.PubKey) == 0 {
		return fmt.Errorf("%w: missing public key", ErrBadSignature)
	}
	if AddressFromPub(tx.PubKey) != tx.From {
		return ErrAddressMismatch
	}
	// SigningHash returns an array, which must be bound to a variable
	// before it can be sliced (a call result is not addressable).
	hash := tx.SigningHash()
	if !crypto.Verify(tx.PubKey, hash[:], tx.Sig) {
		return ErrBadSignature
	}
	return nil
}

// DecodeTx parses a canonical transaction encoding. It rejects unsupported
// types, trailing bytes and any over-long field.
func DecodeTx(b []byte) (*Tx, error) {
	d := NewDecoder(b)
	rawType, err := d.U8()
	if err != nil {
		return nil, err
	}
	tx := &Tx{Type: TxType(rawType)}
	if tx.Type != TxTransfer {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedTxType, rawType)
	}
	if tx.From, err = d.Fixed20(); err != nil {
		return nil, err
	}
	if tx.PubKey, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if tx.Nonce, err = d.U64(); err != nil {
		return nil, err
	}
	if tx.To, err = d.Fixed20(); err != nil {
		return nil, err
	}
	if tx.Amount, err = d.U64(); err != nil {
		return nil, err
	}
	if tx.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return tx, nil
}

// Equal reports whether two transactions are byte-identical when encoded.
func (tx *Tx) Equal(other *Tx) bool {
	return bytes.Equal(tx.Encode(), other.Encode())
}
