package types

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
)

// ed25519PublicKeySize is the expected length of a proposer or signer key.
const ed25519PublicKeySize = ed25519.PublicKeySize

var (
	ErrUnsupportedTxType = errors.New("types: unsupported transaction type")
	ErrBadSignature      = errors.New("types: bad signature")
	ErrAddressMismatch   = errors.New("types: pubkey does not match sender address")
)

// TxType discriminates the transaction union. TxTransfer (M1) and
// TxFaucetClaim (M2) are implemented; TxBond, TxUnbond and TxWithdraw are
// reserved so the encoding is stable.
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
//
// VALIDITY WINDOW (audit S-19): a signed transaction carries NO expiry or
// height window. Its only bound is the account nonce - once the nonce is
// consumed the transaction can never apply again, and a transfer sits
// spendable indefinitely until then. This is a deliberate, acknowledged
// property, not a latent bug: a window needs a height/timestamp field inside
// the signed body, which is a hard-fork-shaped encoding change. S-1 and S-3
// already spent one such change on the chain identifier and the fee; adding
// the expiry field belongs in the same place (Header has no version field, so
// there is no in-band signal for a second one). Do not add an unsigned
// expiry: an unauthenticated bound is worse than none.
type Tx struct {
	Type   TxType
	From   Address
	PubKey []byte
	Nonce  uint64
	// Fee is the cost the sender pays the protocol for including this
	// transaction (audit S-3). It is signed for EVERY type, so it is never an
	// unauthenticated field that could vary under one transaction ID; a
	// transfer must pay the chain's minimum, and a faucet claim must pay
	// nothing (the protocol pays the claimant; a claim can come from an
	// account holding nothing at all, so charging one would close the faucet).
	Fee uint64

	// TxTransfer only.
	To     Address
	Amount uint64

	// TxFaucetClaim only. The puzzle's parameters are genesis state, not carried
	// on the wire: a claimant and a verifier must agree on them, and if they
	// disagree the claim simply fails to verify.
	Epoch    uint64
	PowNonce uint64

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
	e.U64(tx.Fee)
	if tx.Type == TxTransfer {
		e.Raw(tx.To[:])
		e.U64(tx.Amount)
	}
	if tx.Type == TxFaucetClaim {
		e.U64(tx.Epoch)
		e.U64(tx.PowNonce)
	}
	return e.Bytes()
}

// SigningHash is the digest that must be signed. It deliberately excludes
// Sig, so signing is not recursive.
//
// genesisHash is the CHAIN IDENTIFIER the signature is bound to (audit S-1):
// the hash of the chain's genesis, which commits to every genesis parameter.
// Without it a transfer signed on one chain was valid on any other chain that
// shared the same nonce and balance, so a transaction could be replayed across
// a testnet and a community fork, or across a devnet and a testnet. It is a
// domain-separated HashParts part - length-prefixed like every other part, 32
// fixed-width bytes - so no two chains' signatures can be confused and the
// encoding stays canonical.
func (tx *Tx) SigningHash(genesisHash [32]byte) [32]byte {
	return crypto.HashParts([]byte("b10coin-tx"), genesisHash[:], tx.encodeBody())
}

// ID is the transaction identifier used for deduplication and indexing. It
// covers the signature, not only the body (audit S-13).
//
// That is deliberate and was re-checked rather than changed. The audit's
// concern - "the signer can produce unlimited valid IDs for one body and fill
// the pool with copies" - does not hold: Ed25519 signing (crypto.Sign, hence
// ed25519.Sign) is DETERMINISTIC, so a given key has exactly one signature
// over a given SigningHash. Two byte-different valid encodings of "one body"
// therefore require two different signed bodies, i.e. two different
// transactions, and those are bounded downstream by the mempool's per-sender
// transfer cap and its rule that one sender may hold only one pending
// transfer per nonce (audit S-9). Hashing the signature also means a
// malformed or substituted signature cannot collide with the real
// transaction's ID.
func (tx *Tx) ID() [32]byte {
	return crypto.HashParts([]byte("b10coin-txid"), tx.Encode())
}

// Encode returns the canonical wire encoding, signature included.
//
// Encoding is only meaningful for the implemented types (TxTransfer and
// TxFaucetClaim): encodeBody emits a truncated body for a reserved type
// (TxBond, TxUnbond, TxWithdraw), so DecodeTx(tx.Encode()) is not a round
// trip for those — DecodeTx rejects reserved types outright.
func (tx *Tx) Encode() []byte {
	e := NewEncoder()
	e.Raw(tx.encodeBody())
	e.VarBytes(tx.Sig)
	return e.Bytes()
}

// VerifySignature checks that PubKey matches From and that Sig is valid over
// the chain identifier and the body. genesisHash must be the genesis hash of
// the chain this transaction is being judged for: a transaction signed for
// another chain fails here, which is what makes it unreplayable there.
func (tx *Tx) VerifySignature(genesisHash [32]byte) error {
	if len(tx.PubKey) == 0 {
		return fmt.Errorf("%w: missing public key", ErrBadSignature)
	}
	if AddressFromPub(tx.PubKey) != tx.From {
		return ErrAddressMismatch
	}
	// SigningHash returns an array, which must be bound to a variable
	// before it can be sliced (a call result is not addressable).
	hash := tx.SigningHash(genesisHash)
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
	if tx.Type != TxTransfer && tx.Type != TxFaucetClaim {
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
	if tx.Fee, err = d.U64(); err != nil {
		return nil, err
	}
	switch tx.Type {
	case TxTransfer:
		if tx.To, err = d.Fixed20(); err != nil {
			return nil, err
		}
		if tx.Amount, err = d.U64(); err != nil {
			return nil, err
		}
	case TxFaucetClaim:
		if tx.Epoch, err = d.U64(); err != nil {
			return nil, err
		}
		if tx.PowNonce, err = d.U64(); err != nil {
			return nil, err
		}
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
// A nil receiver or nil argument is never equal (and never panics): a nil
// value is not a transaction, so it matches nothing.
func (tx *Tx) Equal(other *Tx) bool {
	if tx == nil || other == nil {
		return false
	}
	return bytes.Equal(tx.Encode(), other.Encode())
}
