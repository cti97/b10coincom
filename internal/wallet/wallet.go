// Package wallet builds and signs transactions for any client.
//
// It exists so that every client produces the same bytes: the CLI signs with
// it today, and a browser wallet signs with the SAME code compiled to
// WebAssembly rather than a second implementation of the envelope in
// JavaScript. A re-implemented encoder is a second definition of the wire
// format, and the failure it produces — a signature that verifies against a
// hash the node never computes — is invisible until a transaction is rejected
// on the wire.
//
// The package deliberately covers construction and signing only. Reading a
// balance, choosing a nonce and submitting are the caller's: the CLI gets them
// from the node's RPC, and a browser wallet gets them from the same endpoints.
package wallet

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// Errors a caller can act on rather than string-match.
var (
	ErrSelfTransfer   = errors.New("wallet: a transfer to the sender's own address can never apply")
	ErrZeroAmount     = errors.New("wallet: the amount must be positive")
	ErrExitCarriesFee = errors.New("wallet: an exit (unbond/withdraw) must not carry a fee")
	ErrBadKey         = errors.New("wallet: the key material is not an Ed25519 key")
)

// Key is an identity and the address derived from it. Address is computed by
// types.AddressFromPub - the same derivation the chain uses for every
// transaction's From field, never a second scheme.
type Key struct {
	Priv    ed25519.PrivateKey
	Pub     ed25519.PublicKey
	Address types.Address
}

// NewKey generates a fresh identity.
func NewKey() (Key, error) {
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		return Key{}, err
	}
	return keyFromParts(pub, priv)
}

// KeyFromSeed rebuilds an identity from a 32-byte Ed25519 seed (the form a
// wallet should store: the seed is the secret, the 64-byte expanded key is
// derived from it).
func KeyFromSeed(seed []byte) (Key, error) {
	if len(seed) != ed25519.SeedSize {
		return Key{}, fmt.Errorf("%w: a seed is %d bytes, got %d", ErrBadKey, ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return Key{}, ErrBadKey
	}
	return keyFromParts(pub, priv)
}

// KeyFromPrivate rebuilds an identity from a 64-byte private key (the form the
// CLI's key file holds, so the two clients can exchange a key).
func KeyFromPrivate(priv []byte) (Key, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Key{}, fmt.Errorf("%w: a private key is %d bytes, got %d", ErrBadKey, ed25519.PrivateKeySize, len(priv))
	}
	k := ed25519.PrivateKey(append([]byte(nil), priv...))
	pub, ok := k.Public().(ed25519.PublicKey)
	if !ok {
		return Key{}, ErrBadKey
	}
	return keyFromParts(pub, k)
}

func keyFromParts(pub ed25519.PublicKey, priv ed25519.PrivateKey) (Key, error) {
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		return Key{}, ErrBadKey
	}
	return Key{Priv: priv, Pub: pub, Address: types.AddressFromPub(pub)}, nil
}

// Seed returns the 32-byte seed to store. Storing the seed rather than the
// expanded key keeps a wallet file small and independent of Go's private-key
// layout.
func (k Key) Seed() []byte { return k.Priv.Seed() }

// Transfer builds and signs a TxTransfer. amount and fee are sparks; the
// caller takes the fee from the node's reported minimum and the nonce from the
// account, exactly as the CLI does.
func Transfer(k Key, genesis [32]byte, to types.Address, amount, fee, nonce uint64) (*types.Tx, error) {
	if amount == 0 {
		return nil, ErrZeroAmount
	}
	if to == k.Address {
		return nil, ErrSelfTransfer
	}
	return sign(k, genesis, &types.Tx{
		Type:   types.TxTransfer,
		From:   k.Address,
		PubKey: k.Pub,
		Nonce:  nonce,
		Fee:    fee,
		To:     to,
		Amount: amount,
	})
}

// Bond stakes amount sparks. A bond carries the chain minimum fee.
func Bond(k Key, genesis [32]byte, amount, fee, nonce uint64) (*types.Tx, error) {
	if amount == 0 {
		return nil, ErrZeroAmount
	}
	return sign(k, genesis, &types.Tx{
		Type:   types.TxBond,
		From:   k.Address,
		PubKey: k.Pub,
		Nonce:  nonce,
		Fee:    fee,
		Amount: amount,
	})
}

// Unbond releases amount sparks back to the unbonding queue. It carries no
// fee: state.applyUnbond refuses one, so signing it would only produce a
// transaction the chain rejects.
func Unbond(k Key, genesis [32]byte, amount, fee, nonce uint64) (*types.Tx, error) {
	if amount == 0 {
		return nil, ErrZeroAmount
	}
	if fee != 0 {
		return nil, ErrExitCarriesFee
	}
	return sign(k, genesis, &types.Tx{
		Type:   types.TxUnbond,
		From:   k.Address,
		PubKey: k.Pub,
		Nonce:  nonce,
		Amount: amount,
	})
}

// Withdraw releases every matured unbonding record. It carries no fee and no
// amount: the chain derives both from the bond record.
func Withdraw(k Key, genesis [32]byte, fee, nonce uint64) (*types.Tx, error) {
	if fee != 0 {
		return nil, ErrExitCarriesFee
	}
	return sign(k, genesis, &types.Tx{
		Type:   types.TxWithdraw,
		From:   k.Address,
		PubKey: k.Pub,
		Nonce:  nonce,
	})
}

// Claim builds a faucet claim. The caller has solved the puzzle and passes the
// epoch and the winning nonce; a claim never carries a fee.
func Claim(k Key, genesis [32]byte, epoch, powNonce, nonce uint64) (*types.Tx, error) {
	return sign(k, genesis, &types.Tx{
		Type:     types.TxFaucetClaim,
		From:     k.Address,
		PubKey:   k.Pub,
		Nonce:    nonce,
		Epoch:    epoch,
		PowNonce: powNonce,
	})
}

// sign fills the signature over SigningHash(genesis) and returns the
// transaction. It is the one place a signature is produced, so a client can
// never sign a body it did not build with this package.
func sign(k Key, genesis [32]byte, tx *types.Tx) (*types.Tx, error) {
	h := tx.SigningHash(genesis)
	tx.Sig = crypto.Sign(k.Priv, h[:])
	return tx, nil
}

// Hex is the wire encoding as hex, which is what the node's POST /tx accepts
// and what the CLI prints as a txid source.
func Hex(tx *types.Tx) string { return hex.EncodeToString(tx.Encode()) }

// ID is the transaction id the node reports back.
func ID(tx *types.Tx) [32]byte { return tx.ID() }
