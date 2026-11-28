package wallet

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

func testKey(t *testing.T, seed byte) Key {
	t.Helper()
	s := bytes.Repeat([]byte{seed}, ed25519.SeedSize)
	k, err := KeyFromSeed(s)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	return k
}

// The parity test this package exists for: a transfer built by wallet.Transfer
// must be BYTE-IDENTICAL to one built the way the CLI builds it, signature
// included. If that ever fails, a browser wallet and the CLI are signing
// different envelopes and one of them is producing transactions the node
// rejects - which is exactly the failure a second implementation in JavaScript
// would introduce.
func TestTransferIsByteIdenticalToTheCliConstruction(t *testing.T) {
	from := testKey(t, 7)
	to := testKey(t, 9)
	g := genesis.Devnet().Hash()
	const amount, fee, nonce = uint64(250_000_000), uint64(1), uint64(4)

	got, err := Transfer(from, g, to.Address, amount, fee, nonce)
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}

	// The CLI's construction, by hand: a literal, the signing hash, a signature.
	want := &types.Tx{
		Type:   types.TxTransfer,
		From:   types.AddressFromPub(from.Pub),
		PubKey: from.Pub,
		Nonce:  nonce,
		Fee:    fee,
		To:     to.Address,
		Amount: amount,
	}
	h := want.SigningHash(g)
	want.Sig = crypto.Sign(from.Priv, h[:])

	if !bytes.Equal(got.Encode(), want.Encode()) {
		t.Fatalf("wallet.Transfer encoded %x, CLI construction encoded %x", got.Encode(), want.Encode())
	}
	if ID(got) != ID(want) {
		t.Fatalf("txid differs: %x vs %x", ID(got), ID(want))
	}
}

// A signature that does not verify is the one failure a wallet cannot recover
// from, so it is checked against the address the transaction claims to be
// from - not against the key the caller passed.
func TestTransferSignatureVerifiesOverTheSigningHash(t *testing.T) {
	k := testKey(t, 3)
	to := testKey(t, 4)
	g := genesis.Devnet().Hash()

	tx, err := Transfer(k, g, to.Address, 1, 1, 0)
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	h := tx.SigningHash(g)
	if !ed25519.Verify(ed25519.PublicKey(tx.PubKey), h[:], tx.Sig) {
		t.Fatal("the signature does not verify over the signing hash")
	}
	if types.AddressFromPub(tx.PubKey) != tx.From {
		t.Fatal("the transaction's From is not the address of its public key")
	}
}

func TestTransferRefusesTheCasesTheChainWouldReject(t *testing.T) {
	k := testKey(t, 5)
	g := genesis.Devnet().Hash()

	if _, err := Transfer(k, g, k.Address, 1, 1, 0); err != ErrSelfTransfer {
		t.Fatalf("self-transfer: err = %v, want ErrSelfTransfer", err)
	}
	if _, err := Transfer(k, g, testKey(t, 6).Address, 0, 1, 0); err != ErrZeroAmount {
		t.Fatalf("zero amount: err = %v, want ErrZeroAmount", err)
	}
}

func TestExitsCarryNoFeeAndNoAmountOfTheirOwn(t *testing.T) {
	k := testKey(t, 8)
	g := genesis.Devnet().Hash()

	if _, err := Unbond(k, g, 1_000, 1, 0); err != ErrExitCarriesFee {
		t.Fatalf("unbond with fee: err = %v, want ErrExitCarriesFee", err)
	}
	if _, err := Withdraw(k, g, 1, 0); err != ErrExitCarriesFee {
		t.Fatalf("withdraw with fee: err = %v, want ErrExitCarriesFee", err)
	}
	w, err := Withdraw(k, g, 0, 7)
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if w.Type != types.TxWithdraw || w.Amount != 0 || w.Fee != 0 || w.Nonce != 7 {
		t.Fatalf("withdraw encoded unexpected fields: %+v", w)
	}
}

// A key restored from its seed must be the same identity: that is what makes a
// wallet's stored seed worth anything.
func TestSeedRoundTripKeepsTheAddress(t *testing.T) {
	k := testKey(t, 11)
	again, err := KeyFromSeed(k.Seed())
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	if again.Address != k.Address {
		t.Fatalf("address changed across a seed round trip: %s vs %s", again.Address, k.Address)
	}
	// And the 64-byte form the CLI's key file holds must agree too, so a user
	// can move a key between the two clients.
	fromFile, err := KeyFromPrivate(k.Priv)
	if err != nil {
		t.Fatalf("KeyFromPrivate: %v", err)
	}
	if fromFile.Address != k.Address {
		t.Fatalf("private-key round trip changed the address: %s vs %s", fromFile.Address, k.Address)
	}
}

func TestHexIsTheWireEncoding(t *testing.T) {
	k := testKey(t, 12)
	tx, err := Transfer(k, genesis.Devnet().Hash(), testKey(t, 13).Address, 5, 1, 0)
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if h := Hex(tx); h != fmtHex(tx.Encode()) {
		t.Fatalf("Hex = %s, want %s", h, fmtHex(tx.Encode()))
	}
}

func fmtHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}
