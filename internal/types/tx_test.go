package types

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

// signedTransfer builds a valid transfer signed by a fresh key.
func signedTransfer(t *testing.T, nonce, amount uint64) *Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, otherPub, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &Tx{
		Type:   TxTransfer,
		From:   AddressFromPub(pub),
		PubKey: pub,
		Nonce:  nonce,
		To:     AddressFromPub(otherPub),
		Amount: amount,
	}
	// SigningHash returns an array, which must be bound to a variable
	// before it can be sliced (a call result is not addressable).
	hash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, hash[:])
	return tx
}

func TestTxEncodeDecodeRoundTrip(t *testing.T) {
	tx := signedTransfer(t, 7, 1234)
	got, err := DecodeTx(tx.Encode())
	if err != nil {
		t.Fatalf("DecodeTx: %v", err)
	}
	if got.Type != tx.Type || got.From != tx.From || got.Nonce != tx.Nonce ||
		got.To != tx.To || got.Amount != tx.Amount {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, tx)
	}
	if string(got.PubKey) != string(tx.PubKey) || string(got.Sig) != string(tx.Sig) {
		t.Fatal("round trip lost key material")
	}
	if got.ID() != tx.ID() {
		t.Fatal("round trip changed the tx ID")
	}
}

func TestTxIDIsDeterministicAndSensitive(t *testing.T) {
	a := signedTransfer(t, 1, 100)
	b := signedTransfer(t, 1, 100)
	if a.ID() != a.ID() {
		t.Fatal("ID is not deterministic")
	}
	if a.ID() == b.ID() {
		t.Fatal("two distinct transactions shared an ID")
	}
}

func TestVerifySignatureAcceptsValid(t *testing.T) {
	if err := signedTransfer(t, 1, 10).VerifySignature(); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifySignatureRejectsTamperedAmount(t *testing.T) {
	tx := signedTransfer(t, 1, 10)
	tx.Amount = 999999
	if err := tx.VerifySignature(); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

// The signature covers From, so an attacker cannot re-attribute a signed
// transaction to a different account.
func TestVerifySignatureRejectsMismatchedFrom(t *testing.T) {
	tx := signedTransfer(t, 1, 10)
	// Point From at an address that does not match PubKey. The key/address
	// binding check must reject this before the signature is examined.
	tx.From = AddressFromPub([]byte("not-the-real-key"))
	if err := tx.VerifySignature(); !errors.Is(err, ErrAddressMismatch) {
		t.Fatalf("expected ErrAddressMismatch, got %v", err)
	}
}

func TestDecodeTxRejectsUnsupportedType(t *testing.T) {
	e := NewEncoder()
	e.U8(uint8(TxBond))
	// AddressFromPub returns an array, which must be bound to a variable
	// before it can be sliced (a call result is not addressable).
	from := AddressFromPub([]byte("p"))
	e.Raw(from[:])
	e.VarBytes([]byte("pub"))
	e.U64(0)
	e.U64(0)
	e.VarBytes([]byte("sig"))
	if _, err := DecodeTx(e.Bytes()); !errors.Is(err, ErrUnsupportedTxType) {
		t.Fatalf("expected ErrUnsupportedTxType, got %v", err)
	}
}

// The signature must cover the sender's address: if From were dropped from
// the signed body, a signature over the body would survive changing From to
// any other account (the address-binding check in VerifySignature only
// compares PubKey against From AFTER the fact — it cannot catch a digest
// that never contained From).
func TestSigningHashCoversFrom(t *testing.T) {
	tx := signedTransfer(t, 1, 10)
	before := tx.SigningHash()
	tx.From = AddressFromPub([]byte("a-different-sender"))
	if tx.SigningHash() == before {
		t.Fatal("SigningHash ignored the sender address: From is not in the signed body")
	}
}

func TestDecodeTxRejectsTrailingBytes(t *testing.T) {
	enc := signedTransfer(t, 1, 5).Encode()
	_, err := DecodeTx(append(enc, 0xFF))
	if !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("expected ErrTrailingBytes, got %v", err)
	}
}
