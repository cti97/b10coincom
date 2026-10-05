package types

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

// testChain is the chain identifier the types tests sign for. types cannot
// import genesis (genesis imports types), so the tests use their own stable
// 32-byte identifier; nothing here depends on which chain it stands for, only
// that signing and verifying agree on it.
func testChain() [32]byte { return [32]byte{0xC7, 0x4A, 0x11} }

// signedTransfer builds a valid transfer signed by a fresh key.
func signedTransfer(t *testing.T, nonce, amount uint64) *Tx {
	return signedTransferWithFee(t, nonce, amount, 0)
}

// signedTransferWithFee is signedTransfer with the fee under test.
func signedTransferWithFee(t *testing.T, nonce, amount, fee uint64) *Tx {
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
		Fee:    fee,
		To:     AddressFromPub(otherPub),
		Amount: amount,
	}
	// SigningHash returns an array, which must be bound to a variable
	// before it can be sliced (a call result is not addressable).
	hash := tx.SigningHash(testChain())
	tx.Sig = crypto.Sign(priv, hash[:])
	return tx
}

func TestTxEncodeDecodeRoundTrip(t *testing.T) {
	tx := signedTransferWithFee(t, 7, 1234, 9)
	got, err := DecodeTx(tx.Encode())
	if err != nil {
		t.Fatalf("DecodeTx: %v", err)
	}
	if got.Type != tx.Type || got.From != tx.From || got.Nonce != tx.Nonce ||
		got.To != tx.To || got.Amount != tx.Amount || got.Fee != tx.Fee {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, tx)
	}
	if string(got.PubKey) != string(tx.PubKey) || string(got.Sig) != string(tx.Sig) {
		t.Fatal("round trip lost key material")
	}
	if got.ID() != tx.ID() {
		t.Fatal("round trip changed the tx ID")
	}
}

// The fee is part of the signed body (audit S-3): changing it after signing
// must invalidate the signature, or a relayer could raise or lower what the
// sender pays.
func TestSigningHashCoversFee(t *testing.T) {
	tx := signedTransferWithFee(t, 1, 10, 3)
	if err := tx.VerifySignature(testChain()); err != nil {
		t.Fatalf("the signed fee was refused: %v", err)
	}
	base := tx.SigningHash(testChain())
	raised := *tx
	raised.Fee = 4
	if raised.SigningHash(testChain()) == base {
		t.Fatal("SigningHash ignored the fee: the signed body does not cover it")
	}
	raised.Sig = tx.Sig
	if err := raised.VerifySignature(testChain()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a raised fee still verified against the original signature: %v", err)
	}
}

// The chain identifier is inside the signed preimage (audit S-1), so one
// transaction cannot be valid on two chains.
func TestSigningHashCoversTheChainIdentifier(t *testing.T) {
	tx := signedTransferWithFee(t, 1, 10, 1)
	var other [32]byte
	copy(other[:], "another chain\x00\x00\x00")
	if tx.SigningHash(testChain()) == tx.SigningHash(other) {
		t.Fatal("SigningHash ignored the chain identifier")
	}
}

func TestTxIDIsDeterministicAndSensitive(t *testing.T) {
	a := signedTransfer(t, 1, 100)
	b := signedTransfer(t, 1, 100)
	first, second := a.ID(), a.ID()
	if first != second {
		t.Fatal("ID is not deterministic")
	}
	if a.ID() == b.ID() {
		t.Fatal("two distinct transactions shared an ID")
	}
}

func TestVerifySignatureAcceptsValid(t *testing.T) {
	if err := signedTransfer(t, 1, 10).VerifySignature(testChain()); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifySignatureRejectsTamperedAmount(t *testing.T) {
	tx := signedTransfer(t, 1, 10)
	tx.Amount = 999999
	if err := tx.VerifySignature(testChain()); !errors.Is(err, ErrBadSignature) {
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
	if err := tx.VerifySignature(testChain()); !errors.Is(err, ErrAddressMismatch) {
		t.Fatalf("expected ErrAddressMismatch, got %v", err)
	}
}

func TestDecodeTxRejectsUnsupportedType(t *testing.T) {
	for _, reserved := range []TxType{TxBond, TxUnbond, TxWithdraw} {
		e := NewEncoder()
		e.U8(uint8(reserved))
		// AddressFromPub returns an array, which must be bound to a variable
		// before it can be sliced (a call result is not addressable).
		from := AddressFromPub([]byte("p"))
		e.Raw(from[:])
		e.VarBytes([]byte("pub"))
		e.U64(0)
		e.U64(0)
		e.VarBytes([]byte("sig"))
		// The decoder rejects by type before reading anything else, so the
		// remainder of the body above is deliberately not a valid anything.
		if _, err := DecodeTx(e.Bytes()); !errors.Is(err, ErrUnsupportedTxType) {
			t.Fatalf("type %d: expected ErrUnsupportedTxType, got %v", reserved, err)
		}
	}
}

// The signature must cover the sender's address: if From were dropped from
// the signed body, a signature over the body would survive changing From to
// any other account (the address-binding check in VerifySignature only
// compares PubKey against From AFTER the fact — it cannot catch a digest
// that never contained From).
func TestSigningHashCoversFrom(t *testing.T) {
	tx := signedTransfer(t, 1, 10)
	before := tx.SigningHash(testChain())
	tx.From = AddressFromPub([]byte("a-different-sender"))
	if tx.SigningHash(testChain()) == before {
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

// The TxFaucetClaim decode paths need malformed-input coverage of their own:
// TestDecodeTxRejectsTrailingBytes above exercises a transfer only. Each
// subcase names its specific sentinel, and each fails if the guard it names
// were removed (the bounds checks would panic on out-of-range slices, the
// Done check would return a nil error).
func TestDecodeTxFaucetClaimRejectsMalformedEncodings(t *testing.T) {
	tx := signedClaim(t, 3, 9)

	t.Run("truncated claim body", func(t *testing.T) {
		// Built by hand rather than cut from Encode(): the trailing signature
		// sits at the end of a full encoding, so truncating that would fail
		// in the Sig read and never reach the TxFaucetClaim case. Here the
		// header, pubkey and nonce decode cleanly and the FIRST claim-only
		// field (Epoch) is the byte that is missing.
		e := NewEncoder()
		e.U8(uint8(TxFaucetClaim))
		e.Raw(tx.From[:])
		e.VarBytes(tx.PubKey)
		e.U64(tx.Nonce)
		if _, err := DecodeTx(e.Bytes()); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("expected ErrShortBuffer for a truncated claim body, got %v", err)
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := DecodeTx(append(tx.Encode(), 0xFF)); !errors.Is(err, ErrTrailingBytes) {
			t.Fatalf("expected ErrTrailingBytes, got %v", err)
		}
	})

	t.Run("over-long PubKey", func(t *testing.T) {
		e := NewEncoder()
		e.U8(uint8(TxFaucetClaim))
		e.Raw(tx.From[:])
		e.Len(1024) // claims a 1024-byte key that the buffer does not hold
		e.Raw([]byte("short-body"))
		if _, err := DecodeTx(e.Bytes()); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("expected ErrShortBuffer for an over-long PubKey, got %v", err)
		}
	})
}

// signedClaim builds a claim signed by a fresh key.
func signedClaim(t *testing.T, epoch, powNonce uint64) *Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &Tx{
		Type:     TxFaucetClaim,
		From:     AddressFromPub(pub),
		PubKey:   pub,
		Nonce:    0,
		Epoch:    epoch,
		PowNonce: powNonce,
	}
	sigHash := tx.SigningHash(testChain())
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return tx
}

func TestFaucetClaimRoundTrips(t *testing.T) {
	tx := signedClaim(t, 7, 12345)
	got, err := DecodeTx(tx.Encode())
	if err != nil {
		t.Fatalf("DecodeTx: %v", err)
	}
	if got.Type != TxFaucetClaim || got.Epoch != 7 || got.PowNonce != 12345 {
		t.Fatalf("round trip lost the claim fields: %+v", got)
	}
	if got.ID() != tx.ID() {
		t.Fatal("round trip changed the tx ID")
	}
}

// The signature must cover the epoch and the nonce, or an attacker could take a
// valid signed claim and re-aim it at a different epoch or swap in another
// solution.
func TestFaucetClaimSignatureCoversEpochAndNonce(t *testing.T) {
	tx := signedClaim(t, 7, 12345)
	base := tx.SigningHash(testChain())

	// Each variant is a copy of the SAME signed transaction with one field
	// changed, so every other byte of the signed body is held constant and the
	// comparison isolates the field under test. (signedClaim generates a fresh
	// random key on every call: a second signedClaim's hash differs by its key
	// alone, which would let this test pass even if encodeBody ignored the
	// field — the RED run demonstrated exactly that.)
	other := *tx
	other.Epoch = 8
	if other.SigningHash(testChain()) == base {
		t.Fatal("SigningHash ignored the epoch")
	}
	third := *tx
	third.PowNonce = 999
	if third.SigningHash(testChain()) == base {
		t.Fatal("SigningHash ignored the proof-of-work nonce")
	}
}
