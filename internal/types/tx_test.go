package types

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
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

// Tags 1..5 are transactions now; a decoder must still refuse the tags that are
// not. Type 0 and type 6 are the boundary cases, and 255 the far end. Each
// frame carries plenty of trailing bytes so the ONLY thing that can refuse it
// is the tag: a short body would otherwise pass this test for the wrong reason.
//
// Trailing bytes are a separate protocol error on a valid frame: Done() is what
// makes one extra byte on a Bond a refusal rather than a second reading.
func TestDecodeRejectsReservedAndTrailingBytes(t *testing.T) {
	for _, rawType := range []byte{0, 6, 7, 255} {
		e := NewEncoder()
		e.U8(rawType)
		e.Raw(make([]byte, 64))
		if _, err := DecodeTx(e.Bytes()); !errors.Is(err, ErrUnsupportedTxType) {
			t.Fatalf("type %d: expected ErrUnsupportedTxType, got %v", rawType, err)
		}
	}

	bond := signedStaking(t, TxBond, 1, 1000)
	if _, err := DecodeTx(append(bond.Encode(), 0xFF)); !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("expected ErrTrailingBytes for a Bond with one extra byte, got %v", err)
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

// signedStaking builds a signed TxBond, TxUnbond or TxWithdraw. The validator a
// staking transaction names is From, its signer, so no address appears in the
// body; Withdraw carries no amount at all.
func signedStaking(t *testing.T, typ TxType, nonce, amount uint64) *Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &Tx{
		Type:   typ,
		From:   AddressFromPub(pub),
		PubKey: pub,
		Nonce:  nonce,
		Fee:    3,
		Amount: amount,
	}
	hash := tx.SigningHash(testChain())
	tx.Sig = crypto.Sign(priv, hash[:])
	return tx
}

// assertStakingRoundTrip encodes, decodes and re-encodes one staking
// transaction, then checks the encoded LENGTH against a hand-built prefix and
// signature with exactly bodyLen bytes between them.
//
// The length assertion is what makes the test non-vacuous: encode and decode can
// share a misordering and still round-trip, but they cannot fake the offset. A
// missing amount shortens it by 8, an amount on Withdraw lengthens it by 8, and
// either is fatal here.
func assertStakingRoundTrip(t *testing.T, typ TxType, nonce, amount uint64, bodyLen int) {
	t.Helper()
	tx := signedStaking(t, typ, nonce, amount)
	enc := tx.Encode()
	got, err := DecodeTx(enc)
	if err != nil {
		t.Fatalf("DecodeTx(%x): %v", enc, err)
	}
	if got.Type != tx.Type || got.From != tx.From || got.Nonce != tx.Nonce ||
		got.Fee != tx.Fee || got.Amount != tx.Amount ||
		!bytes.Equal(got.PubKey, tx.PubKey) || !bytes.Equal(got.Sig, tx.Sig) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, tx)
	}
	if re := got.Encode(); !bytes.Equal(re, enc) {
		t.Fatalf("re-encoding is not byte-identical:\n got %x\nwant %x", re, enc)
	}

	prefix := NewEncoder()
	prefix.U8(uint8(tx.Type))
	prefix.Raw(tx.From[:])
	prefix.VarBytes(tx.PubKey)
	prefix.U64(tx.Nonce)
	prefix.U64(tx.Fee)
	sig := NewEncoder()
	sig.VarBytes(tx.Sig)
	want := len(prefix.Bytes()) + bodyLen + len(sig.Bytes())
	if len(enc) != want {
		t.Fatalf("encoded length %d, want %d (prefix %d + body %d + sig %d)",
			len(enc), want, len(prefix.Bytes()), bodyLen, len(sig.Bytes()))
	}
	if got.ID() != tx.ID() {
		t.Fatal("round trip changed the tx ID")
	}
}

// Bond is Amount(8) after the common prefix, at zero and at the maximum the
// 8-byte field can hold.
func TestBondRoundTrips(t *testing.T) {
	for _, c := range []struct{ nonce, amount uint64 }{
		{0, 0},
		{1, 1},
		{7, 1000},
		{math.MaxUint64, math.MaxUint64},
	} {
		t.Run(fmt.Sprintf("nonce=%d/amount=%d", c.nonce, c.amount), func(t *testing.T) {
			assertStakingRoundTrip(t, TxBond, c.nonce, c.amount, 8)
		})
	}
}

// Unbond carries the same single fixed-width amount as Bond.
func TestUnbondRoundTrips(t *testing.T) {
	for _, c := range []struct{ nonce, amount uint64 }{
		{0, 0},
		{1, 1},
		{7, 1000},
		{math.MaxUint64, math.MaxUint64},
	} {
		t.Run(fmt.Sprintf("nonce=%d/amount=%d", c.nonce, c.amount), func(t *testing.T) {
			assertStakingRoundTrip(t, TxUnbond, c.nonce, c.amount, 8)
		})
	}
}

// Withdraw adds NO body bytes: its only new information is the signer and the
// nonce, both in the common prefix.
func TestWithdrawRoundTrips(t *testing.T) {
	for _, nonce := range []uint64{0, 1, math.MaxUint64} {
		t.Run(fmt.Sprintf("nonce=%d", nonce), func(t *testing.T) {
			assertStakingRoundTrip(t, TxWithdraw, nonce, 0, 0)
		})
	}

	// A Withdraw that sets Amount still encodes nothing for it: the field is a
	// union member for the other types, and writing it here would be an
	// eight-byte body the decoder does not expect.
	base := signedStaking(t, TxWithdraw, 1, 0)
	withAmount := *base
	withAmount.Amount = 42
	if !bytes.Equal(withAmount.Encode(), base.Encode()) {
		t.Fatal("Withdraw encoded Amount; its body must be empty")
	}
	got, err := DecodeTx(withAmount.Encode())
	if err != nil {
		t.Fatalf("DecodeTx: %v", err)
	}
	if got.Amount != 0 {
		t.Fatalf("Withdraw decoded an amount of %d, want 0", got.Amount)
	}
}

func goldenPub() []byte {
	p := make([]byte, 32)
	for i := range p {
		p[i] = byte(i + 1)
	}
	return p
}

func goldenSig() []byte {
	s := make([]byte, 64)
	for i := range s {
		s[i] = byte(0xA0 + i)
	}
	return s
}

func goldenTo() Address {
	var a Address
	for i := range a {
		a[i] = byte(0x40 + i)
	}
	return a
}

// Both sides of a round trip move together, so only a golden notices a
// renumbering or a prefix change. These two hex strings were captured from the
// PRE-M5 code at e937cfd, before encodeBody gained its staking branches; the
// reservation existed precisely so they would not move.
func TestATransferAndAClaimEncodeToTheSameGoldenBytesAsM2(t *testing.T) {
	pub := goldenPub()
	transfer := &Tx{
		Type:   TxTransfer,
		From:   AddressFromPub(pub),
		PubKey: pub,
		Nonce:  7,
		Fee:    9,
		To:     goldenTo(),
		Amount: 1234,
		Sig:    goldenSig(),
	}
	claim := &Tx{
		Type:     TxFaucetClaim,
		From:     AddressFromPub(pub),
		PubKey:   pub,
		Epoch:    3,
		PowNonce: 42,
		Sig:      goldenSig(),
	}

	const transferGolden = "01af3ce61b11f3ef2ed1545476372f30a23493fcd1200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000000000000000070000000000000009404142434445464748494a4b4c4d4e4f5051525300000000000004d240a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
	const claimGolden = "02af3ce61b11f3ef2ed1545476372f30a23493fcd1200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000000000000000000000000000000000003000000000000002a40a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"

	for _, tc := range []struct {
		name string
		tx   *Tx
		want string
	}{
		{"transfer", transfer, transferGolden},
		{"faucet claim", claim, claimGolden},
	} {
		if got := hex.EncodeToString(tc.tx.Encode()); got != tc.want {
			t.Fatalf("%s encoding moved; every stored chain decodes these bytes:\n got %s\nwant %s",
				tc.name, got, tc.want)
		}
		raw, err := hex.DecodeString(tc.want)
		if err != nil {
			t.Fatalf("%s golden is not hex: %v", tc.name, err)
		}
		// A golden only this build writes and no other reads would still be a
		// fork: the frozen bytes must also decode.
		if _, err := DecodeTx(raw); err != nil {
			t.Fatalf("%s golden does not decode: %v", tc.name, err)
		}
	}
}

// A signature is over encodeBody, so changing the TYPE or the AMOUNT of the
// signed transaction must invalidate it. The chain binding is inherited:
// SigningHash folds genesisHash in, and VerifySignature is type-agnostic.
func TestASignatureForABondDoesNotVerifyForAnotherTypeOrAmount(t *testing.T) {
	bond := signedStaking(t, TxBond, 1, 1000)
	if err := bond.VerifySignature(testChain()); err != nil {
		t.Fatalf("the signed bond was refused: %v", err)
	}

	asUnbond := *bond
	asUnbond.Type = TxUnbond
	if err := asUnbond.VerifySignature(testChain()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a Bond signature verified as an Unbond: %v", err)
	}

	raised := *bond
	raised.Amount = 1001
	if err := raised.VerifySignature(testChain()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a Bond signature verified for a different amount: %v", err)
	}

	foreign := [32]byte{0xEE, 0xEE}
	if foreign == testChain() {
		t.Fatal("test bug: the foreign chain identifier equals the test chain")
	}
	if err := bond.VerifySignature(foreign); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a Bond signed for one chain verified on another: %v", err)
	}
}

// Every new decode path must refuse malformed input with the named sentinel,
// not panic and not silently accept: these encodings come from the network.
func TestDecodeTxRejectsMalformedStakingEncodings(t *testing.T) {
	bond := signedStaking(t, TxBond, 1, 1000)
	unbond := signedStaking(t, TxUnbond, 1, 1000)

	t.Run("truncated Bond body", func(t *testing.T) {
		// Built by hand: cutting Encode() would remove the signature first
		// and never reach the amount branch. Here the prefix decodes and the
		// amount is missing a byte.
		e := NewEncoder()
		e.U8(uint8(TxBond))
		e.Raw(bond.From[:])
		e.VarBytes(bond.PubKey)
		e.U64(bond.Nonce)
		e.U64(bond.Fee)
		e.Raw(make([]byte, 7))
		if _, err := DecodeTx(e.Bytes()); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("expected ErrShortBuffer for a truncated Bond body, got %v", err)
		}
	})

	t.Run("truncated Unbond body", func(t *testing.T) {
		e := NewEncoder()
		e.U8(uint8(TxUnbond))
		e.Raw(unbond.From[:])
		e.VarBytes(unbond.PubKey)
		e.U64(unbond.Nonce)
		e.U64(unbond.Fee)
		if _, err := DecodeTx(e.Bytes()); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("expected ErrShortBuffer for a missing Unbond amount, got %v", err)
		}
	})

	t.Run("non-minimal PubKey length", func(t *testing.T) {
		e := NewEncoder()
		e.U8(uint8(TxBond))
		e.Raw(bond.From[:])
		e.Raw([]byte{0xA0, 0x00}) // 32 in two bytes: redundant continuation
		e.Raw(bond.PubKey)
		e.U64(bond.Nonce)
		e.U64(bond.Fee)
		e.U64(bond.Amount)
		e.VarBytes(bond.Sig)
		if _, err := DecodeTx(e.Bytes()); !errors.Is(err, ErrNonCanonical) {
			t.Fatalf("expected ErrNonCanonical for a redundant length varint, got %v", err)
		}
	})

	t.Run("over-long PubKey length varint", func(t *testing.T) {
		e := NewEncoder()
		e.U8(uint8(TxBond))
		e.Raw(bond.From[:])
		// Nine continuation bytes then a terminator of 0x02: a well-framed
		// 65-bit number, which no length can represent.
		e.Raw([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02})
		if _, err := DecodeTx(e.Bytes()); !errors.Is(err, ErrVarintOverflow) {
			t.Fatalf("expected ErrVarintOverflow for a 64-bit-overflowing length, got %v", err)
		}
	})
}
