package types

// Go fuzz targets for the block and transaction decoders. Design spec §9.2
// names the block decoder as a fuzz target because it consumes untrusted
// input: a peer's proposal carries block bytes this package must parse before
// anything about them is known, and a panic in DecodeBlock or DecodeTx is a
// remote denial of service.
//
// The property each target pins is the one that matters on hostile bytes: a
// decoder NEVER PANICS (the fuzz engine itself fails the run on the first
// panic, in seed-corpus mode under `go test ./...` just as in a live fuzzing
// round) and NEVER ALLOCATES UNBOUNDEDLY - every field it returns is a bounded
// copy of bytes inside the frame it was given, and the transaction count it
// pre-allocates for is bounded by both the frame and MaxTxsPerBlock - while a
// frame it cannot accept returns an error, never a partially-trusted value.
// Each corpus is seeded with valid encodings first, so the fuzzer starts from
// the happy path, plus malformed frames the decoders must reject.
//
// Bounded runs:
//
//	go test -run '^$' -fuzz 'FuzzDecodeBlock$' -fuzztime 5s ./internal/types
//	go test -run '^$' -fuzz 'FuzzDecodeTx$' -fuzztime 5s ./internal/types

import (
	"bytes"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

// fuzzSignedTx builds a transfer or claim properly signed by a fresh key, so
// the seed corpus starts with frames the decoders accept end to end.
func fuzzSignedTx(tb testing.TB, typ TxType, nonce, amount uint64) *Tx {
	tb.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		tb.Fatal(err)
	}
	_, other, err := crypto.GenerateKey()
	if err != nil {
		tb.Fatal(err)
	}
	tx := &Tx{Type: typ, From: AddressFromPub(pub), PubKey: pub, Nonce: nonce}
	if typ == TxTransfer {
		tx.To, tx.Amount = AddressFromPub(other), amount
	}
	if typ == TxFaucetClaim {
		tx.Epoch, tx.PowNonce = 1, 42
	}
	// SigningHash returns an array, which must be bound before it can be sliced.
	hash := tx.SigningHash(testChain())
	tx.Sig = crypto.Sign(priv, hash[:])
	return tx
}

// fuzzBlockOf frames a valid block around the given transactions (an unsigned
// proposer key and empty Sig are enough: the decoder never checks them).
func fuzzBlockOf(tb testing.TB, txs ...Tx) *Block {
	tb.Helper()
	pub, _, err := crypto.GenerateKey()
	if err != nil {
		tb.Fatal(err)
	}
	b := &Block{Header: Header{
		Height: 1, ParentHash: crypto.HashParts([]byte("parent")),
		StateRoot: crypto.HashParts([]byte("state")),
		TxRoot:    ComputeTxRoot(txs),
		Timestamp: 1_700_000_000, Proposer: pub,
	}, Txs: txs}
	return b
}

// fuzzFrameHeader appends a minimal, well-formed block header to e.
func fuzzFrameHeader(e *Encoder) {
	e.U64(1)
	e.Fixed32(crypto.HashParts([]byte("parent")))
	e.Fixed32(crypto.HashParts([]byte("state")))
	e.Fixed32(ComputeTxRoot(nil))
	e.I64(1_700_000_000)
	e.VarBytes(make([]byte, 32))
}

// fuzzBlockWithTxBytes frames a block whose first tx body is raw bytes, for
// seeds that need a shape no valid encoder produces (an unsupported type).
func fuzzBlockWithTxBytes(tb testing.TB, innerTx []byte) []byte {
	tb.Helper()
	e := NewEncoder()
	fuzzFrameHeader(e)
	e.Len(1)
	e.VarBytes(innerTx)
	e.VarBytes(nil) // Sig
	return e.Bytes()
}

// fuzzBlockWithTxCount frames a block header followed by a tx count of n and
// no transactions at all, for count-over-the-bound seeds.
func fuzzBlockWithTxCount(tb testing.TB, n int) []byte {
	tb.Helper()
	e := NewEncoder()
	fuzzFrameHeader(e)
	e.Len(n)
	e.VarBytes(nil)
	return e.Bytes()
}

// fuzzBlockWithRawTxCount frames a block header followed by literal varint
// bytes as the tx count, for non-canonical-length seeds.
func fuzzBlockWithRawTxCount(tb testing.TB, raw []byte) []byte {
	tb.Helper()
	e := NewEncoder()
	fuzzFrameHeader(e)
	e.Raw(raw)
	e.VarBytes(nil)
	return e.Bytes()
}

// fuzzTxWithRawPubKeyLen frames a transfer whose pubkey length field holds the
// literal varint bytes given, followed by no bytes for it: a raw-length seed.
func fuzzTxWithRawPubKeyLen(tb testing.TB, rawLen []byte) []byte {
	tb.Helper()
	e := NewEncoder()
	e.U8(byte(TxTransfer))
	e.Raw(make([]byte, AddressSize))
	e.Raw(rawLen)
	e.Raw(make([]byte, 8)) // Nonce
	e.VarBytes(nil)
	return e.Bytes()
}

func FuzzDecodeBlock(f *testing.F) {
	// Valid blocks: empty, one transfer, a transfer and a claim.
	f.Add(fuzzBlockOf(f).Encode())
	f.Add(fuzzBlockOf(f, *fuzzSignedTx(f, TxTransfer, 1, 50)).Encode())
	f.Add(fuzzBlockOf(f, *fuzzSignedTx(f, TxTransfer, 1, 50), *fuzzSignedTx(f, TxFaucetClaim, 2, 0)).Encode())

	// Malformed frames the decoder must reject - never panic on, never
	// allocate into.
	one := fuzzBlockOf(f, *fuzzSignedTx(f, TxTransfer, 1, 50)).Encode()
	f.Add(one[:len(one)-1])                               // truncated mid-frame
	f.Add(append(append([]byte{}, one...), 0xFF))         // trailing bytes
	f.Add(fuzzBlockWithTxBytes(f, []byte{byte(TxBond)}))  // a reserved tx type inside a block
	f.Add(fuzzBlockWithTxCount(f, MaxTxsPerBlock+1))      // a count over the limit, with no txs to pay for it
	f.Add(fuzzBlockWithRawTxCount(f, []byte{0x88, 0x00})) // a non-canonical (redundant) varint count

	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := DecodeBlock(data)
		if err != nil {
			if b != nil {
				t.Fatalf("a failed decode must hand back nil, got a block with %d txs", len(b.Txs))
			}
			return
		}
		// The allocation bound: whatever count the frame claimed, the decoder
		// returns at most MaxTxsPerBlock transactions, and every variable
		// field it captured is a bounded copy of bytes inside data.
		if len(b.Txs) > MaxTxsPerBlock {
			t.Fatalf("DecodeBlock returned %d transactions; the count limit is %d", len(b.Txs), MaxTxsPerBlock)
		}
		captured := len(b.Header.Proposer) + len(b.Sig)
		for i := range b.Txs {
			captured += len(b.Txs[i].PubKey) + len(b.Txs[i].Sig)
		}
		if captured > len(data) {
			t.Fatalf("the decoded fields hold %d B, more than the %d B they were decoded from", captured, len(data))
		}
		// Canonicality: an accepted frame has exactly one reading.
		if re := b.Encode(); !bytes.Equal(re, data) {
			t.Fatalf("an accepted frame is not canonical: %d B in, %d B back out", len(data), len(re))
		}
	})
}

func FuzzDecodeTx(f *testing.F) {
	f.Add(fuzzSignedTx(f, TxTransfer, 1, 50).Encode())
	f.Add(fuzzSignedTx(f, TxFaucetClaim, 2, 0).Encode())
	// Malformed frames the decoder must reject - never panic on.
	f.Add([]byte{byte(TxBond)})                 // a reserved type: refused outright
	f.Add([]byte{})                             // empty input
	f.Add([]byte{byte(TxTransfer), 0x00, 0x01}) // a truncated body
	valid := fuzzSignedTx(f, TxTransfer, 3, 7).Encode()
	f.Add(valid[:len(valid)-1])                                                                          // truncated
	f.Add(append(append([]byte{}, valid...), 0xFF))                                                      // trailing bytes
	f.Add(fuzzTxWithRawPubKeyLen(f, []byte{0xC1, 0x00}))                                                 // non-canonical length
	f.Add(fuzzTxWithRawPubKeyLen(f, []byte{0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})) // a length larger than the frame

	f.Fuzz(func(t *testing.T, data []byte) {
		tx, err := DecodeTx(data)
		if err != nil {
			if tx != nil {
				t.Fatalf("a failed decode must hand back nil, got a tx of type %d", tx.Type)
			}
			return
		}
		// The allocation bound: both variable fields are bounded copies of
		// bytes inside the frame.
		if got := len(tx.PubKey) + len(tx.Sig); got > len(data) {
			t.Fatalf("the decoded fields hold %d B, more than the %d B they were decoded from", got, len(data))
		}
		// Canonicality: an accepted frame has exactly one reading.
		if re := tx.Encode(); !bytes.Equal(re, data) {
			t.Fatalf("an accepted frame is not canonical: %d B in, %d B back out", len(data), len(re))
		}
		// The verification that always follows a decode on the live path must
		// refuse - or accept - without panicking, whatever the key material.
		_ = tx.VerifySignature(testChain())
	})
}
