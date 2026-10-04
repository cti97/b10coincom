package consensus

// Go fuzz targets for the consensus wire decoders. Design spec §9.2 names the
// wire decoder as a fuzz target because it consumes untrusted input, and M3
// grew exactly that surface: DecodeVote, DecodeProposal and the proposal's
// nested decodeVotes are new, and a Byzantine peer controls every byte they
// see - a panic in any of them is a remote denial of service.
//
// The property each target pins is the one that matters on hostile bytes: a
// decoder NEVER PANICS (the fuzz engine itself fails the run on the first
// panic, in seed-corpus mode under `go test ./...` just as in a live fuzzing
// round) and NEVER ALLOCATES UNBOUNDEDLY - every field it hands back is a
// bounded copy of bytes inside the frame it was given - returning an error
// instead. Each corpus is seeded with a valid encoding first, so the fuzzer
// starts from the happy path, plus malformed frames the decoder must reject.
//
// Bounded run:
//
//	go test -run '^$' -fuzz 'FuzzDecodeVote$' -fuzztime 5s ./internal/consensus
//	go test -run '^$' -fuzz 'FuzzDecodeProposal$' -fuzztime 5s ./internal/consensus

import (
	"bytes"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// fuzzSignedVote builds a vote properly signed by a fresh key, so the seed
// corpus starts with frames the decoders accept end to end.
func fuzzSignedVote(tb testing.TB, typ MsgType, height uint64, round uint32, id [32]byte) *Vote {
	tb.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		tb.Fatal(err)
	}
	v := &Vote{Type: typ, Height: height, Round: round, BlockID: id, Validator: pub}

	// SigningHash returns an array, which must be bound before it can be sliced.
	hash := v.SigningHash()
	v.Sig = crypto.Sign(priv, hash[:])
	return v
}

func FuzzDecodeVote(f *testing.F) {
	id := [32]byte{1, 2, 3}
	prevote := EncodeVote(fuzzSignedVote(f, MsgPrevote, 7, 3, id))
	precommit := EncodeVote(fuzzSignedVote(f, MsgPrecommit, 7, 3, id))
	nilVote := EncodeVote(fuzzSignedVote(f, MsgPrevote, 7, 3, [32]byte{}))
	f.Add(prevote)
	f.Add(precommit)
	f.Add(nilVote)
	// Malformed frames the decoder must reject as errors - and never panic on.
	f.Add([]byte{})                 // empty input
	f.Add([]byte{0x01})             // an unknown message type byte
	f.Add(prevote[:len(prevote)-1]) // a truncated frame
	trailing := append([]byte{}, prevote...)
	f.Add(append(trailing, 0x00))                                             // a valid frame plus a trailing byte
	f.Add([]byte{0x02, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09}) // non-canonical varint

	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := DecodeVote(b)
		if err != nil {
			if v != nil {
				t.Fatalf("a failed decode must hand back nil, got %+v", v)
			}
			return
		}
		if v == nil {
			t.Fatal("DecodeVote returned nil with the error also nil")
		}
		// The decoder must not allocate beyond the frame it was handed: both
		// variable fields it captures are bounded copies of bytes inside b.
		if got := len(v.Validator) + len(v.Sig); got > len(b) {
			t.Fatalf("the decoded fields hold %d B, more than the %d B they were decoded from", got, len(b))
		}
		// Every frame a decoder accepts is canonical: re-encoding must
		// reproduce the input byte for byte, so the bytes have exactly one
		// reading and two validators cannot disagree about what they saw.
		if re := EncodeVote(v); !bytes.Equal(re, b) {
			t.Fatalf("an accepted frame is not canonical: %d B in, %d B back out", len(b), len(re))
		}
		// The verification that always follows a decode on the live path must
		// refuse - or accept - without panicking, whatever the key material.
		_ = v.Verify()
	})
}

func FuzzDecodeProposal(f *testing.F) {
	// A valid proposal. Its justification is a real, signed, decodable
	// prevote pair, so the seed exercises the nested decoder too.
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	blk := types.Block{Header: types.Header{
		Height: 9, ParentHash: [32]byte{1}, StateRoot: [32]byte{2},
		TxRoot: types.ComputeTxRoot(nil), Timestamp: 1_700_000_100, Proposer: pub,
	}}
	inner := fuzzSignedVote(f, MsgPrevote, 9, 2, blk.ID())
	p := &Proposal{Height: 9, Round: 4, Block: blk, Validator: pub, ValidRound: 2,
		Justification: encodeJustification([]*Vote{inner, inner})}
	hash := p.SigningHash()
	p.Sig = crypto.Sign(priv, hash[:])
	valid := EncodeProposal(p)
	f.Add(valid)
	// The honest fresh-proposal shape: ValidRound -1 with no justification at
	// all (the envelope a real round-0 proposal carries).
	plain := &Proposal{Height: 1, Round: 0, Block: blk, Validator: pub, ValidRound: -1}
	plainHash := plain.SigningHash()
	plain.Sig = crypto.Sign(priv, plainHash[:])
	f.Add(EncodeProposal(plain))

	// The nested case: a valid envelope whose justification carries a
	// MALFORMED inner vote. Decoding - and walking the nested bytes the way
	// verifyJustification does - must yield an error path, never a panic.
	junk := types.NewEncoder()
	junk.Len(2)
	junk.VarBytes([]byte{0x02, 0x00}) // a frame too short to be a vote
	junk.VarBytes(nil)
	malformedInner := *p
	malformedInner.Block = p.Block // share the signed block; the envelope is re-signed below
	malformedInner.Justification = junk.Bytes()
	malformedHash := malformedInner.SigningHash()
	malformedInner.Sig = crypto.Sign(priv, malformedHash[:])
	f.Add(EncodeProposal(&malformedInner))

	f.Add(append(append([]byte{}, valid...), 0xFF)) // trailing bytes after the envelope
	f.Add(valid[:len(valid)-1])                     // truncated mid-frame
	f.Add([]byte{0x02})                             // a vote type where a proposal must be
	// An envelope whose block claims far more transactions than the frame
	// carries: the count must hit types.MaxTxsPerBlock's bound, not allocate
	// it from a hostile length and then unwind.
	hugeTxs := types.NewEncoder()
	hugeTxs.U8(uint8(MsgProposal))
	hugeTxs.U64(9)
	hugeTxs.U32(4)
	blk2 := blk
	blk2.Txs = nil
	hugeTxs.VarBytes(func() []byte {
		be := types.NewEncoder()
		be.U64(blk2.Header.Height)
		be.Fixed32(blk2.Header.ParentHash)
		be.Fixed32(blk2.Header.StateRoot)
		be.Fixed32(blk2.Header.TxRoot)
		be.I64(blk2.Header.Timestamp)
		be.VarBytes(blk2.Header.Proposer)
		be.Len(65535) // claims 65,535 transactions with none in the frame
		be.VarBytes(nil)
		return be.Bytes()
	}())
	hugeTxs.I64(-1)
	hugeTxs.VarBytes(nil)
	hugeTxs.VarBytes(pub)
	hugeTxs.VarBytes(nil)
	f.Add(hugeTxs.Bytes())

	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := DecodeProposal(b)
		if err != nil {
			if p != nil {
				t.Fatalf("a failed decode must hand back nil, got a proposal at height %d", p.Height)
			}
			return
		}
		// Every variable field the envelope captured is a bounded copy of
		// bytes inside b (the block re-encode reproduces the framed bytes).
		captured := len(p.Block.Encode()) + len(p.Justification) + len(p.Validator) + len(p.Sig)
		if captured > len(b) {
			t.Fatalf("the decoded fields hold %d B, more than the %d B they were decoded from", captured, len(b))
		}
		// The nested decoder sees attacker bytes: the justification's inner
		// frames must come back as decode errors, never as a panic - this is
		// the first half of the path verifyJustification walks.
		total := 0
		for _, raw := range decodeVotes(p.Justification) {
			total += len(raw)
			inner, ierr := DecodeVote(raw)
			if ierr == nil {
				_ = inner.Verify()
			}
		}
		if total > len(p.Justification) {
			t.Fatalf("the nested decoder captured %d B from a %d B justification", total, len(p.Justification))
		}
		// Canonicality at every level: envelope, block, transaction.
		if re := EncodeProposal(p); !bytes.Equal(re, b) {
			t.Fatalf("an accepted frame is not canonical: %d B in, %d B back out", len(b), len(re))
		}
		_ = p.Verify() // the envelope's signature path must not panic either
	})
}
