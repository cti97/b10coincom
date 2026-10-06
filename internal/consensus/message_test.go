package consensus

import (
	"errors"
	"runtime"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

func testKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signedVote(t *testing.T, typ MsgType, height uint64, round uint32, blockID [32]byte) *Vote {
	t.Helper()
	pub, priv := testKey(t)
	v := &Vote{Type: typ, Height: height, Round: round, BlockID: blockID, Validator: pub}
	h := v.SigningHash()
	v.Sig = crypto.Sign(priv, h[:])
	return v
}

func TestVoteRoundTrips(t *testing.T) {
	var id [32]byte
	id[0] = 9
	v := signedVote(t, MsgPrecommit, 7, 3, id)

	got, err := DecodeVote(EncodeVote(v))
	if err != nil {
		t.Fatalf("DecodeVote: %v", err)
	}
	if got.Type != v.Type || got.Height != v.Height || got.Round != v.Round || got.BlockID != v.BlockID {
		t.Fatalf("round trip lost fields:\n got %+v\nwant %+v", got, v)
	}
	if string(got.Validator) != string(v.Validator) || string(got.Sig) != string(v.Sig) {
		t.Fatal("round trip lost key material")
	}
}

// The signature must cover every field that affects meaning: a validator that
// signed a prevote for block A at round 1 must not be quotable as having
// precommitted block B at round 9.
func TestVoteSignatureCoversEveryField(t *testing.T) {
	var id [32]byte
	id[0] = 9
	v := signedVote(t, MsgPrevote, 7, 3, id)
	base := v.SigningHash()

	cases := map[string]func(*Vote){
		"type":    func(x *Vote) { x.Type = MsgPrecommit },
		"height":  func(x *Vote) { x.Height = 8 },
		"round":   func(x *Vote) { x.Round = 4 },
		"blockID": func(x *Vote) { x.BlockID[0] = 10 },
	}
	for name, mutate := range cases {
		c := *v // a COPY, so every other byte of the signed body stays constant
		mutate(&c)
		if c.SigningHash() == base {
			t.Errorf("SigningHash ignored the %s field", name)
		}
	}
}

func TestVoteVerifyRejectsTampering(t *testing.T) {
	var id [32]byte
	v := signedVote(t, MsgPrevote, 7, 3, id)
	if err := v.Verify(); err != nil {
		t.Fatalf("valid vote rejected: %v", err)
	}
	v.Height = 8
	if err := v.Verify(); !errors.Is(err, ErrBadVoteSignature) {
		t.Fatalf("expected ErrBadVoteSignature, got %v", err)
	}
}

// A nil vote (all-zero BlockID) is a first-class vote: validators must be able to
// advance past a round in which no proposal arrived.
func TestNilVoteRoundTrips(t *testing.T) {
	v := signedVote(t, MsgPrevote, 5, 2, [32]byte{})
	if err := v.Verify(); err != nil {
		t.Fatalf("nil vote rejected: %v", err)
	}
	got, err := DecodeVote(EncodeVote(v))
	if err != nil {
		t.Fatal(err)
	}
	if got.BlockID != ([32]byte{}) {
		t.Fatal("nil vote did not round trip as nil")
	}
	if !got.IsNil() {
		t.Fatal("IsNil should be true for an all-zero BlockID")
	}
}

func TestDecodeVoteRejectsMalformed(t *testing.T) {
	v := signedVote(t, MsgPrevote, 7, 3, [32]byte{})
	enc := EncodeVote(v)
	if _, err := DecodeVote(append(enc, 0xFF)); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}
	if _, err := DecodeVote(enc[:len(enc)-1]); err == nil {
		t.Fatal("a truncated encoding must be rejected")
	}
	if _, err := DecodeVote([]byte{0xFF}); !errors.Is(err, ErrUnknownMsgType) {
		t.Fatalf("an unknown message type must fail with ErrUnknownMsgType, got %v", err)
	}
}

// The proposal envelope must frame the block so DecodeProposal reads back
// exactly what EncodeProposal wrote, and Verify must reject a tampered
// signed header even though the envelope still carries it.
func TestProposalRoundTrips(t *testing.T) {
	pub, priv := testKey(t)
	blk := types.Block{
		Header: types.Header{
			Height:     9,
			ParentHash: [32]byte{1},
			StateRoot:  [32]byte{2},
			TxRoot:     types.ComputeTxRoot(nil),
			Timestamp:  1_700_000_100,
			Proposer:   pub,
		},
	}
	p := &Proposal{Height: 9, Round: 4, Block: blk, Validator: pub,
		// The justification rides the same envelope and the same signature as the
		// rest of the envelope: it is evidence, so it must be tamper-evident too.
		ValidRound: 2,
		Justification: encodeJustification([]*Vote{
			signedVote(t, MsgPrevote, 9, 2, blk.ID()),
			signedVote(t, MsgPrevote, 9, 2, blk.ID()),
		})}
	sig := p.SigningHash()
	p.Sig = crypto.Sign(priv, sig[:])

	if err := p.Verify(); err != nil {
		t.Fatalf("valid proposal rejected: %v", err)
	}
	got, err := DecodeProposal(EncodeProposal(p))
	if err != nil {
		t.Fatalf("DecodeProposal: %v", err)
	}
	if got.Height != p.Height || got.Round != p.Round {
		t.Fatalf("round trip lost envelope fields:\n got %+v\nwant %+v", got, p)
	}
	if got.ValidRound != p.ValidRound {
		t.Fatalf("round trip lost ValidRound: got %d want %d", got.ValidRound, p.ValidRound)
	}
	if len(decodeVotes(got.Justification)) != 2 {
		t.Fatalf("round trip lost the justification's %d prevotes", len(decodeVotes(p.Justification)))
	}
	if got.Block.ID() != p.Block.ID() {
		t.Fatal("round trip lost the block")
	}
	if string(got.Validator) != string(p.Validator) || string(got.Sig) != string(p.Sig) {
		t.Fatal("round trip lost proposal key material")
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("decoded proposal rejected: %v", err)
	}

	c := *p // a COPY, so the signed header of p stays constant
	c.Block.Header.Height = 10
	if err := c.Verify(); !errors.Is(err, ErrBadProposalSignature) {
		t.Fatalf("expected ErrBadProposalSignature, got %v", err)
	}
}

// The proposal envelope's own Height and Round must be inside the signature: a
// proposer that signed an offer for round 4 at height 9 must not be quotable as
// having offered the same block at another height or round. This is the same
// gap TestVoteSignatureCoversEveryField closes for votes, one level up.
//
// ValidRound and Justification are in the signature with them (Task 6, Design
// Decision 11): the locked/unlocked decision keys off ValidRound, so a proposer
// must not be quotable as having claimed a polka - let alone furnished evidence
// of one - at a round it never did.
func TestProposalSignatureCoversHeightAndRound(t *testing.T) {
	pub, priv := testKey(t)
	blk := types.Block{
		Header: types.Header{
			Height:     9,
			ParentHash: [32]byte{1},
			StateRoot:  [32]byte{2},
			TxRoot:     types.ComputeTxRoot(nil),
			Timestamp:  1_700_000_100,
			Proposer:   pub,
		},
	}
	p := &Proposal{Height: 9, Round: 4, Block: blk, Validator: pub,
		ValidRound:    2,
		Justification: []byte{0x07},
	}
	sig := p.SigningHash()
	p.Sig = crypto.Sign(priv, sig[:])
	base := p.SigningHash()

	for _, tc := range []struct {
		name   string
		mutate func(*Proposal)
	}{
		{"height", func(x *Proposal) { x.Height++ }},
		{"round", func(x *Proposal) { x.Round++ }},
		{"validRound", func(x *Proposal) { x.ValidRound++ }},
		{"justification", func(x *Proposal) { x.Justification = []byte{0x08} }},
	} {
		c := *p // a COPY, so every other signed byte stays constant
		tc.mutate(&c)
		if c.SigningHash() == base {
			t.Errorf("SigningHash ignored the %s field", tc.name)
		}
	}
}

// C-17: a vote or proposal "key" that cannot be an Ed25519 public key is
// refused at DECODE, before the decoder copies it, instead of being copied and
// then rejected by Verify. The bound is exact - 32 bytes still round-trips -
// and a 1 MiB key is not copied at all, because the length is checked before
// the allocation.
func TestDecodeRefusesAnOverLongValidatorKey(t *testing.T) {
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	// A valid 32-byte vote still decodes, so the bound refuses the width, not
	// the vote.
	v := &Vote{Type: MsgPrevote, Height: 7, Round: 3, Validator: pub}
	vh := v.SigningHash()
	v.Sig = crypto.Sign(priv, vh[:])
	if _, err := DecodeVote(EncodeVote(v)); err != nil {
		t.Fatalf("a 32-byte vote key no longer decodes: %v", err)
	}
	v.Validator = make([]byte, 1<<20)
	if _, err := DecodeVote(EncodeVote(v)); !errors.Is(err, types.ErrFieldTooLong) {
		t.Fatalf("a 1 MiB vote key decoded (%v); want ErrFieldTooLong before any copy", err)
	}

	// The proposal envelope's proposer key gets the same gate.
	blk := types.Block{Header: types.Header{
		Height: 1, TxRoot: types.ComputeTxRoot(nil), Timestamp: 1_700_000_100, Proposer: pub,
	}}
	p := &Proposal{Height: 1, Round: 0, Block: blk, ValidRound: -1, Validator: pub}
	ph := p.SigningHash()
	p.Sig = crypto.Sign(priv, ph[:])
	if _, err := DecodeProposal(EncodeProposal(p)); err != nil {
		t.Fatalf("a 32-byte proposer key no longer decodes: %v", err)
	}
	p.Validator = make([]byte, 1<<20)
	if _, err := DecodeProposal(EncodeProposal(p)); !errors.Is(err, types.ErrFieldTooLong) {
		t.Fatalf("a 1 MiB proposer key decoded (%v); want ErrFieldTooLong before any copy", err)
	}
}

// The SIGNATURE is a protocol constant too - an Ed25519 signature is 64 bytes
// and nothing else - so it gets the same bound as the key (audit C-17d; review
// F4, which found both consensus Sig fields still an unbounded VarBytes). A
// decoder that trusts the declared width copies the whole claimed signature
// into memory before Verify can reject it; the bound refuses the width before
// the copy. A short or empty signature still decodes, so Verify keeps naming
// the real problem, and the allocation assertion shows the copy never happened.
func TestDecodeVoteAndProposalBoundTheSignatureField(t *testing.T) {
	pub, priv := testKey(t)
	const hostile = 1 << 20

	v := &Vote{Type: MsgPrevote, Height: 7, Round: 3, Validator: pub}
	vh := v.SigningHash()
	v.Sig = crypto.Sign(priv, vh[:])
	if _, err := DecodeVote(EncodeVote(v)); err != nil {
		t.Fatalf("a 64-byte vote signature no longer decodes: %v", err)
	}
	v.Sig = make([]byte, hostile)
	vframe := EncodeVote(v)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := DecodeVote(vframe)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, types.ErrFieldTooLong) {
		t.Fatalf("a %d-byte vote signature decoded (%v); want ErrFieldTooLong before any copy", hostile, err)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > uint64(len(vframe))/4 {
		t.Fatalf("the over-long vote signature was copied before the width bound was applied: allocated %d B for a %d-byte frame", grown, len(vframe))
	}

	blk := types.Block{Header: types.Header{
		Height: 1, TxRoot: types.ComputeTxRoot(nil), Timestamp: 1_700_000_100, Proposer: pub,
	}}
	p := &Proposal{Height: 1, Round: 0, Block: blk, ValidRound: -1, Validator: pub}
	ph := p.SigningHash()
	p.Sig = crypto.Sign(priv, ph[:])
	if _, err := DecodeProposal(EncodeProposal(p)); err != nil {
		t.Fatalf("a 64-byte proposal signature no longer decodes: %v", err)
	}
	p.Sig = make([]byte, hostile)
	pframe := EncodeProposal(p)
	runtime.ReadMemStats(&before)
	_, err = DecodeProposal(pframe)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, types.ErrFieldTooLong) {
		t.Fatalf("a %d-byte proposal signature decoded (%v); want ErrFieldTooLong before any copy", hostile, err)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > uint64(len(pframe))/4 {
		t.Fatalf("the over-long proposal signature was copied before the width bound was applied: allocated %d B for a %d-byte frame", grown, len(pframe))
	}
}

// The justification's element count is attacker bytes, and decodeVotes used to
// size-hint `make([][]byte, 0, n)` from it (review F4, the consensus twin of
// audit N-4). Len refuses a count larger than the bytes remaining, so on a
// 1 MiB justification the count can be ~1 MiB - and a slice header is 24 bytes
// against a MINIMUM element width of ONE wire byte (an empty length-prefixed
// blob), so no remaining-derived hint can ever bind below n. The pre-allocation
// therefore multiplied a 1 MiB frame into ~24 MiB before failing on the short
// buffer. A length-prefixed sequence needs no hint: append grows to the votes
// actually present. TotalAlloc is a monotonic heap counter, so the fix shows up
// here as the allocation collapsing to the frame's own size.
func TestDecodeVotesDoesNotPreallocateAHostileCount(t *testing.T) {
	const hostile = 1 << 20 // one MiB, the frame's whole payload budget
	e := types.NewEncoder()
	e.Len(hostile)
	e.Raw([]byte{0xFE, 0xFF, 0xFF, 0xFF, 0x0F}) // a vote length ~2^32: fails on the first element
	e.Raw(make([]byte, hostile-5))
	frame := e.Bytes()
	// The count must not already be refused by Len for exceeding the remaining
	// bytes, or the test would pass without ever reaching the hint.
	if len(frame) < hostile {
		t.Fatalf("fixture: the frame is %d bytes, shorter than the %d-byte count, so Len refuses it before the hint", len(frame), hostile)
	}
	dense := types.NewEncoder()
	dense.Len(hostile)
	dense.Raw(make([]byte, hostile)) // `hostile` minimal elements really present: the 1M-iteration shape
	denseFrame := dense.Bytes()

	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"count with no elements behind it", frame},
		{"count with minimal elements behind it", denseFrame},
	} {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		out := decodeVotes(tc.frame)
		runtime.ReadMemStats(&after)
		grown := after.TotalAlloc - before.TotalAlloc
		t.Logf("%s: hostile count %d over a %d-byte justification allocated %d B (%.1fx)", tc.name, hostile, len(tc.frame), grown, float64(grown)/float64(len(tc.frame)))
		if out != nil {
			t.Errorf("%s: a justification whose count runs past the frame must decode to nil (got %d elements)", tc.name, len(out))
		}
		if grown > uint64(len(tc.frame))/2 {
			t.Errorf("%s: a %d-byte justification with a hostile count allocated %d B before failing: the count must be capped by the MINIMUM ELEMENT SIZE, not trusted (want at most %d B; pre-fix it was ~24x)",
				tc.name, len(tc.frame), grown, len(tc.frame)/2)
		}
	}

	// Non-vacuity: a justification whose count the frame really can hold still
	// decodes, so the cap refuses impossible counts, not large ones.
	pub, priv := testKey(t)
	var id [32]byte
	id[0] = 0x5a
	real := func(h uint64) *Vote {
		v := &Vote{Type: MsgPrevote, Height: h, Round: 0, BlockID: id, Validator: pub}
		s := v.SigningHash()
		v.Sig = crypto.Sign(priv, s[:])
		return v
	}
	if got := decodeVotes(encodeJustification([]*Vote{real(1), real(2)})); len(got) != 2 {
		t.Fatalf("a two-vote justification decoded to %d votes; the count cap must not refuse frames the bytes can hold", len(got))
	}
}
