package consensus

import (
	"errors"
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
