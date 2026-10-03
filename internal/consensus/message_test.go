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
	if _, err := DecodeVote([]byte{0xFF}); err == nil {
		t.Fatal("an unknown message type must be rejected")
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
	p := &Proposal{Height: 9, Round: 4, Block: blk, Validator: pub}
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
