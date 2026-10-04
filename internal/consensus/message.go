// Package consensus implements b10coin's Byzantine-fault-tolerant agreement.
//
// The engine is a PURE STATE MACHINE. It never reads a clock, never starts a
// goroutine, and never touches the network: the driver feeds it messages and
// timeout events and carries its outgoing messages away. That is what makes a
// failing run reproducible from a seed, and it is what lets M4 swap the
// in-process simulator for real sockets without touching this package.
package consensus

import (
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// MsgType discriminates the consensus message union. It is a wire value: never
// renumber these.
type MsgType uint8

const (
	MsgProposal  MsgType = 1
	MsgPrevote   MsgType = 2
	MsgPrecommit MsgType = 3
)

var (
	ErrBadVoteSignature     = errors.New("consensus: bad vote signature")
	ErrBadProposalSignature = errors.New("consensus: bad proposal signature")
	ErrUnknownMsgType       = errors.New("consensus: unknown message type")
	ErrBadValidatorKey      = errors.New("consensus: validator key cannot derive its address")
	// ErrBadJustification reports a proposal whose claimed ValidRound is not
	// backed by the prevotes it carries: no prevotes at all, prevotes that fail
	// to decode or verify, prevotes for another (height, round), or prevotes
	// that fall short of quorum for the proposal's own block. The engine treats
	// such a proposal as unusable evidence and refuses to prevote it - see
	// Design Decision 11 in docs/plans/2026-10-03-m3-bft-consensus.md.
	ErrBadJustification = errors.New("consensus: proposal's justification does not prove its claimed polka")
)

// Vote is one validator's signed judgement about one (height, round).
//
// An all-zero BlockID is a NIL vote: "this round produced nothing I will accept".
// Nil votes are first-class, not abstentions - without them a round whose proposer
// is offline could never be left behind, and the chain would stall forever.
type Vote struct {
	Type      MsgType
	Height    uint64
	Round     uint32
	BlockID   [32]byte
	Validator []byte // Ed25519 public key
	Sig       []byte
}

// IsNil reports whether this is a nil vote.
func (v *Vote) IsNil() bool { return v.BlockID == ([32]byte{}) }

func (v *Vote) encodeBody() []byte {
	e := types.NewEncoder()
	e.U8(uint8(v.Type))
	e.U64(v.Height)
	e.U32(v.Round)
	e.Fixed32(v.BlockID)
	e.VarBytes(v.Validator)
	return e.Bytes()
}

// SigningHash covers every field that carries meaning, so a validator cannot be
// quoted as having said something it did not.
func (v *Vote) SigningHash() [32]byte {
	return crypto.HashParts([]byte("b10coin-vote"), v.encodeBody())
}

func EncodeVote(v *Vote) []byte {
	e := types.NewEncoder()
	e.Raw(v.encodeBody())
	e.VarBytes(v.Sig)
	return e.Bytes()
}

func DecodeVote(b []byte) (*Vote, error) {
	d := types.NewDecoder(b)
	rawType, err := d.U8()
	if err != nil {
		return nil, err
	}
	v := &Vote{Type: MsgType(rawType)}
	switch v.Type {
	case MsgPrevote, MsgPrecommit:
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownMsgType, rawType)
	}
	if v.Height, err = d.U64(); err != nil {
		return nil, err
	}
	if v.Round, err = d.U32(); err != nil {
		return nil, err
	}
	if v.BlockID, err = d.Fixed32(); err != nil {
		return nil, err
	}
	if v.Validator, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if v.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return v, nil
}

// Verify checks the signature against the validator key carried in the vote.
// Callers must separately check that the key is in the committee.
func (v *Vote) Verify() error {
	if len(v.Validator) == 0 {
		return fmt.Errorf("%w: missing validator key", ErrBadVoteSignature)
	}
	h := v.SigningHash()
	if !crypto.Verify(v.Validator, h[:], v.Sig) {
		return ErrBadVoteSignature
	}
	return nil
}

// Proposal is a block offered for a (height, round) together with its proposer's
// signature over the envelope fields and the block header.
type Proposal struct {
	Height uint64
	Round  uint32
	Block  types.Block

	// ValidRound is the round at which this block reached a polka (2/3 prevotes), or
	// -1 when the proposer knows of none. Justification carries the prevotes proving
	// it. A locked validator prevotes a DIFFERING block only when ValidRound exceeds
	// its own lock round - see Design Decision 11 for why a bare round number is not
	// enough.
	//
	// The engine VERIFIES the evidence rather than trusting the field: an unverified
	// justification would let a proposer assert an unlock that no quorum ever
	// granted. A fresh proposal must set ValidRound to -1 explicitly - the int64
	// zero value 0 CLAIMS a polka at round 0, which the engine would (correctly)
	// refuse as unevidenced.
	ValidRound    int64
	Justification []byte

	Validator []byte // the proposer's Ed25519 public key
	Sig       []byte // over SigningHash(): envelope fields plus Block.Header.SigningHash()
}

// SigningHash covers the envelope's own fields as well as the block header, so a
// valid proposal cannot be re-presented at a different height or round. Hashing
// only the header would leave Height and Round unsigned - the same gap the vote
// encoding closes field by field.
//
// ValidRound and Justification are signed with the rest: a proposer must not be
// quotable as having claimed - or having furnished evidence of - a polka at a
// round it never did.
func (p *Proposal) SigningHash() [32]byte {
	e := types.NewEncoder()
	e.U64(p.Height)
	e.U32(p.Round)
	e.Fixed32(p.Block.Header.SigningHash())
	e.I64(p.ValidRound)
	e.VarBytes(p.Justification)
	return crypto.HashParts([]byte("b10coin-proposal"), e.Bytes())
}

func (p *Proposal) Verify() error {
	if len(p.Validator) == 0 {
		return fmt.Errorf("%w: missing proposer key", ErrBadProposalSignature)
	}
	if string(p.Validator) != string(p.Block.Header.Proposer) {
		return fmt.Errorf("%w: key does not match the header's proposer", ErrBadProposalSignature)
	}
	h := p.SigningHash()
	if !crypto.Verify(p.Validator, h[:], p.Sig) {
		return ErrBadProposalSignature
	}
	return nil
}

// EncodeProposal renders a proposal canonically. The block is length-prefixed so
// the envelope frames it the same way DecodeProposal reads it back.
func EncodeProposal(p *Proposal) []byte {
	e := types.NewEncoder()
	e.U8(uint8(MsgProposal))
	e.U64(p.Height)
	e.U32(p.Round)
	e.VarBytes(p.Block.Encode())
	e.I64(p.ValidRound)
	e.VarBytes(p.Justification)
	e.VarBytes(p.Validator)
	e.VarBytes(p.Sig)
	return e.Bytes()
}

func DecodeProposal(b []byte) (*Proposal, error) {
	d := types.NewDecoder(b)
	rawType, err := d.U8()
	if err != nil {
		return nil, err
	}
	if MsgType(rawType) != MsgProposal {
		return nil, fmt.Errorf("%w: %d", ErrUnknownMsgType, rawType)
	}
	p := &Proposal{}
	if p.Height, err = d.U64(); err != nil {
		return nil, err
	}
	if p.Round, err = d.U32(); err != nil {
		return nil, err
	}
	raw, err := d.VarBytes()
	if err != nil {
		return nil, err
	}
	blk, err := types.DecodeBlock(raw)
	if err != nil {
		return nil, err
	}
	p.Block = *blk
	if p.ValidRound, err = d.I64(); err != nil {
		return nil, err
	}
	if p.Justification, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if p.Validator, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if p.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return p, nil
}

// encodeJustification renders the prevotes that back a proposal's ValidRound as
// a varint count followed by that many length-prefixed encoded votes. The count
// prefix is what makes the sequence self-delimiting: the decoder cannot ask a
// byte slice where it ends, so the element count closes the frame.
//
// It is unexported because only the consensus package currently builds
// justifications: the engine makes fresh proposals (ValidRound -1, none), and a
// future re-proposing engine assembles the polka through this same shape.
func encodeJustification(votes []*Vote) []byte {
	e := types.NewEncoder()
	e.Len(len(votes))
	for _, v := range votes {
		e.VarBytes(EncodeVote(v))
	}
	return e.Bytes()
}

// decodeVotes reads encodeJustification's wire shape. A short, oversized, or
// non-canonical frame decodes to nil, which verifyJustification then rejects by
// finding no quorum.
func decodeVotes(b []byte) [][]byte {
	d := types.NewDecoder(b)
	n, err := d.Len()
	if err != nil {
		return nil
	}
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		raw, err := d.VarBytes()
		if err != nil {
			return nil
		}
		out = append(out, raw)
	}
	if err := d.Done(); err != nil {
		return nil
	}
	return out
}
