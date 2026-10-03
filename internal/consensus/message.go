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
	Height    uint64
	Round     uint32
	Block     types.Block
	Validator []byte // the proposer's Ed25519 public key
	Sig       []byte // over SigningHash(): envelope fields plus Block.Header.SigningHash()
}

// SigningHash covers the envelope's own fields as well as the block header, so a
// valid proposal cannot be re-presented at a different height or round. Hashing
// only the header would leave Height and Round unsigned - the same gap the vote
// encoding closes field by field.
func (p *Proposal) SigningHash() [32]byte {
	e := types.NewEncoder()
	e.U64(p.Height)
	e.U32(p.Round)
	e.Fixed32(p.Block.Header.SigningHash())
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
