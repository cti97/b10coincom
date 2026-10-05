package wire

// The connection's message set: HELLO, which opens a connection, and the
// BLOCK_SYNC pair, which pulls a chain the node has fallen behind on. They
// are not consensus messages; they travel the wire layer of every peer and
// relay connection. Anything they decode is attacker-supplied, so every
// decoder here follows the same canonical discipline as the consensus
// messages in internal/consensus/message.go:
//
//   - a leading tag byte (MsgType) discriminates the message union;
//   - fixed-width integers are big-endian;
//   - byte slices (and the field counts) are minimal LEB128 varint-prefixed;
//   - Done() on decode refuses trailing bytes.
//
// Never a map, never JSON, never gob. The wire shapes below are consensus-
// adjacent network state: never renumber a tag nor reorder a field.

import (
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/types"
)

// MsgType discriminates the wire message union. It is a wire value: never
// renumber these.
//
// The wire tags live in a DISJOINT range from the consensus union
// (consensus.MsgProposal/MsgPrevote/MsgPrecommit = 1/2/3). Design Decision 2
// requires it, and before this renumbering they collided exactly there
// (audit N-5): a router keyed on the first byte alone would have fed votes
// into the sync layer, and a HELLO or BLOCK_SYNC frame made every reader
// decode it as a vote and a proposal before failing. Nothing was deployed, so
// the tags were moved instead of adding a workaround. The range is a wire
// value and is part of the protocol: a peer that does not know these bytes
// cannot speak M4.
//
// The wire namespace starts at 0x80 so it can never grow into the consensus
// tags below it - the reserved boundary is 128, stated once here.
type MsgType uint8

const (
	// MsgHello opens a connection: chain identity, the sender's validator
	// key, and the height it is at.
	MsgHello MsgType = 0x80
	// MsgBlockSyncReq asks a peer for a range of blocks.
	MsgBlockSyncReq MsgType = 0x81
	// MsgBlockSyncResp answers a request with the encoded blocks.
	MsgBlockSyncResp MsgType = 0x82
)

// WireTagFloor is the lowest value the wire message union may use: every
// wire tag is at or above it, and the consensus union (1/2/3) is strictly
// below it. It exists so the disjointness is a named, testable boundary
// rather than a property of three literals (audit N-5).
const WireTagFloor MsgType = 0x80

// ErrUnknownMsgType reports a frame whose tag byte is not the message the
// decoder was asked for. Callers dispatch on the tag first; a decoder is also
// an auditor of its own tag, so a misrouted frame cannot be read as two
// different messages by two different paths.
var ErrUnknownMsgType = errors.New("wire: unknown message type")

// Hello is the first message a connection speaks. It is not signed at this
// layer - the Sig carries whatever the transport's handshake policy needs of
// it, and verifying that policy is the connection's job, not the decoder's.
type Hello struct {
	ChainID   string
	Validator []byte // Ed25519 public key
	Height    uint64
	Sig       []byte
}

// EncodeHello renders h canonically, in struct order:
//
//	tag(1) | len ChainID | len Validator | Height(8) | len Sig
func EncodeHello(h *Hello) []byte {
	e := types.NewEncoder()
	e.U8(uint8(MsgHello))
	e.VarBytes([]byte(h.ChainID))
	e.VarBytes(h.Validator)
	e.U64(h.Height)
	e.VarBytes(h.Sig)
	return e.Bytes()
}

func DecodeHello(b []byte) (*Hello, error) {
	d := types.NewDecoder(b)
	raw, err := d.U8()
	if err != nil {
		return nil, err
	}
	if MsgType(raw) != MsgHello {
		return nil, fmt.Errorf("%w: %d is not a HELLO", ErrUnknownMsgType, raw)
	}
	h := &Hello{}
	var chainID []byte
	if chainID, err = d.VarBytes(); err != nil {
		return nil, err
	}
	h.ChainID = string(chainID)
	if h.Validator, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if h.Height, err = d.U64(); err != nil {
		return nil, err
	}
	if h.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return h, nil
}

// BlockSyncReq asks a peer for blocks [From, To], both inclusive.
type BlockSyncReq struct {
	From uint64
	To   uint64
	// Nonce makes each request unique, so a response can be correlated with
	// the one request it answers and a replayed request can be recognised.
	// It is covered by Sig (the consensus layer's syncReqHash): a peer cannot
	// move it to re-label an old frame. The wire layer only frames it.
	Nonce uint64
	// Requester identifies who asked, so a peer can authenticate the request
	// and rate-limit by asker rather than by connection.
	Requester []byte
	Sig       []byte
}

// EncodeBlockSyncReq renders r canonically, in struct order:
//
//	tag(1) | From(8) | To(8) | Nonce(8) | len Requester | len Sig
func EncodeBlockSyncReq(r *BlockSyncReq) []byte {
	e := types.NewEncoder()
	e.U8(uint8(MsgBlockSyncReq))
	e.U64(r.From)
	e.U64(r.To)
	e.U64(r.Nonce)
	e.VarBytes(r.Requester)
	e.VarBytes(r.Sig)
	return e.Bytes()
}

func DecodeBlockSyncReq(b []byte) (*BlockSyncReq, error) {
	d := types.NewDecoder(b)
	raw, err := d.U8()
	if err != nil {
		return nil, err
	}
	if MsgType(raw) != MsgBlockSyncReq {
		return nil, fmt.Errorf("%w: %d is not a BLOCK_SYNC request", ErrUnknownMsgType, raw)
	}
	r := &BlockSyncReq{}
	if r.From, err = d.U64(); err != nil {
		return nil, err
	}
	if r.To, err = d.U64(); err != nil {
		return nil, err
	}
	if r.Nonce, err = d.U64(); err != nil {
		return nil, err
	}
	if r.Requester, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if r.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return r, nil
}

// BlockSyncUnit is one unit a BLOCK_SYNC response offers a catching-up node:
// an encoded block, the round its commit certificate was cast in, and the
// encoded precommit votes making that certificate up. A response that carries
// a block with no certificate is decoded faithfully and refused LATER, at
// verification - this struct only frames the bytes, it checks nothing.
type BlockSyncUnit struct {
	Block []byte
	// Round is the round Votes were cast in: the (height, round) pair the
	// puller re-tallies them through.
	Round uint32
	// Votes are the encoded precommit votes. Nil votes and duplicates belong
	// to the consensus layer's judgement, not the decoder's.
	Votes [][]byte
}

// BlockSyncResp answers a request with the encoded blocks and their commit
// certificates, the count prefix closing the list the way the consensus
// messages frame a justification: the decoder cannot ask a byte slice where it
// ends, so the count must.
type BlockSyncResp struct {
	// Nonce echoes the request's Nonce. Without it a response carries no
	// reference to the request it answers, so any peer could file one against
	// whatever pull happened to be in flight. The wire layer only frames it;
	// the syncer's Receive is what insists it matches the in-flight request.
	Nonce uint64
	Units []BlockSyncUnit
	// Responder is the Ed25519 public key of the committee member that
	// answered, and Sig is its signature over the consensus layer's
	// domain-separated syncRespHash. They are the responder AUTHENTICATION
	// (audit round 7, F1): a transport name is a routing key, not an identity,
	// and through a relay every member - and every stranger - shares one name.
	// The puller requires the answer to be signed by the member it selected,
	// so a stranger with no committee key cannot produce a response it will
	// accept. The wire layer only frames the two fields; the consensus layer
	// signs and verifies them.
	Responder []byte
	Sig       []byte
}

// EncodeBlockSyncResp renders r canonically:
//
//	tag(1) | Nonce(8) | count | count x (len block | round(4) | count votes | count x (len vote)) | len Responder | len Sig
func EncodeBlockSyncResp(r *BlockSyncResp) []byte {
	e := types.NewEncoder()
	e.U8(uint8(MsgBlockSyncResp))
	e.U64(r.Nonce)
	e.Len(len(r.Units))
	for _, u := range r.Units {
		e.VarBytes(u.Block)
		e.U32(u.Round)
		e.Len(len(u.Votes))
		for _, v := range u.Votes {
			e.VarBytes(v)
		}
	}
	e.VarBytes(r.Responder)
	e.VarBytes(r.Sig)
	return e.Bytes()
}

// The minimum wire size of a BLOCK_SYNC response's unit count. It exists so
// the decoder can cap its allocation HINT against the bytes actually
// available (audit N-4): the count is attacker-supplied and bounded only by
// the remaining frame bytes, while a BlockSyncUnit costs 56 bytes in memory
// (two slice headers and a uint32), roughly 9x its 6-byte minimum wire form.
// Capping at remaining/minBlockSyncUnitWireBytes turns "a hostile unit count"
// from a 56x pre-allocation into at most the number of units the frame could
// possibly carry. The bytes are still decoded exactly count times; only the
// slice CAPACITY is capped, so a short or lying count still fails in the loop
// below with no change in semantics.
const minBlockSyncUnitWireBytes = 1 + 4 + 1 // len(block) varint + Round(4) + len(votes) varint

func DecodeBlockSyncResp(b []byte) (*BlockSyncResp, error) {
	d := types.NewDecoder(b)
	raw, err := d.U8()
	if err != nil {
		return nil, err
	}
	if MsgType(raw) != MsgBlockSyncResp {
		return nil, fmt.Errorf("%w: %d is not a BLOCK_SYNC response", ErrUnknownMsgType, raw)
	}
	r := &BlockSyncResp{}
	if r.Nonce, err = d.U64(); err != nil {
		return nil, err
	}
	count, err := d.Len()
	if err != nil {
		return nil, err
	}
	// The capacity hint is capped to what the remaining bytes could hold
	// (audit N-4): `count` is bounded only by `remaining` (Len refuses a
	// count larger than the bytes left), and a BlockSyncUnit is 56 bytes in
	// memory against 6 on the wire, so trusting it pre-allocates up to 56x
	// the frame. The LOOP still runs `count` times, so the decode semantics -
	// a lying count fails on the short buffer - are unchanged.
	hint := count
	if max := d.Remaining() / minBlockSyncUnitWireBytes; hint > max {
		hint = max
	}
	r.Units = make([]BlockSyncUnit, 0, hint)
	for i := 0; i < count; i++ {
		u := BlockSyncUnit{}
		if u.Block, err = d.VarBytes(); err != nil {
			return nil, err
		}
		if u.Round, err = d.U32(); err != nil {
			return nil, err
		}
		vn, err := d.Len()
		if err != nil {
			return nil, err
		}
		// The vote count is capped by `remaining` too, but a vote is framed
		// as an opaque length-prefixed blob whose minimum wire form is ONE
		// byte, so no capacity hint derived from `remaining` can ever bind
		// below `vn` - and `make([][]byte, 0, vn)` would pre-allocate 24
		// bytes per claimed vote (audit N-4). A length-prefixed sequence
		// needs no hint at all: append grows to the votes actually present,
		// so a hostile `vn` with no bytes behind it costs nothing.
		var votes [][]byte
		for j := 0; j < vn; j++ {
			v, err := d.VarBytes()
			if err != nil {
				return nil, err
			}
			votes = append(votes, v)
		}
		u.Votes = votes
		r.Units = append(r.Units, u)
	}
	if r.Responder, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if r.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return r, nil
}
