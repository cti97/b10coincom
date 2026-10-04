package consensus

// BLOCK_SYNC catch-up: the mechanism M3's limits note deferred. A validator
// that fell behind could watch rounds happen but never adopt the blocks it
// missed, because Transport offered only Broadcast - consensus messages are
// one-to-many events, and "send me your chain" is a question exactly one peer
// answers. The Syncer is that question and its answer, split across the two
// roles a node plays:
//
//   - ANSWERING. Handle/Answer serve encoded blocks out of the local chain for
//     a signed, bounded height range. The transport-facing layer calls Handle
//     when a BLOCK_SYNC_REQ frame arrives and puts the returned frame on the
//     wire; a refusal is (nil, false) and sends nothing.
//   - PULLING. PullAndAdopt asks the chosen peer for the range above the local
//     head, one bounded window at a time, and appends every block it gets back
//     through chain.Append - the same validation a live commit goes through.
//
// The invariant that makes pulling safe enough to point at a stranger:
// CATCH-UP VERIFIES, IT DOES NOT TRUST. The requester chooses the heights it
// asks for, but the responder chooses the bytes it sends back, so nothing a
// response says may reach the chain without the full Append gate: parent link
// against OUR head, height exactly head+1, committee membership, proposer
// signature, and the state root recomputed here. A peer can withhold blocks
// (liveness; the caller re-pulls) or serve genuinely valid ones - anything
// else is refused by Append and the pull stops rather than skipping ahead,
// because a skipped block leaves a hole no later block can link across.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/types"
	"github.com/cti97/b10coincom/internal/wire"
)

// DefaultMaxBlocksPerResponse is the bound a Syncer carries when it is built
// through NewSyncer. With a devnet block (a ~250-byte header and, today, no
// transaction load) a full window encodes to well under the tcp transport's
// 1 MiB frame bound, so a default-window response can never be silently
// dropped by the frame layer for size. A deployment whose blocks carry real
// transaction weight must lower this knob: the bound is in BLOCKS, not bytes,
// and the frame bound is the enforcement point behind it.
const DefaultMaxBlocksPerResponse = 64

var (
	// ErrBadSyncRange reports a request whose range selects nothing: under
	// the wire's inclusive [From, To] semantics, To < From.
	ErrBadSyncRange = errors.New("consensus: BLOCK_SYNC range selects no blocks")
	// ErrRangeTooBig reports a range wider than MaxBlocksPerResponse. The
	// count is refused, never silently truncated, so a requester always
	// knows whether the error is its own window or the peer's height.
	ErrRangeTooBig = errors.New("consensus: BLOCK_SYNC range exceeds MaxBlocksPerResponse")
	// ErrRangeAhead reports a range that starts above the local height. A
	// requester asking for a future block is confused or hostile, and an
	// empty answer would make its retry logic guess.
	ErrRangeAhead = errors.New("consensus: BLOCK_SYNC range starts above the local height")
	// ErrBadSyncAuth reports a request that carries no signature, a signature
	// that does not verify, or a requester outside the validator set. Blocks
	// leak the chain's history; serving them to anonymous askers is not the
	// default.
	ErrBadSyncAuth = errors.New("consensus: BLOCK_SYNC request is not from a signed committee member")
	// ErrNoSyncPeer reports a pull with nowhere to send it.
	ErrNoSyncPeer = errors.New("consensus: no peer to pull blocks from")
	// ErrSyncDisabled reports a Syncer configured with MaxBlocksPerResponse 0:
	// it can serve nothing, so it must offer to pull nothing either.
	ErrSyncDisabled = errors.New("consensus: syncer is configured with MaxBlocksPerResponse 0")
	// ErrBadSyncResp reports a response frame that decodes but carries bytes
	// no block can be read out of.
	ErrBadSyncResp = errors.New("consensus: peer served a block that does not decode")
)

// Syncer answers BLOCK_SYNC requests from a local chain and pulls missed blocks
// into it. It is the mechanism M3's limits note deferred: without it a
// validator that fell behind could never adopt what it missed, because
// Transport offered only Broadcast.
type Syncer struct {
	chain *chain.Chain
	tp    transport.Transport
	priv  ed25519.PrivateKey

	// MaxBlocksPerResponse bounds a response. The wire layer's response
	// decoder allocates count*24 bytes for the block slice, so an unbounded
	// count is a 24x memory amplification of a frame that is already bounded -
	// and the requester controls the count it asks for.
	MaxBlocksPerResponse uint64

	// Peer is the validator this syncer pulls from, set by the
	// transport-facing layer when it knows which peer it is behind (a HELLO
	// height, a commit at a height past this node's head). The empty value
	// means "the transport's first listed peer": Peers() is deterministically
	// ordered, so this stays reproducible, and a two-node run needs no
	// configuration at all.
	Peer transport.PeerID

	// reply files the one response a pull in flight is waiting for. It is
	// written by Receive, which the transport-facing layer calls for every
	// BLOCK_SYNC_RESP frame the connection hands it. A BLOCK_SYNC_RESP
	// carries no reference to the request it answers, so responses cannot be
	// correlated - the syncer therefore does one pull at a time and files at
	// most one frame; a second arriving while the slot is full is dropped,
	// and the pull in flight keeps the frame it was offered first.
	reply chan *wire.BlockSyncResp

	// pub is this node's validator key: the Requester field of every request
	// the syncer signs, the same key the answerer checks membership against.
	pub ed25519.PublicKey
}

// NewSyncer builds a syncer over ch, signing its requests with priv and
// carrying DefaultMaxBlocksPerResponse.
func NewSyncer(ch *chain.Chain, tp transport.Transport, priv ed25519.PrivateKey) *Syncer {
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &Syncer{
		chain:                ch,
		tp:                   tp,
		priv:                 priv,
		MaxBlocksPerResponse: DefaultMaxBlocksPerResponse,
		reply:                make(chan *wire.BlockSyncResp, 1),
		pub:                  pub,
	}
}

// syncReqHash is the canonical challenge a BLOCK_SYNC request signature covers:
// the range asked for and the key that asks. Domain separation keeps a sync
// signature from ever being replayed as a vote or a proposal, the way every
// signing hash in this codebase is kept apart.
func syncReqHash(req *wire.BlockSyncReq) [32]byte {
	e := types.NewEncoder()
	e.U64(req.From)
	e.U64(req.To)
	e.VarBytes(req.Requester)
	return crypto.HashParts([]byte("b10coin-sync-req"), e.Bytes())
}

// verifySyncReq authenticates a request the way consensus messages are
// authenticated: a signature that verifies, bound to a key in the validator
// set. It takes the validator list rather than a Config because the syncer is
// built from a chain, and the chain is where the genesis set lives.
func verifySyncReq(req *wire.BlockSyncReq, vals []genesis.Validator) error {
	if len(req.Requester) == 0 {
		return fmt.Errorf("%w: missing requester key", ErrBadSyncAuth)
	}
	member := false
	for i := range vals {
		if bytes.Equal(vals[i].PubKey, req.Requester) {
			member = true
			break
		}
	}
	if !member {
		return fmt.Errorf("%w: requester is not in the validator set", ErrBadSyncAuth)
	}
	h := syncReqHash(req)
	if !crypto.Verify(req.Requester, h[:], req.Sig) {
		return fmt.Errorf("%w: signature does not verify", ErrBadSyncAuth)
	}
	return nil
}

// Answer serves encoded blocks from the local chain for the requested range.
//
// Three refusal rules, each an ERROR and never a short answer:
//
//   - the range selects nothing (To < From under the wire's inclusive
//     semantics) - malformed;
//   - the range is wider than MaxBlocksPerResponse - the count is bounded
//     BEFORE any allocation, because the requester controls it and the wire
//     response decoder amplifies every declared count 24x into slice memory;
//   - the range starts above the local height - a requester asking for a
//     future block is confused or hostile, and silently answering with less
//     would make its retry logic guess.
//
// A range that merely EXTENDS past the local height is served short: asking
// [from, from+window) of a shorter peer is the normal end of a windowed pull,
// and the served count below the window is how the requester learns the peer
// has run out.
func (s *Syncer) Answer(req *wire.BlockSyncReq) (*wire.BlockSyncResp, error) {
	if err := verifySyncReq(req, s.chain.Genesis().Validators); err != nil {
		return nil, err
	}
	// Refusals come before the first make(): nothing is allocated for a
	// request this syncer has already decided not to answer. The comparison
	// is on To-From, never on To-From+1: at From 0 and To MaxUint64 the +1
	// wraps to zero, and a count that wrapped would look like an empty range
	// instead of the largest range there is.
	if req.To < req.From {
		return nil, ErrBadSyncRange
	}
	if req.To-req.From >= s.MaxBlocksPerResponse {
		return nil, ErrRangeTooBig
	}
	height := s.chain.Height()
	if req.From > height {
		return nil, ErrRangeAhead
	}
	end := req.To
	if end > height {
		end = height
	}
	resp := &wire.BlockSyncResp{Blocks: make([][]byte, 0, end-req.From+1)}
	for h := req.From; h <= end; h++ {
		blk, err := s.chain.BlockAt(h)
		if err != nil {
			// Unreadable history is a local fault, not a range the peer
			// must decode byte by byte: refuse the whole answer.
			return nil, fmt.Errorf("consensus: block %d is unreadable: %w", h, err)
		}
		resp.Blocks = append(resp.Blocks, blk.Encode())
	}
	return resp, nil
}

// Handle is the server-side frame entry point. The transport-facing layer
// calls it with each BLOCK_SYNC_REQ frame a connection delivers and sends the
// returned frame back to the asker.
//
// ok is false for a decode failure and for every Answer refusal, and then NO
// frame goes back: the wire has no negative response, so refusal is silence.
// The consequences of silence are the requester's to interpret, and they are
// written out at PullAndAdopt, which is the reference requester.
func (s *Syncer) Handle(reqFrame []byte) (respFrame []byte, ok bool) {
	req, err := wire.DecodeBlockSyncReq(reqFrame)
	if err != nil {
		return nil, false
	}
	resp, err := s.Answer(req)
	if err != nil {
		return nil, false
	}
	return wire.EncodeBlockSyncResp(resp), true
}

// Receive files a BLOCK_SYNC_RESP frame for the pull in flight. The
// transport-facing layer calls it for every such frame; the syncer keeps at
// most one at a time (see the reply field). A frame that does not decode is
// dropped: a pull that gets nothing for it reads the same silence a refusal
// produces, and stops.
func (s *Syncer) Receive(from transport.PeerID, data []byte) {
	_ = from // BLOCK_SYNC_RESP carries no sender field to check it against
	resp, err := wire.DecodeBlockSyncResp(data)
	if err != nil {
		return
	}
	select {
	case s.reply <- resp:
	default: // one pull in flight; a second response would answer nothing
	}
}

// pullPeer is the peer a pull is sent to: the configured Peer, or the
// transport's first listed one.
func (s *Syncer) pullPeer() (transport.PeerID, error) {
	if s.Peer != "" {
		return s.Peer, nil
	}
	peers := s.tp.Peers()
	if len(peers) == 0 {
		return "", ErrNoSyncPeer
	}
	return peers[0], nil
}

// PullAndAdopt requests blocks from `from` upward and appends each one through
// chain.Append, so the same gate that guards a live commit guards an adopted
// one.
//
// The range is pulled in windows of MaxBlocksPerResponse, the same bound
// Answer refuses past, so a pull's own requests can never be refused as
// oversized (a peer configured with a SMALLER bound does refuse them, in
// silence - see the note on silence below, and the report's known-limitation
// note on mismatched bounds).
//
// Three stop rules:
//
//   - a request the transport refuses (peer down, partitioned, unknown)
//     returns the error: the caller owns retry policy;
//   - a block that fails to decode or fails Append STOPS the pull and is
//     returned as the error - never skipped ahead, because the blocks after a
//     hole cannot link either, and adopting past a refusal would mean
//     trusting the responder's bytes on the responder's say-so;
//   - silence - no response frame for the window - ends the pull with nil.
//     Refusal has no negative wire shape, so silence covers both "the peer
//     has nothing at/after start" (the caught-up case) and a lost frame; the
//     safety of adopting nothing is the same either way, and the node's
//     observation of peer heights (HELLO, commits) is what re-triggers a pull
//     when it still comes up short.
//
// Blocks the chain already holds are never re-asked for: the pull starts at
// max(from, head+1)... precisely, at head+1 whenever `from` does not name a
// height above it, which is what makes a re-pull of an adopted range (or a
// pull on a chain already current with its peer) a cheap no-op rather than a
// stream of refused appends. A `from` ABOVE head+1 is honoured as written and
// fails at Append - "height is not head+1" - because quietly reinterpreting
// the caller's request would hide the caller's confusion.
func (s *Syncer) PullAndAdopt(from uint64) error {
	if s.MaxBlocksPerResponse == 0 {
		return ErrSyncDisabled
	}
	head := s.chain.Height()
	if from <= head {
		from = head + 1 // the prefix through head is adopted; ask past it
	}
	win := s.MaxBlocksPerResponse
	for {
		// The window's To is overflow-safe: at the top of the height space
		// start+win-1 would wrap, and a wrapped To reads to Answer as the
		// empty range it would select.
		start := from
		end := start + (win - 1)
		if end < start {
			end = math.MaxUint64
		}
		peer, err := s.pullPeer()
		if err != nil {
			return err
		}
		req := &wire.BlockSyncReq{From: start, To: end, Requester: s.pub}
		h := syncReqHash(req)
		req.Sig = crypto.Sign(s.priv, h[:])
		if err := s.tp.Send(peer, wire.EncodeBlockSyncReq(req)); err != nil {
			return err
		}
		// The answer is whatever Receive filed while Send ran. Over an
		// in-process (sim or loopback) transport that is already here; over a
		// socket connection the node's reader goroutine files it, and the
		// no-timeout policy below is the seam the node's request/response
		// wiring must own (a deadline there, not here - this package never
		// reads a clock).
		var got *wire.BlockSyncResp
		select {
		case got = <-s.reply:
		default:
		}
		if got == nil || len(got.Blocks) == 0 {
			return nil // silence: nothing to adopt, nothing to retry here
		}
		for i, raw := range got.Blocks {
			blk, err := types.DecodeBlock(raw)
			if err != nil {
				return fmt.Errorf("%w: served block %d of %d does not decode: %v",
					ErrBadSyncResp, i+1, len(got.Blocks), err)
			}
			// THE gate. Every byte the peer chose has to adopt the way a
			// committed block does, or the chain never changes. Append
			// validates before it mutates, so a refusal leaves head, height
			// and store exactly where they were.
			if err := s.chain.Append(blk); err != nil {
				return fmt.Errorf("consensus: peer served block %d of %d (height %d), which does not adopt: %w",
					i+1, len(got.Blocks), blk.Header.Height, err)
			}
		}
		served := uint64(len(got.Blocks))
		if served < win {
			return nil // the peer ran out inside this window: caught up
		}
		from = start + served // a full window: keep pulling past it
		if from < start {
			return nil // the height space is exhausted
		}
	}
}
