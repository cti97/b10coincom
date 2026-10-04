package consensus

// BLOCK_SYNC catch-up: the mechanism M3's limits note deferred. A validator
// that fell behind could watch rounds happen but never adopt the blocks it
// missed, because Transport offered only Broadcast - consensus messages are
// one-to-many events, and "send me your chain" is a question exactly one peer
// answers. The Syncer is that question and its answer, split across the two
// roles a node plays:
//
//   - ANSWERING. Handle/Answer serve encoded blocks out of the local chain for
//     a signed, bounded height range, each block together with the COMMIT
//     CERTIFICATE that proves a quorum of the committee precommitted exactly
//     those bytes. The transport-facing layer calls Handle when a
//     BLOCK_SYNC_REQ frame arrives and puts the returned frame on the wire; a
//     refusal is (nil, false) and sends nothing.
//   - PULLING. PullAndAdopt asks the chosen peer for the range above the local
//     head, one bounded window at a time, and appends every block it gets back
//     through chain.Append - the same validation a live commit goes through.
//
// Two invariants make pulling safe enough to point at a stranger:
//
// CATCH-UP VERIFIES, IT DOES NOT TRUST. The requester chooses the heights it
// asks for, but the responder chooses the bytes it sends back, so nothing a
// response says may reach the chain without the full gate: A COMMIT CERTIFICATE,
// re-tallied here through the ordinary VoteSet the engine tallies with, then
// parent link against OUR head, height exactly head+1, committee membership,
// proposer signature, and the state root recomputed here. The certificate is
// what makes "the proposer's signature" insufficient: Append verifies
// authorship and state validity, NOT quorum commitment - a single committee
// member can Build a state-valid block at head+1 and sign it with zero votes,
// and no live engine would ever commit it. Serving that block uncertified, or
// adopting it, hands the peer the power to fork a catching-up node onto a
// one-validator fork. The certificate is the set of PRECOMMIT votes for that
// block at that height - exactly the evidence a live commit is made of - so a
// block is adoptable if and only if it reaches this node the way a commit does.
// A peer can still withhold blocks (liveness; the caller re-pulls) or serve
// genuinely certified, genuinely valid ones - anything else is refused and the
// pull stops rather than skipping ahead, because a skipped block leaves a hole
// no later block can link across.
//
// DELIVERY IS ASYNCHRONOUS. Neither shipped transport delivers inside Send -
// sim and tcp enqueue (a transport that re-entered its caller mid-send would
// break the engine's step ordering), so the requester cannot read the answer
// where it sent the question. The pull registers nothing itself; the
// transport-facing layer routes arriving BLOCK_SYNC_RESP frames into Receive,
// and the pull waits on that filed frame with a deadline (ReplyWait). Silence
// at the deadline - and a frame filed while no pull waited - is treated as
// "nothing to adopt", never as an error a caller would retry blindly.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/types"
	"github.com/cti97/b10coincom/internal/wire"
)

// DefaultMaxBlocksPerResponse is the bound a Syncer carries when it is built
// through NewSyncer. With a devnet block (a ~250-byte header and, today, no
// transaction load) a full window plus its certificates (three ~180-byte
// precommits per block) encodes to well under the tcp transport's 1 MiB frame
// bound, so a default-window response can never be silently dropped by the
// frame layer for size. A deployment whose blocks carry real transaction
// weight must lower this knob: the bound is in BLOCKS, not bytes, and the
// frame bound is the enforcement point behind it.
const DefaultMaxBlocksPerResponse = 64

// DefaultReplyWait is the deadline a pull waits on ONE response frame when
// ReplyWait is left at zero. It must cover a request/response round trip over
// the slowest deployed link: sim delivers on the next Advance (sub-millisecond
// wall time), tcp on the next frame the peer writes. Expiry is read as
// "nothing came back" - the caught-up-or-lost branch of the pull's stop rules
// - so it must not be so short that honest latency reads as caught-up.
const DefaultReplyWait = 2 * time.Second

var (
	// ErrBadSyncRange reports a request whose range selects nothing: under
	// the wire's inclusive [From, To] semantics, To < From.
	ErrBadSyncRange = errors.New("consensus: BLOCK_SYNC range selects no blocks")
	// ErrRangeTooBig reports a range wider than MaxBlocksPerResponse. The
	// count is refused, never silently truncated, so a requester always
	// knows whether the error is its own window or the peer's height.
	ErrRangeTooBig = errors.New("consensus: BLOCK_SYNC range exceeds MaxBlocksPerResponse")
	// ErrRangeAhead reports a range that starts above the local height - on
	// the ANSWER side, a requester asking for a future block is confused or
	// hostile; on the PULL side, a caller naming a height above head+1 can
	// never adopt anything (Append requires exactly head+1), so the request
	// is refused locally before any wire traffic instead of being honoured
	// into silence.
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
	// ErrBadSyncCommit reports an adoptable-in-form block whose commit
	// CERTIFICATE is missing, malformed, wrong-placed, non-member-signed, or
	// short of the quorum the live commit rule requires. It is the puller's
	// refusal sentinel and the answerer's own: a peer that cannot PROVE a
	// quorum committed a block does not get to serve it either.
	ErrBadSyncCommit = errors.New("consensus: peer served a block whose commit certificate does not prove a quorum commitment")
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
	// decoder allocates ~56 bytes per declared unit (two slice headers and a
	// padded round), so an unbounded count is a remote memory amplification of
	// a frame that is already bounded - and the requester controls the count
	// it asks for. (The Len decoder's own bound - a count larger than the
	// remaining frame bytes is refused - is what keeps the amplification
	// linear in the frame cap.)
	MaxBlocksPerResponse uint64

	// Peer is the validator this syncer pulls from, set by the
	// transport-facing layer when it knows which peer it is behind (a HELLO
	// height, a commit at a height past this node's head). The empty value
	// means "the transport's first listed peer": Peers() is deterministically
	// ordered, so this stays reproducible, and a two-node run needs no
	// configuration at all.
	Peer transport.PeerID

	// ReplyWait is how long one window's request waits for a filed response
	// before the pull reads silence; zero takes DefaultReplyWait. The clock
	// lives HERE, in the wire-facing layer, by the same split as every clock
	// in this package: the ENGINE never reads one, and a requester without a
	// deadline either spins against a silent peer or trusts whatever frame
	// happens to be lying in its slot. The node's wiring owns retry policy;
	// this deadline is the pull's, not consensus protocol time.
	ReplyWait time.Duration

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

	// commits is this syncer's COMMIT CERTIFICATE ARCHIVE: per height, the
	// round and the precommit votes that committed the block the chain holds
	// there. It is written by RecordCommit - from the driver's commit
	// witness (wired by whoever builds both) for commits this node judged
	// live, and from PullAndAdopt for blocks this node itself adopted, so a
	// caught-up node can serve onward what certified it in the first place.
	// In-memory only: a restart forgets it (recorded limit; a restarted node
	// cannot re-serve certificates for heights it committed before it
	// crashed). Every entry was verified against the same quorum rule the
	// puller applies, so Answer never serves a certificate it has not stood
	// behind. Answers read it, so it is mutex-guarded.
	commitMu sync.Mutex
	commits  map[uint64]commitRecord
}

type commitRecord struct {
	round uint32
	votes []*Vote
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

// certVoteSet builds the VoteSet a commit certificate is re-tallied through:
// the ordinary set for (height, round) precommits over the genesis committee.
// A zero TimeoutBase is fine - VoteSet reads only the committee (power,
// membership) and never a clock, and Config.Validate is not the gate here; the
// gate is the tally rules that Add applies.
func certVoteSet(vals []genesis.Validator, height uint64, round uint32) *VoteSet {
	return NewVoteSet(Config{Committee: vals}, height, round, MsgPrecommit)
}

// verifyCertificate is THE quorum gate an adopted unit must clear before
// Append: the carried precommit votes are re-tallied through the same
// VoteSet.Add a live vote arrives through, so the vote's signature, its
// sender's committee membership, and its placement at exactly (block height,
// carried round) are all re-proven, the one-vote-per-validator rule holds, and
// HasQuorum(block ID) demands the same two-thirds-of-total-power a live commit
// musters on precommits.AnyQuorum(). Anything the votes fail on is a refused
// certificate - a certificate that "seems right" would be an unverified claim
// of a commit that may never have happened.
func (s *Syncer) verifyCertificate(blk *types.Block, round uint32, votes []*Vote) error {
	vals := s.chain.Genesis().Validators
	vs := certVoteSet(vals, blk.Header.Height, round)
	for i, v := range votes {
		if v == nil {
			return fmt.Errorf("%w: certificate vote %d is absent", ErrBadSyncCommit, i+1)
		}
		if _, err := vs.Add(v); err != nil {
			// Add rejects: a malformed vote, a wrong type, a missing key, a
			// broken signature, a vote for another (height, round), a
			// non-member key. Any one of them is not evidence.
			return fmt.Errorf("%w: certificate vote %d is unusable here: %v", ErrBadSyncCommit, i+1, err)
		}
	}
	if !vs.HasQuorum(blk.ID()) {
		id := blk.ID()
		return fmt.Errorf("%w: %d carried precommits at (height %d, round %d) do not reach the quorum of %d power for block %x",
			ErrBadSyncCommit, len(votes), blk.Header.Height, round, valsQuorum(vals), id[:8])
	}
	return nil
}

// valsQuorum is the quorum threshold the genesis committee's powers imply, for
// error messages.
func valsQuorum(vals []genesis.Validator) uint64 { return Config{Committee: vals}.Quorum() }

// RecordCommit files a commit certificate for a height. The driver's
// CommitWitness hands the live commits (the engine's own tallied precommits
// for the block that was just appended); PullAndAdopt hands the certificates
// it verified while adopting. A certificate is archived ONLY if it proves
// quorum for the block the chain now holds at that height - an archive entry
// is a claim this syncer will serve to a stranger, and an unverified claim
// served is the same hole the puller refuses.
//
// The first certificate for a height wins; a committed height never changes
// its block, and later calls are the same evidence arriving again.
func (s *Syncer) RecordCommit(height uint64, round uint32, votes []*Vote) {
	blk, err := s.chain.BlockAt(height)
	if err != nil {
		return // no chain block at that height: no served block can stand on it
	}
	if err := s.verifyCertificate(blk, round, votes); err != nil {
		return // never archive (and later serve) evidence that proves nothing
	}
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	if s.commits == nil {
		// Lazy-built under the same lock the map is read under: a hand-built
		// Syncer (or a rebuild) must not race the map's first allocation.
		s.commits = make(map[uint64]commitRecord)
	}
	if _, have := s.commits[height]; have {
		return
	}
	vs := make([]*Vote, len(votes))
	copy(vs, votes)
	s.commits[height] = commitRecord{round: round, votes: vs}
}

// certificateAt returns the archived certificate for height, re-proven against
// the block the chain holds at that height now. A certificate archived for one
// block must never attach to a served block it does not stand behind; a height
// with no (or no longer valid) certificate yields false, which Answer refuses.
func (s *Syncer) certificateAt(height uint64) (uint32, []*Vote, bool) {
	s.commitMu.Lock()
	rec, ok := s.commits[height]
	s.commitMu.Unlock()
	if !ok {
		return 0, nil, false
	}
	blk, err := s.chain.BlockAt(height)
	if err != nil {
		return 0, nil, false
	}
	if err := s.verifyCertificate(blk, rec.round, rec.votes); err != nil {
		return 0, nil, false
	}
	return rec.round, rec.votes, true
}

// Answer serves encoded blocks from the local chain for the requested range,
// WITH their commit certificates: each unit carries the block and the archived
// precommit votes that committed it.
//
// Five refusal rules, each an ERROR and never a short answer:
//
//   - the request is not from a signed committee member (ErrBadSyncAuth);
//   - the range selects nothing (To < From under the wire's inclusive
//     semantics) - malformed (ErrBadSyncRange);
//   - the range is wider than MaxBlocksPerResponse - the count is bounded
//     BEFORE any allocation, because the requester controls it and the wire
//     response decoder amplifies every declared unit's memory (ErrRangeTooBig);
//   - the range starts above the local height (ErrRangeAhead);
//   - ANY height in the range has no archived commit certificate that still
//     proves quorum for the block held there (ErrBadSyncCommit) - a peer that
//     cannot prove a quorum committed a block does not serve it, which is
//     half of the certificate rule; the puller's refusal is the other half.
//     This is the one rule that narrows what a catch-up server can honestly
//     serve: only blocks this node held the certificate evidence for.
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
	units := make([]wire.BlockSyncUnit, 0, end-req.From+1)
	for h := req.From; h <= end; h++ {
		blk, err := s.chain.BlockAt(h)
		if err != nil {
			// Unreadable history is a local fault, not a range the peer
			// must decode byte by byte: refuse the whole answer.
			return nil, fmt.Errorf("consensus: block %d is unreadable: %w", h, err)
		}
		round, votes, ok := s.certificateAt(h)
		if !ok {
			return nil, fmt.Errorf("%w: this node holds no commit certificate for height %d", ErrBadSyncCommit, h)
		}
		encoded := make([][]byte, 0, len(votes))
		for _, v := range votes {
			encoded = append(encoded, EncodeVote(v))
		}
		units = append(units, wire.BlockSyncUnit{Block: blk.Encode(), Round: round, Votes: encoded})
	}
	return &wire.BlockSyncResp{Units: units}, nil
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
// transport-facing layer calls it for every such frame (its message router
// decides what a frame is); the syncer keeps at most one at a time (see the
// reply field). A frame that does not decode is dropped: a pull that gets
// nothing for it reads the same silence a refused request produces, and stops.
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

// drainReply discards whatever frame sits in the reply slot. A pull runs one
// window at a time, but frames do not stop arriving between pulls: an answer
// filed before the pull started, or left behind by an earlier pull that
// stopped on an error mid-window, is a reply to a request that is no longer in
// flight. Consuming it as the fresh answer would adopt exactly what the
// transport delivered on the LAST pull's timing - the stale-slot reading the
// synchronous version of this code could not see.
func (s *Syncer) drainReply() {
	select {
	case <-s.reply:
	default:
	}
}

// awaitReply blocks until a response is filed or the deadline finds nothing:
// it is the requester's half of asynchronous delivery, because neither shipped
// transport delivers inside Send. nil means "nothing came back", which is the
// caught-up-or-lost branch of the stop rules, never a retry here. Zero or
// negative ReplyWait means the default - a knob that silently waited zero
// would reinstall the synchronous read this deadline exists to replace.
func (s *Syncer) awaitReply() *wire.BlockSyncResp {
	wait := s.ReplyWait
	if wait <= 0 {
		wait = DefaultReplyWait
	}
	select {
	case got := <-s.reply:
		return got
	case <-time.After(wait):
		return nil
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
// chain.Append, so the same gate that guards a live commit - and, above it,
// the certificate gate that guard alone does not cover - guards an adopted one.
//
// The range is pulled in windows of MaxBlocksPerResponse, the same bound
// Answer refuses past, so a pull's own requests can never be refused as
// oversized (a peer configured with a SMALLER bound does refuse them, in
// silence - see the note on silence below, and the report's known-limitation
// note on mismatched bounds).
//
// A `from` ABOVE head+1 is refused LOCALLY with ErrRangeAhead before any wire
// traffic: Append requires exactly head+1, so the caller is confused (or
// testing), and the previous behaviour - honour the range as written, get
// silence back from a shorter or refusing peer, and return nil - read silence
// as caught-up while the caller had named an impossible target. The refusal
// names the confusion instead of hiding it.
//
// Four stop rules:
//
//   - a request the transport refuses (peer down, partitioned, unknown)
//     returns the error: the caller owns retry policy;
//   - a unit that fails to decode, carries no usable COMMIT CERTIFICATE
//     (missing, malformed, wrong-placed, non-member, or sub-quorum), or a
//     block that fails Append STOPS the pull and is returned as the error -
//     never skipped ahead. Without the certificate the block is a single
//     validator's fork in the making no matter how valid its state is; with a
//     hole, the blocks after it cannot link either; adopting past either
//     would mean trusting the responder's bytes on the responder's say-so;
//   - a file left in the reply slot between pulls is drained, not consumed:
//     it answers no request in flight;
//   - silence - no response for the window within ReplyWait - ends the pull
//     with nil. Refusal has no negative wire shape, so silence covers both
//     "the peer has nothing at/after start" (the caught-up case) and a peer
//     that went quiet; the safety of adopting nothing is the same either way,
//     and the node's observation of peer heights (HELLO, commits) is what
//     re-triggers a pull when it still comes up short.
//
// Blocks the chain already holds are never re-asked for: the pull starts at
// max(from, head+1)... precisely, at head+1 whenever `from` does not name a
// height above it, which is what makes a re-pull of an adopted range (or a
// pull on a chain already current with its peer) a cheap no-op rather than a
// stream of refused appends.
//
// Every block adopted is a block certified: the pull files each unit's
// verified certificate into its own archive (RecordCommit), so a node that
// caught up can serve the same evidence onward.
func (s *Syncer) PullAndAdopt(from uint64) error {
	if s.MaxBlocksPerResponse == 0 {
		return ErrSyncDisabled
	}
	head := s.chain.Height()
	if from <= head {
		from = head + 1 // the prefix through head is adopted; ask past it
	}
	if from > head+1 {
		return fmt.Errorf("%w: the pull names height %d, above this chain's head+1 %d", ErrRangeAhead, from, head+1)
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
		s.drainReply() // a frame filed between pulls answers nothing now in flight
		if err := s.tp.Send(peer, wire.EncodeBlockSyncReq(req)); err != nil {
			return err
		}
		// The answer is whatever Receive files while the request is on the
		// wire; awaitReply waits for it up to ReplyWait, because neither
		// shipped transport delivers inside Send. Over sim the node's own
		// Advance delivers; over tcp the connection's reader does.
		got := s.awaitReply()
		if got == nil || len(got.Units) == 0 {
			return nil // silence: nothing to adopt, nothing to retry here
		}
		for i, unit := range got.Units {
			blk, err := types.DecodeBlock(unit.Block)
			if err != nil {
				return fmt.Errorf("%w: served block %d of %d does not decode: %v",
					ErrBadSyncResp, i+1, len(got.Units), err)
			}
			if len(unit.Votes) == 0 {
				// Named for what it is: zero votes is the one-validator fork
				// the certificate rule exists for, and it must not ride
				// through Add's "no votes in, no quorum" quietly.
				return fmt.Errorf("%w: served block %d of %d (height %d) carries no precommit votes at all",
					ErrBadSyncCommit, i+1, len(got.Units), blk.Header.Height)
			}
			votes := make([]*Vote, 0, len(unit.Votes))
			for j, raw := range unit.Votes {
				v, err := DecodeVote(raw)
				if err != nil {
					return fmt.Errorf("%w: served block %d of %d (height %d) certificate vote %d does not decode: %v",
						ErrBadSyncCommit, i+1, len(got.Units), blk.Header.Height, j+1, err)
				}
				votes = append(votes, v)
			}
			// THE quorum gate: the carried precommits must prove, through the
			// ordinary tally, that the committee committed exactly these
			// bytes at exactly this height - before Append is ever offered.
			if err := s.verifyCertificate(blk, unit.Round, votes); err != nil {
				return fmt.Errorf("consensus: peer served block %d of %d (height %d): %w",
					i+1, len(got.Units), blk.Header.Height, err)
			}
			// THE state gate. Every remaining byte the peer chose has to
			// adopt the way a committed block does, or the chain never
			// changes. Append validates before it mutates, so a refusal
			// leaves head, height and store exactly where they were.
			if err := s.chain.Append(blk); err != nil {
				return fmt.Errorf("consensus: peer served block %d of %d (height %d), which does not adopt: %w",
					i+1, len(got.Units), blk.Header.Height, err)
			}
			s.RecordCommit(blk.Header.Height, unit.Round, votes) // serve what certified this onwards
		}
		served := uint64(len(got.Units))
		if served < win {
			return nil // the peer ran out inside this window: caught up
		}
		from = start + served // a full window: keep pulling past it
		if from < start {
			return nil // the height space is exhausted
		}
	}
}
