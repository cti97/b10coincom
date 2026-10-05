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
// A RESPONSE BELONGS TO ONE REQUEST. A request carries a nonce, the signed
// challenge covers it, and the answer echoes it. A pull registers the ONE
// request it has in flight (peer, nonce, and a private reply channel) and files
// a response only when the sender is that peer AND the nonce is that request's:
// a response for an earlier request - a late answer arriving after a retry - is
// dropped, never consumed as the current request's answer. Every served unit
// must also fall inside the requested window [start, end], so a peer cannot
// answer a one-window request with a block from somewhere else. Requesting is
// itself bounded three ways: a served (requester, nonce) is remembered for a
// short window so the SAME signed request cannot be replayed for another
// answer; a per-requester token bucket caps how many requests one asker can
// make the node serve; and each request authenticates as a signed committee
// member.
//
// DELIVERY IS ASYNCHRONOUS. Neither shipped transport delivers inside Send -
// sim and tcp enqueue (a transport that re-entered its caller mid-send would
// break the engine's step ordering), so the requester cannot read the answer
// where it sent the question. The pull registers its request before sending;
// the transport-facing layer routes arriving BLOCK_SYNC_RESP frames into
// Receive, and the pull waits on that request's channel with a deadline
// (ReplyWait). Silence at the deadline - and a frame filed while no pull
// waited - is treated as "nothing to adopt", never as an error a caller would
// retry blindly.

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
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

// Defaults for the answer side's resource bounds (audit C-4). A request costs
// the responder up to a window of disk reads plus quorum-many Ed25519 verifies
// per height, so an unbounded asker is an amplifier. The bucket is per
// requester key, sized for a legitimate windowed catch-up (a full 64-block
// window per request means 128 requests/second is over 8000 blocks/second,
// far past any honest pull) while still bounding a flood.
const (
	// DefaultSyncRateLimit is how many authenticated requests one requester
	// may be served per DefaultSyncRateWindow when RateLimit is zero.
	DefaultSyncRateLimit = 128
	// DefaultSyncRateWindow is the length of the rate-limit window.
	DefaultSyncRateWindow = time.Second
	// DefaultSyncSeenTTL is how long a served (requester, nonce) is
	// remembered, so a replayed request is refused while it is fresh. It is
	// SHORT-LIVED by design: the set is in memory and bounded, not durable.
	DefaultSyncSeenTTL = 30 * time.Second
	// syncSeenMax caps the replay set's size. Reaching it evicts expired
	// entries first and then an arbitrary one: the set is a short-lived
	// replay cache, not a commitment.
	syncSeenMax = 4096
)

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
	// ErrSyncUnitOutOfRange reports a response unit whose block stands outside
	// the window the request asked for. A peer that answers a range it was not
	// asked about is refused before its certificate is even considered: the
	// range, not the certificate, is the first thing the response must honour.
	ErrSyncUnitOutOfRange = errors.New("consensus: peer served a block outside the requested range")
	// ErrBadSyncCommit reports an adoptable-in-form block whose commit
	// CERTIFICATE is missing, malformed, wrong-placed, non-member-signed, or
	// short of the quorum the live commit rule requires. It is the puller's
	// refusal sentinel and the answerer's own: a peer that cannot PROVE a
	// quorum committed a block does not get to serve it either.
	ErrBadSyncCommit = errors.New("consensus: peer served a block whose commit certificate does not prove a quorum commitment")
	// ErrSyncRateLimited reports an authenticated requester that has spent its
	// per-window budget. It is an answer-side refusal: Handle turns it into
	// silence, and the asker's pull reads that as "nothing came back".
	ErrSyncRateLimited = errors.New("consensus: BLOCK_SYNC request exceeds the requester's rate limit")
	// ErrSyncReplayed reports the same signed request arriving twice within
	// the seen-set window. Serving it again would let one signed request make
	// the node do its full answer work repeatedly (audit C-4).
	ErrSyncReplayed = errors.New("consensus: BLOCK_SYNC request was already served (replay)")
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

	// RateLimit is how many authenticated requests one requester may be
	// served per RateWindow; zero takes DefaultSyncRateLimit. A request costs
	// a window of disk reads and quorum-many verifies per height, so an
	// unbounded asker is an amplifier. The bucket is per requester KEY, not
	// per connection: one flooder cannot spend an honest peer's budget.
	RateLimit uint64
	// RateWindow is the rate-limit window; zero takes DefaultSyncRateWindow.
	RateWindow time.Duration
	// SeenTTL is how long a served (requester, nonce) is remembered, so the
	// same signed request cannot be replayed for a second answer; zero takes
	// DefaultSyncSeenTTL. A restarted node seeds a fresh nonce sequence (see
	// nonceSeed), so its first post-restart request is never mistaken for a
	// replay of its pre-restart one.
	SeenTTL time.Duration

	// reqMu guards waiting: the ONE request a pull has in flight, and the
	// channel its answer will be filed on. A response is filed only when the
	// sender and nonce match this request (see Receive).
	reqMu   sync.Mutex
	waiting *pendingReply

	// nonce is this syncer's request counter, seeded randomly at NewSyncer so
	// a restart does not repeat a sequence a peer's seen-set may still hold.
	nonce atomic.Uint64

	// rateMu guards rate, the per-requester token buckets.
	rateMu sync.Mutex
	rate   map[string]*rateBucket

	// seenMu guards seen, the short-lived replay set keyed by (requester,
	// nonce).
	seenMu sync.Mutex
	seen   map[seenKey]time.Time

	// clock is a test seam for the rate-limit and seen-set windows; nil means
	// time.Now, the wire-facing layer owning every clock in this file.
	clock func() time.Time

	// pub is this node's validator key: the Requester field of every request
	// the syncer signs, the same key the answerer checks membership against.
	pub ed25519.PublicKey

	// commits is this syncer's COMMIT CERTIFICATE ARCHIVE: per height, the
	// round and the precommit votes that committed the block the chain holds
	// there, plus their encoded wire form. The encoded form is built ONCE, at
	// RecordCommit, because Answer would otherwise re-encode a quorum's votes
	// for every served height (audit C-4's answer cost). It is written by
	// RecordCommit - from the driver's commit witness (wired by whoever builds
	// both) for commits this node judged live, and from PullAndAdopt for
	// blocks this node itself adopted, so a caught-up node can serve onward
	// what certified it in the first place. In-memory only: a restart forgets
	// it (recorded limit; a restarted node cannot re-serve certificates for
	// heights it committed before it crashed). Every entry was verified
	// against the same quorum rule the puller applies, so Answer never serves
	// a certificate it has not stood behind. Answers read it, so it is
	// mutex-guarded.
	commitMu sync.Mutex
	commits  map[uint64]commitRecord
}

// pendingReply is the ONE request a pull has in flight. Receive files into ch
// only a response whose nonce equals nonce and whose sender equals peer.
type pendingReply struct {
	nonce uint64
	peer  transport.PeerID
	ch    chan *wire.BlockSyncResp
}

type commitRecord struct {
	round   uint32
	votes   []*Vote
	encoded [][]byte // the wire form of votes, built once at RecordCommit
}

// rateBucket is one requester's fixed-window token bucket.
type rateBucket struct {
	tokens uint64
	reset  time.Time
}

// seenKey identifies one served request for the replay set.
type seenKey struct {
	who   string
	nonce uint64
}

// NewSyncer builds a syncer over ch, signing its requests with priv and
// carrying DefaultMaxBlocksPerResponse.
func NewSyncer(ch *chain.Chain, tp transport.Transport, priv ed25519.PrivateKey) *Syncer {
	pub, _ := priv.Public().(ed25519.PublicKey)
	s := &Syncer{
		chain:                ch,
		tp:                   tp,
		priv:                 priv,
		MaxBlocksPerResponse: DefaultMaxBlocksPerResponse,
		pub:                  pub,
	}
	s.nonce.Store(nonceSeed())
	return s
}

// nonceSeed is the random start of one syncer's request-nonce sequence. It is
// random, not zero, for one specific reason: a restarted node builds a FRESH
// syncer, and a counter starting at 1 would repeat the pre-restart sequence -
// a peer still holding the old (requester, nonce) in its short-lived seen-set
// would refuse the rejoin as a replay. Randomness makes the rejoin's first
// request a request the peer has never seen.
func nonceSeed() uint64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(b[:])
}

// nextNonce returns the next request nonce. Nonces are unique within one
// syncer's lifetime (a 64-bit counter), which is all the correlation needs.
func (s *Syncer) nextNonce() uint64 { return s.nonce.Add(1) }

// now reads the syncer's clock (nil: the wall clock). Tests inject a clock so
// the rate-limit and seen-set windows are exercised without sleeping.
func (s *Syncer) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// syncReqHash is the canonical challenge a BLOCK_SYNC request signature covers:
// the range asked for, the request's nonce, and the key that asks. Domain
// separation keeps a sync signature from ever being replayed as a vote or a
// proposal, the way every signing hash in this codebase is kept apart, and the
// nonce is bound here so a peer cannot move it to re-label an old request.
func syncReqHash(req *wire.BlockSyncReq) [32]byte {
	e := types.NewEncoder()
	e.U64(req.From)
	e.U64(req.To)
	e.U64(req.Nonce)
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

// allowRequest charges one token to the requester's bucket. A requester over
// its budget is refused (ErrSyncRateLimited) rather than served: the answer
// side's work is bounded by the bucket, per requester key.
func (s *Syncer) allowRequest(req *wire.BlockSyncReq) bool {
	limit := s.RateLimit
	if limit == 0 {
		limit = DefaultSyncRateLimit
	}
	window := s.RateWindow
	if window <= 0 {
		window = DefaultSyncRateWindow
	}
	now := s.now()
	key := string(req.Requester)
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if s.rate == nil {
		s.rate = make(map[string]*rateBucket)
	}
	b := s.rate[key]
	if b == nil || now.Sub(b.reset) >= window {
		b = &rateBucket{tokens: limit, reset: now}
		s.rate[key] = b
	}
	if b.tokens == 0 {
		return false
	}
	b.tokens--
	return true
}

// noteRequest records a served (requester, nonce) and reports false when the
// same signed request has already been served within SeenTTL. This is the
// replay gate: the nonce makes each request's frame unique, and this set makes
// a duplicate inert instead of a second full answer's work.
func (s *Syncer) noteRequest(req *wire.BlockSyncReq) bool {
	ttl := s.SeenTTL
	if ttl <= 0 {
		ttl = DefaultSyncSeenTTL
	}
	now := s.now()
	k := seenKey{who: string(req.Requester), nonce: req.Nonce}
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	if s.seen == nil {
		s.seen = make(map[seenKey]time.Time)
	}
	if t, ok := s.seen[k]; ok && now.Sub(t) < ttl {
		return false
	}
	if len(s.seen) >= syncSeenMax {
		// Reclaim expired entries; if the set is still full, drop an
		// arbitrary one. A short-lived replay cache needs bounded memory, not
		// a perfect eviction order.
		for key, t := range s.seen {
			if now.Sub(t) >= ttl {
				delete(s.seen, key)
			}
		}
		if len(s.seen) >= syncSeenMax {
			for key := range s.seen {
				delete(s.seen, key)
				break
			}
		}
	}
	s.seen[k] = now
	return true
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
// served is the same hole the puller refuses. The votes' wire encoding is
// built HERE, once, so Answer serves cached bytes instead of re-encoding a
// quorum's votes per height.
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
	encoded := make([][]byte, 0, len(vs))
	for _, v := range vs {
		encoded = append(encoded, EncodeVote(v))
	}
	s.commits[height] = commitRecord{round: round, votes: vs, encoded: encoded}
}

// certificateAt returns the archived certificate for height, re-proven against
// the block the chain holds at that height now. A certificate archived for one
// block must never attach to a served block it does not stand behind; a height
// with no (or no longer valid) certificate yields false, which Answer refuses.
// The returned record's encoded form is the wire form Answer serves.
func (s *Syncer) certificateAt(height uint64) (commitRecord, bool) {
	s.commitMu.Lock()
	rec, ok := s.commits[height]
	s.commitMu.Unlock()
	if !ok {
		return commitRecord{}, false
	}
	blk, err := s.chain.BlockAt(height)
	if err != nil {
		return commitRecord{}, false
	}
	if err := s.verifyCertificate(blk, rec.round, rec.votes); err != nil {
		return commitRecord{}, false
	}
	if len(rec.encoded) == 0 && len(rec.votes) > 0 {
		// A record written before the encoding cache existed (or by a test
		// that seeded one): fill it here rather than re-encoding per answer.
		rec.encoded = make([][]byte, 0, len(rec.votes))
		for _, v := range rec.votes {
			rec.encoded = append(rec.encoded, EncodeVote(v))
		}
	}
	return rec, true
}

// Answer serves encoded blocks from the local chain for the requested range,
// WITH their commit certificates: each unit carries the block and the archived
// precommit votes that committed it.
//
// Refusal rules, each an ERROR and never a short answer:
//
//   - the request is not from a signed committee member (ErrBadSyncAuth);
//   - the requester is over its per-window budget (ErrSyncRateLimited);
//   - the same signed (requester, nonce) was already served (ErrSyncReplayed);
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
	// The resource gates come before any allocation or disk read. The rate
	// bucket is charged first so even a replay flood is bounded by it.
	if !s.allowRequest(req) {
		return nil, fmt.Errorf("%w: %s", ErrSyncRateLimited, requesterLabel(req.Requester))
	}
	if !s.noteRequest(req) {
		return nil, fmt.Errorf("%w: nonce %d was already served", ErrSyncReplayed, req.Nonce)
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
		rec, ok := s.certificateAt(h)
		if !ok {
			return nil, fmt.Errorf("%w: this node holds no commit certificate for height %d", ErrBadSyncCommit, h)
		}
		units = append(units, wire.BlockSyncUnit{Block: blk.Encode(), Round: rec.round, Votes: rec.encoded})
	}
	return &wire.BlockSyncResp{Nonce: req.Nonce, Units: units}, nil
}

// requesterLabel renders a requester key for an error message without pulling
// in a hex import: the first four bytes are enough to tell two askers apart.
func requesterLabel(key []byte) string {
	if len(key) > 4 {
		key = key[:4]
	}
	return fmt.Sprintf("%x", key)
}

// Handle is the server-side frame entry point. The transport-facing layer
// calls it with each BLOCK_SYNC_REQ frame a connection delivers and sends the
// returned frame back to the asker.
//
// ok is false for a decode failure and for every Answer refusal, and then NO
// frame goes back: the wire has no negative response, so refusal is silence.
// The consequences of silence are the requester's to interpret, and they are
// written out at PullAndAdopt, which is the reference requester.
//
// Handle does the full answer on ITS caller's goroutine. The transport-facing
// layer must therefore not call it on a goroutine whose stall would block
// consensus dispatch (audit C-4): MessageRouter.AsyncServe exists to hand the
// frame to a bounded worker instead, and the node layer installs one.
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

// Receive files a BLOCK_SYNC_RESP frame for the pull in flight, and ONLY that
// pull's frame. A response is accepted when a request is in flight, when it
// arrived from the peer that request was sent to, and when its nonce equals
// that request's. Anything else is dropped: a response for a different request
// (including a late answer to an earlier retry), a response from a peer that
// was never asked, and a frame arriving while no pull waits all read the same
// silence. A frame that does not decode is dropped for the same reason.
func (s *Syncer) Receive(from transport.PeerID, data []byte) {
	resp, err := wire.DecodeBlockSyncResp(data)
	if err != nil {
		return
	}
	s.reqMu.Lock()
	w := s.waiting
	s.reqMu.Unlock()
	if w == nil {
		return // no request in flight: nothing this frame could answer
	}
	if w.peer != from {
		// The sender check: a peer that was not asked cannot answer.
		return
	}
	if resp.Nonce != w.nonce {
		// The correlation check: a reply to another request - an earlier one
		// that timed out, or one never sent by us - is not this request's
		// answer.
		return
	}
	select {
	case w.ch <- resp:
	default: // the request's channel is full: the first matching frame wins
	}
}

// awaitReply waits on one request's private channel until an accepted response
// is filed or the deadline finds nothing: it is the requester's half of
// asynchronous delivery, because neither shipped transport delivers inside
// Send. nil means "nothing came back", which is the caught-up-or-lost branch
// of the stop rules, never a retry here. Zero or negative ReplyWait means the
// default - a knob that silently waited zero would reinstall the synchronous
// read this deadline exists to replace.
func (s *Syncer) awaitReply(ch <-chan *wire.BlockSyncResp) *wire.BlockSyncResp {
	wait := s.ReplyWait
	if wait <= 0 {
		wait = DefaultReplyWait
	}
	select {
	case got := <-ch:
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
// Each window's request carries a fresh nonce, is registered as the ONE
// request in flight before it is sent, and is answered only by a response from
// the peer it went to whose nonce echoes it. A stale answer for an earlier
// window (a retry after a timeout) is therefore dropped, not consumed.
//
// Four stop rules:
//
//   - a request the transport refuses (peer down, partitioned, unknown)
//     returns the error: the caller owns retry policy;
//   - a unit outside the requested window, one that fails to decode, carries
//     no usable COMMIT CERTIFICATE (missing, malformed, wrong-placed,
//     non-member, or sub-quorum), or a block that fails Append STOPS the pull
//     and is returned as the error - never skipped ahead. Without the
//     certificate the block is a single validator's fork in the making no
//     matter how valid its state is; with a hole, the blocks after it cannot
//     link either; adopting past either would mean trusting the responder's
//     bytes on the responder's say-so;
//   - a response filed while no pull waits is dropped by Receive: it answers
//     no request in flight;
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
		nonce := s.nextNonce()
		req := &wire.BlockSyncReq{From: start, To: end, Nonce: nonce, Requester: s.pub}
		h := syncReqHash(req)
		req.Sig = crypto.Sign(s.priv, h[:])
		// Register the one request in flight BEFORE Send: a transport that
		// delivers on its own goroutine must find the slot already armed, or
		// its answer would be filed as a frame for no request and dropped.
		pending := &pendingReply{nonce: nonce, peer: peer, ch: make(chan *wire.BlockSyncResp, 1)}
		s.reqMu.Lock()
		s.waiting = pending
		s.reqMu.Unlock()
		clear := func() {
			s.reqMu.Lock()
			if s.waiting == pending {
				s.waiting = nil
			}
			s.reqMu.Unlock()
		}
		if err := s.tp.Send(peer, wire.EncodeBlockSyncReq(req)); err != nil {
			clear()
			return err
		}
		// The answer is whatever Receive files on this request's channel
		// while the request is on the wire; awaitReply waits for it up to
		// ReplyWait, because neither shipped transport delivers inside Send.
		// Over sim the node's own Advance delivers; over tcp the
		// connection's reader does.
		got := s.awaitReply(pending.ch)
		clear()
		if got == nil || len(got.Units) == 0 {
			return nil // silence: nothing to adopt, nothing to retry here
		}
		for i, unit := range got.Units {
			blk, err := types.DecodeBlock(unit.Block)
			if err != nil {
				return fmt.Errorf("%w: served block %d of %d does not decode: %v",
					ErrBadSyncResp, i+1, len(got.Units), err)
			}
			// The window gate: a response may only carry blocks the request
			// named. Checked before the certificate, because a block outside
			// the range is refused whatever evidence is attached to it.
			if h := blk.Header.Height; h < start || h > end {
				return fmt.Errorf("%w: served block %d of %d is at height %d, outside the requested window [%d, %d]",
					ErrSyncUnitOutOfRange, i+1, len(got.Units), h, start, end)
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
