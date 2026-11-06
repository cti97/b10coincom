package consensus

// The message router for a node whose transport carries BOTH message unions:
// consensus votes and proposals, and the wire's HELLO / BLOCK_SYNC frames.
//
// THE TAG HISTORY THIS EXISTS FOR (Task 4 fix round, progress.md): before
// audit N-5, the consensus vote tags and the wire tags shared the numeric
// range 1-3 — MsgProposal/MsgPrevote/MsgPrecommit were 1/2/3, and
// MsgHello/MsgBlockSyncReq/MsgBlockSyncResp were ALSO 1/2/3. A router keyed
// on the first byte alone would feed every prevote and precommit (tags 2 and
// 3) into the sync layer and lose the whole consensus stream; the Task-4 rig
// stalled exactly this way before it dispatched by what a frame VERIFIES as.
// The rule, written down then and kept: route by verified decode, never by a
// bare tag comparison.
//
// Audit N-5 then renumbered the wire tags into a disjoint range
// (wire.WireTagFloor = 0x80 upward), so the two unions can no longer collide
// by construction. The verified-decode discipline stays anyway: a tag is a
// claim about bytes, and the only thing that decides what a frame IS remains
// a full decode plus, for the consensus messages, a verifying signature. What
// the renumbering bought is that a wire frame now fails the consensus
// branches on its FIRST byte (0x80+ is not a vote or proposal tag), so a
// HELLO or a 1 MiB BLOCK_SYNC frame no longer costs a wasted vote-and-
// proposal decode on every reader.
//
// "Verified" means decode into the full type (every decoder asserts its own
// tag, refuses trailing bytes) AND, for the consensus messages, a verifying
// signature. That makes the classification decisive rather than lucky:
//
//   - an honest committee-signed vote or proposal decodes and verifies in the
//     FIRST branch, so it can never be re-parsed as a same-tagged wire frame;
//   - a wire frame (HELLO etc.) fails the vote/proposal branches (its tag is
//     disjoint from both), and reaches its own branch;
//   - a frame with a consensus tag that is NOT from the committee is refused
//     by the membership check BEFORE any signature work, and a vote whose
//     height is outside the window the live engine can judge is refused by
//     the height check, also before verification. The one branch without a
//     signature (BLOCK_SYNC response) is safe to misroute INTO, because
//     nothing there reaches the chain except through the pull's certificate
//     gate.
//
// An earlier version of this comment claimed an attacker frame "cannot pass"
// the consensus branches because it cannot forge a signature. That was wrong,
// and audit C-8 records why: a signature is not a secret, so a stranger can
// self-sign a perfectly valid vote with its OWN key and pass Verify. The
// signature check proves the frame is internally consistent, never that its
// signer belongs to this chain. Membership is what the signature cannot
// prove, so it is checked first - both here and, in the same order, in
// VoteSet.Add and the engine's proposal path - and the engine remains the
// final gate for anything the router lets through.
//
// The struct deliberately holds no engine and takes no locks on the consensus
// branch: the CALLER serialises its driver (a socket transport's readers are
// concurrent with the node's own tick loop, and exactly the caller knows the
// locking shape). Route returns true for consensus frames — "the engine must
// see this" — and false for everything it consumed itself.
//
// A frame that decodes as nothing is counted (Unknown()) and dropped: silence
// for garbage is the protocol-error posture everywhere else in this package.

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

// The proposal envelope's fixed prefix (audit S-5), and why reading it before
// decoding the block is safe rather than a guessed offset.
//
// EncodeProposal writes, in order: the one-byte message tag, Height as a
// fixed-width 8-byte big-endian uint64, Round as 4 fixed bytes, and only THEN
// the length-prefixed block. Nothing before Height is variable-width, and the
// transport hands Route the frame's PAYLOAD with its wire length prefix already
// stripped (wire.ReadFrame), so Height sits at a constant offset from the front
// of Message.Data for every proposal that can decode at all.
//
// The peek is therefore exact, not heuristic: for any frame DecodeProposal
// accepts, big-endian data[1:9] IS p.Height, because DecodeProposal reads those
// same nine bytes in the same order.
// TestProposalHeightPeekAgreesWithTheDecodedEnvelope pins the agreement across
// heights, rounds and block sizes, so a future change to the envelope's field
// order fails loudly there instead of silently rejecting honest proposals.
const (
	proposalHeightOffset = 1
	proposalHeightBytes  = 8
	proposalPrefixBytes  = proposalHeightOffset + proposalHeightBytes
)

// peekProposalHeight reads a proposal envelope's Height WITHOUT decoding the
// block, and reports whether data has the shape that makes the read valid: the
// proposal tag and at least the fixed prefix. ok=false means "not a proposal,
// or too short to hold one", and the caller must fall through to the decoders,
// which name the malformed field themselves.
func peekProposalHeight(data []byte) (height uint64, ok bool) {
	if len(data) < proposalPrefixBytes || MsgType(data[0]) != MsgProposal {
		return 0, false
	}
	return binary.BigEndian.Uint64(data[proposalHeightOffset:proposalPrefixBytes]), true
}

// MessageRouter dispatches one transport message by what it verifies as.
//
// Sync must be set for a node that serves and pulls blocks; a nil Sync means
// the node carries no catch-up at all and every BLOCK_SYNC frame is counted
// and dropped. SendReply is the unicast that returns a response to the asker
// (the transport's Send); a nil SendReply drops the reply like an unsent
// frame — the pull reads silence either way. OnHello observes a peer's
// height announcement; nil means hello frames are merely counted with the
// unknown frames.
//
// AsyncServe, when non-nil, receives a decoded BLOCK_SYNC request INSTEAD of
// the router serving it inline (audit C-4). Serving a request costs up to a
// window of disk reads and quorum-many Ed25519 verifies per height; run on the
// transport's dispatch goroutine it holds the dispatch lock and stalls every
// consensus frame behind it — especially on a relay star, where one connection
// carries the whole committee. The node layer installs a bounded worker pool
// here. A nil AsyncServe keeps the inline path the deterministic in-process
// simulator depends on.
type MessageRouter struct {
	Sync       *Syncer
	SendReply  func(peer transport.PeerID, frame []byte) error
	OnHello    func(peer transport.PeerID, h *wire.Hello)
	AsyncServe func(m transport.Message)
	// OnPeerExchange, when non-nil, observes a decoded PEER_EXCHANGE frame:
	// a list of listening addresses the sender claims it (or a peer it knows)
	// can be reached at. It is a HINT, never a peer. The callback is where the
	// node layer applies the dial policy - parse as IP:port, refuse the node's
	// own address, the reserved relay:<addr> name and local addresses from a
	// hint, deduplicate, and call transport.AddPeer (never a raw dial) - and it
	// runs on the transport's dispatch goroutine, so it must not block.
	//
	// The frame IS signed (audit PX-1): the sender signs (chain id, height,
	// address list) with its validator key, and the authority is that signature
	// plus a seat at the advertised height - NOT the connection it arrived on,
	// because on a relay every member and every stranger shares one connection.
	// The node layer verifies both (devnet's observePeerExchange through
	// hintAuthority) before it dials anything; a stranger's frame, however it
	// arrived, is refused. Nothing here may treat the addresses as evidence
	// about the chain. Nil means such frames are counted and dropped.
	OnPeerExchange func(peer transport.PeerID, p *wire.PeerExchange)
	// Committee, when non-nil, is the validator set whose keys may carry a
	// consensus frame. A vote or proposal whose key is absent from it is
	// refused BEFORE any Ed25519 verification (audit C-8): the key set check
	// is a free linear scan, the signature is not, and a self-signed frame
	// from a stranger is valid cryptography from an invalid signer. Nil means
	// "derive from Sync's chain"; a router with neither has no membership
	// source, which is the unit-test-only shape - NewMessageRouter, the way
	// every node builds a router, always has one.
	Committee []genesis.Validator
	// Dedup, when non-nil, is the seen-set for verified consensus messages
	// (audit N-7). It is consulted STRICTLY AFTER Verify, inside the branch
	// that already decoded and verified the frame: a key is recorded only for
	// a message whose signature checked out, so a stranger cannot pre-seed an
	// honest vote's (validator, height, round, type) key with a forged frame
	// and have the honest vote dropped. The set is height-sharded and
	// bounded, so a node that never calls Forget still cannot grow it without
	// limit.
	Dedup *transport.Dedup

	unknown   atomic.Uint64
	hellos    atomic.Uint64
	servedReq atomic.Uint64
	filed     atomic.Uint64
	dups      atomic.Uint64
	// peerExchanges counts PEER_EXCHANGE frames routed. It is an observable
	// only: the message moves no consensus state, so the healthy number says
	// how the mesh is forming, never whether the chain is advancing.
	peerExchanges atomic.Uint64
	// refused counts consensus-tagged frames this router refused before any
	// signature verification: a non-member's key, a vote whose height the live
	// engine cannot judge, or (audit S-5) a proposal whose PEEKED height is
	// outside that same window. A steady nonzero count on a healthy committee
	// means a peer is sending frames for a chain this node is not on (or a
	// stranger reached the port); zero is the healthy value.
	refused atomic.Uint64
	// verified counts successful signature verifications - the work a relay
	// link's replay flood used to buy once per frame (audit PX-4). It is an
	// observable, not a signal: it exists so "a replayed vote costs one lookup,
	// not one Ed25519" can be asserted as a number instead of inferred.
	verified atomic.Uint64
}

// NewMessageRouter builds a router with the given server half. The optional
// callbacks stay nil until the node layer fills them.
//
// The router derives its committee key set from the syncer's chain, so the
// membership gate of audit C-8 is wired by construction: every node builds
// its router through here with a live syncer, and there is no field a caller
// must remember to fill before the gate exists. Deriving it per frame (rather
// than caching a snapshot here) also keeps it correct across a simnet
// reseat, which swaps Sync to a reopened chain.
func NewMessageRouter(sync *Syncer) *MessageRouter {
	return &MessageRouter{Sync: sync}
}

// isMemberAt reports whether pub is a committee key at height h, and whether a
// committee is known at all. known=false (no syncer chain and no explicit
// Committee) means the caller must fall back to the signature check alone: the
// unit-test shape, never a node built through NewMessageRouter.
//
// On the chain path this asks Chain.IsSeatedAt, NOT Chain.CommitteeAt: every
// vote and every proposal runs this check before its signature is verified, and
// CommitteeAt's defensive deep copy (a slice plus one allocation per seat, up
// to 255) was paid per frame for an answer that is a boolean (audit RT-6). The
// set tested is the same memoised epoch committee; only the copy is gone.
func (r *MessageRouter) isMemberAt(pub []byte, h uint64) (member, known bool) {
	if r.Committee != nil {
		for i := range r.Committee {
			if string(r.Committee[i].PubKey) == string(pub) {
				return true, true
			}
		}
		return false, true
	}
	if r.Sync != nil && r.Sync.chain != nil {
		return r.Sync.chain.IsSeatedAt(h, pub), true
	}
	return false, false
}

// voteHeightInWindow reports whether a vote at height could still be judged by
// the live engine, and whether a local head height is known. The engine always
// voteHeightInWindow reports whether a vote at height could still be acted on
// locally, and whether a local head height is known. The live engine judges
// exactly head+1, and head is the height it has just committed - a quorum vote
// for head can be the very frame that completed that commit, and an
// equivocator's conflicting twin arrives right behind it, so both heights are
// frames of a round the node is still acting on. Anything older is history the
// chain already holds; anything further ahead cannot be judged until this node
// catches up (the engine would drop it anyway). The window is therefore two
// heights wide, not unbounded. known=false (no syncer chain) disables it.
func (r *MessageRouter) voteHeightInWindow(height uint64) (ok, known bool) {
	if r.Sync == nil || r.Sync.chain == nil {
		return true, false
	}
	head := r.Sync.chain.Height()
	return height == head || height == head+1, true
}

// proposalHeightInWindow reports whether a proposal at height could still be
// acted on by the live engine, and whether a local head height is known.
//
// It is DELIBERATELY the vote window, not a separate one. The driver builds its
// engine for chain head + 1 (Driver.newEngine judges that height), so the height
// an honest proposer proposes at is exactly head+1; head is the height this node
// has just committed, and a proposal for it is stale - the engine returns nil
// without touching state - but it is not a frame to silently refuse, since votes
// at head are still tallied into the commit that finishes it. Nothing ABOVE
// head+1 can be acted on: the engine drops any p.Height != its own, and unlike a
// future ROUND at the same height (bufferProposal) there is no future-height
// buffering anywhere.
//
// So this filter cannot reject a proposal the engine would otherwise ACCEPT: it
// contains the engine's own height by construction (engine height == head+1), and
// every height it drops is one the engine answers with a nil return and no state
// change. TestAnHonestProposalAtTheLiveHeightIsStillPrevoted pins the acceptance
// half end to end; TestTheProposalHeightWindowContainsTheEngineHeight pins the
// containment.
//
// THE ONE TRANSIENT, stated rather than hidden: after a catch-up pull adopts
// blocks, the chain head moves before rebuildDriver replaces the engine
// (devnet.tcpnode's documented handoff), so for that instant the engine judges a
// height the window no longer contains. A proposal there is dropped by this gate
// where it used to reach the stale engine - and the stale engine could only
// prevote a height the chain has ALREADY decided, whose Append fails and whose
// round state the rebuild discards. A pull that adopts exactly one block leaves
// the stale engine's height equal to the new head, which IS inside the window, so
// the ordinary one-behind case is unchanged.
func (r *MessageRouter) proposalHeightInWindow(height uint64) (ok, known bool) {
	return r.voteHeightInWindow(height)
}

// voteDedupKey is the dedup key a decoded vote records.
func voteDedupKey(v *Vote) transport.VoteKey {
	return transport.VoteKey{
		Validator: string(v.Validator),
		Height:    v.Height,
		Round:     v.Round,
		Type:      uint8(v.Type),
	}
}

// proposalDedupKey is the dedup key a decoded proposal records. Proposals
// share the seen-set with votes but never collide with them: their Type is
// MsgProposal (1), which no vote carries (votes are prevote/precommit).
func proposalDedupKey(p *Proposal) transport.VoteKey {
	return transport.VoteKey{
		Validator: string(p.Validator),
		Height:    p.Height,
		Round:     p.Round,
		Type:      uint8(MsgProposal),
	}
}

// Route classifies one received frame and dispatches it.
//
// It returns TRUE when the frame verified as a consensus message: the caller
// drives its own DRIVER with the message (locking is the caller's). It returns
// false for HELLO and BLOCK_SYNC traffic consumed here and for frames that
// decode as nothing (counted, dropped).
func (r *MessageRouter) Route(m transport.Message) bool {
	// READ A PROPOSAL'S HEIGHT BEFORE DECODING ITS BLOCK (audit S-5). The
	// proposal branch below used to decode a whole block - up to the frame bound
	// - before ANY height or membership check, because the proposer key is the
	// envelope's LAST field and only a decoded envelope names it. One dispatch
	// mutex serialises every reader (TcpTransport.dispatch holds dispatchMu
	// across every OnMessage), so each decode stalled every consensus frame
	// behind it, and a peer could force one per frame at distinct (height, round)
	// pairs: dedup cannot help, because its key needs the validator identity the
	// decode yields.
	//
	// The height needs none of that: it sits in the fixed prefix
	// (proposalHeightOffset), so the two-height window the vote branch already
	// uses can be applied first and a foreign-height proposal dropped without
	// touching its block. That is what makes this cheap and this is why it runs
	// FIRST: a refused frame costs one compare and zero allocations.
	//
	// This is a REJECTION filter, never a classification - the discipline
	// DecodeVote exists to keep. The byte it keys on is the proposal tag (1),
	// which DecodeProposal itself demands and which NO other branch accepts:
	// votes are 2/3, wire frames are >= 0x80. So it can only ever drop frames
	// the proposal branch would have handled, and proposalHeightInWindow drops
	// only heights the live engine answers with a nil return and no state change.
	//
	// One observable changes: a frame that both fails to decode AND names a
	// foreign height now lands in RefusedBeforeVerify instead of UnknownDropped.
	// The bytes are dropped either way; both counters are diagnostics, never
	// decisions.
	if h, ok := peekProposalHeight(m.Data); ok {
		if inWindow, known := r.proposalHeightInWindow(h); known && !inWindow {
			r.refused.Add(1)
			return false
		}
	}
	// Consensus first. The two unions are tag-disjoint (audit N-5), so a wire
	// frame fails these branches on its first byte. Within them the ORDER is
	// the audit C-8 fix: the two free checks - is the carried key a committee
	// member, and can the live engine still judge this height - run BEFORE the
	// Ed25519 evaluation. A self-signed frame from a stranger passes Verify by
	// construction (its own key signs it), so verification alone never gates
	// membership; and a vote for a height the engine has already left or has
	// not reached is dead weight whatever its signature says.
	//
	// Dedup has TWO calls and their placement is the whole of audit PX-4:
	//
	//   - Has runs FIRST, before Verify and before the free membership checks.
	//     It RECORDS NOTHING, so it cannot poison anything, and it is the cheap
	//     map lookup that turns a genuine, already-seen member vote replayed at
	//     line rate over the relay link - one Ed25519 verification per replay
	//     before this - into one lookup and a drop. Measured by
	//     TestAReplayedVoteCostsNoSecondVerification.
	//   - Seen runs ONLY after Verify succeeded, and it is the only call that
	//     records. That is audit N-7's no-poisoning property, unchanged: a frame
	//     that fails Verify must not record a key, or a stranger could pre-seed
	//     the key of an honest vote it cannot sign and silence it. Has-before
	//     does not weaken it, because Has does not write; the test that fires
	//     a forged frame carrying the honest key and then the honest vote pins
	//     both halves.
	//
	// The window between Has and Seen is not a race in production: the transport
	// serialises every reader's Route under one dispatch mutex, and the node's
	// own tick loop never calls Route concurrently with itself. If that ever
	// changed, the worst case is two verifications of the same frame, never a
	// lost honest message.
	if v, err := DecodeVote(m.Data); err == nil {
		key := voteDedupKey(v)
		if r.Dedup != nil && r.Dedup.Has(key) {
			r.dups.Add(1)
			return false
		}
		if member, known := r.isMemberAt(v.Validator, v.Height); known && !member {
			r.refused.Add(1)
			return false
		}
		if ok, known := r.voteHeightInWindow(v.Height); known && !ok {
			r.refused.Add(1)
			return false
		}
		if v.Verify() == nil {
			r.verified.Add(1)
			if r.Dedup != nil && r.Dedup.Seen(key) {
				// Records ONLY now (the no-poisoning rule) AND keeps its return:
				// the Has above is the fast path, this is the second line for the
				// Has/Seen window, and it is what a caller that skips Has still
				// gets. Deleting Has must not turn dedup into a no-op.
				r.dups.Add(1)
				return false
			}
			return true
		}
	}
	if p, err := DecodeProposal(m.Data); err == nil {
		// The proposer key is inside the proposal, after the block, so a decode
		// is still unavoidable to check MEMBERSHIP; the membership check still
		// runs before the signature, which is the expensive part of judging the
		// decoded frame (audit C-8). A non-member's proposal costs one decode,
		// never a verification, and never reaches the engine. The height gate
		// at the top of Route is what stops a foreign-height block from costing
		// that decode at all (audit S-5).
		if member, known := r.isMemberAt(p.Validator, p.Height); known && !member {
			r.refused.Add(1)
			return false
		}
		// The same Has-before / record-after split as the vote branch (audit
		// PX-4), for the same reason: a replayed proposal is one map lookup.
		key := proposalDedupKey(p)
		if r.Dedup != nil && r.Dedup.Has(key) {
			r.dups.Add(1)
			return false
		}
		if p.Verify() == nil {
			r.verified.Add(1)
			if r.Dedup != nil && r.Dedup.Seen(key) {
				r.dups.Add(1)
				return false
			}
			return true
		}
	}
	if r.Sync != nil {
		// A BLOCK_SYNC request: served out of the local chain, the reply
		// sent back to the one asker through SendReply. Refusal is silence
		// (the wire has no negative response) - Handle's contract. With
		// AsyncServe installed the serving happens on the node's worker, off
		// this dispatch goroutine (audit C-4): the router hands the frame
		// over and returns, so a slow Answer cannot hold the transport's
		// dispatch lock.
		if _, err := wire.DecodeBlockSyncReq(m.Data); err == nil {
			if r.AsyncServe != nil {
				// Handed to the bounded worker pool; the request is SERVED
				// (and counted) there, off this dispatch goroutine (audit
				// C-4). Counting it here would over-report: a request shed by
				// a full queue was never served (round 7, F4).
				r.AsyncServe(m)
				return false
			}
			if frame, ok := r.Sync.Handle(m.Data); ok {
				r.servedReq.Add(1) // SERVED, not queued: Handle returned an answer (round 7, F4)
				if r.SendReply != nil {
					_ = r.SendReply(m.From, frame) // a lost reply is the pull's retry, not an error here
				}
			}
			return false
		}
		// A BLOCK_SYNC response: filed for the pull in flight.
		if _, err := wire.DecodeBlockSyncResp(m.Data); err == nil {
			r.Sync.Receive(m.From, m.Data)
			r.filed.Add(1)
			return false
		}
	}
	if h, err := wire.DecodeHello(m.Data); err == nil {
		r.hellos.Add(1)
		if r.OnHello != nil {
			r.OnHello(m.From, h)
		}
		return false
	}
	// PEER_EXCHANGE: a list of listening addresses, consumed by the node
	// layer's dial policy. It is NOT a consensus message and is deliberately
	// not deduplicated: recording an address frame in the seen-set would let
	// repeated advertisements evict real vote keys under the bucket ceiling,
	// and there is no engine state it could double-apply (audit N-7's ordering
	// is about verified votes and proposals, which this branch is disjoint
	// from). A frame that decodes as nothing still reaches the unknown counter
	// below, so silence stays the posture for garbage.
	if p, err := wire.DecodePeerExchange(m.Data); err == nil {
		r.peerExchanges.Add(1)
		if r.OnPeerExchange != nil {
			r.OnPeerExchange(m.From, p)
		}
		return false
	}
	r.unknown.Add(1)
	return false
}

// HellosSeen reports how many HELLO frames were routed; an observable for
// node-level wiring tests.
func (r *MessageRouter) HellosSeen() uint64 { return r.hellos.Load() }

// SyncRequestsServed reports how many BLOCK_SYNC requests this node actually
// ANSWERED: the wire evidence that SOME peer pulled from it (a loss scenario
// reads it to prove catch-up was actually needed, not asserted). A request
// handed to the async server is counted by the server once Handle returns an
// answer, never at handoff, so a shed request is not counted (round 7, F4).
func (r *MessageRouter) SyncRequestsServed() uint64 { return r.servedReq.Load() }

// NoteServed records that one BLOCK_SYNC request was answered. The inline path
// calls it itself; a node with AsyncServe installed calls it from the worker
// that ran Handle, so the counter means served rather than queued.
func (r *MessageRouter) NoteServed() { r.servedReq.Add(1) }

// SyncRepliesFiled reports how many BLOCK_SYNC responses were routed into the
// local syncer's reply slot.
func (r *MessageRouter) SyncRepliesFiled() uint64 { return r.filed.Load() }

// PeerExchangesSeen reports how many PEER_EXCHANGE frames were routed. The
// message carries no consensus meaning, so this is a mesh-formation observable
// and never a liveness signal: a zero count on a mesh run means the nodes are
// not advertising, not that consensus is broken.
func (r *MessageRouter) PeerExchangesSeen() uint64 { return r.peerExchanges.Load() }

// DuplicatesDropped reports how many VERIFIED consensus messages were refused
// because their dedup key had already been recorded. Zero is healthy in the
// star topology (no loops); a nonzero count means a message arrived twice, as
// a mesh would produce.
// SignatureVerifications reports how many consensus frames this router verified
// successfully (audit PX-4). A replayed, already-seen vote must not move it.
func (r *MessageRouter) SignatureVerifications() uint64 { return r.verified.Load() }

func (r *MessageRouter) DuplicatesDropped() uint64 { return r.dups.Load() }

// UnknownDropped reports how many frames decoded as nothing. A steady nonzero
// count on a healthy committee means a peer is speaking a language this node
// does not (an old tag scheme, or garbage) and is the number to check first
// when nothing finalises.
func (r *MessageRouter) UnknownDropped() uint64 { return r.unknown.Load() }

// RefusedBeforeVerify reports how many consensus-tagged frames were refused
// before any signature verification: a key outside the committee, or a vote
// for a height the live engine cannot judge (audit C-8). It is the observable
// that the reorder is actually running - a router with a committee and a
// syncer must count a self-signed stranger's vote here, and the Ed25519
// evaluation count must stay flat for it.
func (r *MessageRouter) RefusedBeforeVerify() uint64 { return r.refused.Load() }
