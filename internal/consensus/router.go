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
	"sync/atomic"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

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
	// refused counts consensus-tagged frames this router refused before any
	// signature verification: a non-member's key, or a vote whose height the
	// live engine cannot judge. A steady nonzero count on a healthy committee
	// means a peer is sending frames for a chain this node is not on (or a
	// stranger reached the port); zero is the healthy value.
	refused atomic.Uint64
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

// committee returns the validator set membership is checked against.
// Committee, when set explicitly, wins; otherwise it is the syncer's chain's
// genesis committee. The returned slice is never mutated here.
func (r *MessageRouter) committee() []genesis.Validator {
	if r.Committee != nil {
		return r.Committee
	}
	if r.Sync != nil && r.Sync.chain != nil {
		return r.Sync.chain.Genesis().Validators
	}
	return nil
}

// isMember reports whether pub is a committee key, and whether a committee is
// known at all. known=false (no syncer chain and no explicit Committee) means
// the caller must fall back to the signature check alone: the unit-test shape,
// never a node built through NewMessageRouter.
func (r *MessageRouter) isMember(pub []byte) (member, known bool) {
	vals := r.committee()
	if len(vals) == 0 {
		return false, false
	}
	for i := range vals {
		if string(vals[i].PubKey) == string(pub) {
			return true, true
		}
	}
	return false, true
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
	// Consensus first. The two unions are tag-disjoint (audit N-5), so a wire
	// frame fails these branches on its first byte. Within them the ORDER is
	// the audit C-8 fix: the two free checks - is the carried key a committee
	// member, and can the live engine still judge this height - run BEFORE the
	// Ed25519 evaluation. A self-signed frame from a stranger passes Verify by
	// construction (its own key signs it), so verification alone never gates
	// membership; and a vote for a height the engine has already left or has
	// not reached is dead weight whatever its signature says.
	//
	// Dedup is consulted AFTER Verify, never before (audit N-7): a frame that
	// fails Verify must not record a key, or a stranger could poison the key
	// of an honest vote it cannot sign and silence it.
	if v, err := DecodeVote(m.Data); err == nil {
		if member, known := r.isMember(v.Validator); known && !member {
			r.refused.Add(1)
			return false
		}
		if ok, known := r.voteHeightInWindow(v.Height); known && !ok {
			r.refused.Add(1)
			return false
		}
		if v.Verify() == nil {
			if r.Dedup != nil && r.Dedup.Seen(voteDedupKey(v)) {
				r.dups.Add(1)
				return false
			}
			return true
		}
	}
	if p, err := DecodeProposal(m.Data); err == nil {
		// The proposer key is inside the proposal, after the block, so the
		// decode is unavoidable; the membership check still runs before the
		// signature, which is the expensive part of judging the decoded frame
		// (audit C-8). A non-member's proposal costs one decode, never a
		// verification, and never reaches the engine.
		if member, known := r.isMember(p.Validator); known && !member {
			r.refused.Add(1)
			return false
		}
		if p.Verify() == nil {
			if r.Dedup != nil && r.Dedup.Seen(proposalDedupKey(p)) {
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

// DuplicatesDropped reports how many VERIFIED consensus messages were refused
// because their dedup key had already been recorded. Zero is healthy in the
// star topology (no loops); a nonzero count means a message arrived twice, as
// a mesh would produce.
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
