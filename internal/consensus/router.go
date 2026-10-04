package consensus

// The message router for a node whose transport carries BOTH message unions:
// consensus votes and proposals, and the wire's HELLO / BLOCK_SYNC frames.
//
// THE HAZARD THIS EXISTS FOR (Task 4 fix round, progress.md): the consensus
// vote tags and the wire tags share the numeric range 1-3 —
// MsgProposal/MsgPrevote/MsgPrecommit are 1/2/3, and MsgHello/MsgBlockSyncReq/
// MsgBlockSyncResp are ALSO 1/2/3. A router keyed on the first byte alone
// would feed every prevote and precommit (tags 2 and 3) into the sync layer
// and lose the whole consensus stream; the Task-4 rig stalled exactly this
// way before it dispatched by what a frame VERIFIES as. The rule, written
// down: route by verified decode, never by a bare tag comparison.
//
// "Verified" means decode into the full type (every decoder asserts its own
// tag, refuses trailing bytes) AND, for the consensus messages, a verifying
// signature. That makes the classification decisive rather than lucky:
//
//   - an honest committee-signed vote or proposal decodes and verifies in the
//     FIRST branch, so it can never be re-parsed as a same-tagged wire frame;
//   - a wire frame (HELLO etc.) fails the vote/proposal branches (its tag is
//     in range, but its body is not a vote or proposal, or the signature
//     never verifies without a committee key), and reaches its own branch;
//   - an ATTACKER frame can pass at most one branch: each branch's check is
//     a signature over a domain-separated hash the attacker cannot forge, and
//     the one branch without a signature (BLOCK_SYNC response) is safe to
//     misroute INTO, because nothing there reaches the chain except through
//     the pull's certificate gate.
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
type MessageRouter struct {
	Sync      *Syncer
	SendReply func(peer transport.PeerID, frame []byte) error
	OnHello   func(peer transport.PeerID, h *wire.Hello)

	unknown   atomic.Uint64
	hellos    atomic.Uint64
	servedReq atomic.Uint64
	filed     atomic.Uint64
}

// NewMessageRouter builds a router with the given server half. The optional
// callbacks stay nil until the node layer fills them.
func NewMessageRouter(sync *Syncer) *MessageRouter {
	return &MessageRouter{Sync: sync}
}

// Route classifies one received frame and dispatches it.
//
// It returns TRUE when the frame verified as a consensus message: the caller
// drives its own DRIVER with the message (locking is the caller's). It returns
// false for HELLO and BLOCK_SYNC traffic consumed here and for frames that
// decode as nothing (counted, dropped).
func (r *MessageRouter) Route(m transport.Message) bool {
	// Consensus first, verified: an honest committee-signed frame belongs to
	// the engine, and a verified vote/proposal can never ALSO be a valid
	// same-tagged wire frame, because each namespace's signature covers a
	// different domain-separated hash.
	if v, err := DecodeVote(m.Data); err == nil && v.Verify() == nil {
		return true
	}
	if p, err := DecodeProposal(m.Data); err == nil && p.Verify() == nil {
		return true
	}
	if r.Sync != nil {
		// A BLOCK_SYNC request: served out of the local chain, the reply
		// sent back to the one asker through SendReply. Refusal is silence
		// (the wire has no negative response) - Handle's contract.
		if _, err := wire.DecodeBlockSyncReq(m.Data); err == nil {
			r.servedReq.Add(1)
			if frame, ok := r.Sync.Handle(m.Data); ok {
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

// SyncRequestsServed reports how many BLOCK_SYNC requests this node was asked
// to answer: the wire evidence that SOME peer pulled from it (a loss scenario
// reads it to prove catch-up was actually needed, not asserted).
func (r *MessageRouter) SyncRequestsServed() uint64 { return r.servedReq.Load() }

// SyncRepliesFiled reports how many BLOCK_SYNC responses were routed into the
// local syncer's reply slot.
func (r *MessageRouter) SyncRepliesFiled() uint64 { return r.filed.Load() }

// UnknownDropped reports how many frames decoded as nothing. A steady nonzero
// count on a healthy committee means misrouted traffic - the tag hazard
// arriving once more - and is the number to check first when nothing
// finalises.
func (r *MessageRouter) UnknownDropped() uint64 { return r.unknown.Load() }
