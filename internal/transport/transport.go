// Package transport is the network boundary that consensus is allowed to know
// about, and nothing more. The engine never imports a networking type: it calls
// Broadcast, receives through OnMessage, and lists Peers. That boundary is what
// lets the deterministic simulator, the M4 outbound relay and a future libp2p
// stack be swapped without touching consensus code.
package transport

// PeerID identifies a connected peer.
type PeerID string

// Message is one received payload with its sender.
type Message struct {
	From PeerID
	Data []byte
}

// Transport moves opaque bytes between peers.
//
// Implementations MUST NOT deliver synchronously from within Broadcast: the
// sender's callback re-entering the engine mid-send would make the order of
// state transitions depend on the transport's internals. Queue instead.
type Transport interface {
	// Broadcast sends data to every connected peer except the sender.
	//
	// data is read-only: an implementation must not modify it, and must copy
	// it before retaining it beyond the call, so a caller may reuse its
	// buffer as soon as Broadcast returns.
	Broadcast(data []byte) error
	// Send delivers data to exactly one peer.
	//
	// It exists because BLOCK_SYNC is a request/response between exactly two
	// peers, not gossip: broadcasting a sync request would make every
	// validator answer a question only one asked, N-1 of which would discard
	// the answer. Unicast is the M4 ruling on the Transport interface
	// (progress.md, ruling 1). Implementations must deliver to that peer
	// only, and — like Broadcast — must neither block on a slow peer beyond
	// their own queuing bound nor re-enter the caller mid-send.
	//
	// An unknown or disconnected peer is an error, never a silent success:
	// the caller decides what a missing peer means (the syncer retries and
	// may re-pull from another peer), so the transport must not decide for
	// it.
	Send(peer PeerID, data []byte) error
	// OnMessage registers the callback invoked once per received message.
	OnMessage(fn func(Message))
	// Peers lists the currently connected peers.
	//
	// The returned slice MUST be deterministically ordered — same peer set,
	// same order, every call, regardless of insertion or connect order — and
	// implementations should sort by PeerID. Consensus iterates peers by
	// position, so a map-ordered implementation would silently permute state
	// transitions between runs and break replay: a run could no longer be
	// reproduced from its recorded inputs.
	Peers() []PeerID
	// Close releases the transport's resources.
	Close() error
}
