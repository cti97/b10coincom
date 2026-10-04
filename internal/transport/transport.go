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
