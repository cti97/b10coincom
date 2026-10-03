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
	Broadcast(data []byte) error
	// OnMessage registers the callback invoked once per received message.
	OnMessage(fn func(Message))
	// Peers lists the currently connected peers.
	Peers() []PeerID
	// Close releases the transport's resources.
	Close() error
}
