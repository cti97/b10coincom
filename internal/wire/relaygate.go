package wire

// The relay access-token gate's two fixed frames, and the minimum token
// length (review, audit fix round 4).
//
// The gate fixes three problems with the original N-8 handshake, all of them
// in the ORDER of the frames rather than in the comparison:
//
//  1. the node sent the token to a relay that had not proved it wanted one. A
//     relay started without --access-token-file skips its token read entirely
//     and forwards whatever arrives as ordinary payload, so a misconfigured,
//     rolled-back or older relay broadcast the operator's secret to every
//     registered peer, strangers included, and neither side noticed;
//  2. nothing distinguished "the relay refused my token" from "the link
//     dropped", so a node with a wrong token redialled forever in silence;
//  3. a token of any length, including one byte, was accepted.
//
// The repair keeps the relay's "parses nothing" posture intact: these are
// FIXED BYTE STRINGS, sent by the relay only to announce that it gates, and
// echoed by it only to announce that the token it read matched. The relay
// still calls no decoder on any frame and still understands nothing about
// consensus. The greeting is a wire-format fact both ends must agree on, so
// it lives here - in the framing package both ends already import - rather
// than being duplicated as a string literal on each side.
//
// The exchange, in frame order:
//
//	relay -> node   RelayGateGreeting   (only when the relay has a token)
//	node  -> relay  <the access token>
//	relay -> node   RelayGateAccepted   (token matched; the node is admitted)
//
// A relay WITHOUT a token sends nothing, so a token-configured node reads the
// greeting, does not get it, refuses to send the secret and logs the refusal
// (tcp.adoptRelay). That is the whole fix for case 1: the secret is never sent
// to a relay that has not announced gating. A relay WITH a token closes the
// socket on a wrong token, so the node's read of RelayGateAccepted fails and
// the node logs that too - case 2. Both frames are the same on every
// connection: nothing here is derived from the token or from any peer, so
// neither frame leaks token bytes or token LENGTH (the node writes the token
// only after the greeting, and the relay's ack is unconditional on match).
var (
	// RelayGateGreeting is the first frame a token-configured relay sends to a
	// connection it has accepted. Its presence is the relay's only claim: "I
	// will ask for a token". It carries no token material.
	RelayGateGreeting = []byte("b10coin-relay-gate-v1")
	// RelayGateAccepted is the frame a relay sends after the presented token
	// matched, and ONLY then. It is how the node tells a refusal from a dead
	// socket instead of redialling in silence.
	RelayGateAccepted = []byte("b10coin-relay-gate-v1-ok")
)

// MinRelayAccessTokenBytes is the shortest access token either end accepts.
//
// The token is the relay's only credential, and its check is one comparison
// per dial, so a short token is brute-forceable at the speed of the network: a
// 1-byte token falls to 256 dials and a 4-byte one to 2^32. Sixteen bytes (128
// bits) is the floor a randomly generated token needs to be out of reach of
// any offline-or-online search, and it is enforced on both ends - the relay
// refuses to start with a shorter token, the node refuses to send one (see
// cmd/b10coin-relay, cmd/b10coin and tcp.Options.RelayAccessToken) - because a
// limit enforced on one side only is a limit an operator can miss.
const MinRelayAccessTokenBytes = 16
