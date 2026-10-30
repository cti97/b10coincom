package wire

import (
	"crypto/hmac"
	"crypto/sha256"
)

// The relay access-token gate (review, audit fix round 4; challenge-response,
// audit PX-3).
//
// The gate exists because a relay is a dumb forwarder that every validator
// trusts with no cryptographic relationship. The first version sent the token
// as the FIRST frame; the second waited for a fixed greeting. Both shared one
// defect the audit called PX-3: the token is a PUBLIC-CONSTANT-triggered
// secret. The greeting is a constant any stranger behind a token-less relay
// can make that relay forward into a token-configured node's handshake, so one
// registered stranger could make the node send the token and the relay would
// forward it to everyone.
//
// The exchange is now a challenge-response, still with no decoder on either
// side:
//
//	relay -> node   RelayGateGreeting                        (only with a token)
//	relay -> node   RelayGateNonceBytes random bytes ‖ the relay's own
//	                address bytes                           (the challenge)
//	node  -> relay  RelayGateProof(token, challenge)         (HMAC-SHA-256)
//	relay -> node   RelayGateAccepted                        (proof matched)
//
// Everything here is FIXED-WIDTH or self-delimiting by construction, and the
// relay never interprets a node's frame: it writes a constant, writes 32
// random bytes it generated plus its own address, reads at most
// RelayGateMACBytes and compares them in constant time. Its "parses nothing"
// posture (pinned structurally by TestTheRelayCallsNoDecoder) is intact.
//
// What the challenge buys:
//
//   - The secret is never on the wire. A token-less relay that forwards the
//     node's answer to every peer forwards a MAC, not the token.
//   - A captured exchange is not replayable. The challenge contains 32 fresh
//     random bytes and the relay's own listening address, so the relay's MAC
//     for one connection is wrong for every other connection, and for every
//     later connection to the same relay.
//   - A stranger can still make a node answer with a MAC for a challenge the
//     stranger chose (by looping the greeting through a token-less relay).
//     That is a chosen-message oracle on HMAC-SHA-256 with a key of at least
//     MinRelayAccessTokenBytes, not a disclosure: it yields no token bytes and
//     no usable proof for any challenge the stranger did not choose.
//
// A relay WITHOUT a token sends nothing, so a token-configured node reads the
// greeting, does not get it, refuses to answer and logs the refusal
// (tcp.adoptRelay). A relay WITH a token closes the socket on a wrong proof, so
// the node's read of RelayGateAccepted fails and the node logs that too.
var (
	// RelayGateGreeting is the first frame a token-configured relay sends to a
	// connection it has accepted. Its presence is the relay's only claim: "I
	// will ask for a proof". It carries no token material and no nonce.
	RelayGateGreeting = []byte("b10coin-relay-gate-v1")
	// RelayGateAccepted is the frame a relay sends after the proof matched,
	// and ONLY then. It is how the node tells a refusal from a dead socket
	// instead of redialling in silence.
	RelayGateAccepted = []byte("b10coin-relay-gate-v1-ok")
)

// RelayGateProof is the answer to a gate challenge: HMAC-SHA-256 keyed by the
// access token, over the challenge bytes EXACTLY as the relay sent them
// (nonce ‖ the relay's address). Both ends already import this package, so the
// one primitive lives here rather than being written twice; nothing about it
// is a decode - it hashes bytes it is handed.
//
// The relay verifies the answer with hmac.Equal, which is constant-time, and
// the node never sends the token itself, so a relay that forwards the answer
// forwards no secret (audit PX-3).
func RelayGateProof(token, challenge []byte) []byte {
	m := hmac.New(sha256.New, token)
	m.Write(challenge)
	return m.Sum(nil)
}

const (
	// RelayGateNonceBytes is the fixed width of the random part of the
	// challenge. 32 bytes is the HMAC-SHA-256 block-friendly size and far
	// beyond birthday collisions on a per-connection value.
	RelayGateNonceBytes = 32
	// RelayGateMACBytes is the fixed width of the answer: one HMAC-SHA-256
	// output. The relay reads at most this many bytes, so the read is bounded
	// before allocation whatever the sender declares.
	RelayGateMACBytes = 32
	// MaxRelayGateChallengeBytes bounds the challenge frame: the fixed nonce
	// plus the relay's own listening address. The address is a string this
	// side does not interpret beyond its length (the relay never parses the
	// node's frame, and the node only needs the same bytes the relay hashed),
	// so the bound is generous rather than semantic.
	MaxRelayGateChallengeBytes = RelayGateNonceBytes + 256
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
