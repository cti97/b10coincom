package wire

// PEER_EXCHANGE advertises LISTENING ADDRESSES and nothing else. It is the
// message that turns M4's relay star into a mesh: two validators that know
// only the relay can each say "here is where I accept direct connections",
// and each dials the other through the transport's ordinary maintainer.
//
// # What it is not
//
// The message carries no vote and no chain state (design decision 5). A peer
// that receives it learns a HINT TO DIAL and nothing about the chain. The only
// admission path is still the signed committee HELLO checked by the node's
// Admit policy: a learned address that never completes that handshake stays a
// socket the node dialled, never a committee peer, and nothing it sends
// reaches the engine.
//
// # The frame IS signed (audit PX-1)
//
// This message used to carry a bare address list and take its authority from
// the CONNECTION it arrived on. That was false on the relay, which cannot
// authenticate anybody by design: every member's frames arrive under the one
// relay:<addr> name, so any relay sender - including a stranger on a token-less
// relay - was a hint authority, and one frame made every validator dial up to
// eight attacker-chosen addresses. The authority now travels IN the frame: the
// advertising member's Ed25519 key, the chain height it is advertising at, the
// address list, and a signature over all three (domain-separated, chain-bound;
// the node layer owns the signing hash, exactly as it owns the HELLO's). The
// receiver requires the key to hold a seat at that height before it acts, so a
// hint is one committee member's opinion about where it can be reached - which
// is what the message was always meant to be.
//
// Signing does not put addresses into the consensus signature domain: this is
// a peer-discovery message whose signature proves WHO is advertising, never
// that anything about the chain is true. A relay still forwards it without
// understanding a byte of it.
//
// # Canonical form
//
//	tag(1) | height(8) | len key | key | count(minimal LEB128) |
//	count x (len(minimal LEB128) | addr bytes) | len sig | sig
//
// The count is bounded BEFORE a slice is grown (the audit N-12 discipline the
// HELLO and BLOCK_SYNC decoders already apply), and each address is bounded
// before its copy. Both bounds are protocol constants, not policy: the node
// layer decides which addresses are acceptable, but no frame may present
// more than MaxPeerExchangeAddrs of them or an address longer than
// MaxListenAddrBytes. The key and signature have exactly one legal width each
// and are checked before either is copied.

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/types"
)

// MsgPeerExchange is the listening-address advertisement's tag, declared with
// the rest of the wire union in message.go. It sits above WireTagFloor, so it
// fails every consensus decoder on its first byte (audit N-5), and it is the
// next free tag after the BLOCK_SYNC pair.

const (
	// MaxPeerExchangeAddrs bounds how many addresses one frame may carry. A
	// node needs one (its own listener); eight leaves room to aggregate a
	// small set without turning a single frame into a dial amplifier. The
	// decoder refuses a larger count before it allocates the slice, so a
	// hostile count costs one comparison, not a make().
	MaxPeerExchangeAddrs = 8
	// MaxListenAddrBytes bounds one advertised address before its copy. A
	// host:port is at most a bracketed IPv6 literal (45 + brackets) plus a
	// five-digit port; 255 is far above that and far below the frame bound,
	// so a hostile length cannot make the decoder copy a frame-sized
	// "address" it will then discard.
	MaxListenAddrBytes = 255
)

// Errors returned by DecodePeerExchange. They are distinct because a caller
// that counts refusals cares which bound bit: an over-long list is an
// amplification attempt, an empty one is a bug in the sender, and an empty
// entry is neither. The two envelope errors are the signed frame's own: a key
// or signature of the wrong width cannot have been produced by this protocol.
var (
	ErrEmptyPeerExchange     = errors.New("wire: peer exchange advertises no addresses")
	ErrTooManyPeerExchange   = errors.New("wire: peer exchange advertises more addresses than the bound")
	ErrEmptyPeerExchangeAddr = errors.New("wire: peer exchange carries an empty listening address")
	ErrBadPeerExchangeKey    = errors.New("wire: peer exchange carries a validator key of the wrong width")
	ErrBadPeerExchangeSig    = errors.New("wire: peer exchange carries a signature of the wrong width")
)

// PeerExchange is a SIGNED list of listening addresses ("host:port"), each a
// hint to dial, advertised by one committee member at one chain height.
//
// Validator is the advertising member's Ed25519 public key, Height the chain
// height it advertised at, and Sig the signature over the domain-separated
// hash of (chain id, Height, Addrs) - the node layer computes and checks that
// hash, because it is the layer that knows the chain id and the committee.
// The wire layer frames the fields; it does not parse the address strings,
// because only the receiving node knows its own address, its own policy and
// whether a hint is acceptable at all.
type PeerExchange struct {
	Height    uint64
	Validator []byte
	Addrs     []string
	Sig       []byte
}

// EncodePeerExchange renders p canonically:
//
//	tag(1) | height(8) | key | count | count x (len addr | addr) | sig
//
// The encoder renders what it is given. It does NOT enforce MaxPeerExchangeAddrs,
// MaxListenAddrBytes or the key/signature widths: silently truncating a caller's
// list would hide a bug the receiver is about to refuse anyway. The decoder is
// the wire contract's gate; the sender's policy (the only code that builds a
// frame) emits its own listener, its own key and a real signature.
func EncodePeerExchange(p *PeerExchange) []byte {
	e := types.NewEncoder()
	e.U8(uint8(MsgPeerExchange))
	e.U64(p.Height)
	e.VarBytes(p.Validator)
	e.Len(len(p.Addrs))
	for _, a := range p.Addrs {
		e.VarBytes([]byte(a))
	}
	e.VarBytes(p.Sig)
	return e.Bytes()
}

// DecodePeerExchange decodes a PEER_EXCHANGE frame, refusing:
//
//   - any other tag (ErrUnknownMsgType), on the first byte;
//   - a validator key that is not exactly an Ed25519 public key, before its
//     copy (the HELLO decoder's discipline, audit N-12);
//   - a count above MaxPeerExchangeAddrs, BEFORE the slice is made;
//   - a count the remaining bytes could not hold, also before the slice is
//     made, so a lying count never buys memory;
//   - an empty list (a message that says nothing is a sender bug, not a
//     no-op);
//   - an empty address entry, and an entry longer than MaxListenAddrBytes;
//   - a signature that is not exactly an Ed25519 signature, before its copy;
//   - trailing bytes (Done), so the frame has exactly one reading.
//
// The address strings are NOT parsed here. "host:port" is a policy claim the
// node layer judges against its own address, the local network and the
// reserved relay: name; a decoder that accepted only IP literals would put
// that policy in the framing layer, where a future policy change would have to
// edit the protocol. Membership and the signature itself are likewise the node
// layer's: framing cannot know which chain or which committee is meant.
func DecodePeerExchange(b []byte) (*PeerExchange, error) {
	d := types.NewDecoder(b)
	raw, err := d.U8()
	if err != nil {
		return nil, err
	}
	if MsgType(raw) != MsgPeerExchange {
		return nil, fmt.Errorf("%w: %d is not a PEER_EXCHANGE", ErrUnknownMsgType, raw)
	}
	p := &PeerExchange{}
	if p.Height, err = d.U64(); err != nil {
		return nil, err
	}
	// One legal width, checked before the copy (audit N-12), exactly as the
	// HELLO decoder bounds its key.
	key, err := d.VarBytesMax(ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("wire: peer exchange validator key: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrBadPeerExchangeKey, len(key), ed25519.PublicKeySize)
	}
	p.Validator = append([]byte(nil), key...)
	count, err := d.Len()
	if err != nil {
		return nil, err
	}
	// Both bounds before the allocation (audit N-4/N-12): the count is
	// attacker-supplied, and a PeerExchange is a []string - 16 bytes per
	// claimed element in memory against a minimum of ONE byte on the wire - so
	// trusting a 1 MiB frame's count would pre-allocate ~16x the frame. The
	// protocol ceiling is checked first (it is the contract), then the bytes
	// actually available (the frame's own lie detector).
	if count == 0 {
		return nil, ErrEmptyPeerExchange
	}
	if count > MaxPeerExchangeAddrs {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooManyPeerExchange, count, MaxPeerExchangeAddrs)
	}
	if count > d.Remaining() {
		return nil, fmt.Errorf("wire: peer exchange claims %d addresses but only %d bytes remain", count, d.Remaining())
	}
	p.Addrs = make([]string, 0, count)
	for i := 0; i < count; i++ {
		addr, err := d.VarBytesMax(MaxListenAddrBytes)
		if err != nil {
			return nil, fmt.Errorf("wire: peer exchange address %d: %w", i, err)
		}
		if len(addr) == 0 {
			return nil, fmt.Errorf("%w: entry %d", ErrEmptyPeerExchangeAddr, i)
		}
		p.Addrs = append(p.Addrs, string(addr))
	}
	sig, err := d.VarBytesMax(ed25519.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("wire: peer exchange signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrBadPeerExchangeSig, len(sig), ed25519.SignatureSize)
	}
	p.Sig = append([]byte(nil), sig...)
	if err := d.Done(); err != nil {
		return nil, err
	}
	return p, nil
}
