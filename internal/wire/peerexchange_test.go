package wire

// PEER_EXCHANGE's framing pins. The message is the first wire message whose
// payload is a LIST of attacker-sized strings AND a signed envelope, so the
// things that must hold before any node-layer policy runs are:
//
//   - the frame has exactly one reading: a canonical encode round-trips, and
//     a trailing byte, a non-minimal count varint or an oversized entry is
//     refused;
//   - neither the list nor an entry can make the decoder allocate first: the
//     count is checked against MaxPeerExchangeAddrs and against the bytes
//     actually present BEFORE the []string is made, exactly the audit N-4/N-12
//     discipline the HELLO key and BLOCK_SYNC unit list already follow;
//   - the signed envelope has one legal width per field: a validator key that
//     is not 32 bytes and a signature that is not 64 bytes are refused before
//     either is copied, so the node layer never sees a "signature" a decoder
//     invented (audit PX-1).

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/types"
)

// eightAddrs is a fully legal list at the protocol ceiling: eight listening
// addresses of differing shapes, none of them a hostname.
func eightAddrs() []string {
	return []string{
		"127.0.0.1:6001",
		"10.0.0.5:6002",
		"192.168.1.9:6003",
		"[::1]:6004",
		"[2001:db8::7]:6005",
		"169.254.1.1:6006",
		"203.0.113.4:65535",
		"198.51.100.20:1",
	}
}

// signedExchange is a fully legal frame: a real height, a key of the one legal
// width and a signature of the one legal width. The wire layer does not check
// what either MEANS (that is the node layer's committee and chain-id work), so
// the bytes need not verify against anything.
func signedExchange(addrs []string) *PeerExchange {
	return &PeerExchange{
		Height:    42,
		Validator: bytes.Repeat([]byte{0xA5}, ed25519.PublicKeySize),
		Addrs:     addrs,
		Sig:       bytes.Repeat([]byte{0x5A}, ed25519.SignatureSize),
	}
}

// pxPrefix is the fixed part of a frame up to (not including) the address
// count: tag, height, and a well-formed key. Hostile COUNT tests append their
// own count to it, so they exercise the count bound rather than the envelope -
// EncodePeerExchange cannot express a malformed count, which is the point.
func pxPrefix() []byte {
	e := types.NewEncoder()
	e.U8(uint8(MsgPeerExchange))
	e.U64(42)
	e.VarBytes(bytes.Repeat([]byte{0xA5}, ed25519.PublicKeySize))
	return e.Bytes()
}

func TestPeerExchangeRoundTripsAndRefusesTooManyAddresses(t *testing.T) {
	// Exactly the ceiling round-trips, and re-encodes byte for byte. The
	// height and the advertising key are part of the reading: they are what
	// the receiver binds its committee check to (audit PX-1).
	p := signedExchange(eightAddrs())
	frame := EncodePeerExchange(p)
	got, err := DecodePeerExchange(frame)
	if err != nil {
		t.Fatalf("a legal %d-address PEER_EXCHANGE was refused: %v", MaxPeerExchangeAddrs, err)
	}
	if len(got.Addrs) != len(p.Addrs) {
		t.Fatalf("decoded %d addresses, want %d", len(got.Addrs), len(p.Addrs))
	}
	for i := range p.Addrs {
		if got.Addrs[i] != p.Addrs[i] {
			t.Fatalf("address %d round-tripped as %q, want %q", i, got.Addrs[i], p.Addrs[i])
		}
	}
	if got.Height != p.Height {
		t.Fatalf("height round-tripped as %d, want %d", got.Height, p.Height)
	}
	if !bytes.Equal(got.Validator, p.Validator) || !bytes.Equal(got.Sig, p.Sig) {
		t.Fatal("the signed envelope did not round-trip")
	}
	if again := EncodePeerExchange(got); !bytes.Equal(again, frame) {
		t.Fatalf("re-encode differs from the frame that produced it:\n got %x\nwant %x", again, frame)
	}

	// One over the ceiling is refused, and the refusal happens BEFORE the
	// slice is made: the decoder returns nil, and the error is the protocol
	// ceiling rather than a short buffer or a length error once the bytes the
	// count claims are actually present. That ordering is the whole point - a
	// 16-bytes-per-element pre-allocation must not be reachable from an
	// attacker-chosen count.
	nine := append(eightAddrs(), "203.0.113.99:9")
	if got, err := DecodePeerExchange(EncodePeerExchange(signedExchange(nine))); !errors.Is(err, ErrTooManyPeerExchange) || got != nil {
		t.Fatalf("9 addresses = (%v, %v), want (nil, ErrTooManyPeerExchange)", got, err)
	}
	bare := append(pxPrefix(), byte(MaxPeerExchangeAddrs+1))
	bare = append(bare, make([]byte, MaxPeerExchangeAddrs+1)...)
	if got, err := DecodePeerExchange(bare); !errors.Is(err, ErrTooManyPeerExchange) || got != nil {
		t.Fatalf("a bare count of 9 = (%v, %v), want (nil, ErrTooManyPeerExchange) before any allocation", got, err)
	}
	// A count far beyond the ceiling - the 1 MiB frame's lie, with the bytes it
	// claims present - is the same refusal, not an overflow or a make() of that
	// size.
	huge := append(pxPrefix(), 0xFF, 0xFF, 0x03)
	huge = append(huge, make([]byte, 0xFFFF)...)
	if got, err := DecodePeerExchange(huge); !errors.Is(err, ErrTooManyPeerExchange) || got != nil {
		t.Fatalf("a huge count = (%v, %v), want (nil, ErrTooManyPeerExchange)", got, err)
	}
	// And a count the bytes could not hold is refused by the length reader
	// itself, still before any make.
	if got, err := DecodePeerExchange(append(pxPrefix(), byte(MaxPeerExchangeAddrs+1))); !errors.Is(err, types.ErrShortBuffer) || got != nil {
		t.Fatalf("a count with no bodies = (%v, %v), want (nil, types.ErrShortBuffer)", got, err)
	}

	// A message that says nothing is a sender bug, not a no-op.
	if got, err := DecodePeerExchange(EncodePeerExchange(signedExchange(nil))); !errors.Is(err, ErrEmptyPeerExchange) || got != nil {
		t.Fatalf("an empty list = (%v, %v), want (nil, ErrEmptyPeerExchange)", got, err)
	}

	// An entry with no bytes is refused, so a decoder never hands the node
	// layer an address that cannot be parsed even in principle.
	if got, err := DecodePeerExchange(EncodePeerExchange(signedExchange([]string{""}))); !errors.Is(err, ErrEmptyPeerExchangeAddr) || got != nil {
		t.Fatalf("an empty entry = (%v, %v), want (nil, ErrEmptyPeerExchangeAddr)", got, err)
	}

	// An over-long entry is refused before its copy. The boundary is exact:
	// MaxListenAddrBytes decodes, one more does not.
	long := strings.Repeat("a", MaxListenAddrBytes)
	if _, err := DecodePeerExchange(EncodePeerExchange(signedExchange([]string{long}))); err != nil {
		t.Fatalf("an address of exactly MaxListenAddrBytes was refused: %v", err)
	}
	tooLong := strings.Repeat("a", MaxListenAddrBytes+1)
	if got, err := DecodePeerExchange(EncodePeerExchange(signedExchange([]string{tooLong}))); !errors.Is(err, types.ErrFieldTooLong) || got != nil {
		t.Fatalf("an over-long address = (%v, %v), want (nil, types.ErrFieldTooLong)", got, err)
	}

	// One frame, one reading: a trailing byte is refused (Done), and a
	// non-minimal count varint is not a second legal encoding of the same
	// list.
	withTrailer := append(append([]byte{}, frame...), 0x00)
	if got, err := DecodePeerExchange(withTrailer); err == nil || got != nil {
		t.Fatalf("a frame with a trailing byte = (%v, %v), want (nil, error)", got, err)
	}
	nonCanonical := append(pxPrefix(), 0x80, 0x00) // count 0, two bytes
	if got, err := DecodePeerExchange(nonCanonical); !errors.Is(err, types.ErrNonCanonical) || got != nil {
		t.Fatalf("a non-minimal count = (%v, %v), want (nil, types.ErrNonCanonical)", got, err)
	}
	if got, err := DecodePeerExchange(nil); !errors.Is(err, types.ErrShortBuffer) || got != nil {
		t.Fatalf("an empty frame = (%v, %v), want (nil, types.ErrShortBuffer)", got, err)
	}

	// The decoder is an auditor of its own tag: a consensus tag (1..3) or
	// another wire tag in this position is an unknown message, never a list.
	// The consensus side of the same boundary (0x83 fails Vote/Proposal/
	// HELLO) lives in internal/consensus where those decoders are visible.
	for _, tag := range []byte{1, 2, 3, byte(MsgHello), byte(MsgBlockSyncReq), byte(MsgBlockSyncResp)} {
		if got, err := DecodePeerExchange([]byte{tag, 0x01, 0x01, 'x'}); !errors.Is(err, ErrUnknownMsgType) || got != nil {
			t.Fatalf("tag %#x = (%v, %v), want (nil, ErrUnknownMsgType)", tag, got, err)
		}
	}
}

// TestPeerExchangeRefusesAMalformedSignedEnvelope pins the two widths the
// envelope admits (audit PX-1): a key that is not an Ed25519 public key and a
// signature that is not an Ed25519 signature are refused in the framing layer,
// before either is copied, so a node never verifies against a key the protocol
// cannot have issued.
func TestPeerExchangeRefusesAMalformedSignedEnvelope(t *testing.T) {
	// A short key is the one a truncating sender would produce: refused by
	// width, not verified against.
	short := signedExchange([]string{"203.0.113.4:6001"})
	short.Validator = short.Validator[:ed25519.PublicKeySize-1]
	if got, err := DecodePeerExchange(EncodePeerExchange(short)); !errors.Is(err, ErrBadPeerExchangeKey) || got != nil {
		t.Fatalf("a %d-byte key = (%v, %v), want (nil, ErrBadPeerExchangeKey)", len(short.Validator), got, err)
	}
	// An over-long key is refused before the copy, by the same bound the HELLO
	// decoder applies.
	wide := signedExchange([]string{"203.0.113.4:6001"})
	wide.Validator = append(wide.Validator, 0x00)
	if got, err := DecodePeerExchange(EncodePeerExchange(wide)); !errors.Is(err, types.ErrFieldTooLong) || got != nil {
		t.Fatalf("a %d-byte key = (%v, %v), want (nil, types.ErrFieldTooLong)", len(wide.Validator), got, err)
	}
	// And the signature: short is a width refusal, long is refused before the
	// copy.
	shortSig := signedExchange([]string{"203.0.113.4:6001"})
	shortSig.Sig = shortSig.Sig[:ed25519.SignatureSize-1]
	if got, err := DecodePeerExchange(EncodePeerExchange(shortSig)); !errors.Is(err, ErrBadPeerExchangeSig) || got != nil {
		t.Fatalf("a %d-byte signature = (%v, %v), want (nil, ErrBadPeerExchangeSig)", len(shortSig.Sig), got, err)
	}
	wideSig := signedExchange([]string{"203.0.113.4:6001"})
	wideSig.Sig = append(wideSig.Sig, 0x00)
	if got, err := DecodePeerExchange(EncodePeerExchange(wideSig)); !errors.Is(err, types.ErrFieldTooLong) || got != nil {
		t.Fatalf("a %d-byte signature = (%v, %v), want (nil, types.ErrFieldTooLong)", len(wideSig.Sig), got, err)
	}
	// No address may be read from a frame whose envelope is malformed: every
	// refusal above handed back a nil message.
}
