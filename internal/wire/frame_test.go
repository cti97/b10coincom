package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"testing"
)

// TestFrameRoundTrips pins the frame layer's contract: it DELIMITS a payload
// and nothing else. Write then read returns exactly the bytes written - and a
// stream of frames is read back one at a time, so a reader that over-reads
// past its frame (grabbing the next frame's header) dies here too.
func TestFrameRoundTrips(t *testing.T) {
	first := []byte{0x00, 0xFF, 'x', 0x00, 0x42} // arbitrary bytes: the frame layer must not interpret them
	second := []byte("b10coin")
	var buf bytes.Buffer
	if err := WriteFrame(&buf, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, second); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("first frame: want %v, got %v", first, got)
	}
	got, err = ReadFrame(&buf, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("second frame: want %q, got %q", second, got)
	}
	if buf.Len() != 0 {
		t.Fatalf("the reader left %d bytes behind", buf.Len())
	}
}

// TestReadFrameRejectsAnOversizedLength is the test that matters: a length
// prefix is hostile bytes. The maximum a 4-byte big-endian prefix can claim is
// 0xFFFFFFFF - just under 4 GiB - and a reader that trusts it will `make` that
// allocation before it ever learns there is no payload behind it. That is a
// remote denial of service on any node that accepts an inbound connection,
// which is exactly what M4 introduces. The bound must be enforced BEFORE the
// allocation, and this test watches both halves of that order:
//
//   - the error is ErrFrameTooLarge, so a reader that hits EOF on the
//     unprovided payload (bound checked too late, after the attempt to read)
//     fails with a short read instead and is caught here;
//   - the allocation never happens: runtime.MemStats.TotalAlloc is a
//     monotonic count of every heap byte allocated, so a reader that
//     `make`s before it checks shows up here as a ~4 GiB jump in an
//     otherwise few-hundred-byte window. The two regressions are different
//     mutants: error identity alone lets "allocate first, then refuse"
//     survive, and only the allocation counter proves the DoS never ran.
func TestReadFrameRejectsAnOversizedLength(t *testing.T) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	var buf bytes.Buffer
	var hdr [4]byte // header only: the 4 GiB of payload it claims does not exist
	binary.BigEndian.PutUint32(hdr[:], 0xFFFF_FFFF)
	buf.Write(hdr[:])
	_, err := ReadFrame(&buf, 1024)

	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a 4-GiB declared length must be refused as ErrFrameTooLarge before anything is allocated, got %v", err)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 1<<20 {
		t.Fatalf("refusing an oversized frame allocated %d B before refusing it - the bound must run before the allocation (the remote denial of service)", grown)
	}
}

// TestReadFrameRejectsATruncatedPayload pins the reader against trusting what
// it knows: EOF mid-payload is an error, not a short read. A caller that gets
// back a partial slice with a nil error will treat attacker bytes as frames.
func TestReadFrameRejectsATruncatedPayload(t *testing.T) {
	payload := []byte("b10coin") // 7 bytes declared
	var buf bytes.Buffer
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	truncated := buf.Bytes()[:4+3] // header intact, only 3 of the 7 payload bytes present
	_, err := ReadFrame(bytes.NewReader(truncated), 1024)
	if !errors.Is(err, ErrShortFrame) {
		t.Fatalf("EOF mid-payload must be ErrShortFrame, got %v", err)
	}
}

// TestReadFrameRejectsAZeroLengthFrame: a zero-length frame carries no message
// - every message begins with its tag byte - so an empty frame is a protocol
// error, not an empty message.
func TestReadFrameRejectsAZeroLengthFrame(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x00}), 1024)
	if !errors.Is(err, ErrShortFrame) {
		t.Fatalf("a zero-length frame must be refused, got %v", err)
	}
}

// TestReadFrameAcceptsAFrameAtTheMaximum pins the boundary the DoS bound
// guards: a frame of exactly `max` passes, `max`+1 is refused. An off-by-one
// in either direction here is either a rejected honest block or an unbounded
// allocation.
func TestReadFrameAcceptsAFrameAtTheMaximum(t *testing.T) {
	const max = 1024
	var buf bytes.Buffer
	payload := bytes.Repeat([]byte{0xAB}, max)
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, max)
	if err != nil {
		t.Fatalf("a frame of exactly max must be accepted, got %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the frame at max did not round-trip")
	}

	if err = WriteFrame(&buf, append(payload, 0xAB)); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadFrame(&buf, max); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a frame of max+1 must be refused as ErrFrameTooLarge, got %v", err)
	}
}

// TestTheFrameOnTheWire pins the exact byte layout a peer must match: a
// 4-byte BIG-ENDIAN length, then the payload, nothing else. An encoding and
// decoding pair that drift together (say, both little-endian) would still
// round-trip against itself while speaking a language no honest peer
// understands - the layout comparison is what catches that.
func TestTheFrameOnTheWire(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte{0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	want := []byte{0x00, 0x00, 0x00, 0x02, 0x01, 0x02}
	if got := buf.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("on the wire: want %v, got %v", want, got)
	}
}

// TestHelloRoundTrips: every field survives encode/decode, and the encoding is
// canonical - re-encoding a decoded message reproduces the input byte for
// byte. The field-by-field comparison is what pins each field: an encoder and
// decoder that BOTH drop a field still round-trip the bytes while silently
// losing the message.
func TestHelloRoundTrips(t *testing.T) {
	h := &Hello{ChainID: "b10coin-devnet", Validator: []byte("validator-key"), Height: 42, Sig: []byte("signature")}
	enc := EncodeHello(h)
	if len(enc) == 0 || MsgType(enc[0]) != MsgHello {
		t.Fatalf("the encoded HELLO must open with its tag byte, got %v", enc)
	}
	dec, err := DecodeHello(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.ChainID != h.ChainID || dec.Height != h.Height ||
		string(dec.Validator) != string(h.Validator) || string(dec.Sig) != string(h.Sig) {
		t.Fatalf("round trip lost fields: want %+v, got %+v", h, dec)
	}
	if re := EncodeHello(dec); !bytes.Equal(re, enc) {
		t.Fatalf("a decoded HELLO did not re-encode byte for byte: %d B in, %d B out", len(enc), len(re))
	}
}

// TestBlockSyncReqRoundTrips: same discipline as HELLO, with the request's
// range carried fixed-width so a peer cannot misread an off-by-one block
// boundary.
func TestBlockSyncReqRoundTrips(t *testing.T) {
	req := &BlockSyncReq{From: 1, To: 100, Nonce: 42, Requester: []byte("requester-key"), Sig: []byte("signature")}
	enc := EncodeBlockSyncReq(req)
	if len(enc) == 0 || MsgType(enc[0]) != MsgBlockSyncReq {
		t.Fatalf("the encoded BLOCK_SYNC request must open with its tag byte, got %v", enc)
	}
	dec, err := DecodeBlockSyncReq(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.From != req.From || dec.To != req.To || dec.Nonce != req.Nonce ||
		string(dec.Requester) != string(req.Requester) || string(dec.Sig) != string(req.Sig) {
		t.Fatalf("round trip lost fields: want %+v, got %+v", req, dec)
	}
	if re := EncodeBlockSyncReq(dec); !bytes.Equal(re, enc) {
		t.Fatalf("a decoded request did not re-encode byte for byte: %d B in, %d B out", len(enc), len(re))
	}
}

// TestBlockSyncRespRoundTrips: the response's unit list is self-delimiting -
// a count, then that many units, each a length-prefixed encoded block, the
// round its certificate was cast in, and a count of length-prefixed encoded
// precommit votes - so a decoder can never ask a byte slice where it ends. An
// empty list round-trips too: it is an honest "I have nothing for you", and a
// unit with no votes decodes (the puller, not the decoder, refuses it).
func TestBlockSyncRespRoundTrips(t *testing.T) {
	resp := &BlockSyncResp{Nonce: 9, Units: []BlockSyncUnit{
		{Block: []byte{0xAA, 0xBB}, Round: 4, Votes: [][]byte{{0x01, 0x02}, {0x03}}},
		{}, // a fully empty unit still round-trips: the wire frames bytes, it refuses nothing
		{Block: []byte{0xCC}, Round: 0},
	}, Responder: []byte{0x11, 0x22}, Sig: []byte{0x33, 0x44, 0x55}}
	enc := EncodeBlockSyncResp(resp)
	if len(enc) == 0 || MsgType(enc[0]) != MsgBlockSyncResp {
		t.Fatalf("the encoded BLOCK_SYNC response must open with its tag byte, got %v", enc)
	}
	dec, err := DecodeBlockSyncResp(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Nonce != resp.Nonce {
		t.Fatalf("the response's echoed nonce was lost: want %d, got %d", resp.Nonce, dec.Nonce)
	}
	if !bytes.Equal(dec.Responder, resp.Responder) || !bytes.Equal(dec.Sig, resp.Sig) {
		t.Fatalf("the response's responder authentication was lost: want %x/%x, got %x/%x",
			resp.Responder, resp.Sig, dec.Responder, dec.Sig)
	}
	if len(dec.Units) != len(resp.Units) {
		t.Fatalf("want %d units, got %d", len(resp.Units), len(dec.Units))
	}
	for i, u := range resp.Units {
		if !bytes.Equal(dec.Units[i].Block, u.Block) {
			t.Fatalf("unit %d: block want %v, got %v", i, u.Block, dec.Units[i].Block)
		}
		if dec.Units[i].Round != u.Round {
			t.Fatalf("unit %d: round want %d, got %d", i, u.Round, dec.Units[i].Round)
		}
		if len(dec.Units[i].Votes) != len(u.Votes) {
			t.Fatalf("unit %d: want %d votes, got %d", i, len(u.Votes), len(dec.Units[i].Votes))
		}
		for j, v := range u.Votes {
			if !bytes.Equal(dec.Units[i].Votes[j], v) {
				t.Fatalf("unit %d vote %d: want %v, got %v", i, j, v, dec.Units[i].Votes[j])
			}
		}
	}
	if re := EncodeBlockSyncResp(dec); !bytes.Equal(re, enc) {
		t.Fatalf("a decoded response did not re-encode byte for byte: %d B in, %d B out", len(enc), len(re))
	}
}

// TestMessagesRejectForeignTags pins the tag byte as the DISCRIMINATOR, not
// just a constant: a decoder handed another message's frame must refuse it,
// and the refusal must BE the tag check - ErrUnknownMsgType - not an
// accidental parse failure. Asserting merely "some error" would let a mutant
// that drops the tag from both sides survive on a misalignment coincidence:
// without the tag check, an arbitrary re-tagged frame can still happen to
// fail on field boundaries, which looks like rejection but is not. A pure
// round-trip cannot pin this at all: encode and decode can drop the tag
// together and round-trip byte for byte. This is the test the round-trip
// pair cannot replace.
func TestMessagesRejectForeignTags(t *testing.T) {
	hello := EncodeHello(&Hello{ChainID: "b10coin-devnet", Height: 1})
	foreign := make([]byte, len(hello))
	copy(foreign, hello)
	foreign[0] = byte(MsgBlockSyncReq) // a HELLO wearing a BLOCK_SYNC request's tag
	if _, err := DecodeHello(foreign); !errors.Is(err, ErrUnknownMsgType) {
		t.Fatalf("DecodeHello must refuse a foreign tag with ErrUnknownMsgType, got %v", err)
	}
	req := EncodeBlockSyncReq(&BlockSyncReq{From: 1, To: 2})
	req[0] = byte(MsgBlockSyncResp)
	if _, err := DecodeBlockSyncReq(req); !errors.Is(err, ErrUnknownMsgType) {
		t.Fatalf("DecodeBlockSyncReq must refuse a foreign tag with ErrUnknownMsgType, got %v", err)
	}
	resp := EncodeBlockSyncResp(&BlockSyncResp{Units: []BlockSyncUnit{{Block: []byte{0x01}}}})
	resp[0] = byte(MsgHello)
	if _, err := DecodeBlockSyncResp(resp); !errors.Is(err, ErrUnknownMsgType) {
		t.Fatalf("DecodeBlockSyncResp must refuse a foreign tag with ErrUnknownMsgType, got %v", err)
	}
}

// TestMessagesRejectTrailingBytes: a decoder that stops reading where its
// fields end would accept a frame with a second interpretation hidden behind
// the bytes it consumed. The tag check alone cannot catch the same message
// wearing padding; Done() can.
func TestMessagesRejectTrailingBytes(t *testing.T) {
	padded := append(EncodeHello(&Hello{ChainID: "b10coin-devnet", Height: 1}), 0xFF)
	if _, err := DecodeHello(padded); err == nil {
		t.Fatal("DecodeHello accepted bytes trailing its fields")
	}
	padded = append(EncodeBlockSyncReq(&BlockSyncReq{From: 1, To: 2}), 0xFF)
	if _, err := DecodeBlockSyncReq(padded); err == nil {
		t.Fatal("DecodeBlockSyncReq accepted bytes trailing its fields")
	}
	padded = append(EncodeBlockSyncResp(&BlockSyncResp{}), 0xFF)
	if _, err := DecodeBlockSyncResp(padded); err == nil {
		t.Fatal("DecodeBlockSyncResp accepted bytes trailing its fields")
	}
}
