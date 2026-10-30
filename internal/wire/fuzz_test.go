package wire

// Go fuzz targets for the wire layer. Design spec §9.2 names the wire decoder
// as a fuzz target because it consumes untrusted input; M4 introduces the
// first code that parses bytes a remote peer chose - the frame reader and the
// HELLO/BLOCK_SYNC message decoders. A panic in any of them is a remote
// denial of service against a node that accepted an inbound connection.
//
// The property each target pins is the one that matters on hostile bytes: the
// reader NEVER PANICS (the fuzz engine fails the run on the first panic, in
// seed-corpus mode under `go test ./...` just as in a live round), a failed
// read hands back nil with its error, a successful frame is never larger than
// the caller's bound, and an accepted message re-encodes byte for byte - so
// the bytes have exactly one reading.
//
// Bounded run:
//
//	go test -run '^$' -fuzz 'FuzzReadFrame$' -fuzztime 10s ./internal/wire
//	go test -run '^$' -fuzz 'FuzzDecodeHello$' -fuzztime 10s ./internal/wire
//	go test -run '^$' -fuzz 'FuzzDecodeBlockSyncReq$' -fuzztime 10s ./internal/wire
//	go test -run '^$' -fuzz 'FuzzDecodeBlockSyncResp$' -fuzztime 10s ./internal/wire

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func FuzzReadFrame(f *testing.F) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("a valid frame")); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes(), 1024)                              // the happy path
	f.Add([]byte{}, 1024)                                 // nothing at all
	f.Add([]byte{0x00, 0x00}, 1024)                       // a header that never finishes
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF}, 1024)           // a 4-GiB claim over a 4-byte body
	f.Add([]byte{0x00, 0x00, 0x00, 0x00}, 1024)           // a zero-length frame
	f.Add([]byte{0x00, 0x00, 0x00, 0x02, 0x01}, 1024)     // EOF mid-payload
	f.Add([]byte{0x7F, 0x00, 0x00, 0x01, 0x01, 0x02}, -1) // a bound the caller set to nonsense

	f.Fuzz(func(t *testing.T, b []byte, max int) {
		got, err := ReadFrame(bytes.NewReader(b), max)
		if err != nil {
			if got != nil {
				t.Fatalf("a failed read must hand back nil, got %d B", len(got))
			}
			return
		}
		if len(got) > max {
			t.Fatalf("ReadFrame returned %d B, more than the caller's bound of %d B", len(got), max)
		}
		if len(got) == 0 {
			t.Fatal("a zero-length frame must be refused, never returned as success")
		}
	})
}

func FuzzDecodeHello(f *testing.F) {
	valid := EncodeHello(&Hello{ChainID: "b10coin-devnet", Validator: []byte("validator"), Height: 7, Sig: []byte("sig")})
	f.Add(valid)
	f.Add([]byte{})                      // empty input
	f.Add([]byte{byte(MsgBlockSyncReq)}) // another message's tag where a HELLO belongs
	f.Add(valid[:len(valid)-1])          // truncated mid-frame
	padded := append([]byte{}, valid...)
	f.Add(append(padded, 0x00))                          // a valid frame plus a trailing byte
	f.Add([]byte{byte(MsgHello), 0x80, 0x00, 0x00, 'x'}) // a non-canonical varint length

	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DecodeHello(b)
		if err != nil {
			if h != nil {
				t.Fatalf("a failed decode must hand back nil, got %+v", h)
			}
			return
		}
		if h == nil {
			t.Fatal("DecodeHello returned nil with the error also nil")
		}
		// Every variable field the decoder captured is a bounded copy of
		// bytes inside the frame it was given.
		captured := len(h.ChainID) + len(h.Validator) + len(h.Sig)
		if captured > len(b) {
			t.Fatalf("the decoded fields hold %d B, more than the %d B they were decoded from", captured, len(b))
		}
		// Every frame a decoder accepts is canonical: re-encoding must
		// reproduce the input byte for byte.
		if re := EncodeHello(h); !bytes.Equal(re, b) {
			t.Fatalf("an accepted frame is not canonical: %d B in, %d B back out", len(b), len(re))
		}
	})
}

func FuzzDecodeBlockSyncReq(f *testing.F) {
	valid := EncodeBlockSyncReq(&BlockSyncReq{From: 1, To: 100, Requester: []byte("requester"), Sig: []byte("sig")})
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{byte(MsgBlockSyncResp)})
	f.Add(valid[:len(valid)-1])
	padded := append([]byte{}, valid...)
	f.Add(append(padded, 0x00))
	f.Add([]byte{byte(MsgBlockSyncReq), 0xFF, 0xFF, 0xFF}) // truncated inside the fixed-width range

	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeBlockSyncReq(b)
		if err != nil {
			if r != nil {
				t.Fatalf("a failed decode must hand back nil, got %+v", r)
			}
			return
		}
		if r == nil {
			t.Fatal("DecodeBlockSyncReq returned nil with the error also nil")
		}
		captured := len(r.Requester) + len(r.Sig)
		if captured > len(b) {
			t.Fatalf("the decoded fields hold %d B, more than the %d B they were decoded from", captured, len(b))
		}
		if re := EncodeBlockSyncReq(r); !bytes.Equal(re, b) {
			t.Fatalf("an accepted frame is not canonical: %d B in, %d B back out", len(b), len(re))
		}
	})
}

func FuzzDecodeBlockSyncResp(f *testing.F) {
	// The new per-unit shape: block, the cert's round, and the encoded votes.
	oneUnit := EncodeBlockSyncResp(&BlockSyncResp{Units: []BlockSyncUnit{
		{Block: []byte{0xAA, 0xBB}, Round: 2, Votes: [][]byte{{0x01}, {0x02}}},
	}})
	emptyUnit := EncodeBlockSyncResp(&BlockSyncResp{Units: []BlockSyncUnit{{}}})
	f.Add(oneUnit)
	f.Add(EncodeBlockSyncResp(&BlockSyncResp{})) // the honest empty response
	f.Add([]byte{})
	f.Add([]byte{byte(MsgHello)})
	f.Add(oneUnit[:len(oneUnit)-1])                   // truncated inside the votes
	f.Add([]byte{byte(MsgBlockSyncResp), 0x01, 0x02}) // a unit whose block length lies
	f.Add(emptyUnit[:len(emptyUnit)-1])
	padded := append([]byte{}, emptyUnit...)
	f.Add(append(padded, 0x00))
	// A count claiming more units than the frame carries: the decoder must
	// hit the short-buffer error, not loop on - or allocate for - the count.
	f.Add([]byte{byte(MsgBlockSyncResp), 0xFF, 0xFF, 0xFF, 0xFF, 0x0F})

	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeBlockSyncResp(b)
		if err != nil {
			if r != nil {
				t.Fatalf("a failed decode must hand back nil, got %d units", len(r.Units))
			}
			return
		}
		total := 0
		for _, u := range r.Units {
			total += len(u.Block)
			for _, v := range u.Votes {
				total += len(v)
			}
		}
		if total > len(b) {
			t.Fatalf("the decoded units hold %d B, more than the %d B they were decoded from", total, len(b))
		}
		// The nil-field round trip below is not vacuous: an encoder that
		// writes nil slices differently from empty ones would be caught here.
		if re := EncodeBlockSyncResp(r); !bytes.Equal(re, b) {
			t.Fatalf("an accepted frame is not canonical: %d B in, %d B back out", len(b), len(re))
		}
	})
}

func FuzzDecodePeerExchange(f *testing.F) {
	f.Add(EncodePeerExchange(&PeerExchange{
		Height:    3,
		Validator: bytes.Repeat([]byte{0xA5}, ed25519.PublicKeySize),
		Addrs:     []string{"127.0.0.1:6001"},
		Sig:       bytes.Repeat([]byte{0x5A}, ed25519.SignatureSize),
	}))
	f.Add(EncodePeerExchange(&PeerExchange{
		Height:    1 << 40,
		Validator: bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize),
		Addrs:     []string{"[::1]:1", "10.0.0.5:65535"},
		Sig:       bytes.Repeat([]byte{0x22}, ed25519.SignatureSize),
	}))
	f.Add([]byte{})
	f.Add([]byte{byte(MsgPeerExchange)})
	f.Add([]byte{byte(MsgHello), 0x01, 0x01, 'x'})
	f.Add([]byte{byte(MsgPeerExchange), byte(MaxPeerExchangeAddrs + 1)})
	f.Add([]byte{byte(MsgPeerExchange), 0x01, 0x00}) // an empty entry
	f.Add([]byte{byte(MsgPeerExchange), 0x80, 0x00})
	padded := append(EncodePeerExchange(&PeerExchange{Addrs: []string{"1.2.3.4:5"}}), 0x00)
	f.Add(padded)

	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := DecodePeerExchange(b)
		if err != nil {
			if p != nil {
				t.Fatalf("a failed decode must hand back nil, got %d addresses", len(p.Addrs))
			}
			return
		}
		if len(p.Addrs) == 0 || len(p.Addrs) > MaxPeerExchangeAddrs {
			t.Fatalf("a decoded frame carries %d addresses, outside 1..%d", len(p.Addrs), MaxPeerExchangeAddrs)
		}
		total := 0
		for _, a := range p.Addrs {
			if len(a) == 0 || len(a) > MaxListenAddrBytes {
				t.Fatalf("a decoded address is %d B, outside 1..%d", len(a), MaxListenAddrBytes)
			}
			total += len(a)
		}
		if total > len(b) {
			t.Fatalf("the decoded addresses hold %d B, more than the %d B they were decoded from", total, len(b))
		}
		if re := EncodePeerExchange(p); !bytes.Equal(re, b) {
			t.Fatalf("an accepted frame is not canonical: %d B in, %d B back out", len(b), len(re))
		}
	})
}
