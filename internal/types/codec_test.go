package types

import (
	"bytes"
	"errors"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	e := NewEncoder()
	e.U8(0xAB)
	e.U32(0xDEADBEEF)
	e.U64(1<<63 + 7)
	e.I64(-42)
	e.Len(3)
	e.VarBytes([]byte("hello"))
	e.Raw([]byte{1, 2, 3})
	e.Fixed32([32]byte{9})

	d := NewDecoder(e.Bytes())
	if v, err := d.U8(); err != nil || v != 0xAB {
		t.Fatalf("U8 = %v, %v", v, err)
	}
	if v, err := d.U32(); err != nil || v != 0xDEADBEEF {
		t.Fatalf("U32 = %v, %v", v, err)
	}
	if v, err := d.U64(); err != nil || v != 1<<63+7 {
		t.Fatalf("U64 = %v, %v", v, err)
	}
	if v, err := d.I64(); err != nil || v != -42 {
		t.Fatalf("I64 = %v, %v", v, err)
	}
	if v, err := d.Len(); err != nil || v != 3 {
		t.Fatalf("Len = %v, %v", v, err)
	}
	if v, err := d.VarBytes(); err != nil || !bytes.Equal(v, []byte("hello")) {
		t.Fatalf("VarBytes = %q, %v", v, err)
	}
	raw := make([]byte, 3)
	for i := range raw {
		b, err := d.U8()
		if err != nil {
			t.Fatal(err)
		}
		raw[i] = b
	}
	if !bytes.Equal(raw, []byte{1, 2, 3}) {
		t.Fatalf("raw = %v", raw)
	}
	if v, err := d.Fixed32(); err != nil || v != [32]byte{9} {
		t.Fatalf("Fixed32 = %v, %v", v, err)
	}
	if err := d.Done(); err != nil {
		t.Fatalf("Done = %v", err)
	}
}

func TestDecoderRejectsShortBuffer(t *testing.T) {
	d := NewDecoder([]byte{1, 2})
	if _, err := d.U32(); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}

func TestDecoderRejectsTrailingBytes(t *testing.T) {
	d := NewDecoder([]byte{1, 2, 3})
	if _, err := d.U8(); err != nil {
		t.Fatal(err)
	}
	if err := d.Done(); !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("expected ErrTrailingBytes, got %v", err)
	}
}

// A length prefix may not be padded with redundant continuation bytes.
// Without this check the same value has two encodings, which would let an
// attacker change a transaction's bytes without changing its meaning.
func TestDecoderRejectsNonCanonicalVarint(t *testing.T) {
	// 0x80 0x00 is a two-byte encoding of zero; canonical is 0x00.
	d := NewDecoder([]byte{0x80, 0x00})
	if _, err := d.Len(); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("expected ErrNonCanonical, got %v", err)
	}
}

// A varint whose value does not fit in 64 bits is a distinct failure from a
// short buffer (audit S-17): the bytes are all present, the number is just
// unrepresentable. It must not be reported as ErrShortBuffer.
func TestDecoderRejectsVarintOverflowDistinctly(t *testing.T) {
	// Ten bytes: nine continuation bytes and a final byte that carries a
	// value bit above bit 63.
	overflow := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}
	d := NewDecoder(overflow)
	_, err := d.Len()
	if !errors.Is(err, ErrVarintOverflow) {
		t.Fatalf("a 65-bit varint gave %v, want ErrVarintOverflow", err)
	}
	if errors.Is(err, ErrShortBuffer) {
		t.Fatal("a 65-bit varint must not be reported as a short buffer")
	}
}

func TestLenPrefixLargerThanBufferIsShortBuffer(t *testing.T) {
	e := NewEncoder()
	e.Len(1000)
	d := NewDecoder(e.Bytes())
	if _, err := d.VarBytes(); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}

// VarBytesMax is the bounded sibling of VarBytes (audit C-17): a declared
// length above the protocol's fixed width for the field is refused with
// ErrFieldTooLong BEFORE the copy, while exactly the bound is accepted and the
// accepted bytes are byte-for-byte what VarBytes would have returned.
func TestVarBytesMaxRefusesAboveTheBound(t *testing.T) {
	e := NewEncoder()
	e.VarBytes(make([]byte, 33))
	d := NewDecoder(e.Bytes())
	if _, err := d.VarBytesMax(32); !errors.Is(err, ErrFieldTooLong) {
		t.Fatalf("a 33-byte field under a 32-byte bound gave %v, want ErrFieldTooLong", err)
	}

	e2 := NewEncoder()
	payload := bytes.Repeat([]byte{0x5A}, 32)
	e2.VarBytes(payload)
	d2 := NewDecoder(e2.Bytes())
	got, err := d2.VarBytesMax(32)
	if err != nil {
		t.Fatalf("a field exactly at the bound was refused: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the bounded decode returned different bytes than the encoding carried")
	}
	if err := d2.Done(); err != nil {
		t.Fatalf("the bounded decode did not consume exactly its field: %v", err)
	}

	// Non-canonical and short-buffer handling is unchanged: the bound is an
	// extra ceiling, not a second framing.
	if _, err := NewDecoder([]byte{0x80, 0x00}).VarBytesMax(32); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("a non-canonical length under a bound gave %v, want ErrNonCanonical", err)
	}
	short := NewEncoder()
	short.Len(10)
	if _, err := NewDecoder(short.Bytes()).VarBytesMax(32); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("a length past the buffer under a bound gave %v, want ErrShortBuffer", err)
	}
}
