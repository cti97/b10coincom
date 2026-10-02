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

func TestLenPrefixLargerThanBufferIsShortBuffer(t *testing.T) {
	e := NewEncoder()
	e.Len(1000)
	d := NewDecoder(e.Bytes())
	if _, err := d.VarBytes(); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}
