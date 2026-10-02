// Package types holds b10coin's consensus structures and their canonical
// binary encoding.
//
// Encoding rules — these are consensus-critical, and violating them is how
// chains fork:
//
//   - Fixed-width integers are big-endian (uint8/uint32/uint64/int64).
//   - Lengths and counts are unsigned LEB128 varints, minimally encoded.
//   - Byte slices are varint-length-prefixed.
//   - Go maps are NEVER encoded directly; iteration order is not deterministic.
//     Sort keys first.
//   - Nothing that is hashed or signed uses JSON or gob.
package types

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrShortBuffer   = errors.New("types: short buffer")
	ErrTrailingBytes = errors.New("types: trailing bytes after decode")
	ErrNonCanonical  = errors.New("types: non-canonical encoding")
)

// Encoder appends canonically-encoded fields to an internal buffer.
type Encoder struct {
	buf []byte
}

func NewEncoder() *Encoder { return &Encoder{} }

// Bytes returns the accumulated encoding. The result aliases internal
// storage and must not be modified by the caller.
func (e *Encoder) Bytes() []byte { return e.buf }

func (e *Encoder) U8(v uint8) { e.buf = append(e.buf, v) }

func (e *Encoder) U32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	e.buf = append(e.buf, b[:]...)
}

func (e *Encoder) U64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	e.buf = append(e.buf, b[:]...)
}

func (e *Encoder) I64(v int64) { e.U64(uint64(v)) }

// Len writes a count or byte length as a minimal unsigned LEB128 varint.
func (e *Encoder) Len(n int) {
	if n < 0 {
		panic("types: negative length")
	}
	var b [binary.MaxVarintLen64]byte
	m := binary.PutUvarint(b[:], uint64(n))
	e.buf = append(e.buf, b[:m]...)
}

func (e *Encoder) VarBytes(b []byte) {
	e.Len(len(b))
	e.buf = append(e.buf, b...)
}

func (e *Encoder) Raw(b []byte) { e.buf = append(e.buf, b...) }

func (e *Encoder) Fixed32(v [32]byte) { e.buf = append(e.buf, v[:]...) }

// Decoder reads canonically-encoded fields. Every method is bounds-checked
// and returns an error rather than panicking: this code parses untrusted
// network input.
type Decoder struct {
	buf []byte
	off int
}

func NewDecoder(b []byte) *Decoder { return &Decoder{buf: b} }

func (d *Decoder) remaining() int { return len(d.buf) - d.off }

// Done reports whether every byte was consumed. Callers MUST call it after
// decoding: unconsumed bytes mean the input had a second interpretation.
func (d *Decoder) Done() error {
	if n := d.remaining(); n != 0 {
		return fmt.Errorf("%w: %d left", ErrTrailingBytes, n)
	}
	return nil
}

func (d *Decoder) U8() (uint8, error) {
	if d.remaining() < 1 {
		return 0, ErrShortBuffer
	}
	v := d.buf[d.off]
	d.off++
	return v, nil
}

func (d *Decoder) U32() (uint32, error) {
	if d.remaining() < 4 {
		return 0, ErrShortBuffer
	}
	v := binary.BigEndian.Uint32(d.buf[d.off:])
	d.off += 4
	return v, nil
}

func (d *Decoder) U64() (uint64, error) {
	if d.remaining() < 8 {
		return 0, ErrShortBuffer
	}
	v := binary.BigEndian.Uint64(d.buf[d.off:])
	d.off += 8
	return v, nil
}

func (d *Decoder) I64() (int64, error) {
	v, err := d.U64()
	return int64(v), err
}

// Len reads a varint length, rejecting non-minimal encodings.
func (d *Decoder) Len() (int, error) {
	if d.remaining() == 0 {
		return 0, ErrShortBuffer
	}
	n, m := binary.Uvarint(d.buf[d.off:])
	if m <= 0 {
		return 0, ErrShortBuffer
	}
	// A multi-byte varint whose final byte is zero has redundant
	// continuation: it is a non-minimal encoding of the same value.
	if m > 1 && d.buf[d.off+m-1] == 0 {
		return 0, ErrNonCanonical
	}
	d.off += m
	if n > uint64(d.remaining()) {
		return 0, ErrShortBuffer
	}
	return int(n), nil
}

func (d *Decoder) VarBytes() ([]byte, error) {
	n, err := d.Len()
	if err != nil {
		return nil, err
	}
	if n > d.remaining() {
		return nil, ErrShortBuffer
	}
	out := make([]byte, n)
	copy(out, d.buf[d.off:d.off+n])
	d.off += n
	return out, nil
}

func (d *Decoder) Fixed32() ([32]byte, error) {
	var v [32]byte
	if d.remaining() < 32 {
		return v, ErrShortBuffer
	}
	copy(v[:], d.buf[d.off:d.off+32])
	d.off += 32
	return v, nil
}
