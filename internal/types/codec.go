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
	// ErrVarintOverflow reports a LEB128 varint whose value does not fit in
	// 64 bits. It is deliberately distinct from ErrShortBuffer (audit S-17):
	// an over-long value is a well-framed malformed number, while a short
	// buffer is a truncated one, and the two want different diagnostics. The
	// bytes are neither trusted nor turned into a length either way.
	ErrVarintOverflow = errors.New("types: varint value overflows 64 bits")
)

// HashSize is the length in bytes of a full hash field, the fixed-width
// sibling of AddressSize: both named sizes back the fixed-width copy
// accessors so neither accessor hardcodes its literal.
const HashSize = 32

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

func (e *Encoder) Fixed32(v [HashSize]byte) { e.buf = append(e.buf, v[:]...) }

// Decoder reads canonically-encoded fields. Every method is bounds-checked
// and returns an error rather than panicking: this code parses untrusted
// network input.
type Decoder struct {
	buf []byte
	off int
}

func NewDecoder(b []byte) *Decoder { return &Decoder{buf: b} }

// remaining reports the unread byte count.
func (d *Decoder) remaining() int { return len(d.buf) - d.off }

// Remaining exposes the unread byte count. A decoder that must pre-allocate
// from an attacker-supplied element count uses it to cap the allocation hint:
// a count is bounded only by the bytes that could follow it, and a struct is
// often far larger in memory than its minimum wire form, so a hint trusted at
// face value can allocate many times the frame size (audit N-4). The bytes
// themselves are still decoded count-by-count - only the HINT is capped.
func (d *Decoder) Remaining() int { return d.remaining() }

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
	if m < 0 {
		// A value wider than 64 bits. It is not a short buffer: every
		// continuation byte the encoder needs is present, the number itself
		// is simply unrepresentable (audit S-17).
		return 0, ErrVarintOverflow
	}
	if m == 0 {
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

// ErrFieldTooLong reports a variable field whose declared length exceeds the
// fixed bound its protocol role gives it. It is distinct from ErrShortBuffer: a
// short buffer is malformed framing, an over-long field is a well-framed value
// that cannot mean what its position claims.
var ErrFieldTooLong = errors.New("types: field exceeds its protocol bound")

// VarBytesMax is VarBytes with a hard ceiling on the declared length.
//
// A field whose legitimate width is a constant of the protocol - an Ed25519
// public key is exactly 32 bytes - must not be able to make the decoder
// allocate a frame-sized copy before its caller rejects it (audit C-17). The
// length is read and checked BEFORE the make/copy, and the accepted encodings
// are byte-for-byte VarBytes' own, so a bounded field re-encodes canonically
// exactly as an unbounded one does.
func (d *Decoder) VarBytesMax(max int) ([]byte, error) {
	n, err := d.Len()
	if err != nil {
		return nil, err
	}
	if n > max {
		return nil, fmt.Errorf("%w: %d bytes, above the %d-byte bound for this field", ErrFieldTooLong, n, max)
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
	if d.remaining() < HashSize {
		return v, ErrShortBuffer
	}
	copy(v[:], d.buf[d.off:d.off+HashSize])
	d.off += HashSize
	return v, nil
}

func (d *Decoder) Fixed20() (Address, error) {
	var a Address
	if d.remaining() < AddressSize {
		return a, ErrShortBuffer
	}
	copy(a[:], d.buf[d.off:d.off+AddressSize])
	d.off += AddressSize
	return a, nil
}
