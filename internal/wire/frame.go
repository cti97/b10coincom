// Package wire is the framing every real connection speaks: a 4-byte
// big-endian length prefix followed by a canonical payload.
//
// The frame layer only DELIMITS. It does not interpret: the canonical
// encoding's own tag byte already discriminates a HELLO from a vote from a
// block. A frame layer that also parsed would be a second place for the wire
// semantics to live, and the two would drift.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrFrameTooLarge = errors.New("wire: frame exceeds the maximum size")
	ErrShortFrame    = errors.New("wire: frame ended before its declared length")
)

// WriteFrame writes one length-prefixed payload.
func WriteFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed payload, refusing anything over max.
//
// The bound is checked BEFORE the allocation. A reader that trusts the prefix
// would allocate 4 GiB on four hostile bytes, which is a remote denial of
// service on any node that accepts an inbound connection.
//
// The comparison goes through int64 rather than int because int is 32 bits on
// 32-bit targets: there, int(n) wraps a 4-GiB claim negative and the bound
// would pass silently. uint32 and int are exact in int64 on every platform Go
// builds for.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int64(n) > int64(max) {
		return nil, fmt.Errorf("%w: %d bytes, maximum %d", ErrFrameTooLarge, n, max)
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: zero-length frame", ErrShortFrame)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrShortFrame, err)
	}
	return payload, nil
}
