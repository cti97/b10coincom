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

// FrameTooLarge is the structured face of ErrFrameTooLarge: it carries the
// length the frame header DECLARED, so a stream reader that refuses an
// oversized frame can skip exactly that many payload bytes and re-synchronise
// on the next frame, instead of tearing the connection down. Skipping is exact
// because the header is the whole contract of where that frame ends - which is
// the same fact that makes the bound-before-allocation order below safe.
//
// errors.Is(err, ErrFrameTooLarge) keeps working through Unwrap, so existing
// sentinel checks are unaffected; use errors.As to reach the size.
type FrameTooLarge struct {
	// Declared is the payload length the header claimed. It goes through
	// int64, not int, for the same reason ReadFrame's comparison below does:
	// on a 32-bit target a 4-GiB claim wraps int, and a negative skip would
	// silently desynchronise the reader the skip exists to save.
	Declared int64
	Max      int
}

func (e *FrameTooLarge) Error() string {
	return fmt.Sprintf("%s: %d bytes, maximum %d", ErrFrameTooLarge, e.Declared, e.Max)
}

func (e *FrameTooLarge) Unwrap() error { return ErrFrameTooLarge }

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
		return nil, &FrameTooLarge{Declared: int64(n), Max: max}
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
