// Package store persists blocks as append-only segment files.
//
// Record layout:
//
//	uvarint(len(payload)) || payload || uint32be(crc32c(payload))
//
// Open scans the final segment and truncates any partial trailing record:
// that is what makes a crash mid-write survivable. The node restarts,
// re-syncs from the last good block, and loses nothing already committed. A
// structurally complete record whose checksum fails is indexed but never
// trusted: Read reports it as ErrCorruptRecord instead of silently dropping
// committed heights. A damaged record in any non-final segment is genuine
// corruption and fails Open.
package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
)

// BlocksPerSegment is how many blocks share one segment file.
const BlocksPerSegment = 1000

var (
	ErrNotFound      = errors.New("store: height not found")
	ErrBadHeight     = errors.New("store: heights must be appended sequentially")
	ErrCorruptRecord = errors.New("store: record checksum mismatch")
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// Store is an append-only block log over opaque payloads.
type Store struct {
	dir   string
	file  *os.File // append handle on the segment receiving writes
	last  uint64   // highest height present, corrupt ones included
	have  bool
	index map[uint64]int64 // height -> record offset within its segment
}

// segmentName maps a height to the segment file holding it. Names are
// zero-padded, so lexical order is height order — but only while segment
// indices fit in 8 digits (height < 10^11): wider indices print unpadded and
// no longer sort lexicographically.
func segmentName(height uint64) string {
	return fmt.Sprintf("%08d.seg", height/BlocksPerSegment)
}

// Open prepares dir for use and rebuilds the in-memory height index,
// discarding any partial trailing record.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, index: make(map[uint64]int64)}
	if err := s.scan(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.segmentPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	s.file = f
	return s, nil
}

func (s *Store) segmentPath() string {
	if s.have {
		return filepath.Join(s.dir, segmentName(s.last))
	}
	return filepath.Join(s.dir, segmentName(0))
}

// scan rebuilds the index from disk and repairs the final segment's tail.
func (s *Store) scan() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var segs []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".seg" {
			segs = append(segs, e.Name())
		}
	}
	slices.Sort(segs)

	for si, name := range segs {
		if err := s.scanSegment(name, si == len(segs)-1); err != nil {
			return err
		}
	}
	return nil
}

// scanSegment walks one segment record by record. Earlier segments are
// closed, so a damaged record there is real corruption and fails Open; the
// final segment is the only place a crash could have cut a record, so its
// tail is repaired instead: a partial trailing record is truncated away, and
// a complete record with a bad checksum keeps its index slot for Read to
// reject.
func (s *Store) scanSegment(name string, final bool) error {
	path := filepath.Join(s.dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	off := int64(0)
	for off < int64(len(raw)) {
		n, m := binary.Uvarint(raw[off:])
		// A length prefix beyond the file cannot be a valid record and
		// would overflow the arithmetic below.
		if m <= 0 || n > uint64(len(raw)) {
			if final {
				return s.truncateTail(path, off)
			}
			return fmt.Errorf("%w: bad length prefix in %s at offset %d", ErrCorruptRecord, name, off)
		}
		recEnd := off + int64(m) + int64(n) + 4
		if recEnd > int64(len(raw)) {
			if final {
				return s.truncateTail(path, off)
			}
			return fmt.Errorf("%w: truncated record in %s at offset %d", ErrCorruptRecord, name, off)
		}
		payStart := off + int64(m)
		payload := raw[payStart : payStart+int64(n) : payStart+int64(n)]
		want := binary.BigEndian.Uint32(raw[payStart+int64(n) : recEnd])
		corrupt := crc32.Checksum(payload, crcTable) != want
		if corrupt && !final {
			return fmt.Errorf("%w: checksum mismatch in %s at offset %d", ErrCorruptRecord, name, off)
		}
		h := s.last + 1
		s.index[h] = off
		s.last = h
		s.have = true
		off = recEnd
	}
	return nil
}

// truncateTail cuts a partial trailing record off the file. It deliberately
// does NOT rewind s.last or drop index slots: every indexed record starts
// BEFORE size (the partial record was never indexed), so a complete-but-corrupt
// record keeps its height and Read reports ErrCorruptRecord for it. Rewinding
// here would leave that record's bytes on disk while claiming a lower height,
// and the next reopen would re-read them and renumber every height after.
func (s *Store) truncateTail(path string, size int64) error {
	return os.Truncate(path, size)
}

// Append writes payload as the block at height. Heights must be sequential.
func (s *Store) Append(height uint64, payload []byte) error {
	want := uint64(1)
	if s.have {
		want = s.last + 1
	}
	if height != want {
		return fmt.Errorf("%w: got %d, want %d", ErrBadHeight, height, want)
	}

	// Roll to a new segment before writing across a boundary. Open the new
	// segment before closing the old handle, and swap only on success, so a
	// failed rollover leaves s.file on an open handle rather than a closed one.
	if s.have && segmentName(height) != segmentName(s.last) {
		f, err := os.OpenFile(filepath.Join(s.dir, segmentName(height)),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if err := s.file.Close(); err != nil {
			f.Close()
			return err
		}
		s.file = f
	}

	off, err := s.file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if err := writeRecord(s.file, payload); err != nil {
		// Cut a partial record back off so later appends start clean; the
		// next Open also self-heals if this truncate fails.
		_ = s.file.Truncate(off)
		return err
	}
	s.index[height] = off
	s.last = height
	s.have = true
	return nil
}

func writeRecord(f *os.File, payload []byte) error {
	var hdr [binary.MaxVarintLen64]byte
	m := binary.PutUvarint(hdr[:], uint64(len(payload)))
	rec := make([]byte, 0, m+len(payload)+4)
	rec = append(rec, hdr[:m]...)
	rec = append(rec, payload...)
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.Checksum(payload, crcTable))
	rec = append(rec, sum[:]...)
	if _, err := f.Write(rec); err != nil {
		return err
	}
	// Durable before we report success: a block we acknowledged must
	// survive a power loss.
	return f.Sync()
}

// Read returns a copy of the payload stored at height.
func (s *Store) Read(height uint64) ([]byte, error) {
	off, ok := s.index[height]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrNotFound, height)
	}
	path := filepath.Join(s.dir, segmentName(height))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	n, m := binary.Uvarint(raw[off:])
	if m <= 0 {
		return nil, fmt.Errorf("%w: bad length at %d", ErrCorruptRecord, off)
	}
	start := int(off) + m
	end := start + int(n)
	if end+4 > len(raw) {
		return nil, fmt.Errorf("%w: truncated record at %d", ErrCorruptRecord, off)
	}
	payload := raw[start:end]
	want := binary.BigEndian.Uint32(raw[end : end+4])
	if crc32.Checksum(payload, crcTable) != want {
		return nil, fmt.Errorf("%w: at height %d", ErrCorruptRecord, height)
	}
	out := make([]byte, len(payload))
	copy(out, payload)
	return out, nil
}

// Height returns the highest stored height.
func (s *Store) Height() (uint64, bool) { return s.last, s.have }

func (s *Store) Close() error {
	if s.file == nil {
		return nil
	}
	return s.file.Close()
}
