// Package store persists blocks as append-only segment files and a
// per-height lock log, both over opaque payloads.
//
// Record layout: uvarint(len(payload)) || payload || uint32be(crc32c(payload)).
//
// Open scans the final segment and truncates any partial trailing record:
// that is what makes a crash mid-write survivable. The node restarts,
// re-syncs from the last good block, and loses nothing already committed. A
// structurally complete record whose checksum fails is indexed but never
// trusted: Read reports it as ErrCorruptRecord instead of silently dropping
// committed heights. A damaged record in any non-final segment is genuine
// corruption and fails Open.
//
// The lock log (separate file, same framing) holds one validator's own
// lockedRound/lockedBlock per height. Its records have a FIXED payload
// (see lockPayloadLen), so a frame's length prefix can only ever be one
// exact byte - and it is checked against the constant instead of trusted.
// That closes a hole a length-prefix repair would leave: without the check,
// a single flipped bit in an intact record's length byte is indistinguishable
// from a crash for the scanner, and "repairing" it truncates the log and the
// promise with it - degrading a validator to unlocked, the exact unsafe
// direction the lock exists to refuse. So here the truncate is confined to
// what only a crash can produce: a complete length prefix whose record runs
// past EOF. Everything else is corruption and FAILS Open. Blocks are judged
// content-based through their state roots, so a bad block can only stall a
// Read; a lock's whole value is its mere existence, and a missing one reads
// as unlocked.
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

// lockLogName holds the lock log. The name deliberately does not end in
// ".seg": scan would otherwise index lock records as block heights and
// renumber the chain.
const lockLogName = "locks.log"

var (
	ErrNotFound      = errors.New("store: height not found")
	ErrBadHeight     = errors.New("store: heights must be appended sequentially")
	ErrCorruptRecord = errors.New("store: record checksum mismatch")
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// lockPayloadLen is the fixed payload size of one lock record: 8 bytes of
// big-endian height, 4 bytes of big-endian round, 32 bytes of block ID.
//
// The size is a constant of the CODE, not data the file repeats: the length
// prefix that framing puts in front of every record is checked against it.
// Because it never depends on the file's bytes, no single flipped bit - or
// any corruption at all - can make one record's length lie into a shape the
// scanner would mistake for a torn tail and "repair" by truncating: the
// length is either exactly this constant (the only value a write of this
// record format ever produces) or the log is corrupt and Open refuses it.
const lockPayloadLen = 8 + 4 + 32

// LockRecord is the persisted form of a validator's lock: the safety
// promise that the validator precommitted BlockID at Height inRound, and
// that it must not help commit a conflicting block at Height.
//
// It lives in the store package, not in consensus, so the crash-tolerant
// layer owns its framing and consensus never learns how the promise is laid
// out on disk.
type LockRecord struct {
	Height  uint64
	Round   uint32
	BlockID [32]byte
}

// Store is an append-only block log over opaque payloads.
type Store struct {
	dir   string
	file  *os.File // append handle on the segment receiving writes
	last  uint64   // highest height present, corrupt ones included
	have  bool
	index map[uint64]int64 // height -> record offset within its segment

	// lockFile is the append handle on the lock log; locks maps a height to
	// the NEWEST lock record for it. A height may legitimately carry a lock
	// and no block: the lock points at head+1, the height being judged, so
	// lock heights are deliberately NOT required to be appended heights.
	lockFile *os.File
	locks    map[uint64]LockRecord
}

// segmentName maps a height to the segment file holding it. Names are
// zero-padded, so lexical order is height order — but only while segment
// indices fit in 8 digits (height < 10^11): wider indices print unpadded and
// no longer sort lexicographically.
func segmentName(height uint64) string {
	return fmt.Sprintf("%08d.seg", height/BlocksPerSegment)
}

// Open prepares dir for use, rebuilds the in-memory height and lock indexes,
// and discards any partial trailing record.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, index: make(map[uint64]int64), locks: make(map[uint64]LockRecord)}
	if err := s.scan(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.segmentPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(dir, lockLogName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	s.file = f
	s.lockFile = lf
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
	// The lock log is scanned with the blocks: a lock that survived the crash
	// must be loaded in the same pass as the blocks it promises about, or a
	// restarted validator would re-open unlocked.
	return s.scanLocks()
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
	// segment first, then move s.file to it BEFORE closing the old handle:
	// close(2) can fail after the descriptor is really gone, and if s.file
	// still named the old handle on that path, every later Append would
	// re-enter rollover and Close a closed file — failing forever. With the
	// swap first, even a failed Close leaves the store holding an open
	// handle on the new segment, so the retrying Append re-enters rollover
	// and recovers; the abandoned old descriptor is reclaimed by os.File's
	// finalizer. The returned error is unchanged.
	if s.have && segmentName(height) != segmentName(s.last) {
		f, err := os.OpenFile(filepath.Join(s.dir, segmentName(height)),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		old := s.file
		s.file = f
		if err := old.Close(); err != nil {
			return err
		}
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
	// The index offsets come from the store's own scan, but the segment file
	// can be rewritten underneath an open store: nothing here may panic on
	// those bytes.
	if int64(len(raw)) <= off {
		return nil, fmt.Errorf("%w: index offset %d is past the end of %s", ErrCorruptRecord, off, segmentName(height))
	}
	n, m := binary.Uvarint(raw[off:])
	// A length prefix is stored data, not a trusted size: Uvarint legally
	// yields up to 2^64-1, and int(n) overflows for anything above MaxInt64
	// (end would wrap negative, so the truncation guard below would pass).
	// Bound BEFORE any offset arithmetic, exactly as scanSegment does before
	// indexing.
	if m <= 0 || n > uint64(len(raw)) {
		return nil, fmt.Errorf("%w: bad length at %d", ErrCorruptRecord, off)
	}
	start := int(off) + m
	end := start + int(n)
	// Defensive: end may not fall below start, and the record's trailing
	// checksum must still lie inside the segment.
	if end < start || end+4 > len(raw) {
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

// scanLocks rebuilds the lock index from the lock log.
//
// The error policy is deliberately asymmetric with the block segments' and
// is the whole point of the log. What may be truncated is ONLY the one
// signature a crash mid-write can leave here: a complete, correct length
// prefix whose record runs past EOF. Everything else fails Open loudly,
// never truncates:
//
//   - A length prefix that is not exactly the record's constant size is
//     corruption. A write of this record format can emit one byte - the
//     constant - and nothing else, so a torn tail cannot produce a different
//     one, while a single flipped bit in an intact record's length byte can.
//     Truncating it would be how a corrupt log "repairs" itself into
//     unlocked: the destroyed record is replaced by silence, and silence
//     here is a validator free to prevote the very conflicting block its
//     lock exists to refuse. The evidence is also preserved - the file is
//     not rewritten, so what bit rot happened stays readable afterwards.
//   - A COMPLETE record whose checksum fails means the bytes on disk changed
//     under us or were written badly: again loud, for the same reason.
//   - Decode is strict on top (a fixed-width payload that is not exactly
//     lockPayloadLen bytes is corruption), though the framing check above
//     already leaves it nothing of that shape to see.
//
// The node staying down is the honest failure: refusing to start without a
// promise is safer than keeping a promise you cannot see.
func (s *Store) scanLocks() error {
	path := filepath.Join(s.dir, lockLogName)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // no lock was ever recorded
	}
	if err != nil {
		return err
	}
	off := int64(0)
	for off < int64(len(raw)) {
		n, m := binary.Uvarint(raw[off:])
		// A length prefix this record format cannot have written - because
		// it always writes exactly the one-byte constant - is corruption,
		// not a torn tail: fail loudly, never truncate here. Both parts of
		// the check matter: one flipped bit can turn the constant prefix
		// into either a different single byte (m stays 1) or a multi-byte
		// varint whose DECODED value happens to equal the constant again
		// (m becomes 2) - so a value check alone is not enough; the varint
		// must be exactly as wide as the constant is.
		if m != 1 || n != lockPayloadLen {
			return fmt.Errorf("%w: lock record length prefix at offset %d of %s is not the constant %d (corruption, not a torn tail); got length %d, %d varint bytes", ErrCorruptRecord, off, lockLogName, lockPayloadLen, n, m)
		}
		recEnd := off + int64(m) + int64(n) + 4
		if recEnd > int64(len(raw)) {
			// The tail a crash actually cuts: the framing byte completed,
			// the record never did. Nothing from this offset on is intact.
			return s.truncateTail(path, off)
		}
		payStart := off + int64(m)
		payload := raw[payStart : payStart+int64(n) : payStart+int64(n)]
		want := binary.BigEndian.Uint32(raw[payStart+int64(n) : recEnd])
		if crc32.Checksum(payload, crcTable) != want {
			return fmt.Errorf("%w: lock record checksum mismatch at offset %d of %s", ErrCorruptRecord, off, lockLogName)
		}
		rec, err := decodeLockRecord(payload)
		if err != nil {
			return fmt.Errorf("%w: lock record at offset %d of %s: %v", ErrCorruptRecord, off, lockLogName, err)
		}
		// Newest wins: a height whose lock moved appears once per move, and
		// only the last frame carries the promise that stands.
		s.locks[rec.Height] = rec
		off = recEnd
	}
	return nil
}

// encodeLockRecord renders a lock as its fixed-size payload: 8 bytes of
// big-endian height, 4 bytes of big-endian round, the 32-byte block ID -
// exactly lockPayloadLen bytes, the payload the store's CRC framing wraps.
//
// The width is fixed so the framing's length prefix is a value the CODE
// decides, not data the file states: scanLocks can compare the prefix
// against this constant and refuse any disagreement, rather than having to
// guess whether a weird length is bit rot or a crash.
func encodeLockRecord(rec LockRecord) []byte {
	out := make([]byte, lockPayloadLen)
	binary.BigEndian.PutUint64(out[0:8], rec.Height)
	binary.BigEndian.PutUint32(out[8:12], rec.Round)
	copy(out[12:], rec.BlockID[:])
	return out
}

// decodeLockRecord reads encodeLockRecord's payload back. It is strict: a
// payload that is not exactly the fixed-width layout is corruption rather
// than a lock - a misframed reading must never decode into a promise it
// never was.
func decodeLockRecord(payload []byte) (LockRecord, error) {
	var rec LockRecord
	if len(payload) != lockPayloadLen {
		return rec, fmt.Errorf("lock record payload is %d bytes, want the fixed %d", len(payload), lockPayloadLen)
	}
	rec.Height = binary.BigEndian.Uint64(payload[0:8])
	rec.Round = binary.BigEndian.Uint32(payload[8:12])
	copy(rec.BlockID[:], payload[12:12+32])
	return rec, nil
}

// PutLock records that the validator locked on rec.BlockID at rec.Height in
// round rec.Round. It is append-only: a height may be locked several times
// (the lock only ever moves forward), each move appending its own frame so a
// crash mid-move leaves the previous promise intact and the newest frame
// names the promise that stands. Lock heights are NOT required to be
// appended block heights - a lock points at the NEXT height, the one a
// restarted validator must still honour.
func (s *Store) PutLock(rec LockRecord) error {
	payload := encodeLockRecord(rec)
	off, err := s.lockFile.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if err := writeRecord(s.lockFile, payload); err != nil {
		// Cut a partial record back off so later appends start clean; the
		// next Open also self-heals if this truncate fails.
		_ = s.lockFile.Truncate(off)
		return err
	}
	s.locks[rec.Height] = rec
	return nil
}

// LockAt returns the newest lock recorded for height, and whether one
// exists. Absence is a legitimate state - a never-locked height - not an
// error; corruption of the underlying log already fails Open loudly, so this
// can never silently read a torn record as "no lock".
func (s *Store) LockAt(height uint64) (LockRecord, bool) {
	rec, ok := s.locks[height]
	return rec, ok
}

// Close releases both handles - the block segment and the lock log - and
// reports BOTH failures: an early return on the first error would leak the
// other open descriptor every time one close fails. The fields are cleared
// unconditionally (a close error can fire after the descriptor is really
// gone - see Append's rollover), so a repeated Close cannot spin on the
// same handle.
func (s *Store) Close() error {
	var fileErr, lockErr error
	if s.file != nil {
		fileErr = s.file.Close()
		s.file = nil
	}
	if s.lockFile != nil {
		lockErr = s.lockFile.Close()
		s.lockFile = nil
	}
	return errors.Join(fileErr, lockErr)
}
