// Package store persists blocks as append-only segment files, a per-height
// lock log and a per-height commit-certificate log, all over opaque payloads.
//
// Record layout, shared by every log here:
//
//	uint64be(len(payload)) || uint32be(crc32c(len)) || payload || uint32be(crc32c(len || payload))
//
// The header is FIXED WIDTH and checksummed so that the length prefix is
// trustworthy BEFORE it is used to find the record's end. That is the fix
// audit S-2 asks for. Before it, the checksum covered only the payload, so a
// single flipped bit in a length prefix was indistinguishable from a crash:
// the scanner would read the corrupt length, conclude the record ran past
// EOF, and "repair" by truncating the file - silently deleting committed
// blocks and reporting Open success. Here a corrupt length fails its own
// checksum and Open FAILS loudly without touching a byte.
//
// The scan STOPS at the first corruption, in the final segment too: a
// complete record whose payload checksum fails is corruption, not a torn
// tail, and the bytes after it cannot be framed (the corrupt record's own
// length is what would say where they start). Truncating there would delete
// exactly what a repair must preserve, so both logs refuse instead. Truncation
// is confined to what only a crash can produce: the file ends inside a
// record - an incomplete header, or a complete, VALID header whose record
// runs past EOF. A crash cannot invent a different length, because a written
// record's header checksum travels with the length it describes.
//
// The lock log (separate file, same framing) holds one validator's own
// lockedRound/lockedBlock per height. Its records have a FIXED payload (see
// lockPayloadLen), so a valid header claiming any other length is corruption
// by construction and is refused on top of the framing checks - the same
// guarantee as the block log, without having to trust a length at all. A
// lock's whole value is its mere existence, and a missing one reads as
// unlocked, so its error policy is as strict as the framing allows: the node
// staying down is the honest failure.
package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
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

// certLogName holds the commit-certificate log (audit C-7). Like the lock log
// its name avoids the ".seg" suffix for the same reason.
const certLogName = "certs.log"

// RecordHeaderLen and RecordTrailerLen are the on-disk framing's fixed sizes:
// an 8-byte big-endian payload length plus the 4-byte CRC32C of those 8 bytes,
// and a 4-byte CRC32C of the header and the payload. They are exported because
// they are part of the file format, and a tool that walks a segment (or a test
// that rewrites one) must be able to frame records exactly as Open does.
const (
	RecordHeaderLen  = 8 + 4
	RecordTrailerLen = 4
	lengthFieldLen   = 8
)

var (
	ErrNotFound      = errors.New("store: height not found")
	ErrBadHeight     = errors.New("store: heights must be appended sequentially")
	ErrCorruptRecord = errors.New("store: record checksum mismatch")
	// errTornRecord reports a record the file ends inside. It is not
	// corruption: it is the one shape a crash mid-write can leave, and it is
	// the only shape Open may truncate. It is unexported because callers
	// outside this package must treat it as ErrCorruptRecord.
	errTornRecord = errors.New("store: record is incomplete")
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

	// lock is the exclusive data-directory lock, held from Open until Close.
	// See dirlock.go: it keeps a second process (or a second open Store in
	// this process) from interleaving writes into these files.
	lock *dirLock

	// lockFile is the append handle on the lock log; locks maps a height to
	// the NEWEST lock record for it. A height may legitimately carry a lock
	// and no block: the lock points at head+1, the height being judged, so
	// lock heights are deliberately NOT required to be appended heights.
	lockFile *os.File
	locks    map[uint64]LockRecord

	// certFile is the append-and-read handle on the commit-certificate log
	// (audit C-7); certIndex maps a height to the offset of its record in
	// that file. The certificate BYTES are not held in memory: one record
	// per committed height would grow without bound over a long run, and the
	// log exists precisely so a restarted node can serve history it no
	// longer remembers. CertAt reads one record back through this handle.
	certFile  *os.File
	certIndex map[uint64]int64
}

// segmentName maps a height to the segment file holding it. Names are
// zero-padded, so lexical order is height order — but only while segment
// indices fit in 8 digits (height < 10^11): wider indices print unpadded and
// no longer sort lexicographically.
func segmentName(height uint64) string {
	return fmt.Sprintf("%08d.seg", height/BlocksPerSegment)
}

// Open prepares dir for use, rebuilds the in-memory height and lock indexes,
// and discards any partial trailing record. It takes the directory's
// exclusive single-writer lock first and holds it until Close; a directory
// already owned by a live process (or by another open Store in this process)
// is refused with ErrDataDirInUse before any file is scanned or truncated.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	lock, err := acquireDirLock(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{
		dir:       dir,
		index:     make(map[uint64]int64),
		locks:     make(map[uint64]LockRecord),
		certIndex: make(map[uint64]int64),
		lock:      lock,
	}
	if err := s.scan(); err != nil {
		lock.release()
		return nil, err
	}
	f, err := os.OpenFile(s.segmentPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		lock.release()
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(dir, lockLogName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		_ = f.Close()
		lock.release()
		return nil, err
	}
	// O_RDWR, unlike the append-only handles above: serving an adopted
	// height's certificate reads the record back with ReadAt.
	cf, err := os.OpenFile(filepath.Join(dir, certLogName), os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o644)
	if err != nil {
		_ = f.Close()
		_ = lf.Close()
		lock.release()
		return nil, err
	}
	s.file = f
	s.lockFile = lf
	s.certFile = cf
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
	if err := s.scanLocks(); err != nil {
		return err
	}
	// Certificate records are indexed but their payloads are NOT loaded: a
	// cert log carries one record per committed height, so keeping it all in
	// memory is the unbounded archive audit C-7 names. CertAt reads the one
	// record it needs.
	return s.scanCerts()
}

// frame validates the fixed-width header of the record starting at off in raw
// and returns the payload length and the offset of the record's end.
//
// It separates the two things a record can be: errTornRecord means the file
// ends inside the record (an incomplete header, or a header that is complete
// and VALID but whose payload and trailer do not all fit) - the only shape a
// crash can leave. Any other error means the bytes disagree with themselves,
// which corruption alone produces. The order matters and is the whole fix: the
// header's checksum is verified BEFORE its length is used, so a corrupt length
// can never be mistaken for a torn tail and truncated away.
//
// A non-negative exact demands that length: for a log whose records all carry
// the same fixed payload, a header that checks out but names any other length
// is corruption by construction, not a tear, and must be refused before the
// overrun test can call it one.
func frame(raw []byte, off int64, exact int64) (int64, int64, error) {
	rem := int64(len(raw)) - off
	if rem < int64(RecordHeaderLen) {
		return 0, 0, errTornRecord
	}
	header := raw[off : off+RecordHeaderLen]
	if crc32.Checksum(header[:lengthFieldLen], crcTable) != binary.BigEndian.Uint32(header[lengthFieldLen:]) {
		return 0, 0, errors.New("length-prefix checksum mismatch (the length is not trustworthy)")
	}
	n := binary.BigEndian.Uint64(header[:lengthFieldLen])
	if exact >= 0 && n != uint64(exact) {
		return 0, 0, fmt.Errorf("length prefix names %d bytes, but this record format writes only the constant %d", n, exact)
	}
	// The header is trustworthy, so its length needs no further validation
	// beyond keeping the arithmetic below in range: bound it by what is left.
	if n > uint64(rem) {
		return 0, 0, errTornRecord
	}
	payStart := off + RecordHeaderLen
	recEnd := payStart + int64(n) + RecordTrailerLen
	if recEnd > int64(len(raw)) {
		return 0, 0, errTornRecord
	}
	return int64(n), recEnd, nil
}

// scanSegment walks one segment record by record. Earlier segments are
// closed, so a damaged record there is real corruption and fails Open; the
// final segment is the only place a crash could have cut a record, so a torn
// tail there is truncated away. A COMPLETE record whose checksum fails is
// corruption in either case, and the scan STOPS there (audit S-2): its length
// cannot be trusted to find the next record's start, so indexing past it would
// invent heights, and truncating there would delete the very bytes a repair
// must preserve.
func (s *Store) scanSegment(name string, final bool) error {
	path := filepath.Join(s.dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	off := int64(0)
	for off < int64(len(raw)) {
		n, recEnd, err := frame(raw, off, -1)
		if err != nil {
			if final && errors.Is(err, errTornRecord) {
				return s.truncateTail(path, off)
			}
			return fmt.Errorf("%w: %s in %s at offset %d", ErrCorruptRecord, err, name, off)
		}
		payStart := off + RecordHeaderLen
		// The checksum covers the length prefix AND the payload: a length
		// that disagrees with the bytes it frames cannot pass, whether or not
		// the header's own checksum already caught it.
		framed := raw[off : payStart+n : payStart+n]
		want := binary.BigEndian.Uint32(raw[payStart+n : recEnd])
		if crc32.Checksum(framed, crcTable) != want {
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

// truncateTail cuts a torn trailing record off the file. It is reached only
// for errTornRecord - the file ending inside a record - so nothing a crash did
// not cut can be lost here.
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

// writeRecord renders one framed record and appends it durably.
//
// The fixed-width header (a big-endian length plus the CRC32C of that length)
// comes first so the scanner can decide whether the length is trustworthy
// BEFORE it uses it. The trailing checksum then covers the header AND the
// payload. A single write(2) of the whole buffer keeps a crash from leaving
// any shape other than a prefix of it.
func writeRecord(f *os.File, payload []byte) error {
	rec := make([]byte, 0, RecordHeaderLen+len(payload)+RecordTrailerLen)
	var lenbuf [lengthFieldLen]byte
	binary.BigEndian.PutUint64(lenbuf[:], uint64(len(payload)))
	rec = append(rec, lenbuf[:]...)
	var hsum [RecordTrailerLen]byte
	binary.BigEndian.PutUint32(hsum[:], crc32.Checksum(rec, crcTable))
	rec = append(rec, hsum[:]...)
	rec = append(rec, payload...)
	var sum [RecordTrailerLen]byte
	binary.BigEndian.PutUint32(sum[:], crc32.Checksum(rec, crcTable))
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
	// those bytes. frame re-validates the framing - the length prefix AND its
	// checksum - before any offset arithmetic, exactly as scanSegment does
	// before indexing; a torn or corrupt record is reported, never trusted.
	if off < 0 || off >= int64(len(raw)) {
		return nil, fmt.Errorf("%w: index offset %d is past the end of %s", ErrCorruptRecord, off, segmentName(height))
	}
	n, recEnd, err := frame(raw, off, -1)
	if err != nil {
		return nil, fmt.Errorf("%w: at height %d: %v", ErrCorruptRecord, height, err)
	}
	payStart := off + RecordHeaderLen
	payload := raw[payStart : payStart+n]
	want := binary.BigEndian.Uint32(raw[payStart+n : recEnd])
	if crc32.Checksum(raw[off:payStart+n], crcTable) != want {
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
// is the whole point of the log. What may be truncated is ONLY what a crash
// mid-write can leave here: the file ending inside a record - an incomplete
// header, or a complete and VALID header whose record runs past EOF.
// Everything else fails Open loudly, never truncates:
//
//   - A header whose checksum does not match its length is corruption, not a
//     torn tail: a written header's checksum travels with the length it
//     describes, so a flipped bit in either makes the two disagree, while a
//     crash can only fail to write them at all. Truncating it would be how a
//     corrupt log "repairs" itself into unlocked: the destroyed record is
//     replaced by silence, and silence here is a validator free to prevote
//     the very conflicting block its lock exists to refuse. The evidence is
//     also preserved - the file is not rewritten, so what bit rot happened
//     stays readable afterwards.
//   - A VALID header naming any length other than the constant this record
//     format always writes is corruption too, for the same reason: a torn
//     tail cannot produce a different length, and a corrupt one no longer
//     escapes the framing check that catches it before it is read.
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
		n, recEnd, err := frame(raw, off, lockPayloadLen)
		if err != nil {
			if errors.Is(err, errTornRecord) {
				// The tail a crash actually cuts: the file ends inside the
				// record. Nothing from this offset on is intact.
				return s.truncateTail(path, off)
			}
			return fmt.Errorf("%w: lock record at offset %d of %s: %v", ErrCorruptRecord, off, lockLogName, err)
		}
		payStart := off + RecordHeaderLen
		framed := raw[off : payStart+n : payStart+n]
		want := binary.BigEndian.Uint32(raw[payStart+n : recEnd])
		if crc32.Checksum(framed, crcTable) != want {
			return fmt.Errorf("%w: lock record checksum mismatch at offset %d of %s", ErrCorruptRecord, off, lockLogName)
		}
		rec, err := decodeLockRecord(raw[payStart : payStart+n])
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

// scanCerts indexes the commit-certificate log (audit C-7): a height to the
// offset of its record. The payloads are NOT kept in memory - see the Store
// doc - so this pass rebuilds an index, not an archive.
//
// The error policy is the block log's, not the lock log's: what a torn tail
// can destroy here is archival evidence for one height, never a safety
// promise. A certificate that never completed means this node cannot serve
// that height until it re-adopts it, which is exactly the state persistence
// exists to narrow; the node must not refuse to start over it. Corruption in a
// complete record still stops the scan and fails Open, because the bytes after
// a record whose length cannot be trusted cannot be framed at all.
func (s *Store) scanCerts() error {
	path := filepath.Join(s.dir, certLogName)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // no certificate was ever recorded
	}
	if err != nil {
		return err
	}
	off := int64(0)
	for off < int64(len(raw)) {
		n, recEnd, err := frame(raw, off, -1)
		if err != nil {
			if errors.Is(err, errTornRecord) {
				return s.truncateTail(path, off)
			}
			return fmt.Errorf("%w: certificate record at offset %d of %s: %v", ErrCorruptRecord, off, certLogName, err)
		}
		if n < certHeightLen {
			return fmt.Errorf("%w: certificate record at offset %d of %s carries %d bytes, too few for its height", ErrCorruptRecord, off, certLogName, n)
		}
		payStart := off + RecordHeaderLen
		framed := raw[off : payStart+n : payStart+n]
		want := binary.BigEndian.Uint32(raw[payStart+n : recEnd])
		if crc32.Checksum(framed, crcTable) != want {
			return fmt.Errorf("%w: certificate record checksum mismatch at offset %d of %s", ErrCorruptRecord, off, certLogName)
		}
		height := binary.BigEndian.Uint64(raw[payStart : payStart+certHeightLen])
		// Newest wins: a height is certified once, and the store's PutCert
		// refuses to append a second record for it, so only a hand-written
		// file can present two.
		s.certIndex[height] = off
		off = recEnd
	}
	return nil
}

// certHeightLen is the key the certificate log frames its payload with: the
// height the certificate commits, big-endian, fixed width. The store does not
// interpret the rest of the payload - the consensus package owns that
// encoding - it only needs to find a height's record again.
const certHeightLen = 8

// PutCert appends an opaque certificate payload for height. An entry already
// recorded for that height is kept: a committed height never changes its
// block, so the first certificate this node proved and persisted for it is the
// one that stands, and re-recording would only grow the log.
func (s *Store) PutCert(height uint64, payload []byte) error {
	if _, have := s.certIndex[height]; have {
		return nil
	}
	rec := make([]byte, 0, certHeightLen+len(payload))
	var key [certHeightLen]byte
	binary.BigEndian.PutUint64(key[:], height)
	rec = append(rec, key[:]...)
	rec = append(rec, payload...)
	off, err := s.certFile.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if err := writeRecord(s.certFile, rec); err != nil {
		// Cut a partial record back off so later appends start clean; the
		// next Open also self-heals if this truncate fails.
		_ = s.certFile.Truncate(off)
		return err
	}
	s.certIndex[height] = off
	return nil
}

// CertAt returns a copy of the certificate payload recorded for height, and
// whether one exists. It reads the one record, so the cert log costs memory
// only for the record being served, however long the chain runs.
func (s *Store) CertAt(height uint64) ([]byte, bool) {
	off, ok := s.certIndex[height]
	if !ok {
		return nil, false
	}
	// The record was framed by scanCerts/PutCert, but the file lives on disk:
	// re-validate rather than trusting the offset, and report absence (never
	// a panic, never a short read) if it no longer holds.
	header := make([]byte, RecordHeaderLen)
	if _, err := s.certFile.ReadAt(header, off); err != nil {
		return nil, false
	}
	if crc32.Checksum(header[:lengthFieldLen], crcTable) != binary.BigEndian.Uint32(header[lengthFieldLen:]) {
		return nil, false
	}
	n := binary.BigEndian.Uint64(header[:lengthFieldLen])
	if n < certHeightLen || n > uint64(math.MaxInt) {
		return nil, false
	}
	body := make([]byte, n)
	if _, err := s.certFile.ReadAt(body, off+RecordHeaderLen); err != nil {
		return nil, false
	}
	framed := make([]byte, 0, RecordHeaderLen+int(n))
	framed = append(framed, header...)
	framed = append(framed, body...)
	var trailer [RecordTrailerLen]byte
	if _, err := s.certFile.ReadAt(trailer[:], off+RecordHeaderLen+int64(n)); err != nil {
		return nil, false
	}
	if crc32.Checksum(framed, crcTable) != binary.BigEndian.Uint32(trailer[:]) {
		return nil, false
	}
	out := make([]byte, n-certHeightLen)
	copy(out, body[certHeightLen:])
	return out, true
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
// same handle. The data-directory lock is released last, so the directory
// admits a new writer only once this store's files are closed.
func (s *Store) Close() error {
	var fileErr, lockErr, certErr error
	if s.file != nil {
		fileErr = s.file.Close()
		s.file = nil
	}
	if s.lockFile != nil {
		lockErr = s.lockFile.Close()
		s.lockFile = nil
	}
	if s.certFile != nil {
		certErr = s.certFile.Close()
		s.certFile = nil
	}
	if s.lock != nil {
		s.lock.release()
		s.lock = nil
	}
	return errors.Join(fileErr, lockErr, certErr)
}
