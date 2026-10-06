package store

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func idOf(b byte) (id [32]byte) {
	id[0] = b
	id[31] = b
	return id
}

// The lock record is the restart story's whole foundation: a validator that
// precommitted and crashed must come back still holding its promise. Round
// the record through a full close-and-reopen, and confirm the locks of other
// heights (present and absent) are untouched by it.
func TestPutLockSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A block sits at height 1 too: the lock log must neither disturb nor be
	// disturbed by the block index.
	if err := s.Append(1, []byte("block-one")); err != nil {
		t.Fatal(err)
	}
	rec := LockRecord{Height: 2, Round: 4, BlockID: idOf(9)}
	if err := s.PutLock(rec); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	got, ok := s2.LockAt(2)
	if !ok {
		t.Fatal("the lock recorded before the close was lost across the reopen: a restarted validator would re-enter unlocked")
	}
	if got != rec {
		t.Fatalf("LockAt(2) = %+v, want the recorded %+v", got, rec)
	}
	if _, ok := s2.LockAt(1); ok {
		t.Fatal("a height that was never locked must report no lock")
	}
	if _, ok := s2.LockAt(3); ok {
		t.Fatal("a height after the locked one must report no lock")
	}
	// The lock was written where blocks live but must never have been
	// mistaken for one: the record went into the lock log, not the block
	// stream, so the store still ends at height 1.
	if h, ok := s2.Height(); !ok || h != 1 {
		t.Fatalf("Height() = %d,%v after reopen; want 1,true - a lock record must not renumber the block log", h, ok)
	}
	if got, err := s2.Read(1); err != nil || string(got) != "block-one" {
		t.Fatalf("Read(1) = %q, %v; block bytes must survive the lock write", got, err)
	}
}

// The lock only ever moves forward within a height, so one height can
// accumulate several records. Only the NEWEST may stand: an older frame
// winning the read-back would restore a promise the validator already moved
// past, letting it honour less than its own newest promise.
func TestPutLockKeepsNewestRecordPerHeight(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := LockRecord{Height: 7, Round: 0, BlockID: idOf(1)}
	later := LockRecord{Height: 7, Round: 3, BlockID: idOf(2)}
	if err := s.PutLock(first); err != nil {
		t.Fatal(err)
	}
	if err := s.PutLock(later); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, _ := s2.LockAt(7); got != later {
		t.Fatalf("LockAt(7) = %+v, want the NEWEST record %+v (an earlier promise must not stand over the later one)", got, later)
	}
	// And the live store agrees with the reopened one.
	if got, _ := s.LockAt(7); got != later {
		t.Fatalf("LockAt(7) before the close = %+v, want the newest record %+v", got, later)
	}
}

// A structurally complete lock record whose checksum no longer matches must
// fail Open LOUDLY. Degrading a corrupt lock to "no lock" is the unsafe
// direction: the validator would re-enter unlocked and prevote exactly the
// conflicting block its persisted promise exists to refuse. The node staying
// down is the honest failure.
func TestOpenFailsOnCorruptLockRecord(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutLock(LockRecord{Height: 5, Round: 2, BlockID: idOf(3)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Flip a byte inside the record's payload - the framing stays intact, so
	// only the record checksum can catch this.
	logPath := filepath.Join(dir, lockLogName)
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != RecordHeaderLen+lockPayloadLen+RecordTrailerLen {
		t.Fatalf("lock log is %d bytes; expected the %d-byte framed header, the fixed %d-byte payload (8-byte height, 4-byte round, 32-byte ID) and the %d-byte CRC", len(raw), RecordHeaderLen, lockPayloadLen, RecordTrailerLen)
	}
	raw[RecordHeaderLen+3] ^= 0xFF // a byte inside the record's fixed-width height field
	if err := os.WriteFile(logPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	fresh, err := Open(dir)
	if fresh != nil {
		_ = fresh.Close()
	}
	if err == nil {
		t.Fatal("a corrupt lock record must fail Open, not open as an unlocked store")
	}
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("corrupt lock record: got %v, want an error wrapping ErrCorruptRecord", err)
	}
	// And the store must NOT be usable for consensus afterwards: reopening
	// repeatedly keeps failing, so a broken log cannot be outlived.
	if _, err := Open(dir); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("the corruption is stable: reopening gave %v", err)
	}
}

// A CORRUPT LENGTH PREFIX must fail Open loudly and must NOT be "repaired" by
// truncating. This is the review's demonstrated defect, before the fix: scan
// could not tell a crashed-half-written tail from bit rot in the length byte,
// so a flipped bit led it to destroy the intact record - Open returned nil,
// the log went to 0 bytes on disk, and a validator that had precommitted came
// back UNLOCKED, the exact unsafe direction. Two independent guards now stand
// in the way, and each is exercised by its own case:
//
//   - the fixed-width header's checksum covers the length, so a flipped bit
//     anywhere in it is caught before the length is used; and
//   - a header that DOES check out must still name the one constant this
//     record format writes, so even a hand-consistent wrong length (the shape
//     a writer bug would produce) is refused rather than read as a torn tail
//     and truncated.
func TestOpenFailsOnCorruptLengthPrefixLoudly(t *testing.T) {
	cases := map[string]func(raw []byte){
		"flipped-bit-overruns-EOF": func(raw []byte) {
			// The most significant byte of the length: the record now
			// appears to run past EOF - the exact shape that used to be
			// truncated away as a torn tail.
			raw[0] ^= 0x80
		},
		"valid-header-wrong-constant": func(raw []byte) {
			// A length one byte too long, with the header checksum recomputed
			// so the framing check agrees with it. Only the constant rule can
			// tell this apart from a crash - and without it the record would
			// be truncated away as torn.
			binary.BigEndian.PutUint64(raw[:lengthFieldLen], lockPayloadLen+1)
			binary.BigEndian.PutUint32(raw[lengthFieldLen:RecordHeaderLen],
				crc32.Checksum(raw[:lengthFieldLen], crcTable))
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			rec := LockRecord{Height: 5, Round: 2, BlockID: idOf(9)}
			if err := s.PutLock(rec); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			logPath := filepath.Join(dir, lockLogName)
			raw, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != RecordHeaderLen+lockPayloadLen+RecordTrailerLen {
				t.Fatalf("lock log is %d bytes, want one whole %d-byte record", len(raw), RecordHeaderLen+lockPayloadLen+RecordTrailerLen)
			}
			sizeBefore, err := fileSize(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := binary.BigEndian.Uint64(raw[:lengthFieldLen]); got != lockPayloadLen {
				t.Fatalf("the length field is %d, want the constant %d the writer emits", got, lockPayloadLen)
			}
			corrupt(raw)
			if err := os.WriteFile(logPath, raw, 0o644); err != nil {
				t.Fatal(err)
			}

			fresh, err := Open(dir)
			if fresh != nil {
				_ = fresh.Close()
			}
			if !errors.Is(err, ErrCorruptRecord) {
				t.Fatalf("a corrupt length prefix got %v, want a LOUD ErrCorruptRecord at Open - truncating it would return the validator as unlocked", err)
			}
			// The truncate must be gone: the log is untouched, so the intact
			// record's framing is still there for a later run to diagnose.
			sizeAfter, err := fileSize(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if sizeAfter != sizeBefore {
				t.Fatalf("the corrupt length destroyed the record: log shrank %d -> %d bytes on disk (the review's truncate must never run)", sizeBefore, sizeAfter)
			}
			// And the failure is stable: the node cannot outlive the corrupt
			// log by simply trying again.
			if _, err := Open(dir); !errors.Is(err, ErrCorruptRecord) {
				t.Fatalf("the corruption must stay loud: reopening gave %v", err)
			}
		})
	}
}

// A crash mid-write cuts the tail off the lock log. The torn bytes must be
// truncated away - repaired, not read: a partial record could otherwise be
// mistaken for a lock (or for silence) by a restarted validator. Everything
// recorded before the tear must survive, and appending after the repair must
// work and survive a second reopen.
func TestTornLockTailIsTruncatedNotReadAsALock(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	intact := LockRecord{Height: 5, Round: 0, BlockID: idOf(1)}
	if err := s.PutLock(intact); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash inside the next record: a COMPLETE, VALID framing
	// header, then the start of a payload for height 6 round 1 - and no
	// checksum, because the write never completed. A tail of this shape is
	// what a crash actually costs, and truncating it is what the repair is
	// for. (The checksummed header is what tells the scanner the record was
	// cut rather than corrupted: a corrupt length would fail its own check.)
	logPath := filepath.Join(dir, lockLogName)
	intactLen, err := fileSize(logPath)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tear := make([]byte, 0, RecordHeaderLen+8+4+2)
	var lb [lengthFieldLen]byte
	binary.BigEndian.PutUint64(lb[:], lockPayloadLen)
	tear = append(tear, lb[:]...)
	var hc [RecordTrailerLen]byte
	binary.BigEndian.PutUint32(hc[:], crc32.Checksum(tear[:lengthFieldLen], crcTable))
	tear = append(tear, hc[:]...)
	var hb [8]byte
	binary.BigEndian.PutUint64(hb[:], 6)
	var rb [4]byte
	binary.BigEndian.PutUint32(rb[:], 1)
	tear = append(tear, hb[:]...)
	tear = append(tear, rb[:]...)
	tear = append(tear, 0xAA, 0xBB) // 2 of the 32 ID bytes
	var torn []byte
	torn = append(torn, prefix...)
	torn = append(torn, tear...)
	if err := os.WriteFile(logPath, torn, 0o644); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open with a torn lock tail: %v (the tear is repairable, not fatal)", err)
	}
	defer s2.Close()
	if got, ok := s2.LockAt(5); !ok || got != intact {
		t.Fatalf("the record before the tear was lost: got %+v,%v want %+v", got, ok, intact)
	}
	if _, ok := s2.LockAt(6); ok {
		t.Fatal("the torn trailing record was read as a lock for height 6: partial bytes must never become a promise")
	}
	// The repair must be on disk, not just in memory, and the log must take
	// new records cleanly afterwards.
	if size, err := fileSize(logPath); err != nil || size != intactLen {
		t.Fatalf("torn tail not truncated on disk: size %d, want %d (err %v)", size, intactLen, err)
	}
	after := LockRecord{Height: 6, Round: 1, BlockID: idOf(3)}
	if err := s2.PutLock(after); err != nil {
		t.Fatal(err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	s3, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if got, _ := s3.LockAt(6); got != after {
		t.Fatalf("LockAt(6) after the repaired append = %+v, want %+v", got, after)
	}
	if got, _ := s3.LockAt(5); got != intact {
		t.Fatalf("the first record was disturbed by the repair: %+v, want %+v", got, intact)
	}
}

// Close must close BOTH handles - the block segment and the lock log - and
// report every close's failure, not bail at the first one: an early return on
// the first error leaks the other descriptor exactly whenever one close
// fails, which is the only situation Close's error reporting exists for.
// The lock handle is Task 12's addition, so this is the test that keeps it
// from being stranded by an early return.
func TestCloseClosesBothHandlesAndReportsBothErrors(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutLock(LockRecord{Height: 1, Round: 0, BlockID: idOf(1)}); err != nil {
		t.Fatal(err)
	}
	// Replace the segment handle with one whose Close FAILS (a bogus
	// descriptor: close(2) answers EBADF), without closing the real one -
	// abandoning it is this test's own leak, not the store's path.
	bogus := os.NewFile(1<<20, "b10coin-test-bogus-fd")
	s.file = bogus
	seg := s.lockFile
	closeErr := s.Close()
	if closeErr == nil {
		t.Fatal("Close must report the failing handle's error, not nil")
	}
	// The early-return shape (s.file.Close errors; return) would leave the
	// lock handle OPEN here: closing it again must instead say it is already
	// closed, proving Close got to it despite the segment's error.
	if err := seg.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("the second handle was leaked by Close's early return: closing it reports %v, want os.ErrClosed", err)
	}
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// A lock record's payload must be laid out exactly as the store's CRC framing
// wraps it: fixed-width big-endian height (8 bytes), then big-endian round
// (4 bytes), the 32-byte block ID - and nothing else, so decode can reject a
// payload of any other width as corruption instead of decoding a promise it
// never was. This is the record a restart reads and the framing the
// length-prefix tests are written against.
func TestLockRecordPayloadFraming(t *testing.T) {
	raw := encodeLockRecord(LockRecord{Height: 5, Round: 2, BlockID: idOf(7)})
	if len(raw) != lockPayloadLen {
		t.Fatalf("payload is %d bytes, want the fixed %d (8-byte height + 4-byte round + 32-byte ID)", len(raw), lockPayloadLen)
	}
	if got := binary.BigEndian.Uint64(raw[0:8]); got != 5 {
		t.Fatalf("payload height is %d, want 5 as big-endian bytes at the head", got)
	}
	if got := binary.BigEndian.Uint32(raw[8:12]); got != 2 {
		t.Fatalf("payload round is %d, want 2 as big-endian bytes at offset 8", got)
	}
	got, err := decodeLockRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Height != 5 || got.Round != 2 || got.BlockID != idOf(7) {
		t.Fatalf("decode = %+v, want the encoded record", got)
	}
	// Big heights keep the layout constant: no varint anywhere in the payload
	// may silently change its width, or the length prefix stops being a
	// constant the scan can check.
	wide := encodeLockRecord(LockRecord{Height: 1 << 40, Round: 1 << 30, BlockID: idOf(1)})
	if len(wide) != lockPayloadLen {
		t.Fatalf("a big record is %d bytes; the payload width must not depend on the values", len(wide))
	}
	if got, err := decodeLockRecord(wide); err != nil {
		t.Fatalf("a wide record must decode in the same fixed layout: %v", err)
	} else if got.Height != 1<<40 || got.Round != 1<<30 || got.BlockID != idOf(1) {
		t.Fatalf("the wide record decoded as %+v, want what was encoded", got)
	}
	// Strictness: a payload of ANY other width is corruption.
	if _, err := decodeLockRecord(raw[:lockPayloadLen-1]); err == nil {
		t.Fatal("a short payload must be rejected, not decoded")
	}
	if _, err := decodeLockRecord(append(append([]byte(nil), raw...), 0xFF)); err == nil {
		t.Fatal("a payload with junk after the block ID must be rejected, not decoded")
	}
}

// PutLock fsyncs through the same writeRecord the blocks use; a move must be
// readable from the live store immediately, since the persist hook runs while
// the engine is mid-round with no crash and no close in sight.
func TestLockAtReportsTheLiveStore(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok := s.LockAt(1); ok {
		t.Fatal("a store that never recorded a lock must report none")
	}
	rec := LockRecord{Height: 1, Round: 3, BlockID: idOf(4)}
	if err := s.PutLock(rec); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.LockAt(1); !ok || got != rec {
		t.Fatalf("LockAt(1) immediately after PutLock = %+v,%v; want %+v", got, ok, rec)
	}
}

// countLockFrames reads locks.log back through the store's own framing and
// counts its records, so a prune test can assert the FILE really shrank rather
// than only the map.
func countLockFrames(t *testing.T, dir string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, lockLogName))
	if err != nil {
		t.Fatal(err)
	}
	n, off := 0, int64(0)
	for off < int64(len(raw)) {
		_, recEnd, err := frame(raw, off, lockPayloadLen)
		if err != nil {
			t.Fatalf("framing locks.log at offset %d: %v", off, err)
		}
		n++
		off = recEnd
	}
	return n
}

// PruneLocks drops every promise strictly below the committed head and keeps
// the two that can still be read - the head's own record (conservative
// headroom) and the head+1 promise a restart restores - across both the live
// store and a reopen (audit C-13).
func TestPruneLocksDropsBelowTheCommittedHead(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The chain has committed through height 5, so the store knows its head on
	// reopen.
	for h := uint64(1); h <= 5; h++ {
		if err := s.Append(h, []byte("block")); err != nil {
			t.Fatal(err)
		}
	}
	for h := uint64(1); h <= 6; h++ {
		if err := s.PutLock(LockRecord{Height: h, Round: 1, BlockID: idOf(byte(h))}); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.PruneLocks(5); err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h < 5; h++ {
		if _, ok := s.LockAt(h); ok {
			t.Fatalf("LockAt(%d) survived a prune below the committed head 5", h)
		}
	}
	if _, ok := s.LockAt(5); !ok {
		t.Fatal("the head's own lock was pruned; the fix deliberately keeps it")
	}
	if _, ok := s.LockAt(6); !ok {
		t.Fatal("the head+1 promise was pruned: that record is the lock a restart reads, and dropping it reopens the M3 lock-persistence finding")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The reopen prunes below its committed head too, so the same promises
	// stand and the same heights are absent.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	for h := uint64(1); h < 5; h++ {
		if _, ok := s2.LockAt(h); ok {
			t.Fatalf("after reopen LockAt(%d) is present for a height below the committed head", h)
		}
	}
	if _, ok := s2.LockAt(5); !ok {
		t.Fatal("the head's own lock did not survive the reopen")
	}
	if _, ok := s2.LockAt(6); !ok {
		t.Fatal("the head+1 promise did not survive the reopen")
	}
}

// A log of repeated relocks at one height grows one frame per move; once
// enough stale frames have accumulated, PruneLocks rewrites the file to the
// promises that stand, and the rewrite replays identically (audit C-13).
func TestPruneLocksCompactsTheLog(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const moves = lockCompactThreshold + 2
	newest := LockRecord{}
	for i := 0; i < moves; i++ {
		newest = LockRecord{Height: 9, Round: uint32(i), BlockID: idOf(byte(i))}
		if err := s.PutLock(newest); err != nil {
			t.Fatal(err)
		}
	}
	if before := countLockFrames(t, dir); before != moves {
		t.Fatalf("fixture: locks.log holds %d frames before the prune, want %d", before, moves)
	}

	if err := s.PruneLocks(0); err != nil {
		t.Fatal(err)
	}
	if got := countLockFrames(t, dir); got != 1 {
		t.Fatalf("the compacted log holds %d frames, want the single newest promise", got)
	}
	if got, ok := s.LockAt(9); !ok || got != newest {
		t.Fatalf("after compaction LockAt(9) = %+v,%v; want the newest %+v", got, ok, newest)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, ok := s2.LockAt(9); !ok || got != newest {
		t.Fatalf("across the reopen the compacted log reads %+v,%v; want the newest %+v", got, ok, newest)
	}
	if _, ok := s2.LockAt(8); ok {
		t.Fatal("a height that was never locked appeared after compaction")
	}
}
