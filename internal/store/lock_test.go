package store

import (
	"encoding/binary"
	"errors"
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

	// Flip a byte inside the record's payload - the length stays intact, so
	// only the checksum can catch this.
	logPath := filepath.Join(dir, lockLogName)
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1+lockPayloadLen+4 {
		t.Fatalf("lock log is %d bytes; expected the 1-byte length prefix, the fixed %d-byte payload (8-byte height, 4-byte round, 32-byte ID) and 4-byte CRC", len(raw), lockPayloadLen)
	}
	raw[3] ^= 0xFF // a byte inside the record's fixed-width height field
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
// back UNLOCKED, the exact unsafe direction. The framing's length prefix is
// now checked against the record's constant size, so any other value is
// corruption and fails Open; the destructive truncate is gone, the bytes
// (the evidence) stay on disk.
func TestOpenFailsOnCorruptLengthPrefixLoudly(t *testing.T) {
	// bit 7 turns the single-byte constant prefix into a MULTI-BYTE varint
	// (the scanner reads the next payload byte as continuation data); bit 0
	// leaves it single-byte but with a different value. Both are exactly the
	// one flipped bit the review demands cannot degrade a validator to
	// unlocked, and they exercise both bad-prefix shapes.
	for name, mask := range map[string]byte{"bit7": 0x80, "bit0": 0x01} {
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
			if len(raw) != 1+lockPayloadLen+4 {
				t.Fatalf("lock log is %d bytes, want one whole 49-byte record", len(raw))
			}
			sizeBefore, err := fileSize(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if raw[0] != byte(lockPayloadLen) {
				t.Fatalf("the length prefix is %#x, want the constant %#x the writer emits", raw[0], byte(lockPayloadLen))
			}
			raw[0] ^= mask // corrupt ONLY the length prefix
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

	// Simulate a crash inside the next record: the framing byte (the ONLY
	// byte this format's length prefix can be), then the start of a payload
	// for height 6 round 1 - and no checksum, because the write never
	// completed. A tail of this shape is what a crash actually costs, and
	// truncating it is what the repair is for.
	logPath := filepath.Join(dir, lockLogName)
	intactLen, err := fileSize(logPath)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tear := make([]byte, 0, 1+8+4+2)
	tear = append(tear, byte(lockPayloadLen))
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
