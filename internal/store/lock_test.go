package store

import (
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
	if len(raw) != 1+2+32+4 {
		t.Fatalf("lock log is %d bytes; expected the 1-byte length prefix, 2-byte varints, 32-byte ID and 4-byte CRC", len(raw))
	}
	raw[3] ^= 0xFF // first payload byte: inside the record's payload
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

	// Simulate a crash inside the next record: a length prefix, the start of
	// a payload for height 6 round 1 - and no checksum, because the write
	// never completed.
	logPath := filepath.Join(dir, lockLogName)
	intactLen, err := fileSize(logPath)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tear := []byte{byte(2 + 32), 0x06, 0x01, 0xAA, 0xBB} // length, height 6, round 1, 2 of 32 ID bytes
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

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// A lock record's payload must be laid out exactly as the store's CRC framing
// wraps it, height-then-round-then-block-ID: this is the record a restart
// reads and the framing a foreign tail-byte flip is tested against.
func TestLockRecordPayloadFraming(t *testing.T) {
	raw := encodeLockRecord(LockRecord{Height: 5, Round: 2, BlockID: idOf(7)})
	if len(raw) != 34 {
		t.Fatalf("payload is %d bytes, want 34 (1-byte height + 1-byte round + 32-byte ID)", len(raw))
	}
	if raw[0] != 0x05 || raw[1] != 0x02 {
		t.Fatalf("payload head % x, want height 0x05 then round 0x02", raw[:2])
	}
	got, err := decodeLockRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Height != 5 || got.Round != 2 || got.BlockID != idOf(7) {
		t.Fatalf("decode = %+v, want the encoded record", got)
	}
	// Strictness: a payload claiming a round above uint32, or a block ID with
	// junk after it, is corruption - it must be rejected rather than decoded
	// with silently wrapped or dropped bytes.
	var huge []byte
	huge = append(huge, 0x05)
	huge = append(huge, uvarintBytes(1<<32)...)
	huge = append(huge, make([]byte, 32)...)
	if _, err := decodeLockRecord(huge); err == nil {
		t.Fatal("a round above uint32 must not decode silently truncated")
	}
	trailing := append(encodeLockRecord(LockRecord{Height: 5, Round: 2, BlockID: idOf(1)}), 0xFF)
	if _, err := decodeLockRecord(trailing); err == nil {
		t.Fatal("a payload with junk after the block ID must be rejected, not decoded")
	}
}

func uvarintBytes(v uint64) []byte {
	var buf [10]byte
	n := 0
	for v > 0x7F {
		buf[n] = byte(v) | 0x80
		v >>= 7
		n++
	}
	buf[n] = byte(v)
	return buf[:n+1]
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
