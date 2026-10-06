package store

// The round log's own pins (audit C-3). It is the lock log's sibling in shape
// - fixed-width, framed, fsynced, newest-record-wins - but not in stakes: a
// lock is a safety promise, a round is a liveness position. The tests below
// still hold it to the framing discipline, because a log that cannot be framed
// cannot be trusted to say which round stands, and a silent truncation of a
// complete record is exactly the repair-by-deletion the store refuses.

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

// TestPutRoundSurvivesReopen: the round a validator had reached must be read
// back by the same Open that replays the blocks, so a restart resumes where
// the crash left off. The newest record per height wins, exactly as a lock's
// moves do.
func TestPutRoundSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := s.RoundAt(2); ok {
		t.Fatal("a never-recorded height reported a round")
	}
	if err := s.PutRound(RoundRecord{Height: 2, Round: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRound(RoundRecord{Height: 2, Round: 4}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRound(RoundRecord{Height: 3, Round: 7}); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.RoundAt(2); !ok || got != 4 {
		t.Fatalf("RoundAt(2) before reopen = %d,%v; want the NEWEST round 4", got, ok)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, ok := s2.RoundAt(2); !ok || got != 4 {
		t.Fatalf("RoundAt(2) after reopen = %d,%v; want the newest round 4", got, ok)
	}
	if got, ok := s2.RoundAt(3); !ok || got != 7 {
		t.Fatalf("RoundAt(3) after reopen = %d,%v; want 7", got, ok)
	}
	if _, ok := s2.RoundAt(1); ok {
		t.Fatal("RoundAt(1) reported a round nobody recorded")
	}
}

// A structurally complete round record whose checksum no longer matches must
// fail Open loudly rather than read as "round 0". The round is not a safety
// promise, so the alternative is survivable - but the bytes after an
// unframeable record cannot be located, and silently resuming a validator at
// round 0 for a contested height is the defect C-3 exists to remove.
func TestOpenFailsOnCorruptRoundRecord(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutRound(RoundRecord{Height: 5, Round: 2}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, roundLogName)
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != RecordHeaderLen+roundPayloadLen+RecordTrailerLen {
		t.Fatalf("round log is %d bytes; want the %d-byte framed header, the fixed %d-byte payload (8-byte height, 4-byte round) and the %d-byte CRC",
			len(raw), RecordHeaderLen, roundPayloadLen, RecordTrailerLen)
	}
	raw[RecordHeaderLen+2] ^= 0xFF // a byte inside the record's fixed-width height field
	if err := os.WriteFile(logPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	fresh, err := Open(dir)
	if fresh != nil {
		_ = fresh.Close()
	}
	if err == nil {
		t.Fatal("a corrupt round record must fail Open, not open as round 0")
	}
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("corrupt round record: got %v, want an error wrapping ErrCorruptRecord", err)
	}
}

// A crash mid-write cuts the tail off the round log. The torn bytes must be
// truncated away - repaired, not read. Everything before the tear survives,
// the torn record is never read as a round, and appending afterwards works.
func TestTornRoundTailIsTruncatedNotReadAsARound(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	intact := RoundRecord{Height: 5, Round: 0}
	if err := s.PutRound(intact); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A COMPLETE, VALID framing header, then the start of the next payload -
	// and no checksum, because the write never completed. This is the shape a
	// crash actually leaves; truncating it is the repair.
	logPath := filepath.Join(dir, roundLogName)
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
	binary.BigEndian.PutUint64(lb[:], roundPayloadLen)
	tear = append(tear, lb[:]...)
	var hc [RecordTrailerLen]byte
	binary.BigEndian.PutUint32(hc[:], crc32.Checksum(tear[:lengthFieldLen], crcTable))
	tear = append(tear, hc[:]...)
	var hb [8]byte
	binary.BigEndian.PutUint64(hb[:], 6)
	var rb [4]byte
	binary.BigEndian.PutUint32(rb[:], 9)
	tear = append(tear, hb[:]...)
	tear = append(tear, rb[:]...)
	tear = append(tear, 0xAA, 0xBB) // 2 of the 4 round bytes
	var torn []byte
	torn = append(torn, prefix...)
	torn = append(torn, tear...)
	if err := os.WriteFile(logPath, torn, 0o644); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open with a torn round tail: %v (the tear is repairable, not fatal)", err)
	}
	defer s2.Close()
	if got, ok := s2.RoundAt(5); !ok || got != intact.Round {
		t.Fatalf("the record before the tear was lost: got %d,%v want round %d", got, ok, intact.Round)
	}
	if _, ok := s2.RoundAt(6); ok {
		t.Fatal("the torn trailing record was read as a round for height 6: partial bytes must never become a position")
	}
	if size, err := fileSize(logPath); err != nil || size != intactLen {
		t.Fatalf("torn tail not truncated on disk: size %d, want %d (err %v)", size, intactLen, err)
	}
	after := RoundRecord{Height: 6, Round: 1}
	if err := s2.PutRound(after); err != nil {
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
	if got, _ := s3.RoundAt(6); got != after.Round {
		t.Fatalf("RoundAt(6) after the repaired append = %d, want %d", got, after.Round)
	}
	if got, _ := s3.RoundAt(5); got != intact.Round {
		t.Fatalf("the first record was disturbed by the repair: %d, want %d", got, intact.Round)
	}
}

// TestRoundRecordPayloadFraming pins the fixed width the framing check relies
// on: a payload of any other size must never decode into a position.
func TestRoundRecordPayloadFraming(t *testing.T) {
	rec := RoundRecord{Height: 0x0102030405060708, Round: 0x0a0b0c0d}
	payload := encodeRoundRecord(rec)
	if len(payload) != roundPayloadLen {
		t.Fatalf("encodeRoundRecord produced %d bytes, want the constant %d", len(payload), roundPayloadLen)
	}
	got, err := decodeRoundRecord(payload)
	if err != nil {
		t.Fatalf("decodeRoundRecord: %v", err)
	}
	if got != rec {
		t.Fatalf("round-trip = %+v, want %+v", got, rec)
	}
	if _, err := decodeRoundRecord(payload[:len(payload)-1]); err == nil {
		t.Fatal("a short payload decoded into a round: the strict width check is gone")
	}
	if _, err := decodeRoundRecord(append(append([]byte(nil), payload...), 0)); err == nil {
		t.Fatal("an oversized payload decoded into a round: the strict width check is gone")
	}
}
