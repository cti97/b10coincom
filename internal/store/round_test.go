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
	if len(raw) != SegmentHeaderLen+RecordHeaderLen+roundPayloadLen+RecordTrailerLen {
		t.Fatalf("round log is %d bytes; want the %d-byte segment header, the %d-byte framed header, the fixed %d-byte payload (8-byte height, 4-byte round) and the %d-byte CRC",
			len(raw), SegmentHeaderLen, RecordHeaderLen, roundPayloadLen, RecordTrailerLen)
	}
	raw[SegmentHeaderLen+RecordHeaderLen+2] ^= 0xFF // a byte inside the record's fixed-width height field
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

// countRoundFrames frames the round log and returns how many records it holds.
// It is the round log's half of countLockFrames, and it fails the test on a
// framing error rather than guessing, so a bound asserted with it cannot pass
// over a corrupt file.
func countRoundFrames(t *testing.T, dir string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, roundLogName))
	if err != nil {
		t.Fatal(err)
	}
	n, off := 0, int64(SegmentHeaderLen)
	for off < int64(len(raw)) {
		_, recEnd, err := frame(raw, off, roundPayloadLen)
		if err != nil {
			t.Fatalf("framing rounds.log at offset %d: %v", off, err)
		}
		n++
		off = recEnd
	}
	return n
}

// PruneRounds drops every round strictly below the committed head and keeps the
// two that can still be read - the head's own record (conservative headroom)
// and the head+1 round a restart restores - across both the live store and a
// reopen (review F3). This is the round log's half of the C-13 fix.
func TestPruneRoundsDropsBelowTheCommittedHead(t *testing.T) {
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
	// A round at every committed height, plus the head+1 round being judged.
	for h := uint64(1); h <= 6; h++ {
		if err := s.PutRound(RoundRecord{Height: h, Round: uint32(h)}); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.PruneRounds(5); err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h < 5; h++ {
		if _, ok := s.RoundAt(h); ok {
			t.Fatalf("RoundAt(%d) survived a prune below the committed head 5", h)
		}
	}
	if _, ok := s.RoundAt(5); !ok {
		t.Fatal("the head's own round was pruned; the fix deliberately keeps it")
	}
	if got, ok := s.RoundAt(6); !ok || got != 6 {
		t.Fatalf("the head+1 round was pruned: that record is the round a restart reads, so dropping it breaks the restart-resume property (got %d,%v)", got, ok)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The reopen prunes below its committed head too, so the same rounds stand
	// and the same heights are absent.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	for h := uint64(1); h < 5; h++ {
		if _, ok := s2.RoundAt(h); ok {
			t.Fatalf("after reopen RoundAt(%d) is present for a height below the committed head", h)
		}
	}
	if _, ok := s2.RoundAt(5); !ok {
		t.Fatal("the head's own round did not survive the reopen")
	}
	if got, ok := s2.RoundAt(6); !ok || got != 6 {
		t.Fatalf("after reopen RoundAt(6) = %d,%v; the head+1 round must survive - without it a restarted validator re-enters round 0 for a height the committee has already carried forward", got, ok)
	}
}

// A long-running validator must not grow its round log without bound (review
// F3). Each round ENTERED appends and fsyncs a frame, and each height keeps a
// map entry forever, so a node that runs for thousands of heights used to carry
// one frame per round per height with no prune path. This test drives 600
// heights through the live rule - PutRound at the height being judged, then the
// head advancing past it (PruneRounds, exactly as Chain.Append calls it) - and
// asserts three things: the file stays bounded, the map stays bounded, and the
// restart-resume property holds at EVERY step (the round persisted for head+1
// is readable, so a crash here resumes at the right round rather than at 0).
// The height count is 600 rather than thousands only because every PutRound
// fsyncs; one frame per round entered would already be ~2400 frames against a
// bound of ~264.
func TestPruneRoundsBoundsALongRunningValidatorsLog(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const heights = 600
	const roundsPerHeight = 2 // rounds 0..2 entered while judging one height

	for h := uint64(1); h <= heights; h++ {
		// The engine judges height h (head is h-1) and enters rounds 0..2.
		for r := uint32(0); r <= roundsPerHeight; r++ {
			if err := s.PutRound(RoundRecord{Height: h, Round: r}); err != nil {
				t.Fatal(err)
			}
		}
		// Committing h prunes strictly below h, exactly as Chain.Append does.
		if err := s.PruneRounds(h); err != nil {
			t.Fatal(err)
		}
		// The engine for the NEXT height persists its round; a crash right here
		// must resume at that round, not at 0.
		if err := s.PutRound(RoundRecord{Height: h + 1, Round: 7}); err != nil {
			t.Fatal(err)
		}
		if got, ok := s.RoundAt(h + 1); !ok || got != 7 {
			t.Fatalf("at head %d the head+1 round is %d,%v; want the persisted 7 - the restart-resume property must hold at every step", h, got, ok)
		}
	}

	frames := countRoundFrames(t, dir)
	t.Logf("%d heights x %d rounds/height: rounds.log holds %d frames (one frame per round entered would be %d; the map holds %d entries)",
		heights, roundsPerHeight+1, frames, heights*(roundsPerHeight+2), len(s.rounds))
	// After the last prune the log holds the live rounds plus at most the
	// compaction threshold. Allow the last iteration's few puts on top.
	if max := roundCompactThreshold + 2*(roundsPerHeight+2); frames > max {
		t.Fatalf("rounds.log holds %d frames after %d heights, want at most %d: the log grows without bound", frames, heights, max)
	}
	if live := len(s.rounds); live > 2 {
		t.Fatalf("the round map holds %d entries after the head moved past %d heights, want at most 2 (head and head+1)", live, heights)
	}
	unbounded := heights * (roundsPerHeight + 2)
	if frames*4 >= unbounded {
		t.Fatalf("rounds.log holds %d frames; one frame per round entered would be %d, and the bound must be far below it", frames, unbounded)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen: the log replays to the same bounded set, and the head+1 round the
	// restart needs is still there.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, ok := s2.RoundAt(heights); !ok {
		t.Fatal("after reopen the committed head's round is gone")
	}
	if got, ok := s2.RoundAt(heights + 1); !ok || got != 7 {
		t.Fatalf("after reopen the head+1 round is %d,%v, want 7: a restart must resume at the persisted round", got, ok)
	}
}
