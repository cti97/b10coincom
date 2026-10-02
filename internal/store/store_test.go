package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendAndReadRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	payload := []byte("block-at-height-1")
	if err := s.Append(1, payload); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read(1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("read %q, want %q", got, payload)
	}
}

func TestHeightReportsHighestStored(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()

	if _, ok := s.Height(); ok {
		t.Fatal("empty store should report no height")
	}
	for h := uint64(1); h <= 3; h++ {
		if err := s.Append(h, []byte(fmt.Sprintf("h%d", h))); err != nil {
			t.Fatal(err)
		}
	}
	h, ok := s.Height()
	if !ok || h != 3 {
		t.Fatalf("Height = %d, %v; want 3, true", h, ok)
	}
}

func TestReopenPreservesData(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for h := uint64(1); h <= 5; h++ {
		if err := s.Append(h, []byte(fmt.Sprintf("payload-%d", h))); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	h, ok := s2.Height()
	if !ok || h != 5 {
		t.Fatalf("Height after reopen = %d, %v; want 5, true", h, ok)
	}
	got, err := s2.Read(3)
	if err != nil || string(got) != "payload-3" {
		t.Fatalf("Read(3) = %q, %v", got, err)
	}
}

func TestReadMissingHeightFails(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	if err := s.Append(1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAppendRejectsNonSequentialHeight(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	if err := s.Append(5, []byte("x")); !errors.Is(err, ErrBadHeight) {
		t.Fatalf("expected ErrBadHeight, got %v", err)
	}
}

// A crash mid-write leaves a truncated trailing record. Open must discard
// it rather than failing, so the node can restart and re-sync.
func TestTruncatedTailIsDiscardedOnOpen(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for h := uint64(1); h <= 3; h++ {
		if err := s.Append(h, []byte(fmt.Sprintf("good-%d", h))); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
	good, err := os.Stat(seg)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(seg, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// Length prefix claims 64 bytes, but only 3 follow.
	if _, err := f.Write([]byte{64, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after a truncated tail must succeed, got %v", err)
	}
	defer s2.Close()

	h, ok := s2.Height()
	if !ok || h != 3 {
		t.Fatalf("Height = %d, %v; want 3, true", h, ok)
	}
	if _, err := s2.Read(3); err != nil {
		t.Fatalf("good records must survive: %v", err)
	}
	// The partial record must be cut out of the file itself, not merely
	// skipped by the index; otherwise the next segment write lands after it.
	dropped, err := os.Stat(seg)
	if err != nil {
		t.Fatal(err)
	}
	if dropped.Size() != good.Size() {
		t.Fatalf("Open left the partial tail in place: size = %d, want %d", dropped.Size(), good.Size())
	}
}

// A corrupted payload must be detected by the checksum.
func TestCorruptPayloadIsDetected(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Append(1, []byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	s.Close()

	seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	raw[2] ^= 0xFF // flip a payload byte; the length stays intact, so only the checksum can catch this
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.Read(1); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("expected ErrCorruptRecord, got %v", err)
	}
}

func TestSegmentRolloverAtBlocksPerSegment(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for h := uint64(1); h <= BlocksPerSegment+2; h++ {
		if err := s.Append(h, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected a second segment file, got %d files", len(entries))
	}
}

// Beyond the brief's eight tests: binding constraint check. A damaged record
// in a NON-final segment is genuine corruption — earlier segments are closed,
// so no crash could have cut a record there — and must fail Open instead of
// being truncated away like a crashed tail.
func TestCorruptRecordInEarlierSegmentFailsOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= BlocksPerSegment+2; h++ {
		if err := s.Append(h, []byte("a")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Heights 1..999 live in segment 0, which is non-final here because
	// segment 1 already holds heights 1000..1002.
	seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	raw[1] ^= 0xFF // corrupt the first record's payload byte, keeping the length valid
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("corruption in a non-final segment must fail Open with ErrCorruptRecord, got %v", err)
	}
}

// A complete record with a bad checksum followed by a partial trailing record
// is the layout that exposed a height-renumbering bug in recovery: the corrupt
// record's bytes must NOT survive while the in-memory height is rewound. The
// repair must keep the corrupt record at its own height, so that appending on
// top and reopening yields the same heights.
func TestCorruptCompleteRecordThenPartialTailKeepsHeights(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(1, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(2, []byte("two")); err != nil {
		t.Fatal(err)
	}
	s.Close()

	seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	// Record 1 occupies bytes 0..7 (varint len + payload + crc32), so record 2
	// starts at 8 and its payload begins at 9.
	raw[9] ^= 0xFF
	// Append a truncated trailing record: a length prefix claiming 64 bytes
	// with only 3 following.
	raw = append(raw, 64, 1, 2, 3)
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after repair must succeed: %v", err)
	}
	h, _ := s2.Height()
	if h != 2 {
		t.Fatalf("repaired Height() = %d, want 2 - the corrupt complete record keeps its own height", h)
	}
	if _, err := s2.Read(2); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("Read(2) = %v, want ErrCorruptRecord", err)
	}
	if err := s2.Append(3, []byte("three")); err != nil {
		t.Fatal(err)
	}
	s2.Close()

	s3, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if h3, _ := s3.Height(); h3 != 3 {
		t.Fatalf("reopened Height() = %d, want 3 - heights were renumbered", h3)
	}
	if b, err := s3.Read(3); err != nil || string(b) != "three" {
		t.Fatalf("Read(3) = %q, %v; want \"three\", nil", b, err)
	}
}

// Read must return a copy: mutating the returned slice must not corrupt the
// store's view of the recorded bytes.
func TestReadReturnsACopy(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Append(1, []byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read(1)
	if err != nil {
		t.Fatal(err)
	}
	got[0] = 'Z'
	again, err := s.Read(1)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != "abcdef" {
		t.Fatalf("mutation of a returned slice changed the store: got %q", again)
	}
}

// The layout admits a zero-length payload (a 5-byte record): an empty payload
// must round-trip, and Read must hand back a non-nil, zero-length slice.
func TestZeroLengthPayloadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(1, []byte{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(2, []byte("after")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Read(1); err != nil {
		t.Fatal(err)
	} else if got == nil || len(got) != 0 {
		t.Fatalf("fresh Read(1) = %#v (len %d), want non-nil zero-length slice", got, len(got))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, err := s2.Read(1); err != nil {
		t.Fatal(err)
	} else if got == nil || len(got) != 0 {
		t.Fatalf("reopened Read(1) = %#v (len %d), want non-nil zero-length slice", got, len(got))
	}
	if h, ok := s2.Height(); !ok || h != 2 {
		t.Fatalf("reopened Height() = %d, %v; want 2, true", h, ok)
	}
	if b, err := s2.Read(2); err != nil || string(b) != "after" {
		t.Fatalf("Read(2) = %q, %v; want \"after\", nil", b, err)
	}
}
