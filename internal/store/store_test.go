package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
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
// it rather than failing, so the node can restart and re-sync. The tail here
// is the shape a crash really leaves: a COMPLETE, VALID header whose payload
// and trailer never arrived.
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
	// A valid header claiming 64 bytes, then only 3 of them: the file ends
	// inside the record, which is the one thing only a crash can produce.
	var header [RecordHeaderLen]byte
	binary.BigEndian.PutUint64(header[:8], 64)
	binary.BigEndian.PutUint32(header[8:], crc32.Checksum(header[:8], crcTable))
	if _, err := f.Write(append(header[:], 1, 2, 3)); err != nil {
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

// A header of fewer than RecordHeaderLen bytes is the other shape a crash
// leaves: the write stopped inside the framing header itself. It is torn, not
// corrupt, because corruption changes bytes rather than removing them.
func TestPartialHeaderIsTreatedAsATornTail(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Append(1, []byte("one")); err != nil {
		t.Fatal(err)
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
	if _, err := f.Write([]byte{0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("a partial header must be truncated, not fail Open: %v", err)
	}
	defer s2.Close()
	if h, ok := s2.Height(); !ok || h != 1 {
		t.Fatalf("Height = %d, %v; want 1, true", h, ok)
	}
	if st, err := os.Stat(seg); err != nil || st.Size() != good.Size() {
		t.Fatalf("the partial header was not cut: size = %d, want %d (%v)", st.Size(), good.Size(), err)
	}
}

// A corrupted payload must be detected by the checksum, and the scan must STOP
// there: the record's own length is what would say where the next one starts,
// so indexing past a record whose checksum failed would invent heights, and
// truncating there would delete committed blocks. Open refuses, and the file
// is left exactly as it was found.
func TestCorruptPayloadStopsTheScanAndFailsOpen(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Append(1, []byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(2, []byte("ghijkl")); err != nil {
		t.Fatal(err)
	}
	s.Close()

	seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	raw[SegmentHeaderLen+RecordHeaderLen+2] ^= 0xFF // a payload byte of record 1; the framing stays valid
	before := append([]byte(nil), raw...)
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("a corrupt payload must fail Open with ErrCorruptRecord, got %v", err)
	}
	after, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Open rewrote the segment: corruption must fail loudly, never be repaired away")
	}
}

// S-2's own case: a single flipped bit in a record's LENGTH PREFIX. The fixed
// width header checksums the length, so the corrupt length fails its own check
// BEFORE it is used to find the record's end - Open refuses rather than
// "repairing" the log by truncating everything from there, which is what
// silently deleted committed blocks before the fix.
//
// Two shapes are exercised: a middle record whose corrupt length would still
// frame inside the file, and the FINAL record's corrupt length, which used to
// overrun EOF and be deleted as if it were a torn tail.
func TestCorruptLengthPrefixIsRefusedNotTrusted(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flips func(raw []byte) int
	}{
		{
			name: "middle record",
			// The length field of record 2 (after record 1's "aaa").
			flips: func(raw []byte) int { return SegmentHeaderLen + RecordHeaderLen + 3 + RecordTrailerLen },
		},
		{
			name: "final record overrunning EOF",
			// The length field of the last record: flipping a high bit used
			// to make the record appear to run past EOF and be truncated away.
			flips: func(raw []byte) int {
				rec := SegmentHeaderLen + RecordHeaderLen + 3 + RecordTrailerLen
				rec += RecordHeaderLen + 3 + RecordTrailerLen
				return rec
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			for h := uint64(1); h <= 3; h++ {
				if err := s.Append(h, []byte("aaa")); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
			raw, err := os.ReadFile(seg)
			if err != nil {
				t.Fatal(err)
			}
			raw[tc.flips(raw)] ^= 0x80 // one bit of the big-endian length
			before := append([]byte(nil), raw...)
			if err := os.WriteFile(seg, raw, 0o644); err != nil {
				t.Fatal(err)
			}

			if _, err := Open(dir); !errors.Is(err, ErrCorruptRecord) {
				t.Fatalf("a corrupt length prefix must fail Open with ErrCorruptRecord, got %v", err)
			}
			after, err := os.ReadFile(seg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("Open truncated the segment: a corrupt length was trusted as a torn tail")
			}
		})
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
	raw[SegmentHeaderLen+RecordHeaderLen+1] ^= 0xFF // corrupt the first record's payload byte, keeping the framing valid
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("corruption in a non-final segment must fail Open with ErrCorruptRecord, got %v", err)
	}
}

// A complete record with a bad checksum followed by a partial trailing record
// is the layout that once exposed a height-renumbering bug: the old repair kept
// the corrupt record at its height, truncated the partial tail, and appending
// on top then renumbered everything. The scan now STOPS at the corrupt record,
// so that repair cannot run at all: the store refuses to open, the corrupt
// bytes stay exactly where they are for a human to inspect, and no height is
// ever invented or renumbered. Recovery is an operator's deliberate act
// (restore a backup, or cut the file by hand), not an automatic silence.
func TestCorruptCompleteRecordThenPartialTailFailsOpen(t *testing.T) {
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
	// Corrupt record 2's payload: record 1 is header(12)+3+trailer(4), so
	// record 2's payload starts 12 bytes into it.
	raw[SegmentHeaderLen+RecordHeaderLen+3+RecordTrailerLen+RecordHeaderLen+1] ^= 0xFF
	// Then append a torn trailing record: a valid header claiming 64 bytes
	// with only 3 following.
	var header [RecordHeaderLen]byte
	binary.BigEndian.PutUint64(header[:8], 64)
	binary.BigEndian.PutUint32(header[8:], crc32.Checksum(header[:8], crcTable))
	raw = append(raw, append(header[:], 1, 2, 3)...)
	before := append([]byte(nil), raw...)
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("a corrupt complete record must fail Open, got %v", err)
	}
	after, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Open repaired the file instead of refusing: the scan did not stop at the first corruption")
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

// A length prefix is stored data. With the fixed-width header the length is
// checksummed, so a lying length has to be given a matching header checksum to
// reach the offset arithmetic at all - which is exactly the hand-crafted
// attack this test builds. Read must bound it BEFORE slicing: a length near
// 2^64 makes the record's end wrap negative, and the guard must still report
// corruption rather than panic.
func TestReadRejectsOverflowingLengthPrefixInsteadOfPanicking(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The store is deliberately left OPEN while its file is rewritten
	// underneath it: a reopen would refuse the file and hide the bug.
	defer s.Close()
	for h := uint64(1); h <= 3; h++ {
		if err := s.Append(h, []byte(fmt.Sprintf("payload-%d", h))); err != nil {
			t.Fatal(err)
		}
	}

	seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < SegmentHeaderLen+RecordHeaderLen+RecordTrailerLen {
		t.Fatalf("segment is %d bytes; the corrupt-prefix layout needs more", len(raw))
	}
	// Claim 2^64-1 payload bytes and re-checksum the header, so the length is
	// "trustworthy" as far as the framing check goes and the arithmetic is
	// really reached.
	binary.BigEndian.PutUint64(raw[SegmentHeaderLen:SegmentHeaderLen+8], math.MaxUint64)
	binary.BigEndian.PutUint32(raw[SegmentHeaderLen+8:SegmentHeaderLen+RecordHeaderLen], crc32.Checksum(raw[SegmentHeaderLen:SegmentHeaderLen+8], crcTable))
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// Must report corruption, not panic.
	if _, err := s.Read(1); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("Read(1) = %v, want an error wrapping ErrCorruptRecord (and no panic)", err)
	}
}

// The certificate log (audit C-7) is keyed by height and survives a reopen:
// the bytes a node served for a block it holds must outlive the process that
// adopted it, which is what lets a restarted validator answer for history
// committed before it restarted. First record for a height wins - a committed
// height never changes its block - and an unknown height is an absence, not an
// error or a panic.
func TestCertLogSurvivesReopenAndKeepsTheFirstRecordPerHeight(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(1, []byte("certificate-one")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(2, []byte("certificate-two")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(1, []byte("a second claim for the same height")); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.CertAt(1); !ok || string(got) != "certificate-one" {
		t.Fatalf("CertAt(1) = %q, %v; want the first record for that height", got, ok)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen with a certificate log: %v", err)
	}
	defer s2.Close()
	for h, want := range map[uint64]string{1: "certificate-one", 2: "certificate-two"} {
		got, ok := s2.CertAt(h)
		if !ok || string(got) != want {
			t.Fatalf("CertAt(%d) after reopen = %q, %v; want %q", h, got, ok, want)
		}
	}
	if _, ok := s2.CertAt(3); ok {
		t.Fatal("CertAt on a height with no certificate reported one")
	}
	// The returned slice is a copy: mutating it must not change what is served.
	got, _ := s2.CertAt(1)
	got[0] = 'Z'
	if again, _ := s2.CertAt(1); string(again) != "certificate-one" {
		t.Fatalf("mutating a returned certificate changed the log: %q", again)
	}
}

// A crash mid-append leaves the certificate log with a torn tail. The tear is
// the one shape only a crash can leave, so Open truncates it and every earlier
// certificate survives: losing one height's evidence costs that height's
// service, never the node's ability to start. Corruption in a COMPLETE record
// is a different thing and still stops the scan.
func TestTornCertificateTailIsTruncatedAndEarlierRecordsSurvive(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(1, []byte("certificate-one")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, certLogName)
	intact, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// A complete, valid header for a record that never finished arriving.
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	var header [RecordHeaderLen]byte
	binary.BigEndian.PutUint64(header[:8], 40)
	binary.BigEndian.PutUint32(header[8:], crc32.Checksum(header[:8], crcTable))
	if _, err := f.Write(append(header[:], 1, 2, 3)); err != nil {
		t.Fatal(err)
	}
	f.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("a torn certificate tail must be truncated, not fail Open: %v", err)
	}
	defer s2.Close()
	if got, ok := s2.CertAt(1); !ok || string(got) != "certificate-one" {
		t.Fatalf("the certificate before the tear was lost: %q, %v", got, ok)
	}
	if st, err := os.Stat(logPath); err != nil || st.Size() != intact.Size() {
		t.Fatalf("the torn certificate tail was not cut: size = %d, want %d (%v)", st.Size(), intact.Size(), err)
	}
}

// Audit O-5: the genesis identity is recorded once and compared on every
// later check, so a mismatched genesis is named for what it is rather than
// surfacing after replay as a divergence.
func TestCheckGenesisRecordsOnceAndRefusesAMismatch(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var a, b [32]byte
	a[0], b[0] = 0xA1, 0xB2
	if err := s.CheckGenesis(a); err != nil {
		t.Fatalf("recording the genesis: %v", err)
	}
	if err := s.CheckGenesis(a); err != nil {
		t.Fatalf("the same genesis must be accepted again: %v", err)
	}
	if err := s.CheckGenesis(b); !errors.Is(err, ErrWrongGenesis) {
		t.Fatalf("a different genesis gave %v, want ErrWrongGenesis", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.CheckGenesis(b); !errors.Is(err, ErrWrongGenesis) {
		t.Fatalf("the recorded genesis did not survive reopen: %v, want ErrWrongGenesis", err)
	}
	if err := s2.CheckGenesis(a); err != nil {
		t.Fatalf("the recorded genesis was not accepted after reopen: %v", err)
	}
}
