package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

// M7 step 1: certs.log is SEGMENTED. The pre-M7 log was a single append-only
// file, so nothing could be pruned out of it; the 18-hour three-host run
// measured it at 381 MB of a 558 MB data directory (68%, ~485 B/block). A
// segment holds certRecordsPerSegment records, which is a fixed-size chunk the
// pruner can delete whole.

// writeCertSegment writes records [first, first+count) of `payload` bytes into
// segment `idx`, framed exactly as PutCert frames one. It bypasses PutCert - and
// its per-record fsync - so a fixture of a thousand records does not turn into a
// thousand disk waits, and it lets a test build a multi-segment directory
// directly. The segment header is written first, as every file this package
// writes must begin with one.
func writeCertSegment(tb testing.TB, dir string, idx uint64, first uint64, count, payload int) {
	tb.Helper()
	body := make([]byte, payload)
	for i := range body {
		body[i] = byte(i)
	}
	var buf bytes.Buffer
	buf.WriteString(SegmentMagic)
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], SegmentFormatVersion)
	buf.Write(version[:])
	for i := 0; i < count; i++ {
		rec := make([]byte, certHeightLen+payload)
		binary.BigEndian.PutUint64(rec, first+uint64(i))
		copy(rec[certHeightLen:], body)
		var length [lengthFieldLen]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(rec)))
		var lengthSum [RecordTrailerLen]byte
		binary.BigEndian.PutUint32(lengthSum[:], crc32.Checksum(length[:], crcTable))
		framed := make([]byte, 0, RecordHeaderLen+len(rec)+RecordTrailerLen)
		framed = append(framed, length[:]...)
		framed = append(framed, lengthSum[:]...)
		framed = append(framed, rec...)
		var sum [RecordTrailerLen]byte
		binary.BigEndian.PutUint32(sum[:], crc32.Checksum(framed, crcTable))
		buf.Write(framed)
		buf.Write(sum[:])
	}
	if err := os.WriteFile(filepath.Join(dir, certSegmentName(idx)), buf.Bytes(), 0o644); err != nil {
		tb.Fatal(err)
	}
}

// TestCertSegmentsIndexEveryHeightAndServeAtASegmentBoundary is the reader half
// of the segmentation: every height in every segment is indexed on Open, and the
// FIRST record of a non-zero segment - the record a segment-boundary reader has
// to find without knowing anything about the previous segment - is served.
func TestCertSegmentsIndexEveryHeightAndServeAtASegmentBoundary(t *testing.T) {
	dir := t.TempDir()
	// Three segments of 1000 records each, covering heights 1..3000. Segment 0
	// holds 1000 records (heights 1..1000) rather than the 999 a block segment
	// holds, because certificate segments are sized by RECORD COUNT and are not
	// keyed by height.
	for idx := uint64(0); idx < 3; idx++ {
		writeCertSegment(t, dir, idx, idx*certRecordsPerSegment+1, certRecordsPerSegment, 7)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, tc := range []struct{ height, seg uint64 }{
		{1, 0},
		{certRecordsPerSegment, 0},
		{certRecordsPerSegment + 1, 1}, // the boundary record
		{2 * certRecordsPerSegment, 1},
		{2*certRecordsPerSegment + 1, 2},
		{3 * certRecordsPerSegment, 2},
	} {
		if got := s.certIndex[tc.height].seg; got != tc.seg {
			t.Fatalf("height %d was indexed in segment %d, want %d", tc.height, got, tc.seg)
		}
		got, ok := s.CertAt(tc.height)
		if !ok {
			t.Fatalf("CertAt(%d): no certificate at a segment boundary", tc.height)
		}
		if want := len(make([]byte, 7)); len(got) != want {
			t.Fatalf("CertAt(%d) served %d payload bytes, want %d", tc.height, len(got), want)
		}
	}
	if _, ok := s.CertAt(3*certRecordsPerSegment + 1); ok {
		t.Fatal("CertAt served a height no segment holds")
	}
	// The last segment is the append target, so a restart must resume there
	// instead of opening a fresh segment per process.
	if s.certSeg != 2 {
		t.Fatalf("active certificate segment is %d, want the highest present (2)", s.certSeg)
	}
}

// TestPutCertRotatesAtTheSegmentSize pins the write half: the record after a
// full segment lands in the next segment, with that segment's header already in
// place, and the boundary record is still served after a reopen.
func TestPutCertRotatesAtTheSegmentSize(t *testing.T) {
	dir := t.TempDir()
	// Fill segment 0 exactly, without 1000 fsyncs.
	writeCertSegment(t, dir, 0, 1, certRecordsPerSegment, 5)

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	next := uint64(certRecordsPerSegment + 1)
	if err := s.PutCert(next, []byte("boundary")); err != nil {
		t.Fatal(err)
	}
	if loc := s.certIndex[next]; loc.seg != 1 {
		t.Fatalf("record %d was written to segment %d, want 1", next, loc.seg)
	}
	if s.certSeg != 1 {
		t.Fatalf("active segment after rotation is %d, want 1", s.certSeg)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The new segment begins with the format header: a file written by a build
	// that skipped it would be refused by the next Open.
	raw, err := os.ReadFile(filepath.Join(dir, certSegmentName(1)))
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(SegmentMagic), 0, 0, 0, SegmentFormatVersion)
	if len(raw) < SegmentHeaderLen || !bytes.Equal(raw[:SegmentHeaderLen], want) {
		t.Fatalf("segment 1 begins %q, want the segment header", raw[:min(len(raw), SegmentHeaderLen)])
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, ok := s2.CertAt(next); !ok || string(got) != "boundary" {
		t.Fatalf("CertAt(%d) after reopen = %q, %v; want the boundary record", next, got, ok)
	}
	if err := s2.PutCert(next+1, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if loc := s2.certIndex[next+1]; loc.seg != 1 {
		t.Fatalf("the reopened store appended to segment %d, want 1", loc.seg)
	}
}

// TestALegacyCertLogIsStillReadable pins the upgrade path. A directory written
// before M7 holds one certs.log; this build never appends to it again, but it
// must still serve the history that file proves, and new certificates must go to
// the segmented archive.
func TestALegacyCertLogIsStillReadable(t *testing.T) {
	dir := certFixture(t, 3, 9) // writes certs.log with heights 1..3

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= 3; h++ {
		if loc := s.certIndex[h]; loc.seg != legacyCertSeg {
			t.Fatalf("height %d was indexed in segment %d, want the legacy log", h, loc.seg)
		}
		if _, ok := s.CertAt(h); !ok {
			t.Fatalf("CertAt(%d): the legacy certificate log is no longer readable", h)
		}
	}
	if !s.legacyCertExist || s.legacyCertMax != 3 || s.legacyCertRecs != 3 {
		t.Fatalf("legacy cert log was scanned as exist=%v max=%d records=%d, want true/3/3",
			s.legacyCertExist, s.legacyCertMax, s.legacyCertRecs)
	}
	// New records are segmented; the legacy file is not reopened for appending.
	if err := s.PutCert(4, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if loc := s.certIndex[4]; loc.seg == legacyCertSeg {
		t.Fatal("PutCert appended to the legacy certs.log")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, certSegmentName(0))); err != nil {
		t.Fatalf("no certificate segment was created for the new record: %v", err)
	}
}

// TestATornCertSegmentTailIsTruncatedAndEarlierSegmentsSurvive is the
// segmentation's equivalent of the single-file torn-tail policy: only the LAST
// segment may be cut, and every earlier segment still serves.
func TestATornCertSegmentTailIsTruncatedAndEarlierSegmentsSurvive(t *testing.T) {
	dir := t.TempDir()
	writeCertSegment(t, dir, 0, 1, 4, 6)
	writeCertSegment(t, dir, 1, 5, 4, 6)
	last := filepath.Join(dir, certSegmentName(1))
	intact, err := os.Stat(last)
	if err != nil {
		t.Fatal(err)
	}
	// A complete, valid header for a record that never finished arriving.
	f, err := os.OpenFile(last, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	var header [RecordHeaderLen]byte
	binary.BigEndian.PutUint64(header[:8], 40)
	binary.BigEndian.PutUint32(header[8:], crc32.Checksum(header[:8], crcTable))
	if _, err := f.Write(append(header[:], 1, 2, 3)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("a torn certificate segment tail must be truncated, not fail Open: %v", err)
	}
	defer s.Close()
	for h := uint64(1); h <= 8; h++ {
		if _, ok := s.CertAt(h); !ok {
			t.Fatalf("CertAt(%d) after the torn-tail repair: no certificate", h)
		}
	}
	if st, err := os.Stat(last); err != nil || st.Size() != intact.Size() {
		t.Fatalf("the torn tail was not cut: size = %d, want %d (%v)", st.Size(), intact.Size(), err)
	}
}

// TestACorruptRecordInAnEarlierCertSegmentFailsOpen is the other half: a
// COMPLETE record whose length prefix does not checksum is corruption, not a
// crash shape, and a non-final segment cannot be "repaired" by truncation - the
// segment after it was written only after this one was complete.
func TestACorruptRecordInAnEarlierCertSegmentFailsOpen(t *testing.T) {
	dir := t.TempDir()
	writeCertSegment(t, dir, 0, 1, 4, 6)
	writeCertSegment(t, dir, 1, 5, 4, 6)
	path := filepath.Join(dir, certSegmentName(0))
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the FIRST record's length checksum in the earlier segment.
	var sum [RecordTrailerLen]byte
	if _, err := f.ReadAt(sum[:], int64(SegmentHeaderLen+lengthFieldLen)); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(sum[:], binary.BigEndian.Uint32(sum[:])^0xFFFF)
	if _, err := f.WriteAt(sum[:], int64(SegmentHeaderLen+lengthFieldLen)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if _, err := Open(dir); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("corruption in an earlier certificate segment gave %v, want ErrCorruptRecord", err)
	}
}
