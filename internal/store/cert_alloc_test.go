package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Audit S-12: the certificate log is the one log that is NEVER compacted - one
// record per committed height, kept forever, because serving the certificate
// for an old height is the whole point of the file - so it is also the one log
// whose size is guaranteed to grow for the life of the chain. Open must not pay
// for that size.
//
// The tests below are the durable half of the fix. They construct the state
// instead of provoking it: a directory with N certificate records of a known
// payload width is written, closed, and then reopened with the allocator
// measured. No RSS sampling, no timing, no race - two runs of the same
// directory allocate the same bytes.

// certFixture writes `records` certificate records of `payload` bytes each, in
// one append, framed exactly as PutCert frames one: the segment header, then per
// record a checksummed length prefix, the big-endian height key, the opaque
// payload, and the trailer checksum over all of it.
//
// The write is done here rather than through PutCert because PutCert fsyncs
// every record, which turns a ten-thousand-record fixture into half a minute of
// disk waits to establish a fact about memory. openAllocated checks that every
// record was indexed, so a fixture that framed a record wrongly fails loudly
// instead of passing as a trivially small log.
func certFixture(tb testing.TB, records, payload int) string {
	tb.Helper()
	dir := tb.TempDir()
	body := make([]byte, payload)
	for i := range body {
		body[i] = byte(i)
	}
	var buf bytes.Buffer
	buf.WriteString(SegmentMagic)
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], SegmentFormatVersion)
	buf.Write(version[:])
	for h := uint64(1); h <= uint64(records); h++ {
		rec := make([]byte, certHeightLen+payload)
		binary.BigEndian.PutUint64(rec, h)
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
	if err := os.WriteFile(filepath.Join(dir, certLogName), buf.Bytes(), 0o644); err != nil {
		tb.Fatal(err)
	}
	return dir
}

// openAllocated returns the bytes Open allocates for a directory holding
// `records` certificate records of `payload` bytes each.
func openAllocated(tb testing.TB, records, payload int) uint64 {
	tb.Helper()
	dir := certFixture(tb, records, payload)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	s, err := Open(dir)
	if err != nil {
		tb.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if got := len(s.certIndex); got != records {
		tb.Fatalf("fixture indexed %d certificate records, want %d: the fixture is not framing what PutCert frames", got, records)
	}
	if err := s.Close(); err != nil {
		tb.Fatal(err)
	}
	return after.TotalAlloc - before.TotalAlloc
}

// TestCertLogOpenCostDoesNotScaleWithTheRecordPayload is the direct guard on
// S-12's mechanism. scanCerts used os.ReadFile, so Open allocated the WHOLE
// cert log - every payload byte of every record - before indexing anything.
// The index needs one offset per record and not one payload byte, so making
// the records sixteen times wider must not multiply what Open allocates.
//
// The old code fails this by construction: at 200 records of 4 KiB it allocated
// ~800 KiB where the 64-byte case allocated ~20 KiB. The bytes are compared,
// never the elapsed time, exactly as read_alloc_test.go's S-7 guard does.
func TestCertLogOpenCostDoesNotScaleWithTheRecordPayload(t *testing.T) {
	const records = 200
	narrow := openAllocated(t, records, 64)
	wide := openAllocated(t, records, 4096) // 16x the payload per record

	// The two runs differ only in the payload's width: 200 x 4032 = 806,400
	// bytes more payload on disk, and none of it may be read.
	if wide > narrow+64*1024 {
		t.Fatalf("Open allocated %d bytes over %d records of 4 KiB but %d over the same count of 64-byte records "+
			"(+%d); the certificate payload must not be read to build the index - that is audit S-12",
			wide, records, narrow, int64(wide)-int64(narrow))
	}
}

// TestCertLogOpenCostPerRecordIsConstant is the second half of the guard: the
// payload may not be resident AND the per-record cost must stay a small
// constant. A thousand times more records legitimately costs a thousand times
// more INDEX - one uint64 height and one int64 offset per record - and no more.
//
// The threshold is deliberately generous (128 bytes per record against the ~76
// a growing map costs per entry here) because its job is to catch a return to
// whole-record residency - 512 payload bytes per record in this fixture, 1536 in
// read_alloc_test.go's - not to pin the map's layout.
func TestCertLogOpenCostPerRecordIsConstant(t *testing.T) {
	const (
		payload = 512
		records = 10000
		// A Go map's TotalAlloc is roughly three times its resident entry,
		// because every doubling copies the table it grew out of. 128 keeps the
		// budget comfortably above that churn and still BELOW one payload, so the
		// test cannot pass if payloads are resident: 512 bytes per record is the
		// floor a whole-record read would show.
		perRecord = 128
	)
	small := openAllocated(t, 10, payload)
	large := openAllocated(t, records, payload)

	limit := small + perRecord*records + 64*1024
	if large > limit {
		t.Fatalf("Open allocated %d bytes over %d certificate records (%.1f B/record) against a %d-byte budget "+
			"(10 records cost %d); the payload is %d bytes per record and must not be part of this",
			large, records, float64(large)/float64(records), limit, small, payload)
	}
}

// TestCertAtDoesNotAllocateWhatTheHeaderClaims is the companion point the report
// does not make: the finding names Open only, and CertAt had the same hole from
// the other side. CertAt re-frames the record it is about to serve, but it must
// frame it against the file's CURRENT size: a length prefix that a stale index
// or a hand-edited log leaves claiming more than the file holds names an
// absence, not a 64 MiB allocation made on the header's word.
//
// The state is constructed, not raced: the record is indexed by a healthy Open,
// and only then is its header rewritten in place with a valid checksum over a
// length the file cannot possibly hold.
func TestCertAtDoesNotAllocateWhatTheHeaderClaims(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(1, []byte("certificate-one")); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, certLogName)
	off, ok := s.certIndex[1]
	if !ok {
		t.Fatal("PutCert did not index height 1")
	}
	// A complete, VALID header - its length checksum is correct - naming 64 MiB
	// of payload in a file of about a hundred bytes.
	f, err := os.OpenFile(logPath, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	var header [RecordHeaderLen]byte
	binary.BigEndian.PutUint64(header[:lengthFieldLen], 64<<20)
	binary.BigEndian.PutUint32(header[lengthFieldLen:], crc32.Checksum(header[:lengthFieldLen], crcTable))
	if _, err := f.WriteAt(header[:], off); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got, ok := s.CertAt(1)
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	if ok {
		t.Fatalf("CertAt(1) served %d bytes from a record the file cannot hold", len(got))
	}
	if allocated > 1<<20 {
		t.Fatalf("CertAt allocated %d bytes for a record claiming 64 MiB in a %d-byte file; "+
			"the record must be framed against the file size before a payload buffer is made (audit S-12)",
			allocated, certLogSize(t, logPath))
	}
}

// TestCertAtRefusesARecordForAnotherHeight is the integrity check that makes
// an offset-only index safe: the record at an indexed offset must be the record
// for that height, or a reordered log serves one height's certificate under
// another's. Two equal-width records swapped in place keep the framing valid,
// so only the height key can tell.
func TestCertAtRefusesARecordForAnotherHeight(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	one, two := []byte("certificate-one"), []byte("certificate-two")
	if err := s.PutCert(1, one); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(2, two); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, certLogName)
	off1, off2 := s.certIndex[1], s.certIndex[2]
	if off2-off1 != int64(RecordHeaderLen+len(one)+certHeightLen+RecordTrailerLen) {
		t.Fatalf("fixture records are not the same width: offsets %d and %d", off1, off2)
	}
	defer s.Close()

	// Swap the two records' payload bytes, leaving every length prefix and
	// checksum trailer exactly where it was: the framing still validates at both
	// offsets, and only the height key inside each payload is now wrong.
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	width := int(off2 - off1)
	if cap(raw) < int(off1)+2*width || len(raw) != int(off2)+width {
		t.Fatalf("unexpected cert log size %d for offsets %d,%d", len(raw), off1, off2)
	}
	f, err := os.OpenFile(logPath, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	first, second := make([]byte, width), make([]byte, width)
	copy(first, raw[off1:off1+int64(width)])
	copy(second, raw[off2:off2+int64(width)])
	if _, err := f.WriteAt(second, off1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(first, off2); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if got, ok := s.CertAt(1); ok {
		t.Fatalf("CertAt(1) served %q: the record at height 1's offset is height 2's", got)
	}
	if got, ok := s.CertAt(2); ok {
		t.Fatalf("CertAt(2) served %q: the record at height 2's offset is height 1's", got)
	}
}

// TestACorruptCertificateFramingStopsOpen pins the framing policy across the
// streaming rewrite. A record whose length prefix does not checksum is
// CORRUPTION - not the shape a crash leaves - and it stops the scan, exactly as
// it does for the block log. Only a record the file ENDS inside is a torn tail
// Open may cut.
func TestACorruptCertificateFramingStopsOpen(t *testing.T) {
	dir := certFixture(t, 2, 64)
	logPath := filepath.Join(dir, certLogName)
	// Corrupt the SECOND record's length-prefix checksum, leaving its length
	// field alone: the framing is untrustworthy, the file is not torn.
	f, err := os.OpenFile(logPath, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	second := int64(SegmentHeaderLen + RecordHeaderLen + 64 + certHeightLen + RecordTrailerLen)
	// The 4-byte checksum that follows the 8-byte length field, XORed so the
	// length it covers is no longer trusted while the file is not torn.
	var sum [RecordTrailerLen]byte
	if _, err := f.ReadAt(sum[:], second+lengthFieldLen); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(sum[:], binary.BigEndian.Uint32(sum[:])^0xFFFF)
	if _, err := f.WriteAt(sum[:], second+lengthFieldLen); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Open(dir)
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("a corrupt certificate length prefix must fail Open with ErrCorruptRecord, got %v", err)
	}
	if got := certLogSize(t, logPath); got == 0 {
		t.Fatal("Open truncated a corrupt certificate log: corruption must fail loudly, never be repaired away")
	}
}

// TestAPayloadCorruptCertificateIsRefusedAtReadNotAtOpen records the one
// behaviour this fix changes, so the next reader meets it deliberately rather
// than by accident.
//
// scanCerts no longer reads a record's PAYLOAD, so it can no longer verify the
// trailer checksum over that payload: a bit flip inside a complete, well-framed
// certificate is not detected at Open any more. Framing integrity is unaffected
// - the length prefix carries its own checksum, verified before the length is
// trusted, so no corrupt record can mis-frame the ones after it - and CertAt
// re-verifies the payload checksum before serving, so the corruption is an
// ABSENT certificate, never a wrong one. The archive is evidence, not a safety
// promise: losing one height's evidence costs that height's service, while
// failing Open over it costs the node.
func TestAPayloadCorruptCertificateIsRefusedAtReadNotAtOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, second := bytes.Repeat([]byte{0xA1}, 32), bytes.Repeat([]byte{0xB2}, 32)
	if err := s.PutCert(1, first); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(2, second); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, certLogName)
	off2 := s.certIndex[2]
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// One payload bit in height 2's record, with every framing byte untouched.
	f, err := os.OpenFile(logPath, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	at := off2 + RecordHeaderLen + certHeightLen + 1
	if _, err := f.ReadAt(b[:], at); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xFF
	if _, err := f.WriteAt(b[:], at); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("a corrupt payload inside a well-framed certificate must not stop Open: %v", err)
	}
	defer s2.Close()
	if got, ok := s2.CertAt(1); !ok || !bytes.Equal(got, first) {
		t.Fatalf("CertAt(1) = %x, %v; want the intact certificate", got, ok)
	}
	if got, ok := s2.CertAt(2); ok {
		t.Fatalf("CertAt(2) served %x from a record whose payload fails its checksum", got)
	}
}

// BenchmarkOpenCertLog measures the cold open of a certificate log, which is
// the number S-12 is about. Read bytes/op per record: it must stay a small
// constant (the index entry) and must not climb with either the record count or
// the payload width. Run with -benchmem.
func BenchmarkOpenCertLog(b *testing.B) {
	for _, records := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("%d-records", records), func(b *testing.B) {
			dir := certFixture(b, records, 512)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s, err := Open(dir)
				if err != nil {
					b.Fatal(err)
				}
				if err := s.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// certLogSize is the cert log's current size, for a failure message.
func certLogSize(tb testing.TB, path string) int64 {
	tb.Helper()
	size, err := fileSize(path)
	if err != nil {
		tb.Fatal(err)
	}
	return size
}
