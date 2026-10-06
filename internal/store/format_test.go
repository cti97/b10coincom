package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file is the fourth review round's pin for the store's format marker
// (audit-verification new issue 4). The finding: the record framing was
// self-checking but not self-IDENTIFYING, so a data directory written before
// the checksummed length prefix (`4b1f36c`) failed Open as a checksum mismatch
// and the repair hint - correctly, for bytes in that layout - told the operator
// the record was bit rot and to truncate at the failing offset. At offset 0,
// following that hint deletes the chain.
//
// The fix is a segment header of magic plus version at the head of EVERY log
// file, classified before a single record is framed, and two hints that can no
// longer be confused: corruption (a complete record whose checksum fails in
// THIS format) keeps the truncation advice, and an unrecognised format gets a
// hint that says the bytes are not damaged and must NOT be truncated.

// TestEveryLogBeginsWithTheSegmentHeader pins the marker where it matters: on
// disk, at offset 0, in every file this package writes - the block segments, the
// lock log, the round log and the certificate log - and before the first record
// rather than after it.
func TestEveryLogBeginsWithTheSegmentHeader(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(1, []byte("block-one")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutLock(LockRecord{Height: 2, Round: 1, BlockID: idOf(1)}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRound(RoundRecord{Height: 2, Round: 3}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(1, []byte("cert-payload")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	want := append([]byte(SegmentMagic), 0, 0, 0, SegmentFormatVersion)
	for _, name := range []string{"00000000.seg", lockLogName, roundLogName, certLogName} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(raw) < SegmentHeaderLen {
			t.Fatalf("%s is %d bytes; it must begin with the %d-byte segment header", name, len(raw), SegmentHeaderLen)
		}
		if !bytes.Equal(raw[:SegmentHeaderLen], want) {
			t.Fatalf("%s begins %q; want the %q magic and version %d", name, raw[:SegmentHeaderLen], SegmentMagic, SegmentFormatVersion)
		}
	}

	// The marker is a HEADER, not a record: a file holding one lock record is
	// the header plus exactly one framed lock record.
	lockRaw, err := os.ReadFile(filepath.Join(dir, lockLogName))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(lockRaw), SegmentHeaderLen+RecordHeaderLen+lockPayloadLen+RecordTrailerLen; got != want {
		t.Fatalf("locks.log is %d bytes; want %d (segment header + one framed lock record)", got, want)
	}
}

// TestAPreFixDirectoryIsRefusedAsAFormatAndNeverAsCorruption is the finding's
// own case, and the one whose wrong answer deleted chains. Two pre-fix shapes
// are exercised, because a build can be older in two different ways.
//
// The first is the layout the finding names: the framing before `4b1f36c`,
// where the length prefix was NOT covered by its own checksum
// (`uint64be(len) || payload || crc32c(payload)`). A current build reading those
// bytes as its own framing fails the length checksum and reported the result as
// BIT ROT, with a hint telling the operator to truncate at the failing offset -
// at offset 0 for the first record. The second is the framing THIS build writes
// without the segment marker (a directory from any build between `4b1f36c` and
// the marker): its records are valid, so a build without the marker check would
// happily read them as a chain, but it still cannot know their layout version.
//
// Both must fail as an UNRECOGNISED FORMAT: not ErrCorruptRecord, not a checksum
// mismatch dressed as bit rot, and with a hint that says the bytes are not
// damaged and must not be truncated. And the bytes must be untouched: refusing
// to read a directory is recoverable, rewriting it is not.
func TestAPreFixDirectoryIsRefusedAsAFormatAndNeverAsCorruption(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(f *os.File) error
	}{
		{
			name: "pre-4b1f36c framing, whose records fail the current length checksum",
			write: func(f *os.File) error {
				if err := writePreFixRecord(f, []byte("block-one")); err != nil {
					return err
				}
				return writePreFixRecord(f, []byte("block-two"))
			},
		},
		{
			name: "current framing without the segment marker (any build from 4b1f36c to now)",
			write: func(f *os.File) error {
				if err := writeRecord(f, []byte("block-one")); err != nil {
					return err
				}
				return writeRecord(f, []byte("block-two"))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			seg := filepath.Join(dir, "00000000.seg")
			f, err := os.OpenFile(seg, os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.write(f); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(seg)
			if err != nil {
				t.Fatal(err)
			}

			_, err = Open(dir)
			if err == nil {
				t.Fatal("Open accepted a directory with no segment header: the format is not identified")
			}
			if !errors.Is(err, ErrUnrecognisedFormat) {
				t.Fatalf("a pre-fix directory gave %v; want an error wrapping ErrUnrecognisedFormat", err)
			}
			if errors.Is(err, ErrCorruptRecord) {
				t.Fatal("a pre-fix directory was reported as CORRUPTION: the repair hint for that answer tells the operator to truncate, which deletes an intact chain")
			}
			msg := err.Error()
			if strings.Contains(msg, "truncate it at offset") {
				t.Fatalf("the unrecognised-format message still carries the truncation advice: %s", msg)
			}
			if !strings.Contains(msg, "Do NOT truncate") {
				t.Fatalf("the unrecognised-format message does not warn against truncation: %s", msg)
			}
			after, err := os.ReadFile(seg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("Open rewrote a directory it did not recognise: refusing must leave the bytes for a human")
			}
		})
	}
}

// writePreFixRecord writes one record in the layout the build before
// `4b1f36c` used: uint64be(len(payload)) || payload || crc32c(payload). The
// length prefix was not covered by its own checksum, which is precisely why a
// later build read it as a corrupt record - and told the operator to truncate
// it away.
func writePreFixRecord(f *os.File, payload []byte) error {
	var lb [8]byte
	binary.BigEndian.PutUint64(lb[:], uint64(len(payload)))
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.Checksum(payload, crcTable))
	if _, err := f.Write(append(append(lb[:], payload...), sum[:]...)); err != nil {
		return err
	}
	return f.Sync()
}

// TestTheFormatMarkerIsCheckedWithTheVersionNotOnlyTheMagic keeps the marker a
// VERSION, not a decoration. A file that carries this magic at an unknown
// version is a different layout that happens to share the tag, and reading it
// as this one is exactly the misparse the marker exists to prevent. It is
// refused as an unrecognised format - never truncated, because the file may be
// a newer build's intact chain.
func TestTheFormatMarkerIsCheckedWithTheVersionNotOnlyTheMagic(t *testing.T) {
	dir := t.TempDir()
	seg := filepath.Join(dir, "00000000.seg")
	bogus := append([]byte(SegmentMagic), 0, 0, 0, SegmentFormatVersion+1)
	raw := append(bogus, make([]byte, 64)...)
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir)
	if !errors.Is(err, ErrUnrecognisedFormat) {
		t.Fatalf("a file carrying the magic at version %d gave %v; want ErrUnrecognisedFormat", SegmentFormatVersion+1, err)
	}
	after, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, after) {
		t.Fatal("Open rewrote a file whose version it does not implement")
	}
}

// TestATornSegmentHeaderIsRewrittenOnOpen pins the one header shape a crash can
// leave - the file ending inside the header - as repairable. Nothing is lost by
// repairing it: a complete record is longer than the header, so a file shorter
// than SegmentHeaderLen holds none. The repair must leave a WRITABLE store: the
// header is rewritten, the next Append lands after it, and the next Open reads
// that block back.
func TestATornSegmentHeaderIsRewrittenOnOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(1, []byte("doomed-by-the-cut")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	seg := filepath.Join(dir, "00000000.seg")
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	// The cut a crash during the header write leaves: a prefix of the header,
	// and nothing else (a 5-byte file cannot hold a 16-byte-minimum record).
	if err := os.WriteFile(seg, raw[:5], 0o644); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open refused a directory whose segment header was cut short: %v", err)
	}
	if _, have := s2.Height(); have {
		t.Fatal("a 5-byte file was read as holding a block")
	}
	repaired, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if len(repaired) != SegmentHeaderLen {
		t.Fatalf("after the repair %s is %d bytes; want exactly the %d-byte header", seg, len(repaired), SegmentHeaderLen)
	}
	if err := s2.Append(1, []byte("after-the-cut")); err != nil {
		t.Fatalf("appending after a repaired header: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}

	s3, err := Open(dir)
	if err != nil {
		t.Fatalf("reopening after a repaired header: %v", err)
	}
	defer s3.Close()
	if h, have := s3.Height(); !have || h != 1 {
		t.Fatalf("height = %d,%v after the repair and one append; want 1,true", h, have)
	}
	got, err := s3.Read(1)
	if err != nil || !bytes.Equal(got, []byte("after-the-cut")) {
		t.Fatalf("Read(1) = %q,%v; want the block appended after the repaired header", got, err)
	}
}

// TestANewFormatDirectoryReopensAndServes is the round trip the fix must not
// break: a directory written by this build reopens and serves every log back -
// blocks, the lock promise, the round and the certificate - because the header
// is framing, not state.
func TestANewFormatDirectoryReopensAndServes(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= 3; h++ {
		if err := s.Append(h, []byte{byte(h), byte(h), byte(h)}); err != nil {
			t.Fatal(err)
		}
	}
	lock := LockRecord{Height: 4, Round: 2, BlockID: idOf(4)}
	if err := s.PutLock(lock); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRound(RoundRecord{Height: 4, Round: 5}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(2, []byte("cert-for-2")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	re, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer re.Close()
	if h, have := re.Height(); !have || h != 3 {
		t.Fatalf("height = %d,%v; want 3,true", h, have)
	}
	for h := uint64(1); h <= 3; h++ {
		got, err := re.Read(h)
		if err != nil || !bytes.Equal(got, []byte{byte(h), byte(h), byte(h)}) {
			t.Fatalf("Read(%d) = %v,%v; want the appended payload", h, got, err)
		}
	}
	if got, ok := re.LockAt(4); !ok || got != lock {
		t.Fatalf("LockAt(4) = %+v,%v; want %+v", got, ok, lock)
	}
	if r, ok := re.RoundAt(4); !ok || r != 5 {
		t.Fatalf("RoundAt(4) = %d,%v; want 5", r, ok)
	}
	if c, ok := re.CertAt(2); !ok || !bytes.Equal(c, []byte("cert-for-2")) {
		t.Fatalf("CertAt(2) = %q,%v; want the recorded certificate", c, ok)
	}
}
