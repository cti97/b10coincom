package store

import (
	"bytes"
	"runtime"
	"testing"
)

// readFixture builds a store holding `records` records in one segment. The
// payload is large enough that reading a whole segment is visibly more than
// reading one record.
func readFixture(tb testing.TB, records int) *Store {
	tb.Helper()
	s, err := Open(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = s.Close() })
	payload := bytes.Repeat([]byte("b10"), 512) // 1536 bytes
	for h := 1; h <= records; h++ {
		if err := s.Append(uint64(h), payload); err != nil {
			tb.Fatal(err)
		}
	}
	return s
}

// TestReadCostDoesNotScaleWithTheSegmentSize is the audit S-7 regression guard.
// Store.Read used os.ReadFile, so a non-head GET /block/{h} allocated the whole
// segment (here ~1.5 MiB) to return one 1.5 KiB record; replay paid that once
// per block. The read handle plus ReadAt makes the cost the record's own size,
// so a hundred times more records in the segment must not multiply the bytes
// allocated. Like the S-6 guard this compares bytes, never elapsed time.
func TestReadCostDoesNotScaleWithTheSegmentSize(t *testing.T) {
	allocated := func(records int) uint64 {
		s := readFixture(t, records)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		if _, err := s.Read(1); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	small := allocated(10)
	large := allocated(1000)
	// 100x the records must not cost anywhere near 100x the bytes. The old
	// os.ReadFile read allocated ~100x more at 1000 records; the streaming read
	// allocates one record plus its copy at both sizes.
	if large > 4*small {
		t.Fatalf("Read(1) allocated %d bytes in a 1000-record segment but %d in a 10-record one (%.1fx); "+
			"the cost must not scale with the segment, which is the whole-segment read audit S-7 removed",
			large, small, float64(large)/float64(small))
	}
}

// BenchmarkReadNonHead measures the store read a non-head GET /block/{h}
// performs, from a full segment: the bytes/op is the number that collapsed when
// the whole-segment os.ReadFile became a handle plus ReadAt. Run with
// -benchmem.
func BenchmarkReadNonHead(b *testing.B) {
	s := readFixture(b, 1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Read(1); err != nil {
			b.Fatal(err)
		}
	}
}
