package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// M7 step 3: the store's pruner. It removes whole block/certificate segments
// below a horizon, rewrites the one segment the horizon falls inside, and
// records the new first height - which is what stops the next scan from
// renumbering the survivors.

// appendBlocks appends heights 1..n with small payloads.
func appendBlocks(tb testing.TB, s *Store, n int) {
	tb.Helper()
	for h := 1; h <= n; h++ {
		if err := s.Append(uint64(h), []byte("block")); err != nil {
			tb.Fatalf("Append(%d): %v", h, err)
		}
	}
}

// TestPruneBlocksDropsWholeSegments pins the common case: a horizon on a
// segment boundary deletes the segment files below it and leaves the rest
// untouched, and the reopened store still numbers its survivors from the
// recorded base instead of from 1.
func TestPruneBlocksDropsWholeSegments(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const total = 2*BlocksPerSegment + 5
	appendBlocks(t, s, total)
	// upTo = 1999 leaves height 2000.. ; segments 0 and 1 go whole because
	// segment 0 holds 1..999 and segment 1 holds 1000..1999.
	stats, err := s.PruneBlocks(2*BlocksPerSegment - 1)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Blocks != 2 {
		t.Fatalf("pruned %d block segments, want 2", stats.Blocks)
	}
	if stats.FirstHeight != 2*BlocksPerSegment {
		t.Fatalf("recorded first height %d, want %d", stats.FirstHeight, 2*BlocksPerSegment)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{segmentName(0), segmentName(1)} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists after the prune (%v)", name, err)
		}
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, want := s2.FirstHeight(), uint64(2*BlocksPerSegment); got != want {
		t.Fatalf("FirstHeight after reopen = %d, want %d", got, want)
	}
	if h, ok := s2.Height(); !ok || h != total {
		t.Fatalf("Height after reopen = %d, %v; want %d", h, ok, total)
	}
	if _, err := s2.Read(1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read(1) after pruning = %v, want ErrNotFound", err)
	}
	if _, err := s2.Read(2*BlocksPerSegment - 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read below the base = %v, want ErrNotFound", err)
	}
	// The FIRST retained height - the one a segment-boundary reader must find -
	// and the last one before the rollover.
	for _, h := range []uint64{2 * BlocksPerSegment, 2*BlocksPerSegment + 1, total} {
		raw, err := s2.Read(h)
		if err != nil || string(raw) != "block" {
			t.Fatalf("Read(%d) after pruning = %q, %v", h, raw, err)
		}
	}
	// Appending continues at base+count, across the segment rollover.
	if err := s2.Append(total+1, []byte("block")); err != nil {
		t.Fatalf("Append above the pruned base: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	s3, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if h, _ := s3.Height(); h != total+1 {
		t.Fatalf("Height after the rolling append = %d, want %d", h, total+1)
	}
}

// TestAPartialPruneSkipsTheBoundaryPrefix is the partial case: a horizon inside
// a segment leaves that segment exactly where it is (M7 never rewrites one) and
// the store SKIPS the pruned records ahead of the marker's offset. The retained
// heights are served unchanged before and after a reopen.
func TestAPartialPruneSkipsTheBoundaryPrefix(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const total = BlocksPerSegment + 10
	appendBlocks(t, s, total)
	const upTo = 500 // inside segment 0, which holds 1..999
	if _, err := s.PruneBlocks(upTo); err != nil {
		t.Fatal(err)
	}
	for _, h := range []uint64{upTo + 1, 700, BlocksPerSegment - 1, BlocksPerSegment, total} {
		if _, err := s.Read(h); err != nil {
			t.Fatalf("Read(%d) after a partial prune: %v", h, err)
		}
	}
	if _, err := s.Read(upTo); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read(%d) after a partial prune = %v, want ErrNotFound", upTo, err)
	}
	// The boundary segment was NOT rewritten: the pruned prefix is still on
	// disk (bounded by one segment) and the marker's offset is what excludes it.
	raw, err := os.ReadFile(filepath.Join(dir, segmentName(0)))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= SegmentHeaderLen {
		t.Fatal("the boundary segment is empty; this test's premise (a prefix left in place) no longer holds")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	for h := uint64(upTo + 1); h <= total; h++ {
		if _, err := s2.Read(h); err != nil {
			t.Fatalf("Read(%d) after reopen: %v", h, err)
		}
	}
	if got := s2.first; got != upTo+1 {
		t.Fatalf("reopened first height = %d, want %d", got, upTo+1)
	}
}

// TestPruneBlocksRefusesTheHead pins the head's permanence: the block a node
// last committed - and therefore its certificate - is never prunable.
func TestPruneBlocksRefusesTheHead(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	appendBlocks(t, s, 10)
	for _, upTo := range []uint64{10, 11, 99} {
		if _, err := s.PruneBlocks(upTo); err == nil {
			t.Fatalf("PruneBlocks(%d) succeeded; the head (10) must never be prunable", upTo)
		}
	}
	if h, _ := s.Height(); h != 10 {
		t.Fatalf("height moved to %d after a refused prune", h)
	}
	if _, err := s.Read(10); err != nil {
		t.Fatalf("the head was removed by a refused prune: %v", err)
	}
}

// TestPruneBlocksDoesNotTouchRoundsLocksOrGenesis is the store-level half of
// the retention table's promise. rounds.log is the validator's restart
// position and genesis.hash is the chain's identity: a pruning pass must walk
// past both. The lock log is the double-vote promise and is asserted beside
// them.
func TestPruneBlocksDoesNotTouchRoundsLocksOrGenesis(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var gen [32]byte
	gen[0] = 0xAB
	if err := s.CheckGenesis(gen); err != nil {
		t.Fatal(err)
	}
	appendBlocks(t, s, 20)
	if err := s.PutRound(RoundRecord{Height: 21, Round: 7}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutLock(LockRecord{Height: 21, Round: 7, BlockID: idOf(1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneBlocks(10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneCerts(10); err != nil {
		t.Fatal(err)
	}
	if r, ok := s.RoundAt(21); !ok || r != 7 {
		t.Fatalf("RoundAt(21) after pruning = %d, %v; the round record is safety state and must survive", r, ok)
	}
	if _, ok := s.LockAt(21); !ok {
		t.Fatal("LockAt(21) after pruning: the lock promise was removed")
	}
	if err := s.CheckGenesis(gen); err != nil {
		t.Fatalf("CheckGenesis after pruning: %v", err)
	}
	if err := s.CheckGenesis([32]byte{0xCD}); !errors.Is(err, ErrWrongGenesis) {
		t.Fatalf("a different genesis after pruning gave %v; the identity must still disagree", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if r, ok := s2.RoundAt(21); !ok || r != 7 {
		t.Fatalf("RoundAt(21) after reopening a pruned store = %d, %v", r, ok)
	}
	if _, ok := s2.LockAt(21); !ok {
		t.Fatal("LockAt(21) after reopening a pruned store")
	}
	if err := s2.CheckGenesis(gen); err != nil {
		t.Fatalf("checking the genesis after reopening a pruned store: %v", err)
	}
}

// TestACrashBetweenTheMarkerAndTheDeletionIsRecovered pins the crash order
// PruneBlocks documents: the base marker is written FIRST, so a crash before
// any segment is removed must leave a directory that OPENS and skips the
// already-pruned records rather than renumbering them. This test writes the
// marker by hand and leaves every segment in place, which is exactly that
// state.
func TestACrashBetweenTheMarkerAndTheDeletionIsRecovered(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	appendBlocks(t, s, 20)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// The exact crash shape: the marker names height 11 and the offset its
	// index recorded, and not one segment has been removed yet.
	off := s.index[11]
	if err := writeBaseMarker(dir, baseMarker{blockFirst: 11, blockOffset: off, certFirst: 11}); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("a directory with the marker written and the segments still present must open: %v", err)
	}
	defer s2.Close()
	if got := s2.FirstHeight(); got != 11 {
		t.Fatalf("FirstHeight = %d, want 11", got)
	}
	if h, _ := s2.Height(); h != 20 {
		t.Fatalf("Height = %d, want 20", h)
	}
	if _, err := s2.Read(10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read(10) = %v, want ErrNotFound (the marker says it is gone even though its bytes remain)", err)
	}
	if raw, err := s2.Read(11); err != nil || string(raw) != "block" {
		t.Fatalf("Read(11) = %q, %v; the first retained height must be the FIRST indexed one", raw, err)
	}
	// Re-running the prune finishes the job the crash interrupted.
	if _, err := s2.PruneBlocks(10); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Read(11); err != nil {
		t.Fatalf("Read(11) after completing the prune: %v", err)
	}
}

// TestPruneCertsDropsWholeSegmentsAndKeepsTheBoundary is the certificate half:
// whole segments below the horizon go, the boundary segment stays (its pruned
// prefix is skipped through the horizon), and CertAt still serves exactly the
// kept heights after a reopen.
func TestPruneCertsDropsWholeSegmentsAndTrimsTheBoundary(t *testing.T) {
	dir := t.TempDir()
	writeCertSegment(t, dir, 0, 1, certRecordsPerSegment, 5)
	writeCertSegment(t, dir, 1, certRecordsPerSegment+1, certRecordsPerSegment, 5)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const upTo = certRecordsPerSegment + 10
	stats, err := s.PruneCerts(upTo)
	if err != nil {
		t.Fatal(err)
	}
	if stats.CertSegs != 1 {
		t.Fatalf("pruned %d certificate segments, want 1", stats.CertSegs)
	}
	if _, err := os.Stat(filepath.Join(dir, certSegmentName(0))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("certificate segment 0 still exists after the prune (%v)", err)
	}
	if _, ok := s.CertAt(certRecordsPerSegment); ok {
		t.Fatal("CertAt served a height below the certificate horizon")
	}
	// The HORIZON's own certificate is kept: it is the proof of the checkpoint
	// at that height, and re-exporting it later must not need the pruned past.
	if _, ok := s.CertAt(upTo); !ok {
		t.Fatal("CertAt served no certificate at the horizon itself")
	}
	for _, h := range []uint64{upTo + 1, 2 * certRecordsPerSegment} {
		if _, ok := s.CertAt(h); !ok {
			t.Fatalf("CertAt(%d) after pruning: no certificate", h)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, ok := s2.CertAt(upTo - 1); ok {
		t.Fatal("a pruned certificate came back after reopen")
	}
	if _, ok := s2.CertAt(upTo); !ok {
		t.Fatal("the horizon's own certificate did not survive the reopen")
	}
	if _, ok := s2.CertAt(upTo + 1); !ok {
		t.Fatal("the boundary certificate did not survive the reopen")
	}
	// Certificate pruning never rewrites a segment, so the boundary segment is
	// still there - with its pruned records excluded by the horizon.
	if _, err := os.Stat(filepath.Join(dir, certSegmentName(1))); err != nil {
		t.Fatalf("the boundary certificate segment was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, certSegmentName(2))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a surplus certificate segment was created (%v)", err)
	}
}

// TestPruneCertsRemovesTheLegacyLogWhole pins the upgrade path's end state: the
// pre-M7 single certs.log is dropped as a WHOLE once every height it holds is
// below the horizon - it is not partially rewritten, because it is not this
// build's format - and nothing above the horizon is lost.
func TestPruneCertsRemovesTheLegacyLogWhole(t *testing.T) {
	dir := certFixture(t, 5, 8) // certs.log, heights 1..5
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A new record goes to a segment, above the horizon.
	if err := s.PutCert(99, []byte("above")); err != nil {
		t.Fatal(err)
	}
	stats, err := s.PruneCerts(50)
	if err != nil {
		t.Fatal(err)
	}
	if !stats.LegacyCerts {
		t.Fatal("the legacy certs.log was not reported as removed")
	}
	if _, err := os.Stat(filepath.Join(dir, certLogName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("certs.log still exists after the prune (%v)", err)
	}
	for h := uint64(1); h <= 5; h++ {
		if _, ok := s.CertAt(h); ok {
			t.Fatalf("CertAt(%d) served a certificate from the removed legacy log", h)
		}
	}
	if got, ok := s.CertAt(99); !ok || string(got) != "above" {
		t.Fatalf("CertAt(99) after removing the legacy log = %q, %v", got, ok)
	}
	// A later pass must not try to remove it again.
	stats, err = s.PruneCerts(99)
	if err != nil {
		t.Fatal(err)
	}
	if stats.LegacyCerts {
		t.Fatal("the legacy log was reported removed twice")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
