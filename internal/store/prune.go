package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cti97/b10coincom/internal/retention"
)

// M7's PRUNER half. The store grew no way to delete history before M7: blocks
// were segmented from the start, but nothing ever removed a segment, and the
// certificate log was one append-only file. Bounding the directory therefore
// needs two things this file owns:
//
//  1. a PERSISTED HORIZON (base.height): the first block height still present,
//     the BYTE OFFSET within its segment where that block's record starts, and
//     the first certificate height still present. Block segment contents are
//     numbered by record count during scan, so a directory whose first segments
//     were deleted would silently renumber every surviving block - and a
//     renumbered chain replays to the roots its rewritten headers claim. The
//     marker is what tells the next Open that heights below it are ABSENT, not
//     corrupt, and where numbering starts.
//  2. PruneBlocks / PruneCerts: drop whole segments below the horizon and move
//     the marker. That is the whole operation.
//
// NO SEGMENT IS EVER REWRITTEN, and that is deliberate. A rewrite plus a marker
// update are two writes that cannot be made atomic together, and every ordering
// leaves one crash window in which the marker and the file disagree about where
// the retained records begin - and a store that numbers a pruned prefix as
// retained misnumbers the chain. Recording the OFFSET instead makes the marker
// the only thing that moves: the boundary segment keeps its already-pruned
// prefix on disk (at most one segment's worth, ~226 B/block and ~500 B/cert at
// the measured rates), the retained suffix stays exactly where it was, and a
// crash can only leave the marker at the old horizon (nothing deleted yet) or
// the new one (everything below it already skipable). The dead prefix is
// reclaimed whole when the NEXT prune moves past that segment.
//
// WHAT THIS FILE MUST NEVER DELETE is not decided here: every deletion asks
// package retention first, so rounds.log, locks.log, genesis.hash, the head and
// its certificate, the base marker and the checkpoint cannot be pruned even by a
// call site that asks for them.

// baseHeightName holds the persisted horizon: three big-endian uint64s -
//
//	blockFirst   the lowest block height still present (1 = never pruned)
//	blockOffset  the byte offset, within the segment holding blockFirst, of
//	             the first retained block record
//	certFirst    the lowest certificate height still present
//
// It has no ".seg" suffix, so scan never indexes it as a block, and it is
// written atomically (temp, fsync, rename, dir fsync) before any segment is
// removed - see PruneBlocks for the ordering argument.
const baseHeightName = "base.height"

// baseHeightLen is the marker's fixed width. A file of another width is damage,
// not an older layout: no build wrote one.
const baseHeightLen = 8 * 3

// baseMarker is the in-memory form of base.height.
type baseMarker struct {
	blockFirst  uint64
	blockOffset int64
	certFirst   uint64
}

// defaultMarker is a directory that has never been pruned: blocks start at 1 in
// their natural layout (header first), and so do certificates.
func defaultMarker() baseMarker {
	return baseMarker{blockFirst: 1, blockOffset: int64(SegmentHeaderLen), certFirst: 1}
}

// PruneStats reports what one pruning pass removed, for the operator's log and
// for tests that assert the steady state rather than trusting it.
type PruneStats struct {
	FirstHeight uint64 // the first block height the directory still holds
	Blocks      uint64 // block segments removed
	BlockBytes  int64
	CertSegs    uint64 // certificate segments removed
	CertBytes   int64
	LegacyCerts bool // the legacy certs.log was removed
	LegacyBytes int64
}

// Any reports whether the pass removed anything at all.
func (p PruneStats) Any() bool {
	return p.Blocks > 0 || p.CertSegs > 0 || p.LegacyCerts
}

// FirstHeight returns the lowest block height this directory still holds (or
// would hold next, when it is empty). 1 means "never pruned".
func (s *Store) FirstHeight() uint64 {
	s.indexMu.RLock()
	defer s.indexMu.RUnlock()
	return s.first
}

// BaseOf reports the horizon a data directory records, WITHOUT opening it (and
// therefore without taking its writer lock). 1 means the directory has never
// been pruned. It is what a node asks before deciding whether it needs a
// checkpoint to start, and asking by opening the store would either fail on the
// lock or replay the chain twice.
func BaseOf(dir string) (uint64, error) {
	m, err := readBaseMarker(dir)
	return m.blockFirst, err
}

// BlocksPresent reports whether a directory holds any block RECORD yet, without
// opening the store. It exists for exactly one decision (consensus.ResumeForDir):
// a checkpoint may be adopted by a directory with no history, but must never be
// adopted over one that already has blocks - that is a mismatch to refuse, not a
// starting point to choose. A file at exactly the segment header's size holds no
// record, so a directory a crash left with an empty segment still counts as
// empty.
func BlocksPresent(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".seg" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return false, err
		}
		if info.Size() > int64(SegmentHeaderLen) {
			return true, nil
		}
	}
	return false, nil
}

// readBaseMarker reads the persisted horizon, or the default when there is none.
func readBaseMarker(dir string) (baseMarker, error) {
	path := filepath.Join(dir, baseHeightName)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return defaultMarker(), nil
	}
	if err != nil {
		return baseMarker{}, err
	}
	if len(raw) != baseHeightLen {
		return baseMarker{}, fmt.Errorf("store: %s is %d bytes, want the %d-byte horizon record (block height, block offset, certificate height); the data directory is damaged", path, len(raw), baseHeightLen)
	}
	m := baseMarker{
		blockFirst:  binary.BigEndian.Uint64(raw[0:8]),
		blockOffset: int64(binary.BigEndian.Uint64(raw[8:16])),
		certFirst:   binary.BigEndian.Uint64(raw[16:24]),
	}
	if m.blockFirst == 0 || m.certFirst == 0 {
		return baseMarker{}, fmt.Errorf("store: %s records a zero height; heights are 1-based and a 0 marker is damage", path)
	}
	if m.blockOffset < int64(SegmentHeaderLen) {
		return baseMarker{}, fmt.Errorf("store: %s records block offset %d, which is inside the segment header; the marker is damaged", path, m.blockOffset)
	}
	return m, nil
}

// writeBaseMarker persists m atomically: temp, fsync, rename, then a directory
// fsync. The rename is what makes a crash leave either the old marker or the new
// one, never a half-written number - the scan's numbering depends on this value.
func writeBaseMarker(dir string, m baseMarker) error {
	if m.blockFirst == 0 || m.certFirst == 0 {
		return fmt.Errorf("store: refusing to record a horizon with a zero height")
	}
	if m.blockOffset < int64(SegmentHeaderLen) {
		return fmt.Errorf("store: refusing to record block offset %d (inside the segment header)", m.blockOffset)
	}
	path := filepath.Join(dir, baseHeightName)
	tmp, err := os.CreateTemp(dir, baseHeightName+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o644); err != nil {
		cleanup()
		return err
	}
	var buf [baseHeightLen]byte
	binary.BigEndian.PutUint64(buf[0:8], m.blockFirst)
	binary.BigEndian.PutUint64(buf[8:16], uint64(m.blockOffset))
	binary.BigEndian.PutUint64(buf[16:24], m.certFirst)
	if _, err := tmp.Write(buf[:]); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	syncDir(dir)
	return nil
}

// AdoptBase records first as this directory's first height, for a directory that
// holds NO blocks - the state a checkpoint import starts in. It exists so the
// checkpoint import and the pruner write the horizon through the same code, with
// the same atomicity, and it refuses to touch a directory that already holds
// history: adopting a base there would either renumber the blocks or hide them.
func (s *Store) AdoptBase(first uint64) error {
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	if s.have {
		return fmt.Errorf("store: refusing to adopt first height %d: %s already holds blocks up to height %d", first, s.dir, s.last)
	}
	if s.first != 1 {
		return fmt.Errorf("store: %s already records first height %d", s.dir, s.first)
	}
	if first <= 1 {
		return nil
	}
	// A checkpoint import starts with no block records: the next one written
	// goes after the segment header, and no certificate below the horizon will
	// ever be asked for.
	m := baseMarker{blockFirst: first, blockOffset: int64(SegmentHeaderLen), certFirst: first}
	if err := writeBaseMarker(s.dir, m); err != nil {
		return err
	}
	s.first = first
	s.firstOffset = int64(SegmentHeaderLen)
	s.certFirst = first
	s.last = first - 1
	return nil
}

// segmentIndexFromName parses the segment index out of an NNNNNNNN.seg name.
// The name is a fact about the file's absolute position, so the scan can refuse
// a directory whose segments have a HOLE in them instead of renumbering what
// follows the hole.
func segmentIndexFromName(name string) (uint64, error) {
	if !strings.HasSuffix(name, ".seg") {
		return 0, fmt.Errorf("store: %q is not a block segment", name)
	}
	mid := strings.TrimSuffix(name, ".seg")
	// At least 8 digits: segmentName zero-pads to 8, and an index past 10^8
	// prints wider rather than being refused. (Lexical order stops matching
	// height order there, which is the format's documented 10^11-height limit,
	// not something a parser should fail on.)
	if len(mid) < 8 {
		return 0, fmt.Errorf("store: block segment %q does not carry an 8-digit index", name)
	}
	idx, err := strconv.ParseUint(mid, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store: block segment %q does not carry an 8-digit index", name)
	}
	return idx, nil
}

// segmentMaxHeight is the highest height a segment index can hold. Segment 0
// carries heights 1..BlocksPerSegment-1 (height 0 is the synthesized genesis,
// which the store never writes), and every later segment carries a full
// BlocksPerSegment range.
func segmentMaxHeight(idx uint64) uint64 {
	return (idx+1)*BlocksPerSegment - 1
}

// segmentFirstHeight is the lowest height a segment index can hold.
func segmentFirstHeight(idx uint64) uint64 {
	if idx == 0 {
		return 1
	}
	return idx * BlocksPerSegment
}

// closeReaderLocked drops a cached read handle for name, if any. The caller
// must hold readMu.
func (s *Store) closeReaderLocked(name string) {
	if f, ok := s.readers[name]; ok {
		_ = f.Close()
		delete(s.readers, name)
		for i, n := range s.readerLRU {
			if n == name {
				s.readerLRU = append(s.readerLRU[:i], s.readerLRU[i+1:]...)
				break
			}
		}
	}
}

// PruneBlocks deletes every block segment that lies ENTIRELY below the horizon
// and records first as the directory's first height, with off - the offset of
// its record within its segment - as the place scanning resumes from.
//
// The head is never prunable: upTo must be strictly below the highest stored
// height, so the node always keeps the block it last committed.
//
// CRASH ORDER, which is the whole safety argument:
//
//  1. the horizon marker is written and fsynced FIRST, and it is the only thing
//     that has to change atomically. It carries the offset the retained records
//     already sit at, so the segment that straddles the horizon does not move;
//  2. whole segments fully below the horizon are removed.
//
// A crash after (1) leaves the marker pointing at a record that is still there,
// with some now-unreferenced segments on disk; a crash during (2) leaves a
// prefix of them deleted. Both open correctly, both number the retained blocks
// identically, and running the pruner again finishes the deletion. Deleting
// before the marker would be the unsafe order: the scan would number the first
// surviving segment from height 1 and the stored headers would not match, which
// surfaces as a replay divergence rather than as the deliberate absence it is.
func (s *Store) PruneBlocks(upTo uint64) (PruneStats, error) {
	if err := retention.Deletable(retention.BlockSegments); err != nil {
		return PruneStats{}, err // unreachable while the table says prunable; the call site must ask anyway
	}
	var stats PruneStats
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	stats.FirstHeight = s.first
	if !s.have || upTo < s.first {
		return stats, nil // nothing pruned, nothing to record
	}
	if upTo >= s.last {
		return PruneStats{}, fmt.Errorf("store: refusing to prune to height %d: the highest stored height is %d and the HEAD is never prunable", upTo, s.last)
	}
	first := upTo + 1
	// The offset of the first retained record is ALREADY known: the index stores
	// every stored height's offset within its segment. Recording it is what lets
	// the boundary segment stay exactly where it is - see this file's header.
	offsetOfFirstRetained, ok := s.index[first]
	if !ok {
		return PruneStats{}, fmt.Errorf("store: refusing to prune to height %d: height %d is not indexed", upTo, first)
	}
	if offsetOfFirstRetained < int64(SegmentHeaderLen) {
		return PruneStats{}, fmt.Errorf("store: refusing to prune: offset %d of height %d is inside the segment header", offsetOfFirstRetained, first)
	}
	m, err := readBaseMarker(s.dir)
	if err != nil {
		return PruneStats{}, err
	}
	m.blockFirst = first
	m.blockOffset = offsetOfFirstRetained
	if err := writeBaseMarker(s.dir, m); err != nil {
		return PruneStats{}, err
	}

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return PruneStats{}, err
	}
	type segEntry struct {
		idx  uint64
		name string
		size int64
	}
	var segs []segEntry
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".seg" {
			continue
		}
		idx, err := segmentIndexFromName(e.Name())
		if err != nil {
			return PruneStats{}, err
		}
		// The ACTIVE segment - the one holding the head - is never pruned away:
		// it is the append target, and upTo < last guarantees it holds a
		// retained height.
		if s.file != nil {
			path := filepath.Join(s.dir, e.Name())
			if active, aerr := s.fileIsActiveSegment(path); aerr == nil && active {
				continue
			}
		}
		info, err := e.Info()
		if err != nil {
			return PruneStats{}, err
		}
		segs = append(segs, segEntry{idx: idx, name: e.Name(), size: info.Size()})
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].idx < segs[j].idx })

	for _, seg := range segs {
		if segmentMaxHeight(seg.idx) >= first {
			continue // holds a retained height
		}
		if err := os.Remove(filepath.Join(s.dir, seg.name)); err != nil {
			return stats, err
		}
		s.readMu.Lock()
		s.closeReaderLocked(seg.name)
		s.readMu.Unlock()
		stats.Blocks++
		stats.BlockBytes += seg.size
	}
	for h := range s.index {
		if h < first {
			delete(s.index, h)
		}
	}
	s.first = first
	s.firstOffset = offsetOfFirstRetained
	stats.FirstHeight = first
	return stats, nil
}

// fileIsActiveSegment reports whether path is the block segment s.file appends
// to. It compares inodes rather than names, so a caller cannot be fooled by a
// path that happens to look the same.
func (s *Store) fileIsActiveSegment(path string) (bool, error) {
	if s.file == nil {
		return false, nil
	}
	fi, err := s.file.Stat()
	if err != nil {
		return false, err
	}
	target, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return os.SameFile(fi, target), nil
}

// PruneCerts deletes every certificate segment that lies entirely below the
// certificate horizon and records upTo as the first certificate height - the
// HORIZON'S OWN certificate is KEPT, deliberately.
//
// It is kept for the same reason the head's is: it is the proof of the
// checkpoint. The chain's checkpoint at H is (block H, state at H, the votes for
// H), and exporting it again - to move a seat to a new machine, days after the
// prune - must be possible from the pruned directory alone. Dropping cert(H)
// would make the only copy of that proof the checkpoint file itself, so a lost
// or stale checkpoint could never be rebuilt.
//
// Certificate records are self-describing (each carries its own height key), so
// this needs no offset: the segment that straddles the horizon keeps its pruned
// prefix on disk and scanCerts skips anything below the recorded first height.
// That is the same no-rewrite argument PruneBlocks makes, and it leaves at most
// one segment's dead prefix behind (~500 B per record at the measured rate).
//
// It is called AFTER the checkpoint for the horizon has been written, because
// the checkpoint carries the horizon's certificate - that is what makes it
// verifiable - and a crash between the two leaves surplus certificates, which
// the next pass reclaims. The reverse order would delete evidence the checkpoint
// had not yet saved.
func (s *Store) PruneCerts(upTo uint64) (PruneStats, error) {
	if err := retention.Deletable(retention.CertSegments); err != nil {
		return PruneStats{}, err
	}
	if err := retention.Deletable(retention.LegacyCertLog); err != nil {
		return PruneStats{}, err
	}
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	var stats PruneStats
	stats.FirstHeight = s.first
	first := upTo
	if first == 0 {
		first = 1
	}
	if first <= s.certFirst {
		return stats, nil
	}
	m, err := readBaseMarker(s.dir)
	if err != nil {
		return stats, err
	}
	m.certFirst = first
	if err := writeBaseMarker(s.dir, m); err != nil {
		return stats, err
	}

	// A segment is removable when its HIGHEST PHYSICAL certificate - tracked by
	// the scan for every record, including heights below the horizon - is. Using
	// the index alone would leak: after an interrupted pass, a segment can hold
	// nothing but pruned records and therefore have no index entry at all, and
	// it would never be reclaimed. The boundary segment stays, with its dead
	// prefix.
	var segs []uint64
	for idx, max := range s.certSegMax {
		if max < first {
			segs = append(segs, idx)
		}
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i] < segs[j] })
	for _, idx := range segs {
		name := certSegmentName(idx)
		path := filepath.Join(s.dir, name)
		info, statErr := os.Stat(path)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return stats, err
		}
		s.readMu.Lock()
		s.closeReaderLocked(name)
		s.readMu.Unlock()
		for h, loc := range s.certIndex {
			if loc.seg == idx {
				delete(s.certIndex, h)
			}
		}
		delete(s.certSegRecords, idx)
		delete(s.certSegMax, idx)
		stats.CertSegs++
		if statErr == nil {
			stats.CertBytes += info.Size()
		}
	}
	// The in-memory index must agree with the horizon even for the boundary
	// segment, whose records are still on disk: a pruned height is an ABSENT
	// certificate, not a served one.
	for h := range s.certIndex {
		if h < first {
			delete(s.certIndex, h)
		}
	}
	s.certFirst = first

	// The active segment may just have been deleted (a node whose newest
	// certificate is at the horizon still needs an append target for its next
	// commit). Recreate it empty, with a header, at the same index.
	if _, ok := s.certSegRecords[s.certSeg]; !ok && s.certFile != nil {
		path := filepath.Join(s.dir, certSegmentName(s.certSeg))
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if err := s.recreateCertSegmentLocked(path); err != nil {
				return stats, err
			}
		}
	}

	// The legacy single log: removed WHOLE once every height it holds is below
	// the horizon. It is never partially rewritten - it is not this build's
	// format any more, and its bytes are the record of what an older build
	// wrote.
	if s.legacyCertExist && s.legacyCertMax > 0 && s.legacyCertMax < first {
		path := filepath.Join(s.dir, certLogName)
		info, statErr := os.Stat(path)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return stats, err
		}
		s.readMu.Lock()
		s.closeReaderLocked(certLogName)
		s.readMu.Unlock()
		for h, loc := range s.certIndex {
			if loc.seg == legacyCertSeg {
				delete(s.certIndex, h)
			}
		}
		s.legacyCertExist = false
		s.legacyCertRecs = 0
		s.legacyCertMax = 0
		stats.LegacyCerts = true
		if statErr == nil {
			stats.LegacyBytes = info.Size()
		}
	}
	return stats, nil
}

// recreateCertSegmentLocked replaces the active certificate segment with an
// empty one carrying the format header, after a prune deleted it. The caller
// holds indexMu; the handle swap is the certificate log's version of the block
// rollover.
func (s *Store) recreateCertSegmentLocked(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := ensureSegmentHeader(f); err != nil {
		_ = f.Close()
		return err
	}
	old := s.certFile
	s.certFile = f
	s.certSegRecords[s.certSeg] = 0
	s.certSegMax[s.certSeg] = 0
	syncDir(s.dir)
	if old != nil {
		return old.Close()
	}
	return nil
}
