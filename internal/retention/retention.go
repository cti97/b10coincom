// Package retention is THE answer to "what may a pruning pass delete".
//
// M7 bounds a node's history instead of letting the data directory grow
// forever (18 hours of the three-host run: 558 MB, 710 B/block, ~1.7 GB/day).
// The danger in that sentence is the word "delete". Two records on the disk are
// load-bearing for CONSENSUS SAFETY rather than for history, and a pruner that
// treats the data directory as a cache and takes them is a double-vote bug
// wearing a disk-cleanup costume:
//
//   - rounds.log is a validator's position at a height. Losing it can make a
//     restarted validator re-enter a round it already advanced past. The lock
//     log (never pruned here either) still refuses a conflicting VOTE, but the
//     round record is what keeps the restart from re-running the ladder from
//     round 0, and the two together are what the restart tests assert.
//   - genesis.hash is the chain's identity. A pruning pass that removes it
//     leaves a directory that can be opened with the WRONG genesis, and the
//     mismatch becomes a silent re-sync instead of a fatal, named refusal.
//
// Both are PERMANENT here by construction, in ONE table, and the pruner
// consults that table rather than carrying its own list. A test asserts the
// exclusions (retention_test.go), so a future record cannot be made prunable
// by adding it to a deletion call site: it has to be added to the table.
package retention

import "fmt"

// Record identifies one kind of thing a pruning pass could touch. The values
// are stable strings so a log line, a test failure and a doc table can all name
// the same record.
type Record string

const (
	// BlockSegments are the numbered .seg block files. A segment holds
	// BlocksPerSegment blocks; pruning drops whole segments below the horizon
	// and rewrites the one the horizon falls inside. PRUNABLE.
	BlockSegments Record = "block-segments"

	// CertSegments are the certs-NNNNNNNN.cseg certificate segments. One
	// certificate per committed height, so a segment is archival evidence for
	// a bounded height range. PRUNABLE below the horizon.
	CertSegments Record = "cert-segments"

	// LegacyCertLog is a pre-M7 certs.log: the single append-only file that
	// motivated the milestone (68% of the data directory). Read-only in this
	// build and PRUNABLE as a whole once every height it holds is below the
	// horizon, so an upgraded node reaches the same steady state as a new one.
	LegacyCertLog Record = "legacy-cert-log"

	// GenesisMarker is genesis.hash. PERMANENT: it is the chain's identity,
	// and a missing marker makes a wrong genesis an unremarkable re-sync.
	GenesisMarker Record = "genesis.hash"

	// RoundLog is rounds.log. PERMANENT: it is the restart position of a
	// validator, and forgetting it is a liveness regression at best and a
	// re-entered ladder at worst. The lock log is its safety sibling.
	RoundLog Record = "rounds.log"

	// LockLog is locks.log. PERMANENT: it is the double-vote promise. Nothing
	// in M7 prunes it; the store's own below-head compaction (audit C-13),
	// which keeps head and head+1, is a different mechanism and does not run
	// on this table.
	LockLog Record = "locks.log"

	// HeadBlock is the head block itself. PERMANENT: the node must know what
	// it last committed, and the horizon may never reach it.
	HeadBlock Record = "head-block"

	// HeadCertificate is the commit certificate for the head. PERMANENT: it
	// is the proof the node last committed what it says it did, and it is what
	// a peer is served for the head.
	HeadCertificate Record = "head-certificate"

	// HorizonCommittee is the committee that validates the first retained
	// height. With the committee derived per epoch from committed state, the
	// checkpoint's state snapshot IS the horizon committee's source; it is
	// permanent because a replayed state that cannot be checked is not a
	// recovery.
	HorizonCommittee Record = "horizon-committee"

	// BaseHeightMarker is base.height, the first height the directory still
	// holds. PERMANENT: it is what tells the next Open that heights below it
	// are ABSENT rather than corrupt, and losing it renumbers the chain.
	BaseHeightMarker Record = "base.height"

	// Checkpoint is the checkpoint file a pruned directory keeps at its
	// horizon. PERMANENT: it is the ONLY way that directory can restart, and
	// the only way it can hand a recovery to a peer.
	Checkpoint Record = "checkpoint"
)

// Entry is one row of the table: what the record is, whether a pruning pass may
// delete it, and why. The Why column is not decoration - it is the argument a
// reviewer checks when a new record is added.
type Entry struct {
	Record   Record
	Prunable bool
	Why      string
}

// table is THE table. Anything a pruning pass deletes must appear here with
// Prunable true; anything that must survive appears here with Prunable false.
// There is deliberately no "unknown record" default: Deletable refuses a record
// the table does not name, so a new file cannot be pruned by forgetting to
// classify it.
var table = []Entry{
	{BlockSegments, true, "block bodies below the retention horizon; the checkpoint and the retained segments carry the chain forward"},
	{CertSegments, true, "commit certificates below the retention horizon; the head's and the checkpoint's are kept"},
	{LegacyCertLog, true, "a pre-M7 single certs.log, once every height it holds is below the horizon"},
	{GenesisMarker, false, "chain identity: a missing marker turns a wrong genesis into a silent re-sync instead of a fatal refusal"},
	{RoundLog, false, "the validator's restart position; losing it re-runs the round ladder it had already left"},
	{LockLog, false, "the double-vote promise; deleting it is a consensus-safety bug, not disk hygiene"},
	{HeadBlock, false, "the node must know what it last committed"},
	{HeadCertificate, false, "the proof of the head commit, and what a peer is served for it"},
	{HorizonCommittee, false, "the seats that validate the first retained height; a replayed state that cannot be checked is not a recovery"},
	{BaseHeightMarker, false, "the first height still present; losing it renumbers every remaining block"},
	{Checkpoint, false, "the pruned directory's only restart path and its recovery hand-off"},
}

// Table returns a copy of the whole table, in declaration order. A copy, so a
// caller cannot rewrite the policy by mutating what it was handed.
func Table() []Entry {
	out := make([]Entry, len(table))
	copy(out, table)
	return out
}

// lookup finds a record's row.
func lookup(r Record) (Entry, bool) {
	for _, e := range table {
		if e.Record == r {
			return e, true
		}
	}
	return Entry{}, false
}

// Deletable reports whether a pruning pass may delete this record. A record the
// table does not name is NOT deletable: the safe direction for an unclassified
// file is to keep it, and the error tells the caller its table is incomplete.
func Deletable(r Record) error {
	e, ok := lookup(r)
	if !ok {
		return fmt.Errorf("retention: %q is not in the prunable-vs-permanent table; a pruning pass may not guess", r)
	}
	if !e.Prunable {
		return fmt.Errorf("retention: %q is PERMANENT (%s)", r, e.Why)
	}
	return nil
}

// Permanent returns every record the table forbids pruning, in declaration
// order. It is what the exclusion test iterates so that a new permanent record
// is covered the moment it is added to the table.
func Permanent() []Record {
	var out []Record
	for _, e := range table {
		if !e.Prunable {
			out = append(out, e.Record)
		}
	}
	return out
}

// Prunable returns every record the table allows pruning, in declaration order.
// The pruner's deletion path is built from this list, so it can only ever touch
// what the table names as prunable.
func Prunable() []Record {
	var out []Record
	for _, e := range table {
		if e.Prunable {
			out = append(out, e.Record)
		}
	}
	return out
}
