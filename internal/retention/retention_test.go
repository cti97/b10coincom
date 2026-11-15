package retention

import (
	"strings"
	"testing"
)

// TestTheTableForbidsPruningEverySafetyCriticalRecord is the assertion plan §3
// demands in code: the round record, the genesis identity, the head block and
// its certificate, and the committee at the horizon are NEVER prunable. It
// deliberately names the records it expects, so deleting a row fails a test
// instead of quietly widening what a pruning pass may delete.
func TestTheTableForbidsPruningEverySafetyCriticalRecord(t *testing.T) {
	for _, r := range []Record{
		RoundLog,
		GenesisMarker,
		HeadBlock,
		HeadCertificate,
		HorizonCommittee,
		LockLog,
		BaseHeightMarker,
		Checkpoint,
	} {
		if err := Deletable(r); err == nil {
			t.Fatalf("retention says %q is prunable; it must never be", r)
		}
	}
	// The round record is the sharp edge the plan calls out, in its own words:
	// a validator that forgets its highest signed round can sign twice at the
	// same height. Pin the error's reason so the table's argument cannot be
	// replaced by a shrug.
	err := Deletable(RoundLog)
	if err == nil || !strings.Contains(err.Error(), "safety") && !strings.Contains(err.Error(), "restart") {
		t.Fatalf("rounds.log's refusal reads %v; it must state that the record is safety/restart state", err)
	}
}

// TestEveryRecordInTheTableIsClassifiedExactlyOnce guards the table's shape: a
// duplicate row would make Deletable's answer depend on declaration order.
func TestEveryRecordInTheTableIsClassifiedExactlyOnce(t *testing.T) {
	seen := make(map[Record]bool)
	for _, e := range Table() {
		if seen[e.Record] {
			t.Fatalf("%q appears twice in the retention table", e.Record)
		}
		seen[e.Record] = true
		if strings.TrimSpace(e.Why) == "" {
			t.Fatalf("%q has no Why column; the table's value is the argument, not the boolean", e.Record)
		}
	}
	if len(Table()) == 0 {
		t.Fatal("the retention table is empty")
	}
}

// TestThePrunableAndPermanentListsPartitionTheTable pins the two views the
// pruner and the exclusion test read: together they are the whole table, and
// neither contains the other.
func TestThePrunableAndPermanentListsPartitionTheTable(t *testing.T) {
	inPrunable := make(map[Record]bool)
	for _, r := range Prunable() {
		inPrunable[r] = true
	}
	inPermanent := make(map[Record]bool)
	for _, r := range Permanent() {
		inPermanent[r] = true
	}
	for _, e := range Table() {
		if inPrunable[e.Record] == inPermanent[e.Record] {
			t.Fatalf("%q is in both or neither of Prunable() and Permanent()", e.Record)
		}
		if inPrunable[e.Record] != e.Prunable {
			t.Fatalf("%q: Prunable() disagrees with the table row", e.Record)
		}
	}
	if len(inPrunable)+len(inPermanent) != len(Table()) {
		t.Fatalf("the two views hold %d records, the table %d", len(inPrunable)+len(inPermanent), len(Table()))
	}
}

// TestAnUnknownRecordIsNotDeletable is the safe default: a file the table does
// not name cannot be pruned by a call site that forgot to classify it, and the
// error says the table is incomplete rather than pretending the record is safe
// to delete.
func TestAnUnknownRecordIsNotDeletable(t *testing.T) {
	err := Deletable(Record("wallet.dat"))
	if err == nil {
		t.Fatal("an unclassified record was reported deletable")
	}
	if !strings.Contains(err.Error(), "not in the prunable-vs-permanent table") {
		t.Fatalf("an unknown record's refusal reads %v; it must send the reader to the table", err)
	}
}

// TestTheTableIsACopy pins that Table's caller cannot rewrite the policy.
func TestTheTableIsACopy(t *testing.T) {
	tbl := Table()
	tbl[0].Prunable = false
	if e, ok := lookup(tbl[0].Record); !ok || e.Prunable != table[0].Prunable {
		t.Fatalf("mutating the table copy changed the policy for %q", tbl[0].Record)
	}
}
