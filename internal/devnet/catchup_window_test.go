package devnet

import "testing"

// TestALaggingValidatorAboveOneWindowStillPulls pins the H-1 catch-up defect
// (test run 2026-10-30): a validator whose head is already past one response
// window must still pull from an honest, never-yet-pulled member that stands
// ahead of it. An unproven member is meant to be trusted for one window ABOVE
// OUR HEAD, not up to the absolute height of one window.
func TestALaggingValidatorAboveOneWindowStillPulls(t *testing.T) {
	v := startQuietValidator(t)
	win := v.peerWindow()
	for v.ch.Height() < win+36 {
		blk, err := v.ch.Build(v.priv, nil, v.ch.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.ch.Append(blk); err != nil {
			t.Fatal(err)
		}
	}
	mine := v.ch.Height()
	v.recordHeight(memberKey(v, 1), "v1", mine+50) // honest, ahead, never pulled from

	var froms []uint64
	v.pull = func(from uint64) error { froms = append(froms, from); return nil }
	v.maybeCatchUp()
	if len(froms) != 1 || froms[0] != mine+1 {
		t.Fatalf("head %d, member announces %d: pulls %v, want one pull from %d (window %d)", mine, mine+50, froms, mine+1, win)
	}
}
