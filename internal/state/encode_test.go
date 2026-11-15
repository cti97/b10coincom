package state

import (
	"bytes"
	"testing"

	"github.com/cti97/b10coincom/internal/types"
)

// M7: the canonical state encoding a checkpoint carries. The checkpoint's
// certificate authenticates the state ROOT, so the snapshot must decode to a
// state that reproduces that root - and a resumed node must get the SAME state,
// not merely one with the same hash (two states can agree on Root while holding
// different map contents only if the extra content is uncommitted; this encoding
// has no uncommitted fields except the height, which travels too).

func encodeFixtureState(t *testing.T) *State {
	t.Helper()
	st := NewWithParams(Params{FaucetAddress: types.Address{1}, ClaimAmount: 7, EpochBlocks: 4, MinStake: 100})
	a := types.Address{0xAA}
	b := types.Address{0xBB}
	st.Set(a, Account{Balance: 1000, Nonce: 3, ClaimedEpoch: 9})
	st.Set(b, Account{Balance: 5})
	st.SetBond(a, Bond{Validator: bytes.Repeat([]byte{0x11}, 32), Amount: 500, Unfunded: 200, Height: 4})
	st.SetBond(b, Bond{Validator: bytes.Repeat([]byte{0x22}, 32), Amount: 100, Height: 12})
	// Two unbonding records for one address, out of release order on purpose:
	// the encoding preserves the slice, and Equal checks it.
	st.unbonding[a] = []Unbonding{{Amount: 10, ReleaseHeight: 20}, {Amount: 3, ReleaseHeight: 16}}
	st.SetHeight(37)
	return st
}

func TestStateEncodingRoundTripsEveryCommittedField(t *testing.T) {
	st := encodeFixtureState(t)
	enc := st.Encode()
	back, err := DecodeState(enc, st.Params())
	if err != nil {
		t.Fatalf("DecodeState: %v", err)
	}
	if !back.Equal(st) {
		t.Fatal("the decoded state is not the encoded state")
	}
	if root, want := back.Root(), st.Root(); root != want {
		t.Fatalf("the decoded state's root is %x, want %x", root[:8], want[:8])
	}
	// Re-encoding is byte-identical: the encoding is a function of the state.
	if again := back.Encode(); !bytes.Equal(again, enc) {
		t.Fatal("the state does not re-encode to the same bytes")
	}
	// The execution height travels, because a resumed node judges the next
	// block's claims against it.
	if back.height != 37 {
		t.Fatalf("decoded height = %d, want 37", back.height)
	}
}

func TestStateDecodingIsStrict(t *testing.T) {
	st := encodeFixtureState(t)
	enc := st.Encode()
	if _, err := DecodeState(enc[:len(enc)-1], st.Params()); err == nil {
		t.Fatal("a truncated encoding decoded")
	}
	if _, err := DecodeState(append(append([]byte(nil), enc...), 0), st.Params()); err == nil {
		t.Fatal("an encoding with a trailing byte decoded")
	}
	bad := append([]byte(nil), enc...)
	bad[0] = 99
	if _, err := DecodeState(bad, st.Params()); err == nil {
		t.Fatal("a snapshot with an unknown layout version decoded")
	}
}

func TestAParamsMismatchCannotMoveTheRoot(t *testing.T) {
	// Params are protocol configuration, not committed state: decoding a
	// snapshot with different params gives a state with those params (which is
	// what the caller's chain runs with) but the SAME root, so a checkpoint
	// verifier still compares like with like.
	st := encodeFixtureState(t)
	other := st.Params()
	other.ClaimAmount = 999
	back, err := DecodeState(st.Encode(), other)
	if err != nil {
		t.Fatal(err)
	}
	if back.Root() != st.Root() {
		t.Fatal("changing the params moved the root")
	}
	if back.Params().ClaimAmount != 999 {
		t.Fatal("the decoded state did not take the caller's params")
	}
}
