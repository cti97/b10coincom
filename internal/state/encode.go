package state

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/cti97/b10coincom/internal/types"
)

// Canonical state encoding (M7). A checkpoint carries the committed state at
// its horizon, and the checkpoint's quorum certificate authenticates the state
// ROOT - so the import must be able to (a) reproduce that root from the
// snapshot and (b) compare two snapshots byte for byte if it ever needs to.
// That makes this encoding consensus-critical in the same way the block
// encoding is: sorted keys, fixed widths, varint lengths, no maps in iteration
// order, and a strict decoder that refuses trailing bytes.
//
// It is NOT part of the state root - Root() hashes the leaves, not this
// encoding - so the format can change without moving any root, as long as it
// round-trips the same state. Keeping it out of the root is deliberate: the
// root's leaf layout is pinned by fixed vectors (stake_test.go, audit ST-8) and
// a checkpoint format change must not be able to move them.
//
// The height travels with the state because a checkpoint resumes EXECUTION at
// the next block: the claim rule derives its epoch from the state's height, so
// a resumed state with height 0 would judge the first retained block's claims
// against the wrong epoch.

// stateEncodeVersion is the layout version this build writes and reads. The
// decoder refuses any other value rather than guessing at a different layout.
const stateEncodeVersion = 1

// Encode returns the canonical encoding of the committed state: the height, the
// accounts, the bonds and the unbonding records, each group in address order.
// The params are NOT encoded - they are protocol configuration derived from
// genesis, which every node already holds, and they are not part of the root.
func (s *State) Encode() []byte {
	e := types.NewEncoder()
	e.U8(stateEncodeVersion)
	e.U64(s.height)

	addrs := sortedAddressKeys(s.accounts)
	e.Len(len(addrs))
	for _, a := range addrs {
		acc := s.accounts[a]
		e.Raw(a[:])
		e.U64(acc.Balance)
		e.U64(acc.Nonce)
		e.U64(acc.ClaimedEpoch)
	}

	bondAddrs := sortedAddressKeys(s.bonds)
	e.Len(len(bondAddrs))
	for _, a := range bondAddrs {
		b := s.bonds[a]
		e.Raw(a[:])
		e.VarBytes(b.Validator)
		e.U64(b.Amount)
		e.U64(b.Unfunded)
		e.U64(b.Height)
	}

	unbondAddrs := sortedAddressKeys(s.unbonding)
	e.Len(len(unbondAddrs))
	for _, a := range unbondAddrs {
		recs := slices.Clone(s.unbonding[a])
		// Root sorts by (amount, releaseHeight) before hashing; the encoding
		// deliberately keeps the state's own order instead, so a snapshot
		// round-trips the slice exactly. Records are appended by applyUnbond in
		// a deterministic order on every node, so this is stable across nodes.
		e.Raw(a[:])
		e.Len(len(recs))
		for _, rec := range recs {
			e.U64(rec.Amount)
			e.U64(rec.ReleaseHeight)
		}
	}
	return e.Bytes()
}

// DecodeState reads Encode's output. params must be the protocol parameters of
// the chain the snapshot came from (genesis-derived: the faucet, the claim and
// staking rules, the chain identifier). A snapshot decoded with other params
// would compute a different root and be refused by the caller anyway, but
// taking them as an argument keeps the state package's rule that params travel
// with the state they parameterise.
//
// Every read is bounds-checked and the decoder is strict: trailing bytes mean
// the input had a second interpretation and are refused, exactly as the block
// codec refuses them.
func DecodeState(b []byte, params Params) (*State, error) {
	d := types.NewDecoder(b)
	version, err := d.U8()
	if err != nil {
		return nil, err
	}
	if version != stateEncodeVersion {
		return nil, fmt.Errorf("state: snapshot layout version %d, want %d", version, stateEncodeVersion)
	}
	height, err := d.U64()
	if err != nil {
		return nil, err
	}
	s := NewWithParams(params)
	s.height = height

	n, err := d.Len()
	if err != nil {
		return nil, err
	}
	// A count is bounded by the bytes that could follow it; pre-allocating on
	// the declared count alone is how a short frame asks for gigabytes.
	if n > d.Remaining() {
		return nil, fmt.Errorf("%w: account count %d exceeds the %d bytes left", types.ErrShortBuffer, n, d.Remaining())
	}
	for i := 0; i < n; i++ {
		addr, err := d.Fixed20()
		if err != nil {
			return nil, err
		}
		var acc Account
		if acc.Balance, err = d.U64(); err != nil {
			return nil, err
		}
		if acc.Nonce, err = d.U64(); err != nil {
			return nil, err
		}
		if acc.ClaimedEpoch, err = d.U64(); err != nil {
			return nil, err
		}
		if acc.isZero() {
			return nil, fmt.Errorf("state: snapshot carries a zero account for %x; Set prunes those, so this is not a state Encode wrote", addr[:])
		}
		s.accounts[addr] = acc
	}

	n, err = d.Len()
	if err != nil {
		return nil, err
	}
	if n > d.Remaining() {
		return nil, fmt.Errorf("%w: bond count %d exceeds the %d bytes left", types.ErrShortBuffer, n, d.Remaining())
	}
	for i := 0; i < n; i++ {
		addr, err := d.Fixed20()
		if err != nil {
			return nil, err
		}
		var b Bond
		if b.Validator, err = d.VarBytes(); err != nil {
			return nil, err
		}
		if b.Amount, err = d.U64(); err != nil {
			return nil, err
		}
		if b.Unfunded, err = d.U64(); err != nil {
			return nil, err
		}
		if b.Height, err = d.U64(); err != nil {
			return nil, err
		}
		if b.Amount == 0 {
			return nil, fmt.Errorf("state: snapshot carries a zero-amount bond for %x; Root ignores those, so this is not a state Encode wrote", addr[:])
		}
		if b.Unfunded > b.Amount {
			return nil, fmt.Errorf("state: snapshot carries a bond for %x whose unfunded part %d exceeds its amount %d", addr[:], b.Unfunded, b.Amount)
		}
		s.bonds[addr] = b
	}

	n, err = d.Len()
	if err != nil {
		return nil, err
	}
	if n > d.Remaining() {
		return nil, fmt.Errorf("%w: unbonding count %d exceeds the %d bytes left", types.ErrShortBuffer, n, d.Remaining())
	}
	for i := 0; i < n; i++ {
		addr, err := d.Fixed20()
		if err != nil {
			return nil, err
		}
		rn, err := d.Len()
		if err != nil {
			return nil, err
		}
		if rn > d.Remaining() {
			return nil, fmt.Errorf("%w: unbonding record count %d exceeds the %d bytes left", types.ErrShortBuffer, rn, d.Remaining())
		}
		recs := make([]Unbonding, rn)
		for j := 0; j < rn; j++ {
			if recs[j].Amount, err = d.U64(); err != nil {
				return nil, err
			}
			if recs[j].ReleaseHeight, err = d.U64(); err != nil {
				return nil, err
			}
		}
		s.unbonding[addr] = recs
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return s, nil
}

// Equal reports whether two states are identical in every committed field -
// accounts, bonds, unbonding records - and in execution height. It exists for
// the checkpoint tests: comparing roots proves the two states AGREE, but this
// proves the snapshot round-tripped the state itself, which is what a resumed
// node needs (two states with the same root but different map contents would
// diverge on the next block).
func (s *State) Equal(o *State) bool {
	if s == nil || o == nil || s.height != o.height {
		return false
	}
	if len(s.accounts) != len(o.accounts) || len(s.bonds) != len(o.bonds) || len(s.unbonding) != len(o.unbonding) {
		return false
	}
	for a, v := range s.accounts {
		if o.accounts[a] != v {
			return false
		}
	}
	for a, v := range s.bonds {
		w, ok := o.bonds[a]
		if !ok || w.Amount != v.Amount || w.Unfunded != v.Unfunded || w.Height != v.Height || !bytes.Equal(w.Validator, v.Validator) {
			return false
		}
	}
	for a, recs := range s.unbonding {
		w, ok := o.unbonding[a]
		if !ok || len(w) != len(recs) {
			return false
		}
		for i := range recs {
			if w[i] != recs[i] {
				return false
			}
		}
	}
	return true
}
