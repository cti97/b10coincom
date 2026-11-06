package genesis

// Audit S-7 (2026-11-06) said Genesis.Validate accepts an Argon2id tuning whose
// memory is below 8 x lanes, and that golang.org/x/crypto's argon2.IDKey PANICS
// on it, crashing the node on every claim.
//
// The pinned library source (golang.org/x/crypto v0.58.0, argon2/argon2.go
// deriveKey) does NOT do that. Its only panics are:
//
//	if time < 1    { panic("argon2: number of rounds too small") }
//	if threads < 1 { panic("argon2: parallelism degree too low") }
//
// and both are already refused by Validate (and guarded again in
// state.applyFaucetClaim before the call). Memory is COERCED instead:
//
//	memory = memory / (4 * lanes) * (4 * lanes)   // floor to a 4-lane step
//	if memory < 8 * lanes { memory = 8 * lanes }  // raise to that floor
//
// So the finding's mechanism is false; what is true is that a validating genesis
// could declare one memory cost and run another. These tests pin both halves:
// the library does not panic on the tunings the finding names, and Validate now
// accepts only tunings the library uses VERBATIM.

import (
	"errors"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/faucet"
)

// TestValidateAcceptsOnlyArgon2TuningsTheLibraryUsesVerbatim is the refusal: a
// tuning the library would floor or raise is rejected, with a message that names
// the relation; a fixed point of the derivation validates.
func TestValidateAcceptsOnlyArgon2TuningsTheLibraryUsesVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name      string
		memKiB    uint32
		par       uint8
		wantValid bool
	}{
		// The shipped tunings, both one lane and already exact.
		{"shipped devnet", 64, 1, true},
		{"shipped testnet", 8192, 1, true},
		// Fixed points at higher lane counts: >= 8 x lanes, multiple of 4 x lanes.
		{"the 8 x lanes floor at one lane", 8, 1, true},
		{"the 8 x lanes floor at two lanes", 16, 2, true},
		{"a multiple of 4 x lanes", 64, 4, true},
		{"the floor at the maximum lane count", 8 * 255, 255, true},
		// The finding's example and its neighbours: memory below 8 x lanes.
		{"the finding's relation at one lane", 1, 1, false},
		{"below the floor at one lane", 7, 1, false},
		{"below the floor at 255 lanes", 1, 255, false},
		// Above the floor but not a whole number of 4-lane segments: the
		// library floors these, so the declared cost is not the cost paid.
		{"not a multiple of 4 x lanes", 100, 3, false},
		{"just above the floor, unaligned", 10, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := Testnet()
			g.Params.FaucetPowArgon2.MemoryKiB = tc.memKiB
			g.Params.FaucetPowArgon2.Parallelism = tc.par
			err := g.Validate()
			if tc.wantValid {
				if err != nil {
					t.Fatalf("MemoryKiB=%d Parallelism=%d must VALIDATE (it is a fixed point of the library's derivation), got %v", tc.memKiB, tc.par, err)
				}
				return
			}
			if !errors.Is(err, ErrBadGenesis) {
				t.Fatalf("MemoryKiB=%d Parallelism=%d must be REFUSED with ErrBadGenesis, got %v", tc.memKiB, tc.par, err)
			}
			// The message must name the relation, not merely report a bad value:
			// the operator has to be able to see WHICH arithmetic was violated.
			for _, want := range []string{"8 x parallelism", "4 x parallelism"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not name the relation (%q missing): %v", want, err)
				}
			}
		})
	}
}

// TestArgon2DoesNotPanicOnExtremeTunings is the source-reading pin, executed
// rather than asserted. It evaluates the exact tunings the finding says panic -
// memory below 8 x lanes, down to 1 KiB at 255 lanes - and requires the library
// to return a digest. It also pins the OTHER half of the source: the only two
// tunings that DO panic are zero rounds and zero lanes, both of which
// Genesis.Validate refuses before any chain can run.
//
// If a future x/crypto changes either behaviour, this test says so in the
// library's terms rather than leaving a comment that quietly went stale.
func TestArgon2DoesNotPanicOnExtremeTunings(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    faucet.Argon2Params
	}{
		{"1 KiB at one lane", faucet.Argon2Params{MemoryKiB: 1, Iterations: 1, Parallelism: 1}},
		{"1 KiB at 255 lanes", faucet.Argon2Params{MemoryKiB: 1, Iterations: 1, Parallelism: 255}},
		{"7 KiB at one lane", faucet.Argon2Params{MemoryKiB: 7, Iterations: 1, Parallelism: 1}},
		{"100 KiB at three lanes", faucet.Argon2Params{MemoryKiB: 100, Iterations: 1, Parallelism: 3}},
		{"10 KiB at three lanes", faucet.Argon2Params{MemoryKiB: 10, Iterations: 1, Parallelism: 3}},
		{"the 8 x lanes floor at 255 lanes", faucet.Argon2Params{MemoryKiB: 8 * 255, Iterations: 1, Parallelism: 255}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("argon2 PANICKED on MemoryKiB=%d Parallelism=%d: %v - the finding's mechanism would be real at this x/crypto version; record it before trusting the S-7 correction",
						tc.p.MemoryKiB, tc.p.Parallelism, r)
				}
			}()
			got := faucet.PowDigest([]byte("s7-claimant"), 1, 0, tc.p)
			if got == ([32]byte{}) {
				t.Fatalf("MemoryKiB=%d Parallelism=%d produced the zero digest", tc.p.MemoryKiB, tc.p.Parallelism)
			}
		})
	}

	// The library's ONLY panics, in the library's own terms. Both are refused by
	// Validate (TestValidateRejectsAZeroFaucetPuzzleTuning) and guarded again in
	// state.applyFaucetClaim, so no chain can reach them.
	for _, tc := range []struct {
		name string
		p    faucet.Argon2Params
	}{
		{"zero rounds", faucet.Argon2Params{MemoryKiB: 64, Iterations: 0, Parallelism: 1}},
		{"zero lanes", faucet.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			func() {
				defer func() {
					if recover() == nil {
						t.Fatalf("%s: argon2 did NOT panic; the source's panic set has changed and the guards in Validate/applyFaucetClaim must be re-checked", tc.name)
					}
				}()
				_ = faucet.PowDigest([]byte("s7-claimant"), 1, 0, tc.p)
			}()
		})
	}
}
