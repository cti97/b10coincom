package chain

// RT-6's measurement: what the router's membership gate used to cost per vote
// and per proposal, and what it costs now.
//
// The gate runs before any signature verification, once per consensus frame.
// It used Chain.CommitteeAt, whose defensive deep copy is a slice plus one
// allocation per seat; on the project's 255-seat ceiling that is 256
// allocations per frame, for an answer that is a single boolean. IsSeatedAt
// reads the same memo under the same read lock and allocates nothing. This
// benchmark is the evidence for the "before and after" numbers; it is not run
// by `go test` (benchmarks are opt-in) and asserts nothing about correctness -
// the tests do that.

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
)

func benchmarkFullCommittee(b *testing.B) *Chain {
	b.Helper()
	g := genesis.Devnet()
	g.Validators = make([]genesis.Validator, 255)
	for i := range g.Validators {
		pub, _, err := crypto.GenerateKey()
		if err != nil {
			b.Fatal(err)
		}
		g.Validators[i] = genesis.Validator{PubKey: pub, Power: 1}
	}
	g.Params.CommitteeSize = len(g.Validators) // the 255-seat ceiling
	c, err := Open(g, b.TempDir())
	if err != nil {
		b.Fatalf("opening the 255-seat fixture chain: %v", err)
	}
	b.Cleanup(func() { _ = c.Close() })
	if vals, err := c.CommitteeAt(0); err != nil || len(vals) != 255 {
		b.Fatalf("fixture: epoch-0 committee = (%d seats, %v), want 255", len(vals), err)
	}
	return c
}

func BenchmarkCommitteeMembershipPerFrame(b *testing.B) {
	c := benchmarkFullCommittee(b)
	seated := c.Genesis().Validators[127].PubKey
	_, stranger, err := crypto.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}

	b.Run("CommitteeAt copy per frame", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := c.CommitteeAt(0); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("IsSeatedAt seated key", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !c.IsSeatedAt(0, seated) {
				b.Fatal("the seated key was reported unseated")
			}
		}
	})
	b.Run("IsSeatedAt stranger key", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if c.IsSeatedAt(0, stranger) {
				b.Fatal("the stranger key was reported seated")
			}
		}
	})
}
