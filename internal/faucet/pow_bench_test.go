package faucet

import "testing"

// Cost basis for the R-1/S-4 report. Run with:
//
//	go test -run '^$' -bench 'Benchmark(PreCheck|Argon2Verify)' -benchmem ./internal/faucet
//	go test -run '^$' -bench BenchmarkSolveClaim -benchtime=3x ./internal/faucet
//
// The two numbers that matter are the ratio of PreCheck (the cheap admission
// filter) to Argon2Verify (the real check it defers), and the submitter's
// SolveClaim cost, which is what makes the outer puzzle a bound on a flood.

var (
	benchPub     = []byte("a-32-byte-public-key-padded-here!")
	benchDevnet  = Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1}
	benchTestnet = Argon2Params{MemoryKiB: 8192, Iterations: 1, Parallelism: 1}
)

// BenchmarkPreCheck is one cheap outer digest plus its target comparison: the
// cost a node pays to REJECT a claim that did not solve it.
func BenchmarkPreCheck(b *testing.B) {
	var nonce uint64
	for i := 0; i < b.N; i++ {
		_ = MeetsPreTarget(PreDigest(benchPub, 1, nonce))
		nonce++
	}
}

// BenchmarkArgon2Verify is one real claim verification: the work a node defers
// to block build/apply time for a claim that passed admission.
func BenchmarkArgon2Verify(b *testing.B) {
	for _, tc := range []struct {
		name string
		p    Argon2Params
	}{
		{"devnet", benchDevnet},
		{"testnet", benchTestnet},
	} {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = MeetsTarget(PowDigest(benchPub, 1, uint64(i), tc.p), easyTarget())
			}
		})
	}
}

// BenchmarkSolveClaim is the submitter's cost to produce one claim that the
// mempool will admit (outer puzzle + Argon2id). Run it with -benchtime=3x: each
// iteration is a full solve.
func BenchmarkSolveClaim(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, ok := SolveClaim(benchPub, 1, easyTarget(), benchDevnet, 1<<24); !ok {
			b.Fatal("SolveClaim failed")
		}
	}
}
