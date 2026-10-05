package mempool

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/types"
)

// Admission-cost benchmarks for the R-1 report. Run with a bounded iteration
// count, because each iteration needs a distinct freshly signed claim:
//
//	go test -run '^$' -bench BenchmarkAdmitGarbageClaim -benchtime=2000x ./internal/mempool
//
// BenchmarkAdmitGarbageClaim times the COMMITTED path: a garbage claim (no
// outer solution) is rejected by one BLAKE3 hash.
// BenchmarkAdmitGarbageClaimWithoutPrePuzzle times the PRE-FIX shape: the same
// pool with the outer target disabled admits the claim after its signature
// check, exactly as signature-only admission did; the deferred Argon2id
// evaluation it then forces is BenchmarkArgon2Verify in internal/faucet.

func benchNonce(b *testing.B, pub []byte, epoch uint64, wantPass bool) uint64 {
	b.Helper()
	for n := uint64(0); n < 1<<20; n++ {
		if faucet.MeetsPreTarget(faucet.PreDigest(pub, epoch, n)) == wantPass {
			return n
		}
	}
	b.Fatal("no nonce with the requested outer-puzzle outcome")
	return 0
}

func benchClaims(b *testing.B, n int, needOuterSolution bool) []types.Tx {
	b.Helper()
	batch := make([]types.Tx, n)
	for i := range batch {
		pub, priv, err := crypto.GenerateKey()
		if err != nil {
			b.Fatal(err)
		}
		nonce := uint64(0)
		if !needOuterSolution {
			// The pre-fix benchmark pool has a permissive outer target, so
			// nonce 0 is admissible and cheapest. The committed-path
			// benchmark needs a nonce that FAILS the shipped target.
			nonce = benchNonce(b, pub, 1, false)
		}
		tx := &types.Tx{
			Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
			Nonce: 0, Epoch: 1, PowNonce: nonce,
		}
		h := tx.SigningHash(testChain())
		tx.Sig = crypto.Sign(priv, h[:])
		batch[i] = *tx
	}
	return batch
}

func BenchmarkAdmitGarbageClaim(b *testing.B) {
	st := testState()
	m := New(b.N+1, testChain(), testHead(st, 0)) // shipped target
	batch := benchClaims(b, b.N, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Add([]types.Tx{batch[i]})
	}
}

func BenchmarkAdmitGarbageClaimWithoutPrePuzzle(b *testing.B) {
	st := testState()
	m := New(b.N+1, testChain(), testHead(st, 0))
	m.preTarget = allPassPreTarget() // the pre-fix, signature-only admission shape
	batch := benchClaims(b, b.N, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Add([]types.Tx{batch[i]})
	}
}
