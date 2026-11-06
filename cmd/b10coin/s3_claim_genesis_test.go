package main

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
)

// Testrun S-3: claim and claim --key refused every chain that was not
// b10coin-devnet-1, so no shipped command could fund a key on a chain built by
// the deploy recipe. The decision (docs/decisions-2026-11-06-s2-s3.md) is that
// claim FOLLOWS THE NODE'S GENESIS: it signs over the genesis hash the node
// reports and derives the epoch from the epoch length the node reports. The
// gate's real protection - "never sign for a genesis you did not read" - is
// kept, and is now enforced by reading instead of by refusing.
//
// These tests are the contract: a stub reports a chain that is NOT the devnet
// (its own chain ID, its own 32-byte genesis hash, its own epoch length), and
// the claim must be signed for THAT chain.

// foreignChain returns a genesis hash and a chain ID that are certainly not the
// devnet's: a hash derived from a fixed preimage, and an ID naming a committee.
func foreignChain() (hash [32]byte, id string) {
	return sha256.Sum256([]byte("b10coin-committee-file-fixture-not-the-devnet")), "example-committee-1"
}

func TestClaimWithKeySignsForTheNodesGenesisNotTheDevnets(t *testing.T) {
	keyPath, addr, stub := claimTestSetup(t, 0, 0)
	foreign, chainID := foreignChain()
	stub.pointAt(foreign, chainID, 7, 1_000)

	if err := cmdClaim([]string{"--node", stub.url, "--key", keyPath, "--yes"}); err != nil {
		t.Fatalf("claim --key on a non-devnet chain: %v (the gate must not refuse a chain whose genesis it can read)", err)
	}
	tx := stub.posted()
	if tx.From != addr {
		t.Errorf("From = %s, want the key file's address %s", tx.From, addr)
	}
	h := tx.SigningHash(foreign)
	if !crypto.Verify(tx.PubKey, h[:], tx.Sig) {
		t.Error("the claim's signature does not verify over the genesis hash the NODE reported; it was signed for a compiled-in chain instead")
	}
	if devnet := genesis.Devnet().Hash(); devnet != foreign {
		hDev := tx.SigningHash(devnet)
		if crypto.Verify(tx.PubKey, hDev[:], tx.Sig) {
			t.Error("the claim also verifies over the devnet genesis hash: the binding is not the node's chain")
		}
	}
}

func TestEphemeralClaimFollowsTheNodesGenesisAndEpochLength(t *testing.T) {
	_, _, stub := claimTestSetup(t, 0, 0)
	foreign, chainID := foreignChain()
	// An epoch length that is NOT the compiled-in devnet one, and a height at
	// which the two give different epochs: (100+1)/40 + 1 = 3, while
	// (100+1)/1000 + 1 = 1. A verb using the compiled-in length names epoch 1.
	stub.pointAt(foreign, chainID, 100, 40)

	captureStdout(t, func() {
		if err := cmdClaim([]string{"--node", stub.url, "--print-key=false"}); err != nil {
			t.Fatalf("ephemeral claim on a non-devnet chain: %v", err)
		}
	})
	tx := stub.posted()
	if tx.Epoch != 3 {
		t.Errorf("epoch = %d, want 3 = (height 100 + 1)/epoch_blocks 40 + 1; 1 means the compiled-in devnet epoch length was used", tx.Epoch)
	}
	h := tx.SigningHash(foreign)
	if !crypto.Verify(tx.PubKey, h[:], tx.Sig) {
		t.Error("the ephemeral claim is not signed over the genesis hash the node reported")
	}
}

func TestClaimRefusesANodeThatReportsNoEpochLength(t *testing.T) {
	// The epoch is the claim's only time binding and it is derived from this
	// number, so a zero is refused rather than divided by - on both paths.
	keyPath, _, stub := claimTestSetup(t, 0, 0)
	stub.setEpochBlocks(0)

	err := cmdClaim([]string{"--node", stub.url, "--key", keyPath, "--yes"})
	if err == nil {
		t.Fatal("claim --key signed for a node reporting epoch_blocks 0")
	}
	if !strings.Contains(err.Error(), "epoch_blocks 0") {
		t.Errorf("the refusal does not name epoch_blocks: %v", err)
	}

	err = cmdClaim([]string{"--node", stub.url, "--print-key=false"})
	if err == nil {
		t.Fatal("the ephemeral claim signed for a node reporting epoch_blocks 0")
	}
	if !strings.Contains(err.Error(), "epoch_blocks 0") {
		t.Errorf("the ephemeral refusal does not name epoch_blocks: %v", err)
	}
}
