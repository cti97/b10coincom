package main

// Audit W-1, W-2, W-3, W-5, W-6 (2026-11-01): what the wallet verbs do with a
// node's word, and what the ephemeral claim prints by default.

import (
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

func TestClaimWithKeyRefusesANodeWhoseGenesisIsNotTheDevnets(t *testing.T) {
	keyPath, addr, _ := claimTestSetup(t, 0, 0)
	// The node names the devnet chain but reports another genesis hash: a
	// claim signed over that hash would verify on that other chain (audit W-1).
	var other [32]byte
	other[0] = 0x5a
	stub := newStakingStub(t, other, stakingAccount{Address: addr.String()})
	stub.setChainID(genesis.Devnet().ChainID)
	err := cmdClaim([]string{"--node", stub.url, "--key", keyPath, "--yes"})
	if err == nil {
		t.Fatal("claim --key signed for a node whose genesis hash is not the devnet's")
	}
	if !strings.Contains(err.Error(), "genesis") {
		t.Fatalf("the refusal does not name the genesis mismatch: %v", err)
	}
	stub.mu.Lock()
	n := len(stub.posts)
	stub.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d transactions were posted despite the refusal", n)
	}
}

func TestHistoryRefusesARowItCannotParse(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: addr.String()})
	s.setHistory(walletHistory{
		Address: addr.String(), Head: 2, From: 1, To: 2, Blocks: 2,
		Txs: []walletHistoryEntry{
			{TxID: strings.Repeat("ab", 32), Height: 2, Type: "transfer", From: addr.String(), To: "not-an-address", Amount: 1, Fee: 1},
		},
	})
	err := cmdHistory([]string{"--node", s.url, "--key", keyPath})
	if err == nil {
		t.Fatal("history printed a row whose counterparty is not an address (audit W-2)")
	}
	if !strings.Contains(err.Error(), "address") {
		t.Fatalf("the refusal does not say what was wrong: %v", err)
	}
}

func TestHistoryCannotBeMadeToPrintAFabricatedRow(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	toPub, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	to := types.AddressFromPub(toPub).String()
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: addr.String()})
	// A type carrying a newline and a second, fabricated row (audit W-2).
	fake := "transfer\n     9  transfer     100000000 sparks (1 b10)  fee 0  to   " + to
	s.setHistory(walletHistory{
		Address: addr.String(), Head: 2, From: 1, To: 2, Blocks: 2,
		Txs: []walletHistoryEntry{
			{TxID: strings.Repeat("ab", 32), Height: 2, Type: fake, From: addr.String(), To: to, Amount: 1, Fee: 1},
		},
	})
	out := captureStdout(t, func() {
		if err := cmdHistory([]string{"--node", s.url, "--key", keyPath}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "\n     9  transfer") {
		t.Fatalf("a node-supplied type broke the line and printed a row that never existed:\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Fatalf("a terminal escape reached the output:\n%s", out)
	}
}

func TestHistoryRequiresTheNodeToEchoTheAddressItWasAskedFor(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: addr.String()})
	s.setHistory(walletHistory{Head: 2, From: 1, To: 2, Blocks: 2}) // no address echoed
	err := cmdHistory([]string{"--node", s.url, "--key", keyPath})
	if err == nil {
		t.Fatal("history accepted a reply that did not commit to an address (audit W-3)")
	}
	if !strings.Contains(err.Error(), "address") {
		t.Fatalf("the refusal does not say the echo is missing: %v", err)
	}
}

func TestHistoryRefusesAWindowAboveTheMaximumBeforeAskingTheNode(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: addr.String()})
	err := cmdHistory([]string{"--node", s.url, "--key", keyPath, "--blocks", "501"})
	if err == nil {
		t.Fatal("history forwarded --blocks 501, above the node's maximum (audit W-5)")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("the refusal does not name the maximum: %v", err)
	}
	if _, calls := s.historyAsked(); calls != 0 {
		t.Fatalf("history asked the node %d times before refusing the window", calls)
	}
}

func TestEphemeralClaimDoesNotPrintItsKeyUnlessAsked(t *testing.T) {
	_, _, stub := claimTestSetup(t, 0, 0)
	quiet := captureStdout(t, func() {
		if err := cmdClaim([]string{"--node", stub.url}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(quiet, "ephemeral key ") {
		t.Fatalf("the ephemeral claim printed its private key by default (audit W-6):\n%s", quiet)
	}
	if !strings.Contains(quiet, "print-key") {
		t.Fatalf("the output does not say how to see the key when wanted:\n%s", quiet)
	}
	loud := captureStdout(t, func() {
		if err := cmdClaim([]string{"--node", stub.url, "--print-key"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(loud, "ephemeral key ") {
		t.Fatalf("--print-key did not print the key:\n%s", loud)
	}
}
