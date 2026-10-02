package genesis

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

func TestGenesisHashIsDeterministic(t *testing.T) {
	g := Devnet()
	if g.Hash() != g.Hash() {
		t.Fatal("genesis hash is not deterministic")
	}
}

func TestGenesisHashChangesWithParams(t *testing.T) {
	a := Devnet()
	b := Devnet()
	b.Params.ClaimAmountSparks++
	if a.Hash() == b.Hash() {
		t.Fatal("genesis hash ignored a parameter change")
	}
}

func TestFaucetAddressIsDeterministicAndKeyless(t *testing.T) {
	g := Devnet()
	f1, f2 := g.FaucetAddress(), g.FaucetAddress()
	if f1 != f2 {
		t.Fatal("faucet address is not deterministic")
	}
	// The faucet address must not be derivable as address-of-a-pubkey for
	// any key we hold, and it must differ from every validator address.
	for _, v := range g.Validators {
		if types.AddressFromPub(v.PubKey) == f1 {
			t.Fatal("faucet address collided with a validator address")
		}
	}
	if f1 == types.AddressFromPub([]byte("any")) {
		t.Fatal("faucet address looks like a normal key-derived address")
	}
}

func TestFaucetAddressDiffersPerChain(t *testing.T) {
	if Devnet().FaucetAddress() == Testnet().FaucetAddress() {
		t.Fatal("different chains must have different faucet addresses")
	}
}

// This is the load-bearing test for the no-premine promise: any funded
// account in the testnet genesis would be a premine.
func TestTestnetGenesisHasNoPremine(t *testing.T) {
	g := Testnet()
	if len(g.DevAccounts) != 0 {
		t.Fatalf("testnet genesis funds %d accounts; a premine is forbidden", len(g.DevAccounts))
	}
}

func TestDevnetGenesisIsUsableForTesting(t *testing.T) {
	g := Devnet()
	if len(g.Validators) == 0 {
		t.Fatal("devnet needs at least one validator")
	}
	if len(g.DevAccounts) == 0 {
		t.Fatal("devnet needs funded accounts so transfers can be tested before the faucet exists (M2)")
	}
}

func TestValidateRejectsBadGenesis(t *testing.T) {
	g := Devnet()
	g.Validators[0].PubKey = []byte{1, 2, 3}
	if err := g.Validate(); err == nil {
		t.Fatal("expected an error for a malformed validator key")
	}
}

func TestEmissionMathReachesExactlyTheSupplyCap(t *testing.T) {
	for _, g := range []*Genesis{Devnet(), Testnet()} {
		p := g.Params
		// A halving series sums to R0 * interval * 2.
		total := p.InitialRewardSparks * p.HalvingIntervalBlocks * 2
		if total != p.TotalSupplySparks {
			t.Fatalf("%s: emission sums to %d sparks, cap is %d",
				p.ChainID, total, p.TotalSupplySparks)
		}
	}
}

func TestGenesisRoundTripThroughEncoding(t *testing.T) {
	g := Devnet()
	enc := g.Encode()
	got, err := DecodeGenesis(enc)
	if err != nil {
		t.Fatalf("DecodeGenesis: %v", err)
	}
	if got.Hash() != g.Hash() {
		t.Fatal("genesis round trip changed the hash")
	}
}

func TestGenesisUsesBlake3Domain(t *testing.T) {
	g := Devnet()
	want := crypto.HashParts([]byte("b10coin-genesis"), g.Encode())
	if g.Hash() != want {
		t.Fatal("genesis hash does not use the expected domain separation")
	}
}

func TestTestnetGenesisValidatesWithoutValidators(t *testing.T) {
	if err := Testnet().Validate(); err != nil {
		t.Fatalf("testnet genesis must validate before operator keys exist: %v", err)
	}
}

func TestDevnetGenesisValidates(t *testing.T) {
	if err := Devnet().Validate(); err != nil {
		t.Fatalf("devnet genesis must validate: %v", err)
	}
}
