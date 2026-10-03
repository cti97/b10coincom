package genesis

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
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

	// Independently recompute the specified construction. This is the assertion
	// that actually guards the domain label and the derivation: without it,
	// replacing the body with `AddressFromPub(gh[:])` makes the faucet spendable
	// by anyone holding ed25519.NewKeyFromSeed(genesisHash) and every other
	// assertion below still passes.
	gh := g.Hash()
	want := crypto.HashParts([]byte("b10coin-faucet"), gh[:])
	var expected types.Address
	copy(expected[:], want[:types.AddressSize])
	if f1 != expected {
		t.Fatalf("faucet derivation changed:\n got %v\nwant %v", f1, expected)
	}

	// Negative: the faucet must not be the address of any public key we can
	// name, including the genesis hash reinterpreted as one.
	if f1 == types.AddressFromPub(gh[:]) {
		t.Fatal("faucet address is key-derived and therefore spendable")
	}
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

func TestValidateRejectsChainIDMismatch(t *testing.T) {
	g := Devnet()
	g.Params.ChainID = "some-other-chain"
	if err := g.Validate(); !errors.Is(err, ErrBadGenesis) {
		t.Fatalf("expected ErrBadGenesis, got %v", err)
	}
}

// These pin the two ErrEmissionMath guards. That the real Devnet() and
// Testnet() still satisfy them is asserted by TestDevnetGenesisValidates and
// TestTestnetGenesisValidatesWithoutValidators in this same suite.

// (a) An all-zero parameter set must be rejected: 0*0*2 == 0 equals a zero
// supply cap, so only the zero-factor rejection (not the product) stops it.
// The chain ID is kept valid so the test reaches the emission guard rather
// than failing the empty-ChainID check that runs first.
func TestValidateRejectsAllZeroParams(t *testing.T) {
	g := Devnet()
	g.Params = Params{ChainID: g.Params.ChainID}
	if err := g.Validate(); !errors.Is(err, ErrEmissionMath) {
		t.Fatalf("expected ErrEmissionMath for an all-zero parameter set, got %v", err)
	}
}

// (b) The emission product must be checked without uint64 overflow. The
// parameter pairs below WRAP to exactly TotalSupplySparks when computed with
// plain uint64 arithmetic — a wrap-blind implementation would accept them —
// and are only the low 64 bits of a genuinely larger product.
func TestValidateRejectsOverflowingEmissionProduct(t *testing.T) {
	for _, tc := range []struct {
		name    string
		initial uint64
		halving uint64
	}{
		// 4 * halving = 2^64 + 1_050_000_000_000_000: the first Mul64 leg
		// overflows.
		{"first leg overflows", 4, 4_611_948_518_427_387_904},
		// (2^63 + 1_050_000_000_000_000) fits, but *2 = 2^64 + supply: the
		// second Mul64 leg overflows.
		{"second leg overflows", 9_224_422_036_854_775_808, 1},
	} {
		g := Devnet()
		g.Params.InitialRewardSparks = tc.initial
		g.Params.HalvingIntervalBlocks = tc.halving
		// Sanity: the wrap-blind product really does equal the supply cap, so
		// only the overflow (hi) check can reject these values.
		if blind := tc.initial * tc.halving * 2; blind != g.Params.TotalSupplySparks {
			t.Fatalf("%s: test setup: wrap-blind product = %d, want %d",
				tc.name, blind, g.Params.TotalSupplySparks)
		}
		if err := g.Validate(); !errors.Is(err, ErrEmissionMath) {
			t.Fatalf("%s: expected ErrEmissionMath, got %v", tc.name, err)
		}
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

// TestSupplyCapIsPinned pins the ABSOLUTE monetary values. The emission test
// only checks the identity R0 * interval * 2 == supply, which any proportional
// mutation satisfies - halving both the supply and the reward would pass it
// while changing monetary policy. This test is what stops that.
func TestSupplyCapIsPinned(t *testing.T) {
	if SparksPerB10 != 100_000_000 {
		t.Fatalf("SparksPerB10 = %d, want 100000000", SparksPerB10)
	}
	const wantCapSparks = 21_000_000 * SparksPerB10
	for _, g := range []*Genesis{Devnet(), Testnet()} {
		if g.Params.TotalSupplySparks != wantCapSparks {
			t.Fatalf("%s: TotalSupplySparks = %d, want %d",
				g.Params.ChainID, g.Params.TotalSupplySparks, wantCapSparks)
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

// genesisRecord is the JSON shape of the checked records in ../../genesis/.
// JSON is never read by the node — it must never enter a hashed path — so
// these files are records OF the Go constructors below, which are the source
// of truth the node runs from. The test that follows keeps the records
// honest: either copy drifting from the other fails the suite.
type genesisRecord struct {
	ChainID     string `json:"chain_id"`
	Validators  int    `json:"validators"`
	DevAccounts int    `json:"dev_accounts"`
	Note        string `json:"note"`
	Params      struct {
		BlockTimeMS           uint64 `json:"block_time_ms"`
		TotalSupplySparks     uint64 `json:"total_supply_sparks"`
		InitialRewardSparks   uint64 `json:"initial_reward_sparks"`
		HalvingIntervalBlocks uint64 `json:"halving_interval_blocks"`
		ClaimAmountSparks     uint64 `json:"claim_amount_sparks"`
		MinStakeSparks        uint64 `json:"min_stake_sparks"`
		EpochBlocks           uint64 `json:"epoch_blocks"`
		UnbondingEpochs       uint64 `json:"unbonding_epochs"`
		CommitteeSize         int    `json:"committee_size"`
	} `json:"params"`
}

// Each genesis JSON record must agree field-for-field with the Go
// constructor it mirrors: chain_id, validator and dev-account counts, and
// every protocol parameter. DisallowUnknownFields makes the check bind both
// ways: an extra or renamed field — for example a rogue premine array the
// constructor never agreed to — fails too. (encoding/json is used HERE ONLY;
// it appears in no non-test file.)
func TestGenesisJSONRecordsMatchTheGoConstructors(t *testing.T) {
	for _, tc := range []struct {
		file string
		g    *Genesis
	}{
		{"../../genesis/devnet.json", Devnet()},
		{"../../genesis/testnet.json", Testnet()},
	} {
		raw, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var j genesisRecord
		if err := dec.Decode(&j); err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		// A checked record is one clean document: anything after it (another
		// object, a duplicate document) is not part of the record and must
		// fail rather than be glossed over.
		var extra genesisRecord
		if err := dec.Decode(&extra); err != io.EOF {
			t.Fatalf("%s: trailing content after the JSON document", tc.file)
		}

		// Zero-count blind spot: struct decoding turns an ABSENT key into the
		// zero value, which for the testnet record's zero counts (validators
		// 0, dev_accounts 0) is indistinguishable from the constructor's
		// value — a deleted key passes the field-by-field comparisons above.
		// The raw-map checks below therefore require every expected key to be
		// PRESENT in the file. The literal lists mirror genesisRecord's json
		// tags; DisallowUnknownFields already rejects any key not in them.
		var top map[string]json.RawMessage
		if err := json.Unmarshal(raw, &top); err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		for _, key := range []string{"chain_id", "note", "validators", "dev_accounts", "params"} {
			if _, ok := top[key]; !ok {
				t.Errorf("%s: missing required key %q", tc.file, key)
			}
		}
		var params map[string]json.RawMessage
		if paramsRaw, ok := top["params"]; ok && len(paramsRaw) > 0 {
			if err := json.Unmarshal(paramsRaw, &params); err != nil {
				t.Fatalf("%s: params: %v", tc.file, err)
			}
		}
		for _, key := range requiredParamsMissing(params) {
			t.Errorf("%s: params missing required key %q", tc.file, key)
		}

		if j.ChainID != tc.g.ChainID {
			t.Errorf("%s: chain_id = %q, constructor says %q", tc.file, j.ChainID, tc.g.ChainID)
		}
		if j.Validators != len(tc.g.Validators) {
			t.Errorf("%s: validators = %d, constructor has %d", tc.file, j.Validators, len(tc.g.Validators))
		}
		if j.DevAccounts != len(tc.g.DevAccounts) {
			t.Errorf("%s: dev_accounts = %d, constructor has %d", tc.file, j.DevAccounts, len(tc.g.DevAccounts))
		}

		p, q := tc.g.Params, j.Params
		for _, c := range []struct {
			name  string
			jsonV uint64
			goV   uint64
		}{
			{"block_time_ms", q.BlockTimeMS, p.BlockTimeMS},
			{"total_supply_sparks", q.TotalSupplySparks, p.TotalSupplySparks},
			{"initial_reward_sparks", q.InitialRewardSparks, p.InitialRewardSparks},
			{"halving_interval_blocks", q.HalvingIntervalBlocks, p.HalvingIntervalBlocks},
			{"claim_amount_sparks", q.ClaimAmountSparks, p.ClaimAmountSparks},
			{"min_stake_sparks", q.MinStakeSparks, p.MinStakeSparks},
			{"epoch_blocks", q.EpochBlocks, p.EpochBlocks},
			{"unbonding_epochs", q.UnbondingEpochs, p.UnbondingEpochs},
		} {
			if c.jsonV != c.goV {
				t.Errorf("%s: params.%s = %d, constructor says %d", tc.file, c.name, c.jsonV, c.goV)
			}
		}
		if q.CommitteeSize != p.CommitteeSize {
			t.Errorf("%s: params.committee_size = %d, constructor says %d",
				tc.file, q.CommitteeSize, p.CommitteeSize)
		}
	}
}

// requiredParamsMissing returns the params keys from the required list that
// are absent from a raw JSON params object. It is factored out of
// TestGenesisJSONRecordsMatchTheGoConstructors so the key-presence rule can be
// exercised directly — every parameter in both shipped records is non-zero, so
// the shipped files alone can never catch a deleted params key
// (TestParamsKeyPresenceListDetectsAMissingKey does).
func requiredParamsMissing(params map[string]json.RawMessage) []string {
	var missing []string
	for _, key := range []string{
		"block_time_ms", "total_supply_sparks", "initial_reward_sparks",
		"halving_interval_blocks", "claim_amount_sparks", "min_stake_sparks",
		"epoch_blocks", "unbonding_epochs", "committee_size",
	} {
		if _, ok := params[key]; !ok {
			missing = append(missing, key)
		}
	}
	return missing
}

// The params-level key-presence list is unexercised by the shipped records: no
// parameter is zero, so the field-by-field comparisons cannot distinguish a
// deleted params key from the constructor's value. This case calls the helper
// directly on the devnet record's params object with epoch_blocks deleted and
// asserts that key, and only that key, is reported missing.
func TestParamsKeyPresenceListDetectsAMissingKey(t *testing.T) {
	raw, err := os.ReadFile("../../genesis/devnet.json")
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(top["params"], &params); err != nil {
		t.Fatalf("params: %v", err)
	}
	if _, ok := params["epoch_blocks"]; !ok {
		t.Fatal("fixture error: devnet.json has no epoch_blocks under params")
	}
	delete(params, "epoch_blocks")

	got := requiredParamsMissing(params)
	if len(got) != 1 || got[0] != "epoch_blocks" {
		t.Fatalf("requiredParamsMissing = %v, want exactly [epoch_blocks]", got)
	}
}
