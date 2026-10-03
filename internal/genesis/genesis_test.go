package genesis

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
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

// The claim amount is a PER-CHAIN value, like the epoch length and the
// puzzle tuning: emission is 0.5 b10 per block, so the spec's 100-b10 claim
// is payable only after 200 blocks — a fixture-sized devnet could never pay
// one, and every claim would fail ErrFaucetEmpty. The devnet therefore claims
// 1 b10 (about two blocks of emission) and testnet keeps the spec's 100 b10.
// The two chains differ on this DELIBERATELY (the devnet is a fixture, not
// monetary policy); this pin is what stops one silently absorbing the other.
func TestClaimAmountsArePinnedPerChain(t *testing.T) {
	devnet, testnet := Devnet(), Testnet()
	if devnet.Params.ClaimAmountSparks != 1*SparksPerB10 {
		t.Fatalf("devnet ClaimAmountSparks = %d, want %d (a short devnet must be able to fund one claim)",
			devnet.Params.ClaimAmountSparks, 1*SparksPerB10)
	}
	if testnet.Params.ClaimAmountSparks != 100*SparksPerB10 {
		t.Fatalf("testnet ClaimAmountSparks = %d, want the spec's %d",
			testnet.Params.ClaimAmountSparks, 100*SparksPerB10)
	}
	if devnet.Params.ClaimAmountSparks == testnet.Params.ClaimAmountSparks {
		t.Fatal("devnet and testnet claim amounts coincide; they are meant to differ deliberately")
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
	// Explicit field assertions alongside the hash: the hash can only say the
	// round trip broke, these name WHICH parameter failed to survive, so a
	// decode bug is diagnosed rather than merely detected.
	if got.Params.FaucetPowArgon2 != g.Params.FaucetPowArgon2 ||
		got.Params.FaucetPowTarget != g.Params.FaucetPowTarget {
		t.Fatalf("genesis round trip lost the faucet puzzle parameters:\n got %+v target %x\nwant %+v target %x",
			got.Params.FaucetPowArgon2, got.Params.FaucetPowTarget,
			g.Params.FaucetPowArgon2, g.Params.FaucetPowTarget)
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
		// The faucet puzzle's parameters, recorded the way the Go
		// constructor holds them: the Argon2 tuning as a nested object, and
		// the 32-byte difficulty target as the 64-character lowercase
		// hex string of its big-endian bytes (hex is byte-exact where a
		// decimal number would drop leading zero bytes).
		FaucetPowArgon2 struct {
			MemoryKiB   uint32 `json:"memory_kib"`
			Iterations  uint32 `json:"iterations"`
			Parallelism uint8  `json:"parallelism"`
		} `json:"faucet_pow_argon2"`
		FaucetPowTarget string `json:"faucet_pow_target"`
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

		// The faucet puzzle parameters, compared field-for-field the way the
		// other params are. Every shipped Argon2 parameter is non-zero in
		// both records, so a DELETED nested key decodes to zero and fails the
		// comparison; the whole object's presence is still required by the
		// key-presence list the same way the scalar params are.
		a, b := j.Params.FaucetPowArgon2, p.FaucetPowArgon2
		if a.MemoryKiB != b.MemoryKiB {
			t.Errorf("%s: params.faucet_pow_argon2.memory_kib = %d, constructor says %d",
				tc.file, a.MemoryKiB, b.MemoryKiB)
		}
		if a.Iterations != b.Iterations {
			t.Errorf("%s: params.faucet_pow_argon2.iterations = %d, constructor says %d",
				tc.file, a.Iterations, b.Iterations)
		}
		if a.Parallelism != b.Parallelism {
			t.Errorf("%s: params.faucet_pow_argon2.parallelism = %d, constructor says %d",
				tc.file, a.Parallelism, b.Parallelism)
		}
		// The target: decode the recorded hex back to exactly 32 bytes and
		// compare against the constructor's value byte for byte.
		targetRaw, err := hex.DecodeString(j.Params.FaucetPowTarget)
		if err != nil || len(targetRaw) != 32 {
			t.Errorf("%s: params.faucet_pow_target = %q, want the 64-char lowercase hex encoding of the 32-byte target",
				tc.file, j.Params.FaucetPowTarget)
		} else {
			var recorded [32]byte
			copy(recorded[:], targetRaw)
			if recorded != p.FaucetPowTarget {
				t.Errorf("%s: params.faucet_pow_target = %x, constructor says %x",
					tc.file, recorded, p.FaucetPowTarget)
			}
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
		"faucet_pow_argon2", "faucet_pow_target",
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
// directly on the devnet record's params object with keys deleted one at a
// time and asserts that exactly the deleted key is reported missing.
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
	for _, key := range []string{"epoch_blocks", "faucet_pow_argon2", "faucet_pow_target"} {
		if _, ok := params[key]; !ok {
			t.Fatalf("fixture error: devnet.json has no %q under params", key)
		}
		one := map[string]json.RawMessage{}
		for k, v := range params {
			one[k] = v
		}
		delete(one, key)

		got := requiredParamsMissing(one)
		if len(got) != 1 || got[0] != key {
			t.Fatalf("requiredParamsMissing after deleting %q = %v, want exactly [%s]", key, got, key)
		}
	}
}

// independentTarget builds a 0xFF-filled [32]byte with the top byte `top`.
// It deliberately does NOT call the constructors' helper (genesis.go's
// puzzleTarget): the pin below is only load-bearing because the expectation
// is constructed independently of the value under test.
func independentTarget(top byte) [32]byte {
	var t [32]byte
	for i := range t {
		t[i] = 0xFF
	}
	t[0] = top
	return t
}

// The cap is a HARD MAXIMUM on what the chain will actually mint. The
// identity test above (TestEmissionMathReachesExactlyTheSupplyCap) checks the
// idealized relation R0 * interval * 2 == cap, which any proportional
// parameter change satisfies; SeriesTotal is the truncated sum the transition
// really pays, so it is the value that must stay under the cap.
func TestEmissionNeverExceedsTheCap(t *testing.T) {
	for _, g := range []*Genesis{Devnet(), Testnet()} {
		total := faucet.SeriesTotal(g.Params.InitialRewardSparks, g.Params.HalvingIntervalBlocks)
		if total > g.Params.TotalSupplySparks {
			t.Fatalf("%s: realized emission %d exceeds the cap %d",
				g.Params.ChainID, total, g.Params.TotalSupplySparks)
		}
	}
}

// A zero target is unsatisfiable: a claim verifies only if its digest is
// strictly below the target, and no digest is strictly below zero. On any
// chain that must actually pay claims this makes every claim fail forever.
func TestValidateRejectsAnUnsatisfiableTestnetTarget(t *testing.T) {
	g := Testnet()
	g.Params.FaucetPowTarget = [32]byte{}
	if err := g.Validate(); !errors.Is(err, ErrBadGenesis) {
		t.Fatalf("expected ErrBadGenesis for a zero pow target, got %v", err)
	}
}

// The claim rule derives epochs as height/EpochBlocks + 1, so a zero here is
// a divide-by-zero panic reachable from a malformed genesis. The state
// machine guards it too, but a genesis should never validate with it.
func TestValidateRejectsAZeroEpochBlocks(t *testing.T) {
	g := Testnet()
	g.Params.EpochBlocks = 0
	if err := g.Validate(); !errors.Is(err, ErrBadGenesis) {
		t.Fatalf("expected ErrBadGenesis for EpochBlocks == 0, got %v", err)
	}
}

// The two chain tunings are protocol values pinned verbatim from the task
// brief: a devnet puzzle a laptop solves in a blink, a testnet puzzle at the
// spec's ~3 s Argon2id tuning with the placeholder target the constructors
// record. Any change to either must be a deliberate re-pinning, and the
// testnet target must stay strictly below the devnet target (the brief's
// "much smaller") or the difficulty ordering silently inverts.
func TestArgon2TuningsArePinnedPerChain(t *testing.T) {
	devnet, testnet := Devnet(), Testnet()

	if devnet.Params.FaucetPowArgon2 != (faucet.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1}) {
		t.Fatalf("devnet Argon2 tuning = %+v, want {MemoryKiB:64, Iterations:1, Parallelism:1}", devnet.Params.FaucetPowArgon2)
	}
	if devnet.Params.FaucetPowTarget != independentTarget(0x7F) {
		t.Fatalf("devnet pow target = %x, want 0x7F followed by 31 0xFF bytes", devnet.Params.FaucetPowTarget)
	}

	if testnet.Params.FaucetPowArgon2 != (faucet.Argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1}) {
		t.Fatalf("testnet Argon2 tuning = %+v, want {MemoryKiB:65536, Iterations:3, Parallelism:1}", testnet.Params.FaucetPowArgon2)
	}
	if testnet.Params.FaucetPowTarget != independentTarget(0x0F) {
		t.Fatalf("testnet pow target = %x, want 0x0F followed by 31 0xFF bytes", testnet.Params.FaucetPowTarget)
	}
	if bytes.Compare(testnet.Params.FaucetPowTarget[:], devnet.Params.FaucetPowTarget[:]) >= 0 {
		t.Fatal("the testnet target must be strictly smaller than the devnet target")
	}
}
