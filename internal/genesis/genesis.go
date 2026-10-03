// Package genesis defines the parameters that every node must agree on
// before the first block, including the protocol-controlled faucet address.
package genesis

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/bits"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/types"
)

// SparksPerB10 is the number of base units in one b10.
const SparksPerB10 = 100_000_000

// devnetChainID is the throwaway fixture chain's identifier, shared by
// Devnet() and by Validate's one devnet-specific rule.
const devnetChainID = "b10coin-devnet-1"

// puzzleTarget builds the shipped puzzle targets: top byte `top`, every
// remaining byte 0xFF. A claim's digest must be strictly below this value, so
// the expected number of Argon2id runs is 2^(zero bits at the head of `top`)
// — ~2 for the devnet's 0x7F, ~16 for the testnet's 0x0F placeholder.
func puzzleTarget(top byte) [32]byte {
	var t [32]byte
	for i := range t {
		t[i] = 0xFF
	}
	t[0] = top
	return t
}

var (
	ErrBadGenesis   = errors.New("genesis: invalid genesis")
	ErrBadValidator = errors.New("genesis: validator public key must be 32 bytes")
	ErrEmissionMath = errors.New("genesis: emission schedule does not reach the supply cap exactly")
)

// Params are the protocol parameters fixed at genesis. FaucetPowArgon2 and
// FaucetPowTarget configure the faucet claim's proof-of-work (internal/faucet
// implements it); they are genesis parameters so devnet and testnet ship
// different tunings from the one source of truth.
type Params struct {
	ChainID               string
	BlockTimeMS           uint64
	TotalSupplySparks     uint64
	InitialRewardSparks   uint64
	HalvingIntervalBlocks uint64
	ClaimAmountSparks     uint64
	MinStakeSparks        uint64
	EpochBlocks           uint64
	UnbondingEpochs       uint64
	CommitteeSize         int
	FaucetPowArgon2       faucet.Argon2Params
	FaucetPowTarget       [32]byte
}

// Validator is a genesis validator with its initial voting power.
type Validator struct {
	PubKey []byte
	Power  uint64
}

// DevAccount is a TEST FIXTURE ONLY. It exists so transfer logic can be
// exercised in M1, before the faucet (M2) exists. The testnet genesis has
// none, and TestTestnetGenesisHasNoPremine enforces that.
type DevAccount struct {
	PubKey        []byte
	BalanceSparks uint64
}

// Genesis is the chain's starting configuration.
type Genesis struct {
	ChainID     string
	Time        int64
	Validators  []Validator
	DevAccounts []DevAccount
	Params      Params
}

// Encode renders the genesis canonically. Maps are never used, so the
// ordering here is the sole source of determinism.
func (g *Genesis) Encode() []byte {
	e := types.NewEncoder()
	e.VarBytes([]byte(g.ChainID))
	e.I64(g.Time)
	e.Len(len(g.Validators))
	for _, v := range g.Validators {
		e.VarBytes(v.PubKey)
		e.U64(v.Power)
	}
	e.Len(len(g.DevAccounts))
	for _, d := range g.DevAccounts {
		e.VarBytes(d.PubKey)
		e.U64(d.BalanceSparks)
	}
	e.VarBytes([]byte(g.Params.ChainID))
	e.U64(g.Params.BlockTimeMS)
	e.U64(g.Params.TotalSupplySparks)
	e.U64(g.Params.InitialRewardSparks)
	e.U64(g.Params.HalvingIntervalBlocks)
	e.U64(g.Params.ClaimAmountSparks)
	e.U64(g.Params.MinStakeSparks)
	e.U64(g.Params.EpochBlocks)
	e.U64(g.Params.UnbondingEpochs)
	e.U64(uint64(g.Params.CommitteeSize))
	e.U32(g.Params.FaucetPowArgon2.MemoryKiB)
	e.U32(g.Params.FaucetPowArgon2.Iterations)
	e.U8(g.Params.FaucetPowArgon2.Parallelism)
	e.Fixed32(g.Params.FaucetPowTarget)
	return e.Bytes()
}

// Hash is the genesis identifier that seeds the faucet address.
func (g *Genesis) Hash() [32]byte {
	return crypto.HashParts([]byte("b10coin-genesis"), g.Encode())
}

// FaucetAddress derives an address that has NO corresponding private key:
// the preimage is the genesis hash, not a public key, so no signature can
// ever be produced for it. Coins can only leave this account through the
// protocol's claim rule.
func (g *Genesis) FaucetAddress() types.Address {
	gh := g.Hash()
	h := crypto.HashParts([]byte("b10coin-faucet"), gh[:])
	var a types.Address
	copy(a[:], h[:types.AddressSize])
	return a
}

// Validate checks the invariants a genesis must satisfy.
func (g *Genesis) Validate() error {
	if g.ChainID == "" {
		return fmt.Errorf("%w: empty chain ID", ErrBadGenesis)
	}
	// ChainID is duplicated on Genesis and Params; a mismatch would let a
	// genesis describe two different chains at once.
	if g.Params.ChainID != g.ChainID {
		return fmt.Errorf("%w: Params.ChainID %q does not match ChainID %q",
			ErrBadGenesis, g.Params.ChainID, g.ChainID)
	}
	// An empty validator set is legal: the testnet genesis is defined before
	// any operator keys exist. Such a chain simply cannot advance, because
	// chain.Append rejects every proposer (ErrNotValidator).
	for i, v := range g.Validators {
		if len(v.PubKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: validator %d has %d bytes", ErrBadValidator, i, len(v.PubKey))
		}
		if v.Power == 0 {
			return fmt.Errorf("%w: validator %d has zero power", ErrBadValidator, i)
		}
	}
	for i, d := range g.DevAccounts {
		if len(d.PubKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: dev account %d has %d key bytes", ErrBadGenesis, i, len(d.PubKey))
		}
	}
	p := g.Params
	// A zero factor cannot produce an emission schedule that reaches the
	// supply cap: an all-zero parameter set must fail rather than satisfy
	// 0*0*2 == 0.
	if p.InitialRewardSparks == 0 || p.HalvingIntervalBlocks == 0 || p.TotalSupplySparks == 0 {
		return ErrEmissionMath
	}
	// The relation is checked without overflow: raw uint64 multiplication
	// could wrap and make a crafted pair pass, so Mul64 reports the carry
	// bits and any product that does not fit in one uint64 — which cannot
	// equal TotalSupplySparks — fails here.
	hi, lo := bits.Mul64(p.InitialRewardSparks, p.HalvingIntervalBlocks)
	if hi != 0 {
		return ErrEmissionMath
	}
	hi, lo = bits.Mul64(lo, 2)
	if hi != 0 {
		return ErrEmissionMath
	}
	if lo != p.TotalSupplySparks {
		return ErrEmissionMath
	}
	// A zero puzzle target is unsatisfiable: a claim verifies only if its
	// Argon2id digest is strictly below the target, and no digest is strictly
	// below zero, so every claim on such a chain would fail forever. Every
	// chain except the devnet fixture must therefore ship a non-zero target.
	// The devnet is exempt as a fixture; the shipped devnet still sets an easy
	// non-zero target (pinned by TestArgon2TuningsArePinnedPerChain), so real
	// devnet runs keep claims usable.
	if g.ChainID != devnetChainID && p.FaucetPowTarget == ([32]byte{}) {
		return fmt.Errorf("%w: a zero faucet puzzle target is unsatisfiable (every claim would fail)", ErrBadGenesis)
	}
	// The claim rule derives epochs as height/EpochBlocks + 1, so a zero here
	// is a divide-by-zero panic reachable from a malformed genesis. The state
	// machine's claim rule guards it too, but a genesis should never validate
	// with it.
	if p.EpochBlocks == 0 {
		return fmt.Errorf("%w: EpochBlocks must not be zero (the claim rule divides by it)", ErrBadGenesis)
	}
	return nil
}

// DecodeGenesis parses a canonical genesis encoding.
func DecodeGenesis(b []byte) (*Genesis, error) {
	d := types.NewDecoder(b)
	g := &Genesis{}
	var err error
	var raw []byte
	if raw, err = d.VarBytes(); err != nil {
		return nil, err
	}
	g.ChainID = string(raw)
	if g.Time, err = d.I64(); err != nil {
		return nil, err
	}
	n, err := d.Len()
	if err != nil {
		return nil, err
	}
	g.Validators = make([]Validator, n)
	for i := 0; i < n; i++ {
		if g.Validators[i].PubKey, err = d.VarBytes(); err != nil {
			return nil, err
		}
		if g.Validators[i].Power, err = d.U64(); err != nil {
			return nil, err
		}
	}
	m, err := d.Len()
	if err != nil {
		return nil, err
	}
	g.DevAccounts = make([]DevAccount, m)
	for i := 0; i < m; i++ {
		if g.DevAccounts[i].PubKey, err = d.VarBytes(); err != nil {
			return nil, err
		}
		if g.DevAccounts[i].BalanceSparks, err = d.U64(); err != nil {
			return nil, err
		}
	}
	if raw, err = d.VarBytes(); err != nil {
		return nil, err
	}
	g.Params.ChainID = string(raw)
	if g.Params.BlockTimeMS, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.TotalSupplySparks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.InitialRewardSparks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.HalvingIntervalBlocks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.ClaimAmountSparks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.MinStakeSparks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.EpochBlocks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.UnbondingEpochs, err = d.U64(); err != nil {
		return nil, err
	}
	cs, err := d.U64()
	if err != nil {
		return nil, err
	}
	g.Params.CommitteeSize = int(cs)
	if g.Params.FaucetPowArgon2.MemoryKiB, err = d.U32(); err != nil {
		return nil, err
	}
	if g.Params.FaucetPowArgon2.Iterations, err = d.U32(); err != nil {
		return nil, err
	}
	if g.Params.FaucetPowArgon2.Parallelism, err = d.U8(); err != nil {
		return nil, err
	}
	if g.Params.FaucetPowTarget, err = d.Fixed32(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return g, nil
}

// sharedParams are the values fixed by the design spec. The emission
// relation InitialReward * HalvingInterval * 2 == TotalSupply must hold.
// EpochBlocks differs by chain — 1_000 on devnet, 10_000 on testnet — and is
// the claim rule's epoch length: epoch(h) = h/EpochBlocks + 1. The faucet
// puzzle's cost and target are set per chain by Devnet/Testnet, since they
// are deliberately different fixture-vs-real tunings.
func sharedParams(chainID string, epochBlocks uint64, committee int) Params {
	return Params{
		ChainID:               chainID,
		BlockTimeMS:           2000,
		TotalSupplySparks:     21_000_000 * SparksPerB10,
		InitialRewardSparks:   50_000_000, // 0.5 b10
		HalvingIntervalBlocks: 21_000_000,
		ClaimAmountSparks:     100 * SparksPerB10,
		MinStakeSparks:        1_000 * SparksPerB10,
		EpochBlocks:           epochBlocks,
		UnbondingEpochs:       2,
		CommitteeSize:         committee,
	}
}

// Devnet is a single-validator chain with funded test accounts.
func Devnet() *Genesis {
	pub, _, _ := deterministicKey("b10coin-devnet-validator-1")
	devPub, _, _ := deterministicKey("b10coin-devnet-faucet-tester")
	dev2Pub, _, _ := deterministicKey("b10coin-devnet-recipient")
	params := sharedParams(devnetChainID, 1_000, 1)
	// The devnet puzzle is deliberately trivial: 64 KiB of Argon2id for a
	// single pass, under a target of 0x7F followed by 31 0xFF bytes (about one
	// digest in two qualifies, so a solve takes a few attempts). This is a
	// fixture tuning to keep the test suite quick, not a difficulty claim.
	params.FaucetPowArgon2 = faucet.Argon2Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1}
	params.FaucetPowTarget = puzzleTarget(0x7F)
	return &Genesis{
		ChainID:    devnetChainID,
		Time:       1_700_000_000,
		Validators: []Validator{{PubKey: pub, Power: 1}},
		DevAccounts: []DevAccount{
			{PubKey: devPub, BalanceSparks: 1_000_000 * SparksPerB10},
			{PubKey: dev2Pub, BalanceSparks: 0},
		},
		Params: params,
	}
}

// Testnet is the real chain's configuration: federated validators, and
// deliberately no funded accounts.
func Testnet() *Genesis {
	params := sharedParams("b10coin-testnet-1", 10_000, 21)
	// The spec's ≈3 s Argon2id tuning for a Raspberry Pi 4: 64 MiB of memory
	// and three passes, as §8 of the design spec records. A target of 0x0F
	// followed by 31 0xFF bytes is a PLACEHOLDER: it demands roughly sixteen
	// qualifying runs per claim, so a testnet claim costs minutes at this
	// tuning.
	//
	// This target MUST be re-tuned against real hardware (measured end-to-end
	// on a Pi 4, including the solver's attempt policy) before any public
	// testnet opens.
	params.FaucetPowArgon2 = faucet.Argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1}
	params.FaucetPowTarget = puzzleTarget(0x0F)
	return &Genesis{
		ChainID:     "b10coin-testnet-1",
		Time:        1_700_000_000,
		Validators:  []Validator{},
		DevAccounts: nil, // no premine, ever
		Params:      params,
	}
}

// DevValidatorKey returns the devnet validator keypair. It is deterministic
// and PUBLIC: it exists so tests and the devnet CLI can sign blocks. It must
// never be used on any network holding value.
func DevValidatorKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := deterministicKey("b10coin-devnet-validator-1")
	return pub, priv
}

// DevAccountKey returns the keypair for devnet dev account i (0 or 1). It
// panics with an explicit message rather than a bare index error on an
// out-of-range i: callers pass a literal, so a bad index is always a bug.
func DevAccountKey(i int) (ed25519.PublicKey, ed25519.PrivateKey) {
	seeds := []string{"b10coin-devnet-faucet-tester", "b10coin-devnet-recipient"}
	if i < 0 || i >= len(seeds) {
		panic(fmt.Sprintf("genesis: DevAccountKey index %d out of range: valid indices are 0..%d", i, len(seeds)-1))
	}
	pub, priv, _ := deterministicKey(seeds[i])
	return pub, priv
}

// deterministicKey derives a stable keypair from a seed string so devnet
// fixtures are reproducible across machines and runs. It is NOT secret and
// must never be used outside devnet.
func deterministicKey(seed string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	h := crypto.HashParts([]byte("b10coin-devkey"), []byte(seed))
	priv := ed25519.NewKeyFromSeed(h[:])
	return priv.Public().(ed25519.PublicKey), priv, nil
}
