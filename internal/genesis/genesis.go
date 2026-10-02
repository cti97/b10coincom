// Package genesis defines the parameters that every node must agree on
// before the first block, including the protocol-controlled faucet address.
package genesis

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// SparksPerB10 is the number of base units in one b10.
const SparksPerB10 = 100_000_000

var (
	ErrBadGenesis   = errors.New("genesis: invalid genesis")
	ErrBadValidator = errors.New("genesis: validator public key must be 32 bytes")
	ErrEmissionMath = errors.New("genesis: emission schedule does not reach the supply cap exactly")
)

// Params are the protocol parameters fixed at genesis.
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
	if p.InitialRewardSparks*p.HalvingIntervalBlocks*2 != p.TotalSupplySparks {
		return ErrEmissionMath
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
	if err := d.Done(); err != nil {
		return nil, err
	}
	return g, nil
}

// sharedParams are the values fixed by the design spec. The emission
// relation InitialReward * HalvingInterval * 2 == TotalSupply must hold.
func sharedParams(chainID string, committee int) Params {
	return Params{
		ChainID:               chainID,
		BlockTimeMS:           2000,
		TotalSupplySparks:     21_000_000 * SparksPerB10,
		InitialRewardSparks:   50_000_000, // 0.5 b10
		HalvingIntervalBlocks: 21_000_000,
		ClaimAmountSparks:     100 * SparksPerB10,
		MinStakeSparks:        1_000 * SparksPerB10,
		EpochBlocks:           10_000,
		UnbondingEpochs:       2,
		CommitteeSize:         committee,
	}
}

// Devnet is a single-validator chain with funded test accounts.
func Devnet() *Genesis {
	pub, _, _ := deterministicKey("b10coin-devnet-validator-1")
	devPub, _, _ := deterministicKey("b10coin-devnet-faucet-tester")
	dev2Pub, _, _ := deterministicKey("b10coin-devnet-recipient")
	return &Genesis{
		ChainID:    "b10coin-devnet-1",
		Time:       1_700_000_000,
		Validators: []Validator{{PubKey: pub, Power: 1}},
		DevAccounts: []DevAccount{
			{PubKey: devPub, BalanceSparks: 1_000_000 * SparksPerB10},
			{PubKey: dev2Pub, BalanceSparks: 0},
		},
		Params: sharedParams("b10coin-devnet-1", 1),
	}
}

// Testnet is the real chain's configuration: federated validators, and
// deliberately no funded accounts.
func Testnet() *Genesis {
	return &Genesis{
		ChainID:     "b10coin-testnet-1",
		Time:        1_700_000_000,
		Validators:  []Validator{},
		DevAccounts: nil, // no premine, ever
		Params:      sharedParams("b10coin-testnet-1", 21),
	}
}

// DevValidatorKey returns the devnet validator keypair. It is deterministic
// and PUBLIC: it exists so tests and the devnet CLI can sign blocks. It must
// never be used on any network holding value.
func DevValidatorKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := deterministicKey("b10coin-devnet-validator-1")
	return pub, priv
}

// DevAccountKey returns the keypair for devnet dev account i (0 or 1).
func DevAccountKey(i int) (ed25519.PublicKey, ed25519.PrivateKey) {
	seeds := []string{"b10coin-devnet-faucet-tester", "b10coin-devnet-recipient"}
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
