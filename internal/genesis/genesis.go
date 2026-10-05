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

// maxFaucetArgon2MemoryKiB is the ceiling Validate puts on the faucet puzzle's
// memory cost. The parameter is a uint32, so without a bound a genesis can name
// up to ~4 TiB; every validator pays that allocation on every claim in a block,
// so a malformed genesis OOMs the whole committee on the first claim. 256 MiB
// is four times the design spec's original 64 MiB tuning and 32 times the
// shipped testnet value (8 MiB): generous for any real tuning, far below the
// size that would take a small validator down.
const maxFaucetArgon2MemoryKiB = 256 * 1024

// maxCommitteeSize is the seat ceiling a committee may declare. It matches the
// cap the operator committee file (committee_file.go) and the fixture committee
// (simnet.New) already enforce, so the general genesis contract cannot accept a
// committee larger than either production path would build.
const maxCommitteeSize = 255

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
	// ErrDuplicateValidator reports two validator entries naming the same
	// public key. One key holds one seat: a duplicate makes its power count
	// twice in the quorum sum and lets the proposer draw name it twice.
	ErrDuplicateValidator = errors.New("genesis: duplicate validator public key")
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
	// MaxClaimsPerBlock bounds how many faucet claims one block may carry.
	// It is a consensus parameter and is committed in the genesis encoding:
	// two nodes that agreed on every other parameter but held different
	// bounds here would accept and reject the same blocks, so it must travel
	// with everything else that is hashed. state.ApplyBlock enforces it
	// before verifying any puzzle; internal/mempool's local per-block claim
	// courtesy is pinned equal to the shipped chains' value by a test in
	// this package. Validate refuses a genesis that leaves it zero.
	MaxClaimsPerBlock uint64
	// MinFeeSparks is the least a transaction may pay the protocol (audit
	// S-3). It is a consensus parameter, committed in the genesis encoding:
	// two nodes that agreed on everything else but held different minimums
	// would accept and reject the same blocks. state.applyTransfer enforces
	// it, and Validate refuses a genesis that leaves it zero - a zero minimum
	// is the free-transaction regime the finding is about.
	MinFeeSparks    uint64
	MinStakeSparks  uint64
	EpochBlocks     uint64
	UnbondingEpochs uint64
	CommitteeSize   int
	FaucetPowArgon2 faucet.Argon2Params
	FaucetPowTarget [32]byte
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
	e.U64(g.Params.MaxClaimsPerBlock)
	e.U64(g.Params.MinFeeSparks)
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
	// A genesis that leaves the per-block claim bound at zero cannot be
	// validated: any chain paying faucet claims needs the bound, because a
	// block is attacker-chosen input and verifying one claim costs a full
	// Argon2id evaluation (see ApplyBlock in internal/state). state.Params
	// treats a zero bound as "not engaged" for legacy unparameterized
	// states, so without this rule a zero-valued genesis could silently ship
	// the per-block amplification this parameter exists to close.
	if p.MaxClaimsPerBlock == 0 {
		return fmt.Errorf("%w: MaxClaimsPerBlock must be at least 1 (an unbounded claim count per block is the amplification the state machine rejects)", ErrBadGenesis)
	}
	// A zero minimum is a chain whose transactions are free, which is exactly
	// the regime audit S-3 closes. state.Params treats zero as "not engaged"
	// for legacy unparameterized states, so without this rule a zero-valued
	// genesis could silently ship free transactions through the one encoding
	// the finding says must not be re-opened.
	if p.MinFeeSparks == 0 {
		return fmt.Errorf("%w: MinFeeSparks must be at least 1 (a zero minimum is the free-transaction regime the fee exists to end)", ErrBadGenesis)
	}
	// The Argon2id cost bounds (audit S-5). A zero-valued tuning is rejected
	// cleanly by the state machine - applyFaucetClaim guards before calling
	// argon2.IDKey, which would panic - but a genesis that validates with a
	// zero silently ships a faucet whose every claim fails forever. The memory
	// cost is additionally bounded ABOVE: it is reached by every validator on
	// every claim in a block, and a uint32 can name ~4 TiB.
	if p.FaucetPowArgon2.MemoryKiB == 0 {
		return fmt.Errorf("%w: the faucet puzzle's MemoryKiB must be at least 1 (a zero cost cannot be evaluated and would brick the faucet)", ErrBadGenesis)
	}
	if p.FaucetPowArgon2.MemoryKiB > maxFaucetArgon2MemoryKiB {
		return fmt.Errorf("%w: the faucet puzzle's MemoryKiB is %d, above the %d KiB ceiling (every validator would pay that allocation on every claim)",
			ErrBadGenesis, p.FaucetPowArgon2.MemoryKiB, maxFaucetArgon2MemoryKiB)
	}
	if p.FaucetPowArgon2.Iterations == 0 {
		return fmt.Errorf("%w: the faucet puzzle's Iterations must be at least 1 (zero rounds cannot be evaluated and would brick the faucet)", ErrBadGenesis)
	}
	if p.FaucetPowArgon2.Parallelism == 0 {
		return fmt.Errorf("%w: the faucet puzzle's Parallelism must be at least 1 (zero lanes cannot be evaluated and would brick the faucet)", ErrBadGenesis)
	}
	// A claim of zero sparks pays the claimant nothing while still spending the
	// key's one-claim-per-epoch marker: a genesis whose faucet pays zero has no
	// faucet at all.
	if p.ClaimAmountSparks == 0 {
		return fmt.Errorf("%w: ClaimAmountSparks must be at least 1 (a zero claim pays nothing and makes the faucet useless)", ErrBadGenesis)
	}
	// The per-block claim bound must not exceed the block's transaction bound:
	// a block can never carry more transactions than MaxTxsPerBlock, so a
	// larger claim bound can never fire - an inert consensus parameter that
	// could mask the arithmetic or wiring it exists to expose.
	if p.MaxClaimsPerBlock > types.MaxTxsPerBlock {
		return fmt.Errorf("%w: MaxClaimsPerBlock is %d, above the block transaction bound %d (the claim bound could never fire)",
			ErrBadGenesis, p.MaxClaimsPerBlock, types.MaxTxsPerBlock)
	}
	// Duplicate validator keys: one key must hold one seat. The operator
	// committee file already refuses this at the only place operators write by
	// hand, but Genesis.Validate is the general contract chain.Open enforces,
	// so it must refuse it too. The map makes the check O(n); at the 255-seat
	// ceiling this project allows even an O(n^2) scan would be free, but there
	// is no reason to spend it.
	seenKeys := make(map[string]struct{}, len(g.Validators))
	for i, v := range g.Validators {
		if _, dup := seenKeys[string(v.PubKey)]; dup {
			return fmt.Errorf("%w: validator %d repeats a public key already listed (one key holds one seat)", ErrDuplicateValidator, i)
		}
		seenKeys[string(v.PubKey)] = struct{}{}
	}
	// CommitteeSize is a seat COUNT. It is encoded as a uint64 and decoded
	// straight to int, so a value above MaxInt64 arrives negative; a negative
	// count, or one past the ceiling the operator committee file and the
	// fixture committee enforce, is malformed.
	if p.CommitteeSize < 0 || p.CommitteeSize > maxCommitteeSize {
		return fmt.Errorf("%w: CommitteeSize is %d, want 0..%d", ErrBadGenesis, p.CommitteeSize, maxCommitteeSize)
	}
	// The genesis timestamp is the height-0 block's timestamp and obeys the
	// same rule every later block does (types.ValidateStructure: Timestamp > 0).
	// A non-positive genesis time is not a time.
	if g.Time <= 0 {
		return fmt.Errorf("%w: Time must be positive (it is the genesis block's timestamp), got %d", ErrBadGenesis, g.Time)
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
	if g.Params.MaxClaimsPerBlock, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.MinFeeSparks, err = d.U64(); err != nil {
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
//
// claimAmountSparks is the third deliberate chain difference (after the epoch
// length and the puzzle tuning). Emission is 0.5 b10 per block, so the spec's
// 100-b10 claim is payable only after 200 blocks — a fixture-sized devnet
// holds 10.0 b10 at 20 blocks and every claim would fail ErrFaucetEmpty. The
// devnet claims 1 b10 (about two blocks of emission fund it); testnet keeps
// the spec's 100 b10. THE TWO CHAINS DIFFER ON THIS DELIBERATELY: the devnet
// is a fixture, not monetary policy, exactly as its shorter epochs are.
func sharedParams(chainID string, epochBlocks, claimAmountSparks uint64, committee int) Params {
	return Params{
		ChainID:               chainID,
		BlockTimeMS:           2000,
		TotalSupplySparks:     21_000_000 * SparksPerB10,
		InitialRewardSparks:   50_000_000, // 0.5 b10
		HalvingIntervalBlocks: 21_000_000,
		ClaimAmountSparks:     claimAmountSparks,
		// The per-block claim bound, shared by both chains. Verifying one
		// claim costs one Argon2id evaluation, so the worst-case block costs
		// MaxClaimsPerBlock × per-eval time and must fit inside a small
		// multiple of the 2_000 ms block interval — the derivation is in
		// Testnet's tuning comment, where the per-eval cost that constrains
		// this bound is set. internal/mempool's MaxFaucetClaimsPerBlock is
		// pinned equal to this value by a test in this package, so the pool
		// can never hand a block producer more claims than the chain accepts.
		MaxClaimsPerBlock: 8,
		// The least a transfer may pay, on BOTH shipped chains. One spark is
		// deliberately small: this change exists to put a FEE IN THE SIGNED
		// BODY while the encoding is still free to change (audit S-3), not to
		// set monetary policy. The level is a genesis parameter precisely so
		// the level can be re-derived later without another fork; what is
		// already fixed is that a zero-cost transfer is invalid.
		MinFeeSparks:    1,
		MinStakeSparks:  1_000 * SparksPerB10,
		EpochBlocks:     epochBlocks,
		UnbondingEpochs: 2,
		CommitteeSize:   committee,
	}
}

// Devnet is a single-validator chain with funded test accounts.
func Devnet() *Genesis {
	pub, _, _ := deterministicKey("b10coin-devnet-validator-1")
	devPub, _, _ := deterministicKey("b10coin-devnet-faucet-tester")
	dev2Pub, _, _ := deterministicKey("b10coin-devnet-recipient")
	params := sharedParams(devnetChainID, 1_000, 1*SparksPerB10, 1)
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
	params := sharedParams("b10coin-testnet-1", 10_000, 100*SparksPerB10, 21)
	// The puzzle tuning was re-derived in M3's claim-bound task TOGETHER with
	// MaxClaimsPerBlock (8, in sharedParams). The spec's original pairing —
	// 64 MiB × 3 passes at the 0x0F target — was chosen for the CLAIMER, who
	// pays one puzzle once; validators pay PER CLAIM PER BLOCK, and the two
	// budgets cannot both be met at 64 MiB × 3, as the arithmetic below shows.
	//
	// Budgets. A block may carry MaxClaimsPerBlock = 8 claims and blocks are
	// spaced BlockTimeMS = 2_000 ms apart, so the worst-case block must
	// verify well inside 2 × 2 s, giving per-eval <= 4 s / 8 = 0.5 s. The
	// claimer budget is tighter: the 0x0F target accepts one digest in 2^4 =
	// 16, so a solve takes ~16 evaluations, and the spec gives the claimer
	// ~3 s, giving per-eval <= 3 s / 16 = 0.1875 s.
	//
	// Cost basis. The spec records ~3 s per Argon2id evaluation for 64 MiB ×
	// 3 passes = 192 MiB·passes on its Raspberry Pi 4 reference, i.e. ~15.6
	// ms per MiB·pass. 8 MiB × 1 pass therefore lands at ~0.125 s per eval,
	// inside BOTH budgets.
	//
	// Check, on the same reference: a claimer solves in 16 × 0.125 s = 2.0 s
	// (within the ~3 s budget), and the worst-case block verifies in 8 ×
	// 0.125 s = 1.0 s — half the block interval. At the old 64 MiB × 3
	// tuning the same arithmetic gives 16 × 3 s = 48 s to solve one claim
	// and a validator budget of 4 s / 3 s, a bound of 1 — the amplification
	// a per-block bound exists to prevent was priced in by the tuning itself.
	//
	// Trade-off, stated rather than hidden: 8 MiB is a far smaller memory
	// cost than 64 MiB, so the puzzle buys less against GPU-heavy attackers.
	// The faucet's purpose — a rate limit on how fast one key drains the
	// faucet, with the one-claim-per-key-per-epoch rule behind it — does not
	// need mining resistance; the bounded block cost and the bounded per-key
	// payout are what it must guarantee.
	//
	// Everything here is derived from the spec's ONE hardware measurement.
	// The tuning, the target and the bound MUST all be re-measured and
	// re-derived together against real Pi 4 hardware (end to end, including
	// the solver's attempt policy) before any public testnet opens.
	params.FaucetPowArgon2 = faucet.Argon2Params{MemoryKiB: 8192, Iterations: 1, Parallelism: 1}
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
