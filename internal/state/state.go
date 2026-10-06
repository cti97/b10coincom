// Package state implements b10coin's account-based state machine. The
// transition function must be perfectly deterministic: two nodes with the
// same state and the same block must arrive at byte-identical state roots,
// or the chain forks.
package state

import (
	"bytes"
	"slices"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/types"
)

// Account is a single account's balance, replay counter and faucet-claim
// marker. ClaimedEpoch is the epoch of the account's most recent faucet claim.
// 0 unambiguously means "never claimed": epochs are 1-based precisely so that
// the marker of a claim can never collide with the never-claimed value — under
// 0-based epochs a fresh account would be refused in epoch 0. The marker is
// committed consensus state, not local policy.
type Account struct {
	Balance      uint64
	Nonce        uint64
	ClaimedEpoch uint64
}

// isZero reports whether an account carries no information and may be pruned.
// A key that has claimed only retains its claim marker, so an account with a
// non-zero ClaimedEpoch is live even with zero balance and nonce: pruning it
// would reset the one-claim-per-epoch rule on every prune.
func (a Account) isZero() bool {
	return a.Balance == 0 && a.Nonce == 0 && a.ClaimedEpoch == 0
}

// State is a set of accounts. The zero value is not usable; call New.
type State struct {
	accounts map[types.Address]Account

	// params are the protocol values the claim rule verifies against. They
	// are set once at construction rather than read from genesis, because the
	// dependency runs genesis -> state, never back. Zero-valued params (New)
	// mean claims are unusable, never a panic; applyFaucetClaim rejects them
	// cleanly. Params are not part of the state root: they are protocol
	// configuration every node already holds.
	params Params

	// height is the height of the block whose transactions apply next. It is
	// EXECUTION CONTEXT, not committed state: the claim rule needs it to
	// derive the current epoch, the block header already commits to the
	// height, so Root() deliberately does not hash it. The chain sets it once
	// per block, before applying that block's transactions.
	height uint64
}

// Params are the protocol values the claim rule verifies against. They are set
// once when the state is created rather than read from genesis, because the
// dependency runs genesis -> state, never back.
type Params struct {
	FaucetAddress types.Address
	ClaimAmount   uint64
	EpochBlocks   uint64
	PowArgon2     faucet.Argon2Params
	PowTarget     [32]byte

	// MaxClaimsPerBlock is the consensus bound on how many faucet claims one
	// block may carry; ApplyBlock enforces it before evaluating any
	// transaction. It comes from genesis.Params.MaxClaimsPerBlock via the
	// chain. The zero value means "not engaged" - legacy New() states and
	// test fixtures that never set it behave exactly as before - and
	// genesis.Validate refuses to validate a genesis that leaves it at zero,
	// so a state parameterised by a chain that pays claims is always
	// bounded.
	MaxClaimsPerBlock uint64

	// GenesisHash is the CHAIN IDENTIFIER every transaction signature is bound
	// to (audit S-1): the hash of the chain's genesis, which commits to every
	// parameter above. VerifySignature uses it, so a transaction signed for
	// one chain can never apply to another. The zero value means "no chain
	// bound" - legacy New() states and fixtures that never set it verify
	// transactions signed the same way - and a chain always sets it from its
	// genesis, so a chain's state can never verify a foreign transaction.
	GenesisHash [32]byte

	// MinFee is the least a transfer may pay (audit S-3), in sparks. It comes
	// from genesis.Params.MinFeeSparks via the chain; the zero value means
	// "no minimum engaged" for legacy New() states, and genesis.Validate
	// refuses a genesis that leaves it zero, so a real chain never runs with
	// free transfers.
	MinFee uint64
}

// New returns a state with zero-valued params: the M0-M1 behaviour. Claims are
// unusable there - applyFaucetClaim rejects them cleanly - and nothing panics.
func New() *State { return NewWithParams(Params{}) }

// NewWithParams returns a state parameterised for the claim rule: the faucet
// account, the per-claim payout, the epoch length and the puzzle's cost and
// target. The zero value of Params is legal but leaves claims unusable.
func NewWithParams(p Params) *State {
	return &State{accounts: make(map[types.Address]Account), params: p}
}

// SetHeight records the height of the block whose transactions apply next. It
// is execution context only - never committed, never hashed into the state
// root - so the caller sets it once per block, before that block's
// transactions apply, rather than deriving it from any prior transition.
func (s *State) SetHeight(h uint64) { s.height = h }

// Params returns the protocol parameters this state was built with. Params is a
// value with no references, so the copy is safe to hand out. The mempool's
// stateful admission reads EpochBlocks from here (audit R-1) to decide whether
// a claim's epoch is the current or the next one before paying for anything.
func (s *State) Params() Params { return s.params }

// Get returns the account, or the zero Account if it does not exist.
func (s *State) Get(a types.Address) Account { return s.accounts[a] }

// Set stores an account, pruning it if it is zero so that the state root
// depends only on live accounts.
func (s *State) Set(a types.Address, acc Account) {
	if acc.isZero() {
		delete(s.accounts, a)
		return
	}
	s.accounts[a] = acc
}

// Clone returns a deep copy. ApplyBlock clones before mutating so a failure
// cannot leave partial changes behind. The params and the height are
// execution context and configuration rather than account data, but a copy
// without them would derive claim epochs from a wrong height, so both travel.
func (s *State) Clone() *State {
	out := &State{
		accounts: make(map[types.Address]Account, len(s.accounts)),
		params:   s.params,
		height:   s.height,
	}
	for k, v := range s.accounts {
		out.accounts[k] = v
	}
	return out
}

// Len is the number of live accounts.
func (s *State) Len() int { return len(s.accounts) }

// TotalBalance is the sum of every balance. Used by tests and the supply
// invariant check.
func (s *State) TotalBalance() uint64 {
	var total uint64
	for _, acc := range s.accounts {
		total += acc.Balance
	}
	return total
}

// sortedAddresses returns every address in ascending byte order. A Go map's
// iteration order is randomised, so anything that produces bytes for a hash
// must sort first.
func (s *State) sortedAddresses() []types.Address {
	addrs := make([]types.Address, 0, len(s.accounts))
	for a := range s.accounts {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, func(x, y types.Address) int { return bytes.Compare(x[:], y[:]) })
	return addrs
}

// Root commits to the entire account set. The leaf covers all three account
// fields: a claim marker that was not committed would not be consensus, and the
// one-claim-per-epoch rule would be unenforceable across nodes.
func (s *State) Root() [32]byte {
	addrs := s.sortedAddresses()
	leaves := make([][32]byte, 0, len(addrs))
	for _, a := range addrs {
		acc := s.accounts[a]
		c := types.NewEncoder()
		c.U64(acc.Balance)
		c.U64(acc.Nonce)
		c.U64(acc.ClaimedEpoch)
		leaves = append(leaves, crypto.HashParts([]byte("b10coin-account"), a[:], c.Bytes()))
	}
	return crypto.MerkleRoot(leaves)
}
