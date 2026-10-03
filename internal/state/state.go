// Package state implements b10coin's account-based state machine. The
// transition function must be perfectly deterministic: two nodes with the
// same state and the same block must arrive at byte-identical state roots,
// or the chain forks.
package state

import (
	"bytes"
	"slices"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// Account is a single account's balance, replay counter and faucet-claim
// marker. ClaimedEpoch is the epoch of the account's most recent faucet claim
// (0 means no claim was recorded, which is also how a claim made in epoch 0
// looks, and the two behave identically). It is committed consensus state, not
// local policy.
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
}

func New() *State {
	return &State{accounts: make(map[types.Address]Account)}
}

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
// cannot leave partial changes behind.
func (s *State) Clone() *State {
	out := &State{accounts: make(map[types.Address]Account, len(s.accounts))}
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
