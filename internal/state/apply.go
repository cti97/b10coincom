package state

import (
	"errors"
	"fmt"
	"math"

	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrZeroAmount        = errors.New("state: amount must be greater than zero")
	ErrBadNonce          = errors.New("state: nonce does not match account nonce")
	ErrInsufficientFunds = errors.New("state: insufficient funds")
	ErrSelfTransfer      = errors.New("state: cannot transfer to self")
	ErrBalanceOverflow   = errors.New("state: balance would overflow")
	ErrUnsupportedTxType = errors.New("state: unsupported transaction type")
	ErrWrongEpoch        = errors.New("state: claim is not for the current epoch")
	ErrClaimTooSoon      = errors.New("state: this key has already claimed in this epoch")
	ErrBadProofOfWork    = errors.New("state: proof of work does not meet the target")
	ErrFaucetEmpty       = errors.New("state: the faucet account cannot cover a claim")
)

// ApplyTx applies one transaction, mutating the receiver. Every validation
// runs before the first write, so on error the receiver is left unchanged.
// ApplyBlock still clones, so that one transaction's success is not persisted
// when a later transaction in the same block fails.
func (s *State) ApplyTx(tx *types.Tx) error {
	if err := tx.VerifySignature(); err != nil {
		return err
	}
	switch tx.Type {
	case types.TxTransfer:
		return s.applyTransfer(tx)
	case types.TxFaucetClaim:
		return s.applyFaucetClaim(tx)
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedTxType, tx.Type)
	}
}

func (s *State) applyTransfer(tx *types.Tx) error {
	if tx.Amount == 0 {
		return ErrZeroAmount
	}
	// Reject self-transfers: debiting and crediting the same account would
	// alias the two writes and corrupt the balance.
	if tx.From == tx.To {
		return ErrSelfTransfer
	}

	from := s.Get(tx.From)
	if from.Nonce != tx.Nonce {
		return fmt.Errorf("%w: got %d, want %d", ErrBadNonce, tx.Nonce, from.Nonce)
	}
	if from.Balance < tx.Amount {
		return fmt.Errorf("%w: have %d, need %d", ErrInsufficientFunds, from.Balance, tx.Amount)
	}

	to := s.Get(tx.To)
	if to.Balance > math.MaxUint64-tx.Amount {
		return ErrBalanceOverflow
	}

	from.Balance -= tx.Amount
	from.Nonce++
	s.Set(tx.From, from)

	to.Balance += tx.Amount
	s.Set(tx.To, to)
	return nil
}

// applyFaucetClaim pays one claim: verify the puzzle, enforce one claim per
// key per epoch, debit the faucet, credit the claimant. The guards run in a
// deliberate order cheap-to-expensive, each before the first write.
func (s *State) applyFaucetClaim(tx *types.Tx) error {
	// A zero-valued Argon2Params makes argon2.IDKey PANIC ("argon2: number of
	// rounds too small") rather than return an error, and a zero EpochBlocks
	// makes the epoch derivation below divide by zero. New() deliberately
	// holds zero-value params so M0-M1 callers keep working with claims
	// unusable; guard first, so an unparameterized state rejects the claim
	// cleanly instead of crashing the node.
	p := s.params.PowArgon2
	if p.Iterations == 0 || p.MemoryKiB == 0 || p.Parallelism == 0 || s.params.EpochBlocks == 0 {
		return ErrBadProofOfWork
	}

	// The claim must carry the CURRENT epoch: epoch(h) = h/EpochBlocks + 1.
	// This binds the puzzle to a time window - a solution solved for a later
	// epoch cannot be spent early, and a stale one cannot be spent late.
	want := s.height/s.params.EpochBlocks + 1
	if tx.Epoch != want {
		return fmt.Errorf("%w: claim for epoch %d, current epoch is %d", ErrWrongEpoch, tx.Epoch, want)
	}

	// One claim per key per epoch. Epochs are 1-BASED, so a never-claimed
	// account holds ClaimedEpoch == 0 and is accepted at epoch 1; the >= also
	// refuses any solution claimed on a stale epoch.
	claimant := s.Get(tx.From)
	if claimant.ClaimedEpoch >= tx.Epoch {
		return fmt.Errorf("%w: last claimed in epoch %d, claim is for epoch %d",
			ErrClaimTooSoon, claimant.ClaimedEpoch, tx.Epoch)
	}

	// The signature only proved the CLAIMANT authorised this transaction - it
	// says nothing about the work. Verify the puzzle against the parameters
	// this state was constructed with.
	if !faucet.MeetsTarget(faucet.PowDigest(tx.PubKey, tx.Epoch, tx.PowNonce, s.params.PowArgon2), s.params.PowTarget) {
		return ErrBadProofOfWork
	}

	// The nonce rule, exactly as for a transfer: a claim spends the account's
	// replay counter like any other transaction.
	if claimant.Nonce != tx.Nonce {
		return fmt.Errorf("%w: got %d, want %d", ErrBadNonce, tx.Nonce, claimant.Nonce)
	}

	faucetAcc := s.Get(s.params.FaucetAddress)
	if faucetAcc.Balance < s.params.ClaimAmount {
		return fmt.Errorf("%w: holds %d, one claim needs %d", ErrFaucetEmpty, faucetAcc.Balance, s.params.ClaimAmount)
	}

	// THE single place in the codebase where an account is modified without
	// its owner's signature. It is sound because the faucet address is derived
	// from the GENESIS HASH, not from a public key: no private key exists for
	// it, so no signature can ever be produced for it, and no attacker can
	// produce one either. The claimant's signature above authorises the CREDIT
	// side; the protocol rule - one Argon2id puzzle, one claim per key per
	// epoch - authorises the debit side.
	faucetAcc.Balance -= s.params.ClaimAmount
	s.Set(s.params.FaucetAddress, faucetAcc)

	claimant.Balance += s.params.ClaimAmount
	claimant.Nonce++
	claimant.ClaimedEpoch = tx.Epoch
	s.Set(tx.From, claimant)
	return nil
}

// ApplyBlock applies every transaction atomically. On success it returns a
// new State; the receiver is never modified. On failure it returns the error
// and a nil State, leaving the receiver untouched.
func (s *State) ApplyBlock(txs []types.Tx) (*State, error) {
	next := s.Clone()
	for i := range txs {
		if err := next.ApplyTx(&txs[i]); err != nil {
			return nil, fmt.Errorf("tx %d: %w", i, err)
		}
	}
	return next, nil
}
