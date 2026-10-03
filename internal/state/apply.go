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
	// ErrTooManyClaims rejects a whole BLOCK, not a single claim: a block is
	// attacker-chosen input, and the count is the only thing that can be
	// checked without paying for it. See ApplyBlock.
	ErrTooManyClaims = errors.New("state: block carries too many faucet claims")
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
	// account holds ClaimedEpoch == 0 and is accepted at epoch 1. The >=
	// refuses a repeat claim in the SAME epoch: a stale epoch never reaches
	// this line, because the epoch-equality check above rejects it first.
	claimant := s.Get(tx.From)
	if claimant.ClaimedEpoch >= tx.Epoch {
		return fmt.Errorf("%w: last claimed in epoch %d, claim is for epoch %d",
			ErrClaimTooSoon, claimant.ClaimedEpoch, tx.Epoch)
	}

	// The nonce rule, exactly as for a transfer: a claim spends the account's
	// replay counter like any other transaction.
	if claimant.Nonce != tx.Nonce {
		return fmt.Errorf("%w: got %d, want %d", ErrBadNonce, tx.Nonce, claimant.Nonce)
	}

	// The signature only proved the CLAIMANT authorised this transaction - it
	// says nothing about the work. Verify the puzzle against the parameters
	// this state was constructed with.
	if !faucet.MeetsTarget(faucet.PowDigest(tx.PubKey, tx.Epoch, tx.PowNonce, s.params.PowArgon2), s.params.PowTarget) {
		return ErrBadProofOfWork
	}

	faucetAcc := s.Get(s.params.FaucetAddress)
	if faucetAcc.Balance < s.params.ClaimAmount {
		return fmt.Errorf("%w: holds %d, one claim needs %d", ErrFaucetEmpty, faucetAcc.Balance, s.params.ClaimAmount)
	}

	// The credit side carries the same overflow guard applyTransfer puts on
	// the recipient: an addition must return an error, never wrap. Unreachable
	// while the supply is bounded, but free and consistent. It runs BEFORE the
	// debit, honouring the every-validation-before-the-first-write promise both
	// entry points make: with the guard below the debit, this unreachable
	// overflow would leave the faucet debited and the claimant uncredited -
	// a partial application.
	if claimant.Balance > math.MaxUint64-s.params.ClaimAmount {
		return ErrBalanceOverflow
	}

	// THE single place in the codebase where an account is modified without
	// its owner's signature. It is sound because the faucet address is derived
	// from the GENESIS HASH, not from a public key: no private key exists for
	// it, so no signature can ever be produced for it, and no attacker can
	// produce one either. The claimant's signature above authorises the CREDIT
	// side; the protocol rule - one Argon2id puzzle, one claim per key per
	// epoch - authorises the debit side.
	//
	// The account is snapshotted BEFORE the debit (the faucetAcc read at the
	// ErrFaucetEmpty guard) and the claimant is Set last, so a tx whose From
	// were the faucet address would re-publish the PRE-debit faucet account
	// plus a credit, net-INFLATING the faucet by one claim. That aliasing is
	// unreachable: VerifySignature forces tx.From == AddressFromPub(tx.PubKey)
	// (else ErrAddressMismatch), and the faucet address is derived from the
	// genesis hash rather than a public key, so no public key can produce it -
	// which is exactly why no runtime check is spent on it here.
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
//
// The claim bound is consensus, not policy. Validating one claim costs every
// validator a FULL Argon2id evaluation: applyFaucetClaim has no cheap
// pre-check - the puzzle must be evaluated before the claim can be accepted
// OR rejected - so a validator's cost for a block is the block's claim count
// times one puzzle. A block is attacker-chosen input, and MaxTxsPerBlock
// allows 10,000 transactions in a block, so unbounded the count is an
// amplifier: one malicious proposer prices every validator ~10,000 Argon2id
// evaluations (about 21 minutes of Argon2id work at the testnet tuning) as
// the cost of deciding ONE block. MaxClaimsPerBlock (travelled in
// state.Params; 0 means not engaged) is what makes that impossible instead
// of merely priced: the count is checked here, BEFORE any puzzle is
// evaluated, so a block carrying more claims than the bound is INVALID and
// never reaches applyFaucetClaim at all - nothing above the bound is paid
// for, whatever its size. The check must sit ahead of the expensive work
// because a bound enforced after it bounds nothing: the attacker still gets
// the work out of you, and only the verdict changes. The bound travels in
// state.Params so the mempool's local courtesy bound and this consensus rule
// cannot disagree: genesis pins both, and a genesis test asserts the mempool
// constant equals it.
func (s *State) ApplyBlock(txs []types.Tx) (*State, error) {
	// Counting claims costs one type comparison per transaction - nothing.
	// Verifying even the FIRST claim costs a full Argon2id evaluation, so the
	// count must run here, ahead of the loop and of the clone below. The
	// whole block is rejected: accepting the cheap prefix would still let a
	// proposer meter validators' work one block at a time.
	if bound := s.params.MaxClaimsPerBlock; bound > 0 {
		claims := uint64(0)
		for i := range txs {
			if txs[i].Type == types.TxFaucetClaim {
				claims++
			}
		}
		if claims > bound {
			return nil, fmt.Errorf("%w: %d claims, bound is %d", ErrTooManyClaims, claims, bound)
		}
	}
	next := s.Clone()
	for i := range txs {
		if err := next.ApplyTx(&txs[i]); err != nil {
			return nil, fmt.Errorf("tx %d: %w", i, err)
		}
	}
	return next, nil
}
