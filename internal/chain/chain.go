// Package chain owns the canonical block sequence: building candidate
// blocks, validating them against state, appending them durably, and
// rebuilding state by replay on startup.
package chain

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/store"
	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrBadParent       = errors.New("chain: parent hash does not match head")
	ErrBadHeight       = errors.New("chain: height is not head+1")
	ErrBadStateRoot    = errors.New("chain: computed state root does not match header")
	ErrBadProposerSig  = errors.New("chain: proposer signature is missing or invalid")
	ErrNotValidator    = errors.New("chain: proposer does not hold a seat at the block's height")
	ErrGenesisReplay   = errors.New("chain: replay diverged from stored state root")
	ErrUnknownProposer = errors.New("chain: cannot determine proposer key")
	// ErrRuleChange reports a stored block whose transactions replay to a
	// DIFFERENT state root than its header commits. It is deliberately NOT
	// ErrGenesisReplay: the block's height, parent link and bytes all matched,
	// so nothing about the log is structurally wrong. The usual cause is a
	// build whose CONSENSUS RULES differ at that height - the genesis document
	// hash covers no derived state and no header carries a rule version, so a
	// rule change presents exactly like this. The known cases are ST-3 (the
	// bond leaf began committing Bond.Unfunded; its genesis-root change usually
	// fails the height-1 parent-link check first) and C-1 (the FUNDED-FIRST
	// unbond order, which changes the post-state of an exit from a bond holding
	// both a genesis grant and a top-up and therefore diverges at the unbond's
	// own height). An operator sent to look for corruption would apply the
	// wrong remedy; the message names the rule change instead.
	ErrRuleChange = errors.New("chain: stored chain does not replay under this build's consensus rules")
	// ErrWrongGenesis reports a data directory whose recorded genesis hash
	// differs from the genesis the node was started with (audit O-5). It is
	// deliberately distinct from ErrGenesisReplay: a wrong genesis is a
	// configuration mistake knowable BEFORE any block is replayed, not a
	// damaged chain discovered mid-replay.
	ErrWrongGenesis = errors.New("chain: data directory belongs to a different genesis")
	// ErrBadTimestamp reports a block whose timestamp is not strictly greater
	// than its parent's, or - on the consensus path - one that is not exactly
	// the parent's plus one (audit S-8). Timestamps feed no economic rule
	// today (epochs are height-based), but leaving them unvalidated let a
	// proposer set any positive value, including one behind its parent, and
	// made the timestamp a free grinding input for the next proposer draw.
	ErrBadTimestamp = errors.New("chain: block timestamp is not valid for its parent")
	// ErrNoCommittee reports a height whose committee epoch has not been
	// decided yet: the block at that epoch's deciding height (e*E-1, or the
	// genesis state for epoch 0) is not committed. It is an error rather than
	// a derivation from the current head state because deriving from the head
	// is precisely the bug epoch-boundary rotation exists to prevent - a bond
	// changing inside an epoch would move that epoch's seats.
	ErrNoCommittee = errors.New("chain: the committee for that height is not determined")
)

// Chain is a validated, durably-stored block sequence. It is safe for
// concurrent use: mu guards state and head, because one process may serve
// the RPC server (reading Height/Head/State/Genesis/BlockAt) while the node
// loop appends. No exported method may be called while its own lock is
// already held — every mutator works on unexported fields directly.
//
// Returning *types.Block and *state.State under a read lock is sound: an
// appended block is never mutated again (see Head), and state.ApplyBlock
// returns a NEW State without touching its receiver, so published states are
// immutable after Open.
type Chain struct {
	mu    sync.RWMutex
	gen   *genesis.Genesis
	store *store.Store
	state *state.State
	head  *types.Block

	// faucet is the protocol-controlled faucet address this chain mints into,
	// derived from the genesis hash (so no private key exists for it). Set
	// once in Open; advanceLocked uses it rather than recomputing per block.
	faucet types.Address

	// committees memoises, per committee epoch, the seat set derived from the
	// state committed at the last height BEFORE that epoch. It is DERIVED
	// STATE, never written to the store: chain.Open replays every stored block
	// through applyValidatedLocked, so a restart rebuilds every epoch from the
	// same states and derives the same seats (TestTheBoundaryCommitteeSurvivesReplay).
	//
	// It is not a cache that can go stale, and it must never be recomputed
	// from the head. An entry is written exactly once, at the moment the state
	// that DECIDES that epoch is committed (height e*E-1 for epoch e; the
	// genesis state for epoch 0), and is a pure function of that state - see
	// state.Committee. Deriving on demand from whatever the head is now would
	// let a bond changing inside an epoch move that epoch's seats mid-epoch,
	// which is the safety bug rotation-at-boundaries exists to prevent.
	//
	// Guarded by mu: Append writes under the write lock, CommitteeAt reads
	// under the read lock. A lookup MISS is not derived on demand - the state
	// a future epoch needs does not exist yet, and inventing one from the head
	// would be the very bug above. It is an error naming the missing height.
	committees map[uint64][]genesis.Validator

	// everSeated is DERIVED STATE: every validator key that has EVER held a
	// seat on this chain - genesis seats included - whether or not it holds
	// one at the head. Like committees it is rebuilt from committed blocks on
	// Open and never written to the store; the two are filled at the same
	// place (memoCommitteeLocked), so a key enters this set at exactly the
	// height whose state DECIDES the epoch that seats it, i.e. before its
	// seat begins.
	//
	// WHAT IT IS FOR (audit RT-3): a validator that joined after genesis and
	// later rotated out is seated in no set that outlives its epoch - not
	// genesis, not the committee at its own (lagging) head, not the committee
	// at the committee's head - so HELLO admission and BLOCK_SYNC
	// authorisation used to refuse it forever, leaving a live process that
	// could not follow the chain. This set is the "has ever been a member"
	// term those two AUTHORISATION gates consult. It never feeds a consensus
	// decision: a rotated-out key is still refused membership at any height
	// by the router, the tally and the certificate gate, because those ask
	// the committee for the height they are judging, not this set.
	//
	// It is deliberately monotone and permanent. A key that ever bought a seat
	// stays a permitted peer forever, exactly as a genesis key already did
	// (audit RT-7); see committeeMemberAt's comment for what that admits and
	// what it does not. Guarded by mu like committees.
	//
	// BOUNDED, AND WHY THERE IS NO EVICTION (audit S-20). Only two paths insert
	// here - the genesis seats at Open and the derived committee in
	// memoCommitteeLocked, which runs once per epoch boundary - so the set is
	// always exactly the union of the genesis seats and the committees this
	// chain has recorded. That gives a structural bound, not an economic one:
	//
	//	|everSeated| <= len(genesis.Validators) + CommitteeSize x epochs elapsed
	//
	// because each recorded committee contributes at most CommitteeSize keys and
	// a committee is recorded once per epoch. On the shipped testnet parameters
	// (CommitteeSize 21, EpochBlocks 10,000, BlockTimeMS 2,000) an epoch is
	// 20,000 s - 5 h 33 m - so the ceiling is 21 seats per epoch, about 91 keys a
	// day and about 33,100 a year. Measured on 2026-11-06, an entry of this map
	// (a 32-byte ed25519 key plus the map's share of key and value slots) is
	// 67-88 bytes of heap at a million entries, so the ceiling is about 3 MB a
	// year; a gibibyte needs ~11.9 million entries, which is ~360 years of a
	// fully funded committee rotating at that ceiling. Each of those keys must
	// separately hold MIN_STAKE = 10^11 sparks (1,000 b10) to be seatable at all,
	// so the flow is also gated by capital: 21,000 b10 working capital rotating
	// through bond, seat, unbond.
	//
	// A cap was considered and REJECTED. Enforcing one means either refusing
	// HELLO/BLOCK_SYNC to a key that is legitimately seated once the set is
	// full, or evicting an entry - and an entry that is evicted is a rotated-out
	// honest validator that this set exists precisely to keep admitting (audit
	// RT-3). That is the freeze this project has already paid for once, and it
	// buys nothing here: the structural bound above is enforced by the shape of
	// the code rather than by a number someone can tune wrong. Pruning "keys
	// whose bond is gone and whose epoch is past" was also rejected: the bond log
	// is not retained, so that condition is not knowable at admission time
	// without a second unbounded index, and getting it wrong un-admits an honest
	// key on exactly the same path.
	everSeated map[string]struct{}
}

// genesisState builds the state that block 1 builds upon. It applies the
// height-0 emission (the genesis mint the spec names: Reward is NOT
// special-cased at height 0, so the mint uses the same formula every later
// block uses) and wires the faucet claim's parameters, without which no
// claim could ever verify. It cannot fail: genesis validation has already
// checked every key length, so the error return is omitted.
func genesisState(g *genesis.Genesis) *state.State {
	st := state.NewWithParams(state.Params{
		FaucetAddress: g.FaucetAddress(),
		ClaimAmount:   g.Params.ClaimAmountSparks,
		EpochBlocks:   g.Params.EpochBlocks,
		PowArgon2:     g.Params.FaucetPowArgon2,
		PowTarget:     g.Params.FaucetPowTarget,
		// The per-block claim bound is consensus state-machine behaviour
		// parameterised by genesis, exactly like the epoch length: without
		// wiring it here the bound would exist only in states that tests
		// construct by hand, and no real chain would enforce it.
		MaxClaimsPerBlock: g.Params.MaxClaimsPerBlock,
		// The chain identifier every transaction signature is bound to (audit
		// S-1) and the fee floor a transfer must clear (audit S-3). Both are
		// genesis parameters, so two chains that differ on either judge the
		// same bytes differently - which is the point.
		GenesisHash: g.Hash(),
		MinFee:      g.Params.MinFeeSparks,
		// The staking rules' parameters (M5 Task 1). MinStake is the floor a
		// Bond's RESULT must clear, UnbondingEpochs is the cooldown in epochs
		// (the release height is the epoch boundary at or after
		// height + UnbondingEpochs*EpochBlocks, which reuses the EpochBlocks
		// wired above), and CommitteeSize is what the committee derivation
		// will fill. Wiring them here is what makes them
		// consensus behaviour on a real chain rather than values that exist
		// only in states tests construct by hand.
		MinStake:        g.Params.MinStakeSparks,
		UnbondingEpochs: g.Params.UnbondingEpochs,
		CommitteeSize:   g.Params.CommitteeSize,
	})
	for _, d := range g.DevAccounts {
		addr := types.AddressFromPub(d.PubKey)
		acc := st.Get(addr)
		acc.Balance += d.BalanceSparks
		st.Set(addr, acc)
	}
	// GENESIS SEATS ARE BONDED, NOT BOUGHT. The genesis hash is what seats a
	// validator, so height 0 holds bonded stake that no balance ever funded -
	// this is the initial condition of the conservation invariant, not a double
	// count of anything. It is also why the genesis state root (and therefore
	// the acceptance root) moves in M5 Task 1: a bond is committed state, and
	// before this task the state held no bonds at all.
	//
	// Unfunded = Power is what stops that from being a premine (audit ST-3):
	// the seat's voting power is real, but state.applyUnbond DESTROYS the
	// unfunded part instead of recording it for withdrawal, so no spark of it
	// can ever become a balance. A genesis validator that wants withdrawable
	// stake bonds its own funds on top, and those sparks are recorded funded.
	//
	// Amount is the genesis Validator.Power, unscaled: for a genesis seat the
	// power IS its bond, and rescaling it would change every M3/M4 quorum and
	// proposer draw for no milestone reason. Height 0 records that the stake
	// predates the chain.
	for _, v := range g.Validators {
		st.SetBond(types.AddressFromPub(v.PubKey), state.Bond{
			Validator: append([]byte(nil), v.PubKey...),
			Amount:    v.Power,
			Unfunded:  v.Power,
			Height:    0,
		})
	}
	// The genesis mint the spec names. Reward is not special-cased at height 0,
	// so this is the same formula every later block uses.
	if r := faucet.Reward(0, g.Params.InitialRewardSparks, g.Params.HalvingIntervalBlocks); r > 0 {
		acc := st.Get(g.FaucetAddress())
		acc.Balance += r
		st.Set(g.FaucetAddress(), acc)
	}
	return st
}

func genesisBlock(g *genesis.Genesis, st *state.State) *types.Block {
	return &types.Block{
		Header: types.Header{
			Height:     0,
			ParentHash: [32]byte{},
			StateRoot:  st.Root(),
			TxRoot:     crypto.MerkleRoot(nil),
			Timestamp:  g.Time,
			Proposer:   nil,
		},
	}
}

// Open loads the chain from dir, replaying every stored block. If the
// directory is empty it initialises the genesis block instead.
func Open(g *genesis.Genesis, dir string) (*Chain, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	st := genesisState(g)
	s, err := store.Open(dir)
	if err != nil {
		return nil, err
	}
	// Close the store on every failure path after this point: returning an
	// open handle with the chain unset would leak the handle. owned records
	// that the handle was successfully handed to a returned Chain; until
	// then the deferred close owns it. Error values are unchanged.
	owned := false
	defer func() {
		if !owned {
			_ = s.Close()
		}
	}()
	c := &Chain{gen: g, store: s, state: st, head: genesisBlock(g, st), faucet: g.FaucetAddress(),
		committees: make(map[uint64][]genesis.Validator),
		everSeated: make(map[string]struct{}, len(g.Validators))}
	// The genesis seats are seats: every one of them has "ever been seated"
	// from height 0, so the authorisation set is complete even on a chain
	// whose genesis committee cannot be derived (CommitteeSize zero) and on
	// the empty chain before replay. Adding them is not a widening - the
	// genesis list is already an explicit term in every gate that reads this
	// set - it keeps one definition of the set: the keys that have held a
	// seat.
	for _, v := range g.Validators {
		c.everSeated[string(v.PubKey)] = struct{}{}
	}
	// Epoch 0's committee is the one derived from the GENESIS state (height
	// -1 does not exist; the genesis state is its stand-in). It is recorded
	// here for the same reason every later epoch is recorded at its deciding
	// height: the seats epoch 0 validates with must not move when a bond
	// changes inside the epoch.
	//
	// A derivation failure (no bonded candidate, CommitteeSize zero) is NOT an
	// Open failure. Genesis permits an empty validator set - the testnet
	// genesis is defined before keys exist - and such a chain simply cannot
	// judge a height; CommitteeAt reports that, and consensus refuses to act.
	if vals, err := st.Committee(); err == nil {
		c.committees[0] = vals
	}
	// The genesis state is COMMITTED AT HEIGHT 0, so it also decides the epoch
	// that begins at height 1. Under the shipped epoch lengths that epoch is
	// epoch 0 (already recorded above) and memoCommitteeLocked(st, 0) writes
	// nothing; under EpochBlocks == 1 it is epoch 1, and this call is the only
	// place its seats can be recorded - the only block whose commit would decide
	// them is the genesis block, which is never appended. Without it a
	// one-block-epoch chain could not judge its FIRST block: every proposer
	// would be reported unseated at height 1. The gap predates audit A-1 - the
	// old genesis-only proposer check never asked for a committee - but the fix
	// makes the append path ask, so the deciding state must be recorded.
	c.memoCommitteeLocked(st, 0)

	// Compare the genesis BEFORE replaying a single block (audit O-5). A data
	// directory belongs to one chain; opening it with a different genesis
	// used to replay until the divergence surfaced as ErrGenesisReplay, which
	// names neither cause nor fix. The store records the genesis hash once
	// (atomically) and refuses a later mismatch with store.ErrWrongGenesis,
	// which is surfaced as this chain's ErrWrongGenesis.
	if err := s.CheckGenesis(g.Hash()); err != nil {
		if errors.Is(err, store.ErrWrongGenesis) {
			return nil, fmt.Errorf("%w: %w", ErrWrongGenesis, err)
		}
		return nil, err
	}

	height, ok := s.Height()
	if !ok {
		owned = true
		return c, nil
	}
	for h := uint64(1); h <= height; h++ {
		raw, err := s.Read(h)
		if err != nil {
			return nil, err
		}
		blk, err := types.DecodeBlock(raw)
		if err != nil {
			return nil, err
		}
		// The store indexes segments by record count, so a lost or rewritten
		// segment would silently renumber every stored block. applyValidated
		// deliberately skips structure, proposer and signature checks, and
		// the state-root check below cannot substitute for these either:
		// blocks that carry no transactions change no state, so a renumbered
		// chain would replay to the very roots the rewritten headers claim.
		// The cheapest authentication of the stored bytes is to require each
		// block to claim the position it sits at and to link exactly the
		// block replayed before it (for replay position h = 1 that
		// predecessor is the synthesized genesis, which lives at height 0).
		if blk.Header.Height != h {
			return nil, fmt.Errorf("%w at height %d: stored block claims height %d", ErrGenesisReplay, h, blk.Header.Height)
		}
		wantParent := c.head.ID()
		if blk.Header.ParentHash != wantParent {
			// HEIGHT 1 IS A SPECIAL CASE, AND SAYING SO IS THE POINT OF AUDIT
			// C-2. The only predecessor of the first stored block is the
			// SYNTHESIZED genesis block, whose ID is a function of the genesis
			// document AND the genesis state root this build derives from it -
			// while store.CheckGenesis compares the DOCUMENT hash, which covers
			// no derived state. So a directory written by a build whose genesis
			// state root differed passes CheckGenesis and then fails here, at
			// height 1, with the message this file uses for a renumbered or
			// corrupt log. That is not what happened, and an operator sent to
			// look for corruption in a healthy log is a diagnostic failure.
			//
			// The known instance is the ST-3 hard fork: committing Bond.Unfunded
			// in state.bondLeaf changed the genesis state root without changing
			// genesis.Hash, so every data directory written before it is
			// unopenable by a build after it. The fix is a fresh --dir or a
			// resync, never a repair.
			if h == 1 {
				return nil, fmt.Errorf("%w at height 1: the first stored block does not link this build's genesis block (parent %x, expected %x). The genesis HASH matches - the store checks it before replay - so this directory was written by a DIFFERENT BUILD of b10coin whose genesis STATE ROOT differed from this one (the document hash covers no derived state). A data directory written before the ST-3 change, which added Bond.Unfunded to the committed bond leaf, is the known case. Nothing here is corrupt: start a fresh --dir, or resync this node from a peer on this build",
					ErrGenesisReplay, blk.Header.ParentHash[:8], wantParent[:8])
			}
			return nil, fmt.Errorf("%w at height %d: stored block does not link its predecessor (parent %x, expected %x)",
				ErrGenesisReplay, h, blk.Header.ParentHash[:8], wantParent[:8])
		}
		if err := c.applyValidated(blk); err != nil {
			return nil, fmt.Errorf("%w at height %d: %v", ErrGenesisReplay, h, err)
		}
		// The stored header's root must equal what we just recomputed. THIS IS
		// THE C-1 DIVERGENCE POINT (audit N-1). The block's height, parent link
		// and bytes matched, so the log is not structurally damaged; what
		// differs is what its transactions DO to the state. A build that ran
		// the old grant-first unbond order writes a different post-state for
		// any exit from a bond holding both a genesis grant and a top-up, and a
		// mixed-build committee forks at that unbond. Reporting it with
		// ErrGenesisReplay's "replay diverged" text sent the operator looking
		// for corruption; ErrRuleChange says which rule changed and what to do.
		if root := c.state.Root(); root != blk.Header.StateRoot {
			return nil, fmt.Errorf("%w at height %d: this block's transactions replay to state root %x, but the stored header commits %x. Height, parent link and block bytes all matched, so NOTHING HERE IS CORRUPT: the usual cause is a DIFFERENT BUILD of b10coin whose CONSENSUS RULES differ at this height (the genesis hash covers no derived state and a header carries no rule version). Two known cases: ST-3's bond-leaf change (which moves the genesis state root and normally fails the height-1 link check first), and C-1's FUNDED-FIRST unbond order, which changes the post-state of an exit from a bond holding both a genesis grant and a top-up and therefore diverges at that unbond's height. A mixed-build committee forks here. Start a fresh --dir, or resync this node from a peer on this build; do not attempt a repair",
				ErrRuleChange, h, root[:8], blk.Header.StateRoot[:8])
		}
	}
	owned = true
	return c, nil
}

func (c *Chain) Genesis() *genesis.Genesis {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gen
}

func (c *Chain) Height() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.head.Header.Height
}

// CommitteeAt returns the seats that validate height h: the committee of
// epoch h/EpochBlocks (0-based; the faucet claim epoch is h/E+1 and is a
// different number), derived from the state committed at the last height of
// the preceding epoch - e*E-1 - or from the genesis state for epoch 0.
//
// This is the ONE per-height source of committee truth. Consensus for h reads
// it (driver configFor, the vote router's membership check, the certificate
// gate, HELLO admission, BLOCK_SYNC membership), so a validator's seat ends
// exactly at the boundary and begins exactly there: h = E-1 is the last height
// of epoch 0 and h = E the first of epoch 1.
//
// A height mid-epoch therefore sees exactly the set its first block saw. The
// entry is written when the deciding state is committed, never recomputed: a
// bond that changes inside epoch e cannot move epoch e's seats, because the
// function of that state was already taken. The set that committed the
// boundary's parent is the set that judges the boundary.
//
// The returned slice - and every validator key in it - is a COPY: the memo is
// derived state that a caller must not be able to mutate through. A caller
// that only needs to know WHETHER A KEY IS SEATED must call IsSeatedAt
// instead: the copy is a slice plus one allocation per seat (audit RT-6), and
// the router asks this question for every vote and every proposal.
func (c *Chain) CommitteeAt(h uint64) ([]genesis.Validator, error) {
	blocks := c.gen.Params.EpochBlocks
	if blocks == 0 {
		// genesis.Validate refuses this, so it is unreachable from a real
		// chain; a hand-built one must not divide by zero.
		return nil, fmt.Errorf("%w: EpochBlocks is zero", ErrNoCommittee)
	}
	epoch := h / blocks
	c.mu.RLock()
	vals, ok := c.committees[epoch]
	var head uint64
	if !ok {
		head = c.head.Header.Height
	}
	c.mu.RUnlock()
	if !ok {
		switch {
		case epoch == 0:
			return nil, fmt.Errorf("%w: epoch 0's committee is derived from the genesis state, which seats none", ErrNoCommittee)
		case head < epoch*blocks-1:
			return nil, fmt.Errorf("%w: epoch %d (height %d) is decided by the state at height %d, which is not committed yet (head %d)",
				ErrNoCommittee, epoch, h, epoch*blocks-1, head)
		default:
			return nil, fmt.Errorf("%w: epoch %d (height %d) was decided by the state at height %d, which seats no committee",
				ErrNoCommittee, epoch, h, epoch*blocks-1)
		}
	}
	out := make([]genesis.Validator, len(vals))
	for i := range vals {
		out[i] = genesis.Validator{PubKey: append([]byte(nil), vals[i].PubKey...), Power: vals[i].Power}
	}
	return out, nil
}

// IsSeatedAt reports whether pub holds a seat at height h, WITHOUT copying the
// committee (audit RT-6). It answers false both for "not seated" and for "this
// chain cannot derive a committee at h"; a caller that must distinguish those
// two - a diagnostic, never a membership gate - asks CommitteeAt.
//
// This is the hot path's membership test. The router asks it for every vote
// and every proposal before any signature verification, and BLOCK_SYNC asks it
// per request and per response; CommitteeAt's defensive deep copy is a slice
// plus one allocation per seat (up to 255 on a full committee) and nothing on
// these paths mutates the returned seats. Safety is unchanged: the answer is
// read under the same read lock from the same memoised, immutable epoch set
// CommitteeAt returns, so a caller can only ever be told exactly what
// CommitteeAt would have contained at that height.
func (c *Chain) IsSeatedAt(h uint64, pub []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.seatedAtLocked(h, pub)
}

// seatedAtLocked is IsSeatedAt's body. The caller must ALREADY hold c.mu, for
// reading or writing.
//
// It exists because IsSeatedAt cannot be called from validateLocked: Append
// calls validateLocked under the WRITE lock, and a nested RLock blocks while a
// writer is pending (Go's RWMutex is not reentrant), so calling the exported
// method there would deadlock the append path on itself. validateLocked reads
// the memoised map directly through this helper, under the lock it already
// holds, and gets exactly the answer IsSeatedAt would give.
func (c *Chain) seatedAtLocked(h uint64, pub []byte) bool {
	blocks := c.gen.Params.EpochBlocks
	if blocks == 0 {
		return false
	}
	for i := range c.committees[h/blocks] {
		if string(c.committees[h/blocks][i].PubKey) == string(pub) {
			return true
		}
	}
	return false
}

// EverSeated reports whether pub has EVER held a seat on this chain - genesis
// seats included - and is the authorisation term audit RT-3 adds for a
// validator that joined after genesis and later rotated out.
//
// READ THE WIDENING THIS IS (audit RT-3/RT-7): this is not "is a member now".
// It is true forever for every key that was ever seated, including one that has
// since unbonded and withdrawn, and it is used ONLY by the two AUTHORISATION
// gates (HELLO admission in the node, BLOCK_SYNC request/response membership in
// the syncer). Consensus does not read it: votes, proposals and certificates
// are judged against CommitteeAt(height), so a rotated-out key can resync and
// re-announce but cannot vote, propose, count toward a quorum or authorise a
// block. Membership in this set is a DoS-budget question, never a safety one.
func (c *Chain) EverSeated(pub []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.everSeated[string(pub)]
	return ok
}

// Head returns the current head block. Append retains the caller's
// *types.Block as the head and this method hands that same pointer back, so
// a caller must not mutate a block after appending it: doing so silently
// changes Height()/Head().ID() without any store write. Returned blocks are
// therefore immutable by contract.
func (c *Chain) Head() *types.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.head
}

// State returns the current committed state.
//
// IN-PROCESS TRUST ONLY (audit O-3). The returned *state.State is the chain's
// LIVE state value, not a copy: it is replaced (never mutated) by every
// Append, so a reader that holds one snapshot sees a consistent, immutable
// world, but a caller that type-asserts or reaches for state.Set/SetHeight
// can write into the chain's own state and silently desynchronise it from the
// store. Those methods are exported because chain.genesisState and
// state.ApplyBlock build state with them; they are not a public mutator.
// Likewise Head() returns the retained *types.Block and Genesis() returns the
// *genesis.Genesis handed to Open - callers must treat both as read-only.
// This is acceptable for one process whose components trust each other; it is
// not safe across a trust boundary and must not be exposed to one.
func (c *Chain) State() *state.State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// AdmissionHead returns the head state together with the head height, under one
// lock so the pair cannot disagree. The mempool uses it to admit a transaction
// against the state a block would execute now, before paying for any expensive
// verification (audit R-1). The returned *State is immutable once published -
// every transition clones and replaces it - so a caller may read it without the
// chain lock, exactly as Chain.State's contract already allows.
func (c *Chain) AdmissionHead() (*state.State, uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state, c.head.Header.Height
}

// HeadSnapshot returns the head height, the head block's ID and its state
// root in ONE read-locked critical section (audit O-8). RPC's /status used to
// call Head() and Height() separately, so a block committed between the two
// calls produced a response whose height named the new head while the hash
// and root named the old one - internally inconsistent, and a liar to any
// monitor that compared them. All three values now come from the same head.
func (c *Chain) HeadSnapshot() (height uint64, id [32]byte, stateRoot [32]byte) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.head.Header.Height, c.head.ID(), c.head.Header.StateRoot
}

// creditEmissionLocked pays the block's emission into the faucet account. It
// runs BEFORE the block's transactions, for every height including genesis,
// so a claim in block h may spend block h's emission. Build, Append and
// replay must all call this or their state roots diverge.
//
// Called from advanceLocked only, which always holds c.mu.
func (c *Chain) creditEmissionLocked(st *state.State, height uint64) {
	r := faucet.Reward(height, c.gen.Params.InitialRewardSparks, c.gen.Params.HalvingIntervalBlocks)
	if r == 0 {
		return
	}
	acc := st.Get(c.faucet)
	acc.Balance += r
	st.Set(c.faucet, acc)
}

// advanceLocked applies one block's state transition: emission FIRST, then the
// block's transactions, in that order. Every path that moves the chain forward
// calls this - if any of them applied the transactions first, or skipped the
// emission, its state root would differ from the others and the chain would fork.
//
// It mutates only the clone it returns, never c.state; the caller must hold
// c.mu (reading is enough, which is how Build uses it).
func (c *Chain) advanceLocked(height uint64, txs []types.Tx) (*state.State, error) {
	next := c.state.Clone()
	next.SetHeight(height) // execution context only: the claim rule derives its epoch from it
	c.creditEmissionLocked(next, height)
	return next.ApplyBlock(txs)
}

// Probe reports the state a block at head+1 carrying txs would produce, without
// appending anything. It runs the SAME transition as Append - height set, emission
// credited, transactions applied - because a probe that skipped the emission or used the
// head's height would evict valid faucet claims.
func (c *Chain) Probe(txs []types.Tx) (*state.State, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.advanceLocked(c.head.Header.Height+1, txs)
}

// SelectApplicable filters candidates down to the transactions that apply, in
// order, against the state a block at head+1 would be built on, and returns
// them. This is THE one policy for which transactions a block carries: both
// block producers run through it - node.RunOnce for the single-node path and
// consensus.Driver.build for the consensus path - so what a proposer assembles
// and what every validator's Append must accept are decided by the same code.
// A block assembled one way and judged another is how a chain forks; sharing
// this filter is what makes that impossible by construction rather than by
// two implementations that must be kept in step by hand.
//
// THE BYTE BUDGET LIVES HERE (audit S-3). A block is legal only if it is under
// BOTH types.MaxTxsPerBlock and types.MaxBlockBytes, and the count ceiling is
// the looser of the two: the pool can hand a producer 10,000 applicable
// transfers whose framed weight is 1,650,212 bytes, so a filter that judged
// only applicability assembled blocks that chain.Build spent a full state
// transition on before ValidateStructure refused them with ErrBlockTooLarge -
// and node.Run then exited. The budget is accumulated from the SAME encoded
// size the block will carry (types.Tx.FramedSize, measured from Encode) plus
// the signed block's fixed overhead, so the selected list can never exceed
// MaxBlockBytes, and it is charged only for transactions that APPLY: an evicted
// candidate costs the block no room.
//
// It is enforced here, not in Build, because the caller's slice is the pool's
// bookkeeping. Truncating inside Build would drop transactions the caller had
// already removed from the pool with Take, and nothing would put them back;
// the budget returns them as overBudget instead, and the caller's contract is
// to RETURN THEM TO THE POOL they came from (both producers re-add them before
// the head moves, because the nonce floor of an appended block would refuse
// them afterwards). An over-budget transaction is NOT an inapplicable one: it
// is valid, it is eligible, and it belongs in a later block - losing it would
// make a full mempool a silent transaction shredder. Every transaction not in
// selected and not in overBudget was evicted for inapplicability, alone.
//
// The filter's base is Probe(nil) - the state a block at head+1 with no
// transactions would produce: the SAME transition Build runs, height advanced
// and emission credited. Hand-cloning the head state (the old filter) probed
// a claim against the head's epoch and a pre-emission faucet balance, and
// silently evicted valid claims. Candidates then apply on top of the base
// cumulative - each accepted transaction is inside the running state the next
// probe starts from, so a candidate may chain onto its accepted siblings
// (transfers with nonces 0 and 1 both survive; probing each against the bare
// head state would evict the second).
//
// COST (audit S-6): the base is mutated IN PLACE by state.ApplyTx, so the
// account map is cloned ONCE for the whole candidate list, not once per
// candidate. ApplyTx's contract is that every validation runs before the first
// write, so a rejected candidate leaves the running state untouched and the
// next candidate still starts from valid state; that contract is load-bearing
// here and is verified rather than trusted - see
// state.TestApplyTxLeavesNoPartialWriteOnEveryFailurePath. Per candidate the
// cost is one signature verification plus the transition's own writes, not a
// full account-map copy (O(candidates × accounts) before this change, with up
// to MaxTxsPerBlock = 10,000 candidates). A candidate that cannot apply is
// dropped ALONE and leaves no trace on the running state; it does not discard
// its valid siblings, and it is gone for good once the caller's Take does not
// see it again - the caller owns what eviction means for its pool.
//
// The per-block claim bound is deliberately NOT applied here and its callers
// must not duplicate it: state.ApplyBlock enforces it before any Argon2id
// evaluation, on the block as a whole, which is where the bound is consensus.
// The mempool's local claim courtesy that bounds what each block producer
// TAKES lives in mempool.Take. A filter that re-counted claims here would be
// a second claim rule that could drift from the state machine's; the two
// layers this side of ApplyBlock stay exactly where they are.
//
// ORDERING, AND THE FUTURE NONCE THAT USED TO BE DESTROYED (audit S-17). The
// pool admits a transaction whose nonce is ahead of the account's, because it
// may become applicable when its predecessors land. Take hands candidates back
// in insertion order, so a sender whose nonce-2 transaction arrived before its
// nonce-1 predecessor presented [2, 1]: 2 was evicted as inapplicable, 1 was
// selected, and 2 was gone - Take had already removed it and nothing put it
// back. Candidates are therefore permuted so that each sender's transactions
// are in nonce order BEFORE selection, moving only that sender's own entries
// among their own positions. No transaction changes its position relative to
// any other sender, so a transfer that funded another sender keeps its arrival
// order. Within one sender, nonce order is the only order a chain can apply in,
// so this can only turn "inapplicable now" into "applicable now", never the
// reverse; the selected set is exactly what sequential nonce-order arrival
// would have produced.
//
// A candidate that still cannot apply because its nonce is AHEAD of the
// running state - a real gap, where the predecessor is not in this batch at
// all - is not silently destroyed either. It is returned in retry and the
// caller re-adds it to the pool before the head moves, so it is eligible again
// once the gap fills; a gap that never fills ages out through the pool's
// ordinary capacity and per-sender bounds, exactly as any other unapplied
// transaction. Only a nonce-ahead candidate is deferred: one the state refused
// for any other reason (a spent nonce, a bad signature, insufficient funds) is
// genuinely inapplicable, and is evicted as before.
//
// An error return means the empty head+1 transition itself failed, so nothing
// applies and every candidate was lost by the caller's bookkeeping; the caller
// is expected to return its candidates to wherever they came from.
//
// retry is the set of candidates this block cannot carry but that remain
// eligible: the tail the byte budget excluded (which is not judged at all -
// the budget's point is that the work stops there) plus the nonce-ahead
// candidates deferred above. When both kinds are present it is not a view of
// candidates, so the caller must only re-add it. It is empty whenever every
// candidate fits and applies.
func (c *Chain) SelectApplicable(candidates []types.Tx) (selected, retry []types.Tx, err error) {
	// Probe returns a fresh state (advanceLocked clones before applying), so it
	// is the caller's to mutate; no further clone is needed.
	base, err := c.Probe(nil)
	if err != nil {
		return nil, nil, err
	}
	orderBySenderNonce(candidates)
	// used is the encoded size the block would have: the signed overhead plus
	// every selected transaction's framed weight. It is compared before a
	// candidate is applied, because a candidate that does not fit must not
	// touch the running base: the next block is assembled against the state the
	// SELECTED transactions produce, and a probe that included a transaction the
	// block does not carry would judge its successors against a state that never
	// happened.
	used := types.BlockOverheadBytes
	selected = make([]types.Tx, 0, len(candidates))
	for i := range candidates {
		size := candidates[i].FramedSize()
		if used+size > types.MaxBlockBytes {
			if len(retry) == 0 {
				return selected, candidates[i:], nil
			}
			return selected, append(retry, candidates[i:]...), nil
		}
		if err := base.ApplyTx(&candidates[i]); err != nil {
			if notYetApplicable(base, &candidates[i], err) {
				retry = append(retry, candidates[i])
			}
			continue // evict: it cannot apply at this state, leaving base unchanged
		}
		selected = append(selected, candidates[i])
		used += size
	}
	return selected, retry, nil
}

// orderBySenderNonce puts each sender's candidates in nonce order WITHOUT
// moving any entry out of that sender's own positions, so sender order and
// every cross-sender relationship are untouched. It is in place and
// allocation-free unless some sender's entries are actually out of order (the
// common case: the pool's insertion order is the submission order, which a
// correct wallet sends in nonce order).
func orderBySenderNonce(txs []types.Tx) {
	if len(txs) < 2 {
		return
	}
	groups := make(map[types.Address][]int, 8)
	senders := make([]types.Address, 0, 8)
	for i := range txs {
		a := txs[i].From
		if _, ok := groups[a]; !ok {
			senders = append(senders, a)
		}
		groups[a] = append(groups[a], i)
	}
	for _, a := range senders {
		pos := groups[a]
		if len(pos) < 2 {
			continue
		}
		ordered := true
		for k := 1; k < len(pos); k++ {
			if txs[pos[k]].Nonce < txs[pos[k-1]].Nonce {
				ordered = false
				break
			}
		}
		if ordered {
			continue
		}
		group := make([]types.Tx, len(pos))
		for k, i := range pos {
			group[k] = txs[i]
		}
		sort.SliceStable(group, func(i, j int) bool { return group[i].Nonce < group[j].Nonce })
		for k, i := range pos {
			txs[i] = group[k]
		}
	}
}

// notYetApplicable reports whether the running state refused a candidate ONLY
// because its nonce is ahead of its sender's account nonce: the transaction is
// legal and will apply once the missing predecessors land, so it belongs back
// in the pool rather than in the void. A nonce BELOW the account's is spent and
// stays evicted; so does any other refusal.
func notYetApplicable(base *state.State, tx *types.Tx, err error) bool {
	if !errors.Is(err, state.ErrBadNonce) {
		return false
	}
	return base.Get(tx.From).Nonce < tx.Nonce
}

// Build constructs and signs a candidate block. It does not mutate the
// chain: the caller decides whether to Append.
//
// A proposer key that is nil or the wrong length is refused up front (audit
// O-6). ed25519.PrivateKey.Public() indexes the key's seed and public halves,
// so calling it on a short key panics; a wiring bug that passed nil used to
// crash the node instead of returning. The length check makes the existing
// ErrUnknownProposer return reachable for that case.
func (c *Chain) Build(proposer ed25519.PrivateKey, txs []types.Tx, timestamp int64) (*types.Block, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(proposer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: proposer key is %d bytes, want %d", ErrUnknownProposer, len(proposer), ed25519.PrivateKeySize)
	}
	pub, ok := proposer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrUnknownProposer
	}
	next, err := c.advanceLocked(c.head.Header.Height+1, txs)
	if err != nil {
		return nil, err
	}
	b := &types.Block{
		Header: types.Header{
			Height:     c.head.Header.Height + 1,
			ParentHash: c.head.ID(),
			StateRoot:  next.Root(),
			TxRoot:     types.ComputeTxRoot(txs),
			Timestamp:  timestamp,
			Proposer:   pub,
		},
		Txs: txs,
	}
	if err := b.ValidateStructure(); err != nil {
		return nil, err
	}
	headerHash := b.Header.SigningHash()
	b.Sig = crypto.Sign(proposer, headerHash[:])
	return b, nil
}

// applyValidated applies a block whose structure is already trusted.
// Write-locked; the unlocked body lives in applyValidatedLocked so Append can
// reuse it while holding the lock.
//
// TRUST BOUNDARY (audit O-2), stated here because this is the one place that
// skips checks: replay trusts the bytes already in the local data directory.
// It verifies the block's (height, parent link) against its position and the
// recomputed state root against the header - the properties that detect a
// renumbered, reordered or truncated log - but it deliberately does NOT
// re-run ValidateStructure, proposer membership or the proposer signature.
// The bytes were accepted by Append (which runs every check) and then fsynced
// by this process or a predecessor on this disk; the cost of re-verifying
// every stored block on every start buys no safety the disk does not already
// carry. The boundary is the local filesystem: a host that can rewrite the
// data directory can already rewrite the binary or the genesis, so replay's
// job is corruption detection, not authentication. A node that must distrust
// its own disk needs the whole directory authenticated by something outside
// it - out of scope, and not to be half-done here.
func (c *Chain) applyValidated(b *types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applyValidatedLocked(b)
}

func (c *Chain) applyValidatedLocked(b *types.Block) error {
	next, err := c.advanceLocked(b.Header.Height, b.Txs)
	if err != nil {
		return err
	}
	c.state = next
	c.head = b
	c.memoCommitteeLocked(next, b.Header.Height)
	return nil
}

// memoCommitteeLocked records the committee epoch whose deciding state was
// just committed. Epoch e is decided by the state at height e*E-1 (epoch 0 by
// the genesis state), so exactly the block whose height+1 is a multiple of E
// writes an entry - and it writes the entry for the epoch that BEGINS at
// height+1, i.e. (height+1)/E. Writing at any other height, or keying the
// entry by height/E, would shift every boundary by one block; both are pinned
// by TestTheCommitteeChangesExactlyAtTheBoundary.
//
// A derivation failure is swallowed here on purpose: the block is valid, and
// whether the NEXT epoch can be judged is a separate question that CommitteeAt
// reports when someone asks. Refusing an otherwise-valid block because the
// following epoch has no candidates would halt a chain one block early for a
// reason the block itself does not carry. The caller holds mu.
//
// WHO CHOOSES THE NEXT COMMITTEE (audit RT-8), stated because the answer is not
// "the stake holders alone": epoch e's seats are a pure function of the state
// at height e*E-1, so they are decided by whichever bond and unbond
// TRANSACTIONS that block carries. Its proposer draws the block from the
// mempool and is free to include or defer any transaction it holds (subject
// only to validity and the mempool's own admission rules), so the proposer of
// the deciding block chooses, within the transactions available to it, which
// bonded stakes are in the state the epoch is derived from. That is a
// liveness/fairness lever, not a safety one: the derivation is identical on
// every node for the state that block commits, a proposer cannot change a
// bond's amount or key, and a block it withholds is a block no one commits.
// Anyone can also land a bond early to be safely inside the deciding state. The
// ordering among EQUAL stakes is the other half of RT-8: see
// state.compareCandidates - it breaks ties on raw public-key bytes, which a
// key's owner can grind at generation time.
func (c *Chain) memoCommitteeLocked(st *state.State, height uint64) {
	blocks := c.gen.Params.EpochBlocks
	if blocks == 0 {
		return
	}
	next := height + 1 // a wrap to 0 fails the next check, so the last uint64 height is inert
	if next < blocks || next%blocks != 0 {
		return
	}
	epoch := next / blocks
	if vals, err := st.Committee(); err == nil {
		c.committees[epoch] = vals
		// The same state that decides this epoch's seats also says who may
		// ever be treated as a member for AUTHORISATION from now on. Filling
		// it here - and only here - is what makes the set replay-identical:
		// Open replays every stored block through this function, so a restart
		// rebuilds exactly the keys a live run recorded (audit RT-3).
		for i := range vals {
			c.everSeated[string(vals[i].PubKey)] = struct{}{}
		}
	}
}

// validateLocked runs every check Append runs for a block over the chain's
// CURRENT head, and returns the state a valid block would produce.
//
// This is the ONE validation policy for what makes a block acceptable at
// head+1: Append (the durable write) and ValidateNext (the consensus engine's
// pre-vote seam) both call it, so a block the engine prevotes is, by
// construction, a block Append would accept - and a proposer's Build (which
// signs exactly the same transition) cannot disagree with either. Two
// validators can only disagree about the chain, never about the rules.
//
// The checks, in Append's order: parent link, head+1 height, block structure
// (types), the proposer's seat at this block's height (the epoch committee,
// not genesis - audit A-1), proposer signature, then the whole state
// transition through advanceLocked - height set, emission credited,
// transactions applied - whose recomputed root must equal the header's claim.
// That last check is the state-root probe: the same Probe-style transition a
// peer who never saw the block would run to judge it.
//
// Read-lock sufficient: nothing here mutates the chain (advanceLocked works
// on a clone). The caller must hold c.mu.
func (c *Chain) validateLocked(b *types.Block) (*state.State, error) {
	if b.Header.ParentHash != c.head.ID() {
		return nil, ErrBadParent
	}
	if b.Header.Height != c.head.Header.Height+1 {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrBadHeight, b.Header.Height, c.head.Header.Height+1)
	}
	if err := b.ValidateStructure(); err != nil {
		return nil, err
	}
	// Strict monotonicity (audit S-8): a block's timestamp must be greater than
	// its parent's. This is the deterministic half of the fix - it depends only
	// on the two headers, never on a wall clock - so replay and consensus stay
	// exact. It runs before the state transition so a bad timestamp costs no
	// Argon2id work.
	if b.Header.Timestamp <= c.head.Header.Timestamp {
		return nil, fmt.Errorf("%w: block timestamp %d is not after parent timestamp %d",
			ErrBadTimestamp, b.Header.Timestamp, c.head.Header.Timestamp)
	}
	// THE PROPOSER'S SEAT, AT THIS BLOCK'S HEIGHT (audit A-1). This used to scan
	// c.gen.Validators - the GENESIS list - while consensus draws the proposer
	// from the epoch committee that judges this height (Driver.configFor ->
	// Chain.CommitteeAt, then Config.Proposer). A key bonded after genesis was
	// therefore drawn, built a block, and had it refused here by EVERY
	// validator, itself included, while its own prevote seam ran this same
	// check: every round it was drawn was burned, and a committee whose genesis
	// seats had all exited could never append again. Catch-up could not repair
	// it because Syncer.PullAndAdopt ends in this Append. RT-1's rotation-in
	// made that mismatch routinely reachable; this is the correction.
	//
	// The rule is now exactly the committee that drew the block: seated at
	// b.Header.Height means seated by the epoch h/EpochBlocks committee, which
	// is memoised from the state at that epoch's deciding height. No genesis
	// fallback is needed, and none would be safe to add casually: for every
	// genesis chain.Open accepts, the epoch-0 committee derived from the genesis
	// state is EXACTLY the genesis validator set (genesis.Validate requires
	// CommitteeSize >= len(Validators) and every Power > 0; state.Committee
	// clamps powers but never drops a seat, and clamps at seats >= 4 only, where
	// a positive total over at least four seats gives a nonzero quarter), so
	// epoch 0 is unchanged. Pinned by
	// TestTheGenesisCommitteeIsTheEpochZeroCommittee.
	//
	// SAFETY: this cannot admit a proposer that was not entitled to propose.
	// "Entitled" IS this membership: the proposer draw (Config.Proposer) selects
	// from the same CommitteeAt(height) set the router checks every frame
	// against, and the certificate gate re-tallies the commit with it. A key
	// outside the epoch committee is refused here, so the only way a block
	// passes is the way an honest one does - a key the committee for its own
	// height seats. In particular EverSeated is NOT used: "was seated once" is
	// an authorisation widening (RT-3) and would admit a rotated-out proposer.
	if !c.seatedAtLocked(b.Header.Height, b.Header.Proposer) {
		return nil, fmt.Errorf("%w at height %d", ErrNotValidator, b.Header.Height)
	}
	if b.Sig == nil {
		return nil, ErrBadProposerSig
	}
	headerHash := b.Header.SigningHash()
	if !crypto.Verify(b.Header.Proposer, headerHash[:], b.Sig) {
		return nil, ErrBadProposerSig
	}
	next, err := c.advanceLocked(b.Header.Height, b.Txs)
	if err != nil {
		return nil, err
	}
	if computed := next.Root(); computed != b.Header.StateRoot {
		return nil, fmt.Errorf("%w: computed %x, header claims %x",
			ErrBadStateRoot, computed[:8], b.Header.StateRoot[:8])
	}
	return next, nil
}

// ValidateNext reports whether b is a valid block for head+1, WITHOUT
// appending or mutating anything: it runs exactly the checks Append runs -
// they live in one shared method so the two cannot drift - and returns the
// first failure.
//
// COST, stated where the reviewer will look for it (audit round 3, F4): the
// seam is the whole state transition, not a cheap pre-check. A proposal is
// cloned and applied end to end - emission credited, every transaction
// applied - and a faucet claim's puzzle can only be accepted or rejected by
// evaluating it, so each claim in b costs one FULL Argon2id evaluation here,
// bounded exactly as a genuine block is bounded by MaxClaimsPerBlock and
// MaxTxsPerBlock (ApplyBlock refuses the block above any bound before any
// puzzle runs). All of it runs under this chain's READ lock, so a Byzantine
// proposer can force that work for a block it already knows will fail the
// root comparison at the end - and the work is charged to every validator
// the proposal reaches. The bound is structural: the engine judges at most
// ONE proposal per round (the first stored proposal wins; later ones are
// dropped as duplicates), so the attack is at most one full-transition
// validation per round per validator - the price of the pre-vote probing the
// audit asked for (judging the state root BEFORE a vote can rest on it), and
// work the pre-fix prevote path never did. It is accepted cost, documented
// here so no reviewer has to rediscover it.
//
// This is the audit C-1 seam's chain half: the consensus engine must judge a
// proposal BEFORE prevoting it, and the check it makes must be the one a peer
// (and the chain itself) would make at append time. A validator that lets a
// proposal reach a polka, a lock and a commit before the chain sees it risks
// every node parking on the chain's refusal, with no one able to move on -
// the halt one Byzantine proposer can otherwise inflict with a garbage state
// root.
//
// Like Append, validation is all-or-nothing against the current head: a
// refusal leaves height, state and store untouched.
func (c *Chain) ValidateNext(b *types.Block) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, err := c.validateLocked(b)
	return err
}

// ValidateConsensusNext is ValidateNext plus the consensus path's timestamp
// pin (audit S-8): a block this node will prevote must carry EXACTLY the
// parent's timestamp plus one.
//
// This is the second half of the S-8 fix and the stricter one. The audit
// offered a wall-clock future bound (Timestamp <= now + drift) or pinning the
// consensus path to parent+1. The pin was chosen because a wall-clock bound
// would put each validator's local clock into a consensus rule: the same block
// could be valid at one node and invalid at a clock-skewed neighbour, and a
// replayed check could disagree with the live one. The chain's own driver
// already builds every proposal at parent+1 (deterministic and replayable), so
// pinning it as a rule costs honest peers nothing and removes the proposer's
// timestamp-grinding lever (C-14) entirely: on the consensus path there is one
// legal timestamp, not a range.
//
// Append deliberately keeps only the monotonic rule. The single-node/RPC path
// (node.RunOnce) is not consensus - it stamps the block with the local clock -
// and requiring parent+1 there would be a needless hard fork. The weaker rule
// still refuses a timestamp behind the parent on every path.
func (c *Chain) ValidateConsensusNext(b *types.Block) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, err := c.validateLocked(b); err != nil {
		return err
	}
	if want := c.head.Header.Timestamp + 1; b.Header.Timestamp != want {
		return fmt.Errorf("%w: the consensus path pins the timestamp to parent+1; got %d, want %d",
			ErrBadTimestamp, b.Header.Timestamp, want)
	}
	return nil
}

// Append validates a block against the current head and state, then stores
// it. Validation happens before any mutation, so a rejected block leaves the
// chain untouched.
//
// LOCKING AND fsync (audit O-4), stated because it is a real latency choice:
// the whole operation - validation, the store write and its fsync, and the
// in-memory swap - runs under the exclusive c.mu. That means a concurrent
// RPC read (State/Height/Head/AdmissionHead) waits for the block's fsync,
// which on a Raspberry Pi's SD card can be milliseconds. The alternative -
// releasing the lock across the fsync - would let a reader observe a head
// whose block is not yet durable, or let two Appends interleave their store
// writes and state swaps; the store is not built for concurrent writers.
// Correctness over read latency is the deliberate choice for this milestone;
// a future split would need a store-level append lock and a commit protocol
// (write, fsync, then publish) before the read lock could be dropped.
//
// Aliasing contract: on success Append retains the caller's *types.Block as
// the chain's head (no defensive copy), and Head() later hands that same
// pointer back. A caller must not mutate a block after appending it:
// mutating the retained block silently changes Height()/Head().ID() with no
// store write, leaving the stored bytes behind the chain's in-memory view.
func (c *Chain) Append(b *types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The full validation runs first (validateLocked), so a rejected block
	// never reaches the store: a refusal leaves the chain byte-identical to
	// what ValidateNext would have observed.
	next, err := c.validateLocked(b)
	if err != nil {
		return err
	}
	if err := c.store.Append(b.Header.Height, b.Encode()); err != nil {
		return err
	}
	c.state = next
	c.head = b
	// The height just committed may be the boundary that DECIDES the next
	// epoch. Record that epoch's seats from the state now committed - the same
	// place replay records them - before any later height can observe it.
	c.memoCommitteeLocked(next, b.Header.Height)
	// The height just committed is behind every engine this node will build
	// from now on (Driver.newEngine judges head+1, and there is no reorg), so
	// its persisted lock - and every older one - can never be read again.
	// Prune them (audit C-13): the in-memory map immediately, and the log file
	// when enough stale frames have accumulated. The error is deliberately
	// dropped: compacting the lock log is storage maintenance, never a safety
	// step, and the old file (a superset) survives a failed rewrite. A commit
	// must not be reported as failed because a rewrite could not happen.
	_ = c.store.PruneLocks(b.Header.Height)
	// The round log's round belongs to the SAME never-again heights: the round
	// persisted for head+1 (see Chain.PutRound) becomes unreadable the moment
	// head+1 is committed, because the next engine this node builds judges the
	// new head+1. Prune it on exactly the lock log's rule and with the same
	// dropped error (review F3): without this the log grows one frame per
	// round entered, forever, with no prune path at all.
	_ = c.store.PruneRounds(b.Header.Height)
	return nil
}

// BlockAt returns the block stored at height. Only the head is cached, so
// historical reads go to disk. Height 0 is the genesis block, which the
// store deliberately never holds (store heights start at 1): it is
// re-synthesised from the genesis configuration exactly as Open built it.
func (c *Chain) BlockAt(height uint64) (*types.Block, error) {
	// The chain lock covers the HEAD snapshot only (audit R-2). It used to be
	// held across the store's disk read and the decode as well, so every
	// reader already inside a serialised read delayed Append, and a /history
	// scan multiplied that by its window. A historical block never changes
	// once appended, so the read needs no chain state beyond the head it was
	// judged against; the store guards its own index.
	c.mu.RLock()
	head := c.head
	c.mu.RUnlock()
	headHeight := head.Header.Height
	if height > headHeight {
		return nil, fmt.Errorf("%w: %d", store.ErrNotFound, height)
	}
	if height == headHeight {
		return head, nil
	}
	if height == 0 {
		st := genesisState(c.gen)
		return genesisBlock(c.gen, st), nil
	}
	raw, err := c.store.Read(height)
	if err != nil {
		return nil, err
	}
	return types.DecodeBlock(raw)
}

// PutLock durably records a validator's lock: that it precommitted
// rec.BlockID at rec.Height in round rec.Round. The chain exposes the
// store's lock log because the lock must survive a restart, and the store is
// only reachable through the chain - it is the same crash-tolerant directory
// the blocks replay from, so the promise is read back in the same Open that
// rebuilds the chain. Write-locked: it mutates the store (append + fsync +
// index update) and must not interleave with readers.
func (c *Chain) PutLock(rec store.LockRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.PutLock(rec)
}

// LockAt returns the newest lock recorded for height, and whether one
// exists. This is how a restarted validator picks its promise back up: the
// replayed blocks say where the chain stands, the lock log says what it
// promised at the height it is about to judge.
func (c *Chain) LockAt(height uint64) (store.LockRecord, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.store.LockAt(height)
}

// PutRound durably records that a validator entered rec.Round at rec.Height
// (audit C-3). The chain exposes the store's round log for the same reason it
// exposes the lock log: the position a validator had reached must survive a
// restart, and it belongs in the one crash-tolerant directory the blocks
// replay from. Write-locked: it appends, fsyncs and re-indexes the store.
func (c *Chain) PutRound(rec store.RoundRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.PutRound(rec)
}

// RoundAt returns the newest round recorded for height, and whether one
// exists. A restarted validator reads its position back through here, so the
// driver's fresh engine resumes at the round the crashed one had reached
// instead of re-entering round 0 for an already-contested height.
func (c *Chain) RoundAt(height uint64) (uint32, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.store.RoundAt(height)
}

// PutCert durably records the opaque commit certificate for height (audit
// C-7). The chain exposes the store's certificate log for the same reason it
// exposes the lock log: the evidence a node serves for a block it holds must
// outlive the process that adopted the block, and it belongs in the one
// crash-tolerant directory the blocks replay from. The encoding is the
// consensus package's; the chain only files the bytes against a height.
// Write-locked: it appends, fsyncs and re-indexes the store.
func (c *Chain) PutCert(height uint64, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.PutCert(height, payload)
}

// CertAt returns a copy of the recorded commit certificate for height, and
// whether this chain holds one. A restarted node reads its history's
// certificates back through here, so it can serve a peer the proof for blocks
// it adopted in a previous life.
func (c *Chain) CertAt(height uint64) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.store.CertAt(height)
}

func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.Close()
}
