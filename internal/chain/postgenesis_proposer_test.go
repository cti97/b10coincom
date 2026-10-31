package chain_test

// A-1 (audit 2026-10-31, High): the proposer used to be checked against the
// GENESIS validator list in Chain.validateLocked, not against the epoch
// committee that actually draws it. Once RT-1 let a post-genesis key run a
// node, such a key was drawn as proposer by consensus (which reads
// Chain.CommitteeAt), built a block, and every validator - including itself -
// nil-prevoted that block while Chain.Append refused it. Every round the key
// was drawn was burned.
//
// The two central tests CONSTRUCT that state and do not race for it:
//
//   - TestAPostGenesisSeatProposesAndEveryValidatorAppends walks the chain one
//     height at a time until the epoch committee's deterministic proposer draw
//     (consensus.Config.Proposer, the production function) lands on a key that
//     is not in genesis; the key builds the block and EVERY validator's chain
//     is asked to append it. Before the fix all of them refuse with
//     ErrNotValidator; after it all of them append the same block.
//   - TestACommitteeWithNoGenesisSeatsStillAppends is the worst case the audit
//     names: every genesis seat unbonds in full, so the committee that judges
//     the next epoch contains only a post-genesis seat. The chain must still
//     append; before the fix it can never advance again.
//
// Three further tests pin the rule's edges: that the epoch-0 committee is
// exactly the genesis set (so the replacement changes no epoch-0 acceptance),
// that a one-block-epoch chain can judge its first block (its deciding state is
// the never-appended genesis state), and that a key seated only in ANOTHER epoch
// is still refused.
//
// All of them are pure Chain-level constructions (no network, no clock, no
// sleeps): the draw depends only on height, round 0, the parent hash and the
// committed committee, all of which the test reads from the chain it just built.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

const (
	// a1GenesisSeats is how many keys the genesis document lists. There is
	// deliberately more than one so "every validator" is a real set.
	a1GenesisSeats = 3
	// a1EpochBlocks is short so the test crosses the boundary that seats the
	// joining key in a handful of blocks.
	a1EpochBlocks = uint64(4)
	// a1CommitteeSize leaves one spare seat: three genesis bonds plus the
	// joining bond fit, so the rotation-in is a seat ADDITION, not an
	// eviction. Eviction is RT-2's story; this test is about the proposer.
	a1CommitteeSize = 4
	// a1DrawWindow bounds the search for a height the joining key is drawn at.
	// The draw is deterministic for a given chain, and four equal seats make a
	// hit expected within a few heights; the window exists so a change to the
	// draw fails the test instead of looping.
	a1DrawWindow = 200
)

// a1Key derives a stable keypair from a seed string, so the constructed chain
// (and therefore the proposer draw the test searches for) is identical on
// every run. HashParts output is 32 bytes, exactly an ed25519 seed.
func a1Key(seed string) (ed25519.PublicKey, ed25519.PrivateKey) {
	h := crypto.HashParts([]byte("b10coin-a1-test-key"), []byte(seed))
	priv := ed25519.NewKeyFromSeed(h[:])
	return priv.Public().(ed25519.PublicKey), priv
}

// a1Genesis builds the fixture the two tests share: three genesis seats at
// MIN_STAKE, a committee size with one spare seat, four-block epochs, and one
// funded non-genesis key (the joiner) holding exactly its bond plus its fee.
func a1Genesis(t *testing.T) (*genesis.Genesis, []ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	g := genesis.Devnet()
	g.ChainID = "b10coin-a1-post-genesis-proposer"
	g.Params.ChainID = g.ChainID
	g.Params.EpochBlocks = a1EpochBlocks
	g.Params.CommitteeSize = a1CommitteeSize

	keys := make([]ed25519.PrivateKey, a1GenesisSeats)
	vals := make([]genesis.Validator, a1GenesisSeats)
	for i := range keys {
		pub, priv := a1Key(fmt.Sprintf("genesis-%d", i))
		keys[i] = priv
		// A genesis seat's bond IS its Power (chain.genesisState).
		vals[i] = genesis.Validator{PubKey: pub, Power: g.Params.MinStakeSparks}
	}
	g.Validators = vals
	joinerPub, joinerPriv := a1Key("joiner")
	g.DevAccounts = []genesis.DevAccount{{
		PubKey:        joinerPub,
		BalanceSparks: g.Params.MinStakeSparks + g.Params.MinFeeSparks,
	}}
	if err := g.Validate(); err != nil {
		t.Fatalf("the constructed genesis is invalid: %v", err)
	}
	return g, keys, joinerPriv
}

// a1Open opens one independent chain per validator from the SAME genesis. Each
// chain is a validator's own view: every one must validate and append the
// block, exactly as each validator's prevote seam and Append do.
func a1Open(t *testing.T, g *genesis.Genesis, n int) []*chain.Chain {
	t.Helper()
	cs := make([]*chain.Chain, n)
	for i := range cs {
		c, err := chain.Open(g, t.TempDir())
		if err != nil {
			t.Fatalf("opening validator %d's chain: %v", i, err)
		}
		t.Cleanup(func() { _ = c.Close() })
		cs[i] = c
	}
	return cs
}

// a1Build builds head+1 on c. The timestamp is the parent's plus one, so the
// chain's monotonic rule holds no matter what the parent was.
func a1Build(t *testing.T, c *chain.Chain, priv ed25519.PrivateKey, txs []types.Tx) *types.Block {
	t.Helper()
	b, err := c.Build(priv, txs, c.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatalf("building at height %d: %v", c.Height()+1, err)
	}
	return b
}

// a1AppendByEvery has EVERY validator's chain append b and reports all the
// refusals at once. The pre-fix failure is not one chain's opinion: it is every
// validator refusing the same block.
func a1AppendByEvery(t *testing.T, cs []*chain.Chain, b *types.Block) {
	t.Helper()
	var refused []string
	for i, c := range cs {
		if err := c.Append(b); err != nil {
			refused = append(refused, fmt.Sprintf("validator %d: %v", i, err))
		}
	}
	if len(refused) > 0 {
		t.Fatalf("%d of %d validators refused the block at height %d:\n%s",
			len(refused), len(cs), b.Header.Height, strings.Join(refused, "\n"))
	}
	for i := 1; i < len(cs); i++ {
		if cs[i].Height() != cs[0].Height() || cs[i].Head().ID() != cs[0].Head().ID() {
			t.Fatalf("validator %d and validator 0 disagree after appending height %d: heights %d/%d",
				i, b.Header.Height, cs[i].Height(), cs[0].Height())
		}
	}
}

// a1Sign signs a transaction with the chain's genesis hash.
func a1Sign(g *genesis.Genesis, priv ed25519.PrivateKey, tx types.Tx) types.Tx {
	h := tx.SigningHash(g.Hash())
	tx.Sig = crypto.Sign(priv, h[:])
	return tx
}

// a1Bond commits the joining key's bond at the next height, proposed by a
// still-seated genesis key.
func a1Bond(t *testing.T, g *genesis.Genesis, cs []*chain.Chain, builder, joiner ed25519.PrivateKey) {
	t.Helper()
	pub := joiner.Public().(ed25519.PublicKey)
	tx := a1Sign(g, joiner, types.Tx{
		Type:   types.TxBond,
		From:   types.AddressFromPub(pub),
		PubKey: pub,
		Nonce:  0,
		Amount: g.Params.MinStakeSparks,
		Fee:    g.Params.MinFeeSparks,
	})
	a1AppendByEvery(t, cs, a1Build(t, cs[0], builder, []types.Tx{tx}))
}

// TestAPostGenesisSeatProposesAndEveryValidatorAppends is the missing test the
// audit names: a post-genesis seat is DRAWN as proposer, BUILDS a block, and
// that block is appended by every validator - not merely counted as a precommit.
func TestAPostGenesisSeatProposesAndEveryValidatorAppends(t *testing.T) {
	g, keys, joiner := a1Genesis(t)
	joinerPub := joiner.Public().(ed25519.PublicKey)
	if genesis.SeatOfPubKey(g.Validators, joinerPub) >= 0 {
		t.Fatal("the joining key is in genesis: the state is not constructed")
	}

	// One chain per validator: the genesis seats and the joining node itself.
	cs := a1Open(t, g, a1GenesisSeats+1)

	// Height 1 carries the Bond; the epochs before the boundary keep the
	// genesis committee, which signs the filler blocks.
	a1Bond(t, g, cs, keys[0], joiner)
	for cs[0].Height() < a1EpochBlocks-1 {
		a1AppendByEvery(t, cs, a1Build(t, cs[0], keys[0], nil))
	}

	// The boundary committee must seat the joining key, or the draw below could
	// never land on it and the test would be proving nothing.
	boundary := a1EpochBlocks
	vals, err := cs[0].CommitteeAt(boundary)
	if err != nil {
		t.Fatalf("CommitteeAt(%d): %v", boundary, err)
	}
	if genesis.SeatOfPubKey(vals, joinerPub) < 0 {
		t.Fatalf("the committee at height %d does not seat the bonded key: %v", boundary, vals)
	}
	if !cs[0].IsSeatedAt(boundary, joinerPub) {
		t.Fatalf("IsSeatedAt(%d) says the bonded key is not seated", boundary)
	}

	// Walk forward one height at a time. At each height, ask the PRODUCTION
	// draw which key round 0 would propose, from the committed committee and
	// the actual parent. Any other key's block fills the height; when the
	// joining key is drawn, THAT is the block under test.
	for h := boundary; h < boundary+a1DrawWindow; h++ {
		if cs[0].Height() != h-1 {
			t.Fatalf("height bookkeeping: head %d, want %d", cs[0].Height(), h-1)
		}
		vals, err := cs[0].CommitteeAt(h)
		if err != nil {
			t.Fatalf("CommitteeAt(%d): %v", h, err)
		}
		drawn := consensus.Config{Committee: vals}.Proposer(h, 0, cs[0].Head().ID())
		if !bytes.Equal(drawn, joinerPub) {
			// A filler block: any seated key may build it for this test's
			// purpose; the genesis seat is seated throughout epoch 0 and, with
			// four equal seats, in every later epoch too.
			if !cs[0].IsSeatedAt(h, keys[0].Public().(ed25519.PublicKey)) {
				t.Fatalf("filler proposer is not seated at height %d", h)
			}
			a1AppendByEvery(t, cs, a1Build(t, cs[0], keys[0], nil))
			continue
		}

		// THE BLOCK: proposed by a key that is not in genesis, drawn by the
		// epoch committee, and offered to every validator's chain.
		b := a1Build(t, cs[0], joiner, nil)
		if !bytes.Equal(b.Header.Proposer, joinerPub) {
			t.Fatalf("the built block names proposer %x, want the joining key %x", b.Header.Proposer, joinerPub)
		}
		a1AppendByEvery(t, cs, b)
		if cs[0].Height() != h || !bytes.Equal(cs[0].Head().Header.Proposer, joinerPub) {
			t.Fatalf("head after appending height %d: height %d, proposer %x",
				h, cs[0].Height(), cs[0].Head().Header.Proposer)
		}
		t.Logf("height %d: the post-genesis seat was drawn, built, and every one of %d validators appended its block", h, len(cs))
		return
	}
	t.Fatalf("the joining key was not drawn as round-0 proposer in %d heights after the boundary", a1DrawWindow)
}

// TestACommitteeWithNoGenesisSeatsStillAppends pins the deadlock the audit
// names as the worst case: a committee whose genesis seats have ALL exited must
// still be able to append. applyUnbond permits a genesis seat's full exit (its
// unfunded bond is burned, which is the only exit a fixture-power seat can
// take), so the state below is reachable, not hypothetical.
func TestACommitteeWithNoGenesisSeatsStillAppends(t *testing.T) {
	g, keys, joiner := a1Genesis(t)
	joinerPub := joiner.Public().(ed25519.PublicKey)

	// The joining node's chain and one witness. The "every validator" half is
	// the test above; here the point is that no genesis seat remains to sign.
	cs := a1Open(t, g, 2)

	a1Bond(t, g, cs, keys[0], joiner)

	// Every genesis seat exits IN FULL, in one constructed block carried by a
	// still-seated genesis key. The exit is free and legal: genesis bonds are
	// unfunded, so their whole amount is destroyed rather than withdrawable.
	var exits []types.Tx
	for i := range keys {
		pub := keys[i].Public().(ed25519.PublicKey)
		exits = append(exits, a1Sign(g, keys[i], types.Tx{
			Type:   types.TxUnbond,
			From:   types.AddressFromPub(pub),
			PubKey: pub,
			Nonce:  0,
			Amount: g.Params.MinStakeSparks,
		}))
	}
	a1AppendByEvery(t, cs, a1Build(t, cs[0], keys[0], exits))

	// Cross the boundary that derives the next epoch from the state in which no
	// genesis bond exists. The genesis committee still judges these heights.
	for cs[0].Height() < a1EpochBlocks-1 {
		a1AppendByEvery(t, cs, a1Build(t, cs[0], keys[0], nil))
	}

	// Constructed, not assumed: no genesis bond is left, and the boundary's
	// committee is exactly the one post-genesis seat.
	for i := range keys {
		addr := types.AddressFromPub(keys[i].Public().(ed25519.PublicKey))
		if got := cs[0].State().Bonded(addr); got != 0 {
			t.Fatalf("genesis seat %d still bonds %d sparks after its full exit", i, got)
		}
	}
	vals, err := cs[0].CommitteeAt(a1EpochBlocks)
	if err != nil {
		t.Fatalf("CommitteeAt(%d): %v", a1EpochBlocks, err)
	}
	if len(vals) != 1 || !bytes.Equal(vals[0].PubKey, joinerPub) {
		t.Fatalf("the boundary committee is %v, want exactly the post-genesis key", vals)
	}

	// The draw from that one-seat committee is necessarily the joining key, so
	// the next block is the worst case: only a post-genesis seat may propose.
	drawn := consensus.Config{Committee: vals}.Proposer(a1EpochBlocks, 0, cs[0].Head().ID())
	if !bytes.Equal(drawn, joinerPub) {
		t.Fatalf("the one-seat committee drew %x, want the joining key %x", drawn, joinerPub)
	}
	b := a1Build(t, cs[0], joiner, nil)
	a1AppendByEvery(t, cs, b)
	if cs[0].Height() != a1EpochBlocks {
		t.Fatalf("height after the all-genesis-exited boundary = %d, want %d", cs[0].Height(), a1EpochBlocks)
	}
	t.Logf("height %d appended with a committee of one post-genesis seat and no genesis seat left", a1EpochBlocks)
}

// TestTheGenesisCommitteeIsTheEpochZeroCommittee is the equivalence the fix
// rests on, pinned rather than asserted in a comment: for a valid genesis the
// committee derived from the genesis state seats EXACTLY the genesis validator
// keys, so replacing the genesis membership test with the epoch-0 committee
// test cannot refuse a proposer epoch 0 used to accept. It also cannot accept a
// non-genesis key: the derivation's candidates are the genesis bonds.
func TestTheGenesisCommitteeIsTheEpochZeroCommittee(t *testing.T) {
	g, _, _ := a1Genesis(t)
	c, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	vals, err := c.CommitteeAt(0)
	if err != nil {
		t.Fatalf("CommitteeAt(0): %v", err)
	}
	if len(vals) != len(g.Validators) {
		t.Fatalf("epoch 0 seats %d keys, genesis lists %d", len(vals), len(g.Validators))
	}
	for _, v := range g.Validators {
		if genesis.SeatOfPubKey(vals, v.PubKey) < 0 {
			t.Fatalf("genesis key %x is not seated by the epoch-0 committee", v.PubKey)
		}
	}
	// And the predicate the append path now uses agrees at every epoch-0 height
	// the chain can judge.
	for _, v := range g.Validators {
		for h := uint64(1); h < g.Params.EpochBlocks; h++ {
			if !c.IsSeatedAt(h, v.PubKey) {
				t.Fatalf("genesis key %x is not seated at height %d", v.PubKey, h)
			}
		}
	}
	// A key that is in no genesis bond is not seated at epoch 0 either, so the
	// epoch-0 half of the new rule is not a widening.
	strangerPub, strangerPriv := a1Key("stranger")
	if c.IsSeatedAt(1, strangerPub) {
		t.Fatalf("a stranger key is seated at height 1")
	}
	b, err := c.Build(strangerPriv, nil, c.Head().Header.Timestamp+1)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := c.Append(b); !errors.Is(err, chain.ErrNotValidator) {
		t.Fatalf("a stranger proposer at height 1 = %v, want ErrNotValidator", err)
	}
}

// TestAOneBlockEpochChainAppendsItsFirstBlock pins the edge the suite's devnet
// test exposed once the proposer check became committee-based: with
// EpochBlocks == 1 every height is its own epoch, so the epoch that judges
// height 1 is decided by the state at height 0 - the genesis state - and no
// APPENDED block ever commits at height 0. Open must record that epoch, or the
// chain cannot judge (and so cannot append) its very first block.
func TestAOneBlockEpochChainAppendsItsFirstBlock(t *testing.T) {
	g, keys, _ := a1Genesis(t)
	g.Params.EpochBlocks = 1
	c, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	sameSeats := func(a, b []genesis.Validator) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if genesis.SeatOfPubKey(b, a[i].PubKey) < 0 {
				return false
			}
		}
		return true
	}
	// Epoch 1 is decided by the genesis state, exactly like epoch 0: same seats
	// from the same state, so the first block is judgeable before it exists.
	vals0, err := c.CommitteeAt(0)
	if err != nil {
		t.Fatalf("CommitteeAt(0): %v", err)
	}
	vals1, err := c.CommitteeAt(1)
	if err != nil {
		t.Fatalf("CommitteeAt(1) before the first block: %v", err)
	}
	if !sameSeats(vals0, vals1) {
		t.Fatalf("epoch 0 seats %v and epoch 1 seats %v differ, but both are decided by the genesis state", vals0, vals1)
	}
	b := a1Build(t, c, keys[0], nil)
	if err := c.Append(b); err != nil {
		t.Fatalf("a one-block-epoch chain refused its first block: %v", err)
	}
	// Height 2's epoch is decided by the state committed at height 1, which is
	// recorded when that block appended.
	if _, err := c.CommitteeAt(2); err != nil {
		t.Fatalf("CommitteeAt(2) after appending height 1: %v", err)
	}
}

// TestAProposerFromAnotherEpochIsRefused is the safety half of A-1: the rule
// must be the committee for THE BLOCK'S OWN HEIGHT, not "any committee that
// ever contained this key". A post-genesis seat unbonds; its seat ends at the
// boundary that follows the deciding state, so at the next epoch it is seated
// in the PREVIOUS epoch and in no current one. A block it proposes there must
// be refused. A check that read height-EpochBlocks (the epoch that used to seat
// it) would accept it; so would EverSeated. Both are the widening this rule is
// written to avoid, and this test is what catches them.
func TestAProposerFromAnotherEpochIsRefused(t *testing.T) {
	g, keys, joiner := a1Genesis(t)
	joinerPub := joiner.Public().(ed25519.PublicKey)
	joinerAddr := types.AddressFromPub(joinerPub)
	cs := a1Open(t, g, 2)

	a1Bond(t, g, cs, keys[0], joiner)
	for cs[0].Height() < a1EpochBlocks-1 {
		a1AppendByEvery(t, cs, a1Build(t, cs[0], keys[0], nil))
	}

	// The joining key leaves in full at height EPOCH: its bond is deleted from
	// the state, and the state at EPOCH-1 (in the NEXT epoch) is what decides
	// the epoch after that.
	unbond := a1Sign(g, joiner, types.Tx{
		Type:   types.TxUnbond,
		From:   joinerAddr,
		PubKey: joinerPub,
		Nonce:  1, // the Bond was nonce 0
		Amount: g.Params.MinStakeSparks,
	})
	a1AppendByEvery(t, cs, a1Build(t, cs[0], keys[0], []types.Tx{unbond}))
	for cs[0].Height() < 2*a1EpochBlocks-1 {
		a1AppendByEvery(t, cs, a1Build(t, cs[0], keys[0], nil))
	}

	// Constructed: the key IS seated for the whole epoch that just ended, and is
	// NOT seated at the height it is about to propose. The seat it held was
	// epoch 1 (heights EPOCH..2*EPOCH-1); the height under test is the first of
	// epoch 2.
	firstSeat := a1EpochBlocks
	lastSeat := 2*a1EpochBlocks - 1
	if !cs[0].IsSeatedAt(firstSeat, joinerPub) {
		t.Fatalf("the key is not seated at height %d, so the seat is not constructed", firstSeat)
	}
	if !cs[0].IsSeatedAt(lastSeat, joinerPub) {
		t.Fatalf("the key's seat did not cover height %d", lastSeat)
	}
	current := 2 * a1EpochBlocks
	if cs[0].IsSeatedAt(current, joinerPub) {
		t.Fatalf("the key is still seated at height %d; the unbond did not end its seat", current)
	}
	vals, err := cs[0].CommitteeAt(current)
	if err != nil {
		t.Fatalf("CommitteeAt(%d): %v", current, err)
	}
	if genesis.SeatOfPubKey(vals, joinerPub) >= 0 {
		t.Fatalf("the committee at height %d seats the rotated-out key", current)
	}

	// The block is otherwise perfectly valid: right parent, right height, a
	// correct state root and a valid signature. Only the seat check may refuse
	// it, which is what makes this a test of the seat rule.
	b := a1Build(t, cs[0], joiner, nil)
	if err := cs[0].Append(b); !errors.Is(err, chain.ErrNotValidator) {
		t.Fatalf("a proposer seated in the PREVIOUS epoch, proposing at height %d = %v, want ErrNotValidator",
			current, err)
	}

	// And the height is not deadlocked: a current seat can still append.
	a1AppendByEvery(t, cs, a1Build(t, cs[0], keys[0], nil))
	if cs[0].Height() != current {
		t.Fatalf("height after the seated proposer's block = %d, want %d", cs[0].Height(), current)
	}
}

// TestAPostGenesisProposedBlockSurvivesReopenAndAFurtherAppend is A-1's replay
// path, section 6 item 8. The proposer rule reads the epoch committee, and
// Open rebuilds every committee from the replayed blocks; this test constructs a
// post-genesis-proposed block, closes the directory, reopens it, and appends
// ANOTHER block over it. The append after the reopen is the load-bearing half:
// it fails unless replay rebuilt the same seats at the same deciding heights.
//
// The committee is a single post-genesis seat, so the next proposer is
// necessarily the joiner - no genesis key is left to fill the height for it.
func TestAPostGenesisProposedBlockSurvivesReopenAndAFurtherAppend(t *testing.T) {
	g, keys, joiner := a1Genesis(t)
	joinerPub := joiner.Public().(ed25519.PublicKey)
	dir := t.TempDir()
	c, err := chain.Open(g, dir)
	if err != nil {
		t.Fatalf("opening the fixture chain: %v", err)
	}
	appendTo := func(c *chain.Chain, priv ed25519.PrivateKey, txs []types.Tx) *types.Block {
		t.Helper()
		b := a1Build(t, c, priv, txs)
		if err := c.Append(b); err != nil {
			t.Fatalf("appending height %d: %v", b.Header.Height, err)
		}
		return b
	}

	// Height 1 seats the joiner; height 2 exits every genesis bond in full;
	// height 3 commits the state that decides epoch 1. That state holds the
	// joiner's bond and nothing else.
	bond := a1Sign(g, joiner, types.Tx{
		Type:   types.TxBond,
		From:   types.AddressFromPub(joinerPub),
		PubKey: joinerPub,
		Nonce:  0,
		Amount: g.Params.MinStakeSparks,
		Fee:    g.Params.MinFeeSparks,
	})
	appendTo(c, keys[0], []types.Tx{bond})
	var exits []types.Tx
	for i := range keys {
		pub := keys[i].Public().(ed25519.PublicKey)
		exits = append(exits, a1Sign(g, keys[i], types.Tx{
			Type:   types.TxUnbond,
			From:   types.AddressFromPub(pub),
			PubKey: pub,
			Nonce:  0,
			Amount: g.Params.MinStakeSparks,
		}))
	}
	appendTo(c, keys[0], exits)
	appendTo(c, keys[0], nil)

	vals, err := c.CommitteeAt(a1EpochBlocks)
	if err != nil || len(vals) != 1 || !bytes.Equal(vals[0].PubKey, joinerPub) {
		t.Fatalf("fixture: the epoch-1 committee is %v (%v), want exactly the post-genesis key", vals, err)
	}

	// Height 4: the first block only a post-genesis seat may propose.
	first := appendTo(c, joiner, nil)
	if !bytes.Equal(first.Header.Proposer, joinerPub) {
		t.Fatalf("the block at height %d names proposer %x, want the joining key %x", first.Header.Height, first.Header.Proposer, joinerPub)
	}
	heightBefore, idBefore, rootBefore := c.Height(), c.Head().ID(), c.State().Root()
	if err := c.Close(); err != nil {
		t.Fatalf("closing before the reopen: %v", err)
	}

	// REOPEN: replay must rebuild the epoch-1 committee that admitted height 4.
	c2, err := chain.Open(g, dir)
	if err != nil {
		t.Fatalf("reopening after a post-genesis-proposed block: %v", err)
	}
	defer c2.Close()
	if got := c2.Height(); got != heightBefore {
		t.Fatalf("reopened at height %d, want %d", got, heightBefore)
	}
	if got := c2.Head().ID(); got != idBefore {
		t.Fatalf("reopened at head %x, want %x", got, idBefore)
	}
	if got := c2.State().Root(); got != rootBefore {
		t.Fatalf("reopened at root %x, want %x", got, rootBefore)
	}
	next := heightBefore + 1
	if !c2.IsSeatedAt(next, joinerPub) {
		t.Fatalf("after reopening, the post-genesis seat is not seated at height %d: replay did not rebuild the committee", next)
	}
	if !c2.EverSeated(joinerPub) {
		t.Fatal("after reopening, the post-genesis seat has no ever-seated record")
	}

	// AND A FURTHER APPEND over the replayed committee.
	second := appendTo(c2, joiner, nil)
	if got := c2.Height(); got != next {
		t.Fatalf("height after appending over the reopened chain = %d, want %d", got, next)
	}
	if !bytes.Equal(second.Header.Proposer, joinerPub) {
		t.Fatalf("the block after the reopen names proposer %x, want the post-genesis key %x", second.Header.Proposer, joinerPub)
	}
}
