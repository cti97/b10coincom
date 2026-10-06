package chain

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/store"
	"github.com/cti97/b10coincom/internal/types"
)

// devChain opens a chain plus the devnet validator's private key.
func devChain(t *testing.T) (*Chain, ed25519.PrivateKey) {
	t.Helper()
	g := genesis.Devnet()
	// devKey never errors: it returns a deterministic devnet key.
	_, priv := devKey()
	c, err := Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, priv
}

func TestGenesisBlockIsCreatedAtOpen(t *testing.T) {
	c, _ := devChain(t)
	if c.Height() != 0 {
		t.Fatalf("fresh chain height = %d, want 0", c.Height())
	}
	if c.Head().Header.ParentHash != ([32]byte{}) {
		t.Fatal("genesis parent hash must be all zeros")
	}
}

// Devnet genesis funds accounts, so the genesis state root must not be the
// empty root.
func TestDevnetGenesisStateIsNotEmpty(t *testing.T) {
	c, _ := devChain(t)
	if c.Head().Header.StateRoot == ([32]byte{}) {
		t.Fatal("devnet genesis state root is empty; dev accounts were not applied")
	}
}

func TestBuildAndAppendAdvancesChain(t *testing.T) {
	c, priv := devChain(t)

	b, err := c.Build(priv, nil, 1_700_000_100)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if b.Header.Height != 1 {
		t.Fatalf("built height %d, want 1", b.Header.Height)
	}
	if err := c.Append(b); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if c.Height() != 1 {
		t.Fatalf("height after append = %d, want 1", c.Height())
	}
	if c.Head().ID() != b.ID() {
		t.Fatal("head is not the appended block")
	}
}

func TestAppendRejectsWrongParent(t *testing.T) {
	c, priv := devChain(t)
	b, _ := c.Build(priv, nil, 1_700_000_100)
	b.Header.ParentHash = crypto.HashParts([]byte("not-the-parent"))
	if err := c.Append(b); !errors.Is(err, ErrBadParent) {
		t.Fatalf("expected ErrBadParent, got %v", err)
	}
}

func TestAppendRejectsWrongHeight(t *testing.T) {
	c, priv := devChain(t)
	b, _ := c.Build(priv, nil, 1_700_000_100)
	b.Header.Height = 7
	if err := c.Append(b); !errors.Is(err, ErrBadHeight) {
		t.Fatalf("expected ErrBadHeight, got %v", err)
	}
}

// A tampered state root must be caught: this is the check that stops a node
// from silently accepting a block that claims a state it did not compute.
//
// The proposer signature covers the whole header, so tampering the root
// invalidates the block's original signature and Append would reject on
// ErrBadProposerSig before the state-root check is ever reached. The tamper
// is therefore re-signed with the same validator key: what is under test is
// a validator that signs a root it did not compute, and the rejection must
// name the state root, not the signature.
func TestAppendRejectsTamperedStateRoot(t *testing.T) {
	c, priv := devChain(t)
	b, _ := c.Build(priv, nil, 1_700_000_100)
	b.Header.StateRoot = crypto.HashParts([]byte("fabricated"))
	headerHash := b.Header.SigningHash()
	b.Sig = crypto.Sign(priv, headerHash[:])
	if err := c.Append(b); !errors.Is(err, ErrBadStateRoot) {
		t.Fatalf("expected ErrBadStateRoot, got %v", err)
	}
}

func TestAppendRejectsUnsignedOrForgedHeader(t *testing.T) {
	c, priv := devChain(t)
	b, _ := c.Build(priv, nil, 1_700_000_100)
	b.Sig = nil
	if err := c.Append(b); !errors.Is(err, ErrBadProposerSig) {
		t.Fatalf("expected ErrBadProposerSig, got %v", err)
	}
}

// A block whose header was altered after signing must be rejected by the
// signature check ITSELF. This is the only test that reaches crypto.Verify in
// Append: TestAppendRejectsUnsignedOrForgedHeader only clears Sig, which the
// nil check catches first, so deleting the verification call left the whole
// suite green.
func TestAppendRejectsForgedSignature(t *testing.T) {
	c, priv := devChain(t)
	b, err := c.Build(priv, nil, 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate a signed header field WITHOUT re-signing. The timestamp stays
	// positive so ValidateStructure still passes, and parent, height and
	// validator membership are unaffected, so only the signature check can
	// reject this.
	b.Header.Timestamp = 1_700_000_101
	if err := c.Append(b); !errors.Is(err, ErrBadProposerSig) {
		t.Fatalf("expected ErrBadProposerSig, got %v", err)
	}
}

func TestAppendRejectsNonValidatorProposer(t *testing.T) {
	c, _ := devChain(t)
	_, otherPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Build(otherPriv, nil, 1_700_000_100)
	if err != nil {
		t.Fatalf("Build must not validate the proposer: %v", err)
	}
	if err := c.Append(b); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("expected ErrNotValidator, got %v", err)
	}
}

// A genesis with no validators cannot advance: every proposer is rejected.
// This is what makes a validator-less testnet genesis safe rather than broken.
func TestChainWithoutValidatorsCannotAdvance(t *testing.T) {
	c, err := Open(genesis.Testnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_, priv := genesis.DevValidatorKey()
	b, err := c.Build(priv, nil, 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append(b); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("expected ErrNotValidator, got %v", err)
	}
}

// Replay is the core durability guarantee: reopen from disk and confirm the
// recomputed state root matches the stored header.
//
// The blocks carry REAL signed transfers, so replay must re-derive
// transaction effects rather than re-load empty blocks: the final state root
// must differ from the genesis root (value actually moved), yet still equal
// the stored head header's root (replay recomputed exactly what was stored).
// Fixed timestamps and deterministic keys keep the whole sequence
// reproducible.
func TestReplayRebuildsIdenticalState(t *testing.T) {
	dir := t.TempDir()
	g := genesis.Devnet()
	_, priv := devKey()

	fromPub := g.DevAccounts[0].PubKey
	toPub := g.DevAccounts[1].PubKey
	from := types.AddressFromPub(fromPub)
	to := types.AddressFromPub(toPub)
	// The devnet validator key is not the dev account key, so txs are
	// signed with the dev account's deterministic key.
	devPriv := devPrivateKey(t)

	c, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	genesisRoot := c.State().Root()

	var roots [][32]byte
	for h := 1; h <= 5; h++ {
		// Block h pays h b10 from dev account 0 to dev account 1. The
		// nonce is the account's current replay counter, so each block's
		// transfer chains onto the previous one's effect.
		tx := &types.Tx{
			Type:   types.TxTransfer,
			From:   from,
			PubKey: fromPub,
			Nonce:  c.State().Get(from).Nonce,
			Fee:    g.Params.MinFeeSparks,
			To:     to,
			Amount: uint64(h) * genesis.SparksPerB10,
		}
		sigHash := tx.SigningHash(c.Genesis().Hash())
		tx.Sig = crypto.Sign(devPriv, sigHash[:])

		b, err := c.Build(priv, []types.Tx{*tx}, int64(1_700_000_000+h))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, b.Header.StateRoot)
	}
	headID := c.Head().ID()
	c.Close()

	c2, err := Open(g, dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer c2.Close()

	if c2.Height() != 5 {
		t.Fatalf("replayed height = %d, want 5", c2.Height())
	}
	if c2.Head().ID() != headID {
		t.Fatal("replayed head differs from the stored head")
	}
	if c2.State().Root() != roots[len(roots)-1] {
		t.Fatal("replayed state root differs from the stored header")
	}
	// Without this the test could pass with blocks that carry no txs at
	// all: the root-differs assertion is what proves replay re-derived
	// transaction effects from the stored blocks.
	if c2.State().Root() == genesisRoot {
		t.Fatal("replayed state root equals the genesis root after five real transfers; replay did not re-derive transaction effects")
	}
}

func TestTransferThroughChainChangesBalances(t *testing.T) {
	c, priv := devChain(t)

	g := c.Genesis()
	fromPub := g.DevAccounts[0].PubKey
	toPub := g.DevAccounts[1].PubKey
	from := types.AddressFromPub(fromPub)
	to := types.AddressFromPub(toPub)

	startFrom := c.State().Get(from).Balance
	startTo := c.State().Get(to).Balance

	// The devnet validator key is not the dev account key, so sign with the
	// dev account's deterministic key.
	devPriv := devPrivateKey(t)

	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  0,
		Fee:    c.Genesis().Params.MinFeeSparks,
		To:     to,
		Amount: 250 * genesis.SparksPerB10,
	}
	sigHash := tx.SigningHash(c.Genesis().Hash())
	tx.Sig = crypto.Sign(devPriv, sigHash[:])

	b, err := c.Build(priv, []types.Tx{*tx}, 1_700_000_100)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := c.Append(b); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// The sender pays the amount AND the fee (audit S-3); the fee is burned, so
	// it leaves the supply entirely and never reaches the recipient.
	fee := c.Genesis().Params.MinFeeSparks
	if got := c.State().Get(from).Balance; got != startFrom-250*genesis.SparksPerB10-fee {
		t.Fatalf("sender balance = %d, want %d (amount plus the burned fee %d)", got, startFrom-250*genesis.SparksPerB10-fee, fee)
	}
	if got := c.State().Get(to).Balance; got != startTo+250*genesis.SparksPerB10 {
		t.Fatalf("recipient balance = %d, want %d", got, startTo+250*genesis.SparksPerB10)
	}
}

// Total supply must change across a block by EXACTLY the block's emission minus
// the fees the block's transactions paid: a transfer still creates nothing, and
// since audit S-3 it DESTROYS its fee (the fee is burned - the protocol has no
// proposer-reward rule yet). The delta is still fully accounted for, which is
// the point: nothing minted or destroyed can go unaccounted.)
func TestTotalSupplyChangesOnlyByTheBlockEmission(t *testing.T) {
	c, priv := devChain(t)
	before := c.State().TotalBalance()
	if before == 0 {
		t.Fatal("devnet should start with funds")
	}

	g := c.Genesis()
	fromPub := g.DevAccounts[0].PubKey
	toPub := g.DevAccounts[1].PubKey
	from := types.AddressFromPub(fromPub)

	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  c.State().Get(from).Nonce,
		Fee:    c.Genesis().Params.MinFeeSparks,
		To:     types.AddressFromPub(toPub),
		Amount: 123 * genesis.SparksPerB10,
	}
	sigHash := tx.SigningHash(c.Genesis().Hash())
	tx.Sig = crypto.Sign(devPrivateKey(t), sigHash[:])

	b, err := c.Build(priv, []types.Tx{*tx}, 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append(b); err != nil {
		t.Fatal(err)
	}
	want := before +
		faucet.Reward(b.Header.Height, g.Params.InitialRewardSparks, g.Params.HalvingIntervalBlocks) -
		c.Genesis().Params.MinFeeSparks
	if got := c.State().TotalBalance(); got != want {
		t.Fatalf("total supply = %d, want %d (before %d plus one block's emission minus the burned fee)",
			got, want, before)
	}
}

func TestBlockAtReadsHistoricalBlocks(t *testing.T) {
	c, priv := devChain(t)
	for h := 1; h <= 3; h++ {
		b, err := c.Build(priv, nil, int64(1_700_000_000+h))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	for h := uint64(0); h <= 3; h++ {
		b, err := c.BlockAt(h)
		if err != nil {
			t.Fatalf("BlockAt(%d): %v", h, err)
		}
		if b.Header.Height != h {
			t.Fatalf("BlockAt(%d) returned height %d", h, b.Header.Height)
		}
	}
	if _, err := c.BlockAt(4); err == nil {
		t.Fatal("BlockAt beyond head must fail")
	}
}

func devKey() (ed25519.PublicKey, ed25519.PrivateKey) { return genesis.DevValidatorKey() }

// The store indexes segments by RECORD COUNT, so a lost or rewritten segment
// would silently renumber every stored block: replay must refuse to apply a
// stored block whose own header (height, parent link) does not match its
// position. Rewriting the segment here drops the FIRST record, shifting every
// remaining block one slot down — the renumbering a lost segment induces.
// All blocks were built without transactions, so the pre-fix state-root check
// alone would pass across the renumbered chain; the height/link check is what
// catches this, and Open must fail with ErrGenesisReplay rather than succeed.
func TestOpenRejectsRenumberedStoredChain(t *testing.T) {
	dir := t.TempDir()
	g := genesis.Devnet()
	_, priv := devKey()

	c, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	for h := 1; h <= 3; h++ {
		b, err := c.Build(priv, nil, int64(1_700_000_000+h))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	// Skip record 1 entirely: framed header (length || its checksum), payload,
	// trailer checksum. The segment header is NOT part of the record and stays
	// (it is the format marker, and without it Open would refuse the file as an
	// unrecognised format instead of reaching the replay that this test is
	// about).
	recLen := binary.BigEndian.Uint64(raw[store.SegmentHeaderLen:])
	span := store.SegmentHeaderLen + store.RecordHeaderLen + int(recLen) + store.RecordTrailerLen
	if len(raw) < span {
		t.Fatalf("malformed first record in %s; cannot drop it", seg)
	}
	kept := append(append([]byte(nil), raw[:store.SegmentHeaderLen]...), raw[span:]...)
	if err := os.WriteFile(seg, kept, 0o644); err != nil {
		t.Fatal(err)
	}

	c2, err := Open(g, dir)
	if err == nil {
		c2.Close()
		t.Fatal("Open succeeded on a renumbered chain — the stored bytes no longer support the reported heights")
	}
	if !errors.Is(err, ErrGenesisReplay) {
		t.Fatalf("Open = %v, want an error wrapping ErrGenesisReplay", err)
	}
}

func devPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv := genesis.DevAccountKey(0)
	return priv
}

// Emission must be credited exactly once per height, and only once - a second
// application would inflate the supply.
func TestEmissionIsCreditedOncePerBlock(t *testing.T) {
	c, priv := devChain(t)
	faucetAddr := c.Genesis().FaucetAddress()

	genesisBalance := c.State().Get(faucetAddr).Balance
	if want := faucet.Reward(0, c.Genesis().Params.InitialRewardSparks, c.Genesis().Params.HalvingIntervalBlocks); genesisBalance != want {
		t.Fatalf("genesis faucet balance = %d, want the height-0 reward %d", genesisBalance, want)
	}
	for h := uint64(1); h <= 3; h++ {
		before := c.State().Get(faucetAddr).Balance
		b, err := c.Build(priv, nil, int64(1_700_000_000+h))
		if err != nil {
			t.Fatal(err)
		}
		// Build must NOT mutate the chain; the faucet moves only on Append.
		if c.State().Get(faucetAddr).Balance != before {
			t.Fatal("Build mutated the chain's state")
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
		want := before + faucet.Reward(h, c.Genesis().Params.InitialRewardSparks, c.Genesis().Params.HalvingIntervalBlocks)
		if got := c.State().Get(faucetAddr).Balance; got != want {
			t.Fatalf("faucet balance after block %d = %d, want %d", h, got, want)
		}
	}
}

// A claim INSIDE block h may spend block h's emission: advanceLocked credits
// the emission BEFORE applying the block's transactions (plan Decision 3).
// The claim amount here exceeds everything the faucet holds BEFORE block 1's
// emission (the 50M genesis mint) but fits what it holds AFTER it, so only
// the emission-before-transactions ordering can pay this claim; applied in
// the other order the claim fails ErrFaucetEmpty.
func TestClaimMaySpendTheBlocksOwnEmission(t *testing.T) {
	g := *genesis.Devnet()
	g.Params.ClaimAmountSparks = 60_000_000 // genesis mint is 50M; only block 1's own emission covers the rest
	c, err := Open(&g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	pub, key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pow, ok := faucet.Solve(pub, 1, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, 1_000_000)
	if !ok {
		t.Fatal("could not solve the test puzzle")
	}
	tx := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: 0, Epoch: 1, PowNonce: pow}
	sigHash := tx.SigningHash(c.Genesis().Hash())
	tx.Sig = crypto.Sign(key, sigHash[:])

	b, err := c.Build(priv, []types.Tx{*tx}, 1_700_000_100)
	if err != nil {
		t.Fatalf("the emission must be credited before block 1's transactions: %v", err)
	}
	if err := c.Append(b); err != nil {
		t.Fatal(err)
	}
	if got := c.State().Get(types.AddressFromPub(pub)).Balance; got != g.Params.ClaimAmountSparks {
		t.Fatalf("claimant balance = %d, want %d", got, g.Params.ClaimAmountSparks)
	}
	// 50M genesis mint + 50M block-1 emission - the 60M claim.
	if got := c.State().Get(g.FaucetAddress()).Balance; got != 100_000_000-g.Params.ClaimAmountSparks {
		t.Fatalf("faucet balance = %d, want %d", got, 100_000_000-g.Params.ClaimAmountSparks)
	}
}

// The claim rule's epoch derives from the height advanceLocked sets on the
// state (execution context, plan Decision 9a). Under EpochBlocks = 2, block 2
// is the first block of epoch 2, so a claim carrying epoch 2 must verify
// there. Without the SetHeight call the transition's state would still carry
// the genesis state's zero height (epoch 1) and Build would reject this claim
// instead.
func TestClaimVerifiesTheCurrentEpochThroughTheTransition(t *testing.T) {
	g := *genesis.Devnet()
	g.Params.EpochBlocks = 2         // block 2 opens epoch 2
	g.Params.ClaimAmountSparks = 100 // small: the emission already banked covers it
	c, err := Open(&g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	// Block 1 opens epoch 1; nothing claims in it.
	b1, err := c.Build(priv, nil, 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append(b1); err != nil {
		t.Fatal(err)
	}

	pub, key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	claimant := types.AddressFromPub(pub)
	pow, ok := faucet.Solve(pub, 2, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, 1_000_000)
	if !ok {
		t.Fatal("could not solve the test puzzle")
	}
	tx := &types.Tx{Type: types.TxFaucetClaim, From: claimant, PubKey: pub,
		Nonce: 0, Epoch: 2, PowNonce: pow}
	sigHash := tx.SigningHash(c.Genesis().Hash())
	tx.Sig = crypto.Sign(key, sigHash[:])

	b2, err := c.Build(priv, []types.Tx{*tx}, 1_700_000_101)
	if err != nil {
		t.Fatalf("a claim for block 2's epoch must verify inside block 2: %v", err)
	}
	if err := c.Append(b2); err != nil {
		t.Fatal(err)
	}
	if got := c.State().Get(claimant).Balance; got != g.Params.ClaimAmountSparks {
		t.Fatalf("claimant balance = %d, want %d", got, g.Params.ClaimAmountSparks)
	}
	if got := c.State().Get(claimant).ClaimedEpoch; got != 2 {
		t.Fatalf("claim marker = %d, want 2", got)
	}
}

// Probe must run the SAME transition a block at head+1 runs — height set,
// emission credited, transactions applied — without persisting anything. The
// claim below is payable ONLY after block 1's emission is credited (the
// genesis mint of 50M is below the devnet's 100M claim amount), so a probe
// that skipped the emission would refuse to apply it and RunOnce would evict
// a valid claim. The unchanged-height/root assertions are what catch a probe
// that quietly advanced the chain.
func TestProbeMirrorsTheBlockTransition(t *testing.T) {
	c, priv := devChain(t)
	g := c.Genesis()

	pub, key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pow, ok := faucet.Solve(pub, 1, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, 1_000_000)
	if !ok {
		t.Fatal("could not solve the test puzzle")
	}
	claim := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: 0, Epoch: 1, PowNonce: pow}
	sigHash := claim.SigningHash(c.Genesis().Hash())
	claim.Sig = crypto.Sign(key, sigHash[:])

	// Fixture guard: the claim must NEED the block's own emission, or this
	// test can no longer distinguish the mirrored probe from the old
	// head-clone probe.
	faucetBefore := c.State().Get(g.FaucetAddress()).Balance
	if faucetBefore >= g.Params.ClaimAmountSparks {
		t.Fatalf("fixture error: the faucet already holds %d; this claim no longer needs block 1's emission", faucetBefore)
	}

	head := c.Head()
	beforeRoot := c.State().Root()

	probed, err := c.Probe([]types.Tx{*claim})
	if err != nil {
		t.Fatalf("the probe skipped the transition a block at head+1 runs: %v", err)
	}
	if c.Height() != head.Header.Height {
		t.Fatalf("Probe advanced the chain to height %d", c.Height())
	}
	if c.State().Root() != beforeRoot {
		t.Fatal("Probe mutated the chain's committed state")
	}
	if got := probed.Get(types.AddressFromPub(pub)).Balance; got != g.Params.ClaimAmountSparks {
		t.Fatalf("probed claimant balance = %d, want %d", got, g.Params.ClaimAmountSparks)
	}

	// The mirror property: appending the probed transactions for real must
	// reach exactly the root the probe reported.
	b, err := c.Build(priv, []types.Tx{*claim}, 1_700_000_100)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := c.Append(b); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if c.State().Root() != probed.Root() {
		t.Fatalf("the probe diverged from Append:\n probe  %x\n append %x", probed.Root(), c.State().Root())
	}
}

// Probe derives its epoch from the NEXT block's height, not the head's: the
// claim below carries block 2's epoch (EpochBlocks = 2), which the transition
// at head+1 = 2 accepts. A probe that used the head's height would refuse it
// with ErrWrongEpoch and evict a valid claim from RunOnce's filter.
func TestProbeUsesTheNextBlocksEpoch(t *testing.T) {
	g := *genesis.Devnet()
	g.Params.EpochBlocks = 2         // block 2 opens epoch 2
	g.Params.ClaimAmountSparks = 100 // small: the banked emission already covers it
	c, err := Open(&g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	// Block 1 is empty; the head's execution context stays at epoch 1.
	b1, err := c.Build(priv, nil, 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append(b1); err != nil {
		t.Fatal(err)
	}

	pub, key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pow, ok := faucet.Solve(pub, 2, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, 1_000_000)
	if !ok {
		t.Fatal("could not solve the test puzzle")
	}
	claim := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(pub), PubKey: pub,
		Nonce: 0, Epoch: 2, PowNonce: pow}
	sigHash := claim.SigningHash(c.Genesis().Hash())
	claim.Sig = crypto.Sign(key, sigHash[:])

	probed, err := c.Probe([]types.Tx{*claim})
	if err != nil {
		t.Fatalf("a claim for block 2's epoch must survive a probe at head+1: %v", err)
	}
	if got := probed.Get(types.AddressFromPub(pub)).Balance; got != g.Params.ClaimAmountSparks {
		t.Fatalf("probed claimant balance = %d, want %d", got, g.Params.ClaimAmountSparks)
	}

	// And appending the same claim for real reaches the probed root.
	b2, err := c.Build(priv, []types.Tx{*claim}, 1_700_000_101)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := c.Append(b2); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if c.State().Root() != probed.Root() {
		t.Fatalf("the probe diverged from Append:\n probe  %x\n append %x", probed.Root(), c.State().Root())
	}
}

// Replay must reproduce emission, or a restarted node diverges.
func TestReplayReproducesEmission(t *testing.T) {
	dir := t.TempDir()
	g := genesis.Devnet()
	_, priv := genesis.DevValidatorKey()

	c, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	for h := uint64(1); h <= 4; h++ {
		b, err := c.Build(priv, nil, int64(1_700_000_000+h))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	faucetAddr := g.FaucetAddress()
	wantBalance := c.State().Get(faucetAddr).Balance
	// Fixture guard: without emission there is nothing to reproduce and the
	// replay comparison below would be vacuous (both sides would agree on a
	// zero balance). Four blocks of live emission must have been credited
	// before the restart, ON TOP of the genesis mint, for the comparison to
	// mean anything.
	genesisMint := faucet.Reward(0, g.Params.InitialRewardSparks, g.Params.HalvingIntervalBlocks)
	if wantBalance == 0 || wantBalance == genesisMint {
		t.Fatalf("fixture error: pre-restart faucet balance %d carries no block emission; the replay comparison would be vacuous", wantBalance)
	}
	wantRoot := c.State().Root()
	wantHead := c.Head().ID()
	c.Close()

	c2, err := Open(g, dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer c2.Close()

	if got := c2.State().Get(faucetAddr).Balance; got != wantBalance {
		t.Fatalf("replayed faucet balance = %d, want %d - replay did not reproduce emission", got, wantBalance)
	}
	if got := c2.State().Root(); got != wantRoot {
		t.Fatalf("replayed state root diverged:\n got %x\nwant %x", got, wantRoot)
	}
	if got := c2.Head().ID(); got != wantHead {
		t.Fatal("replayed head differs from the stored head")
	}
}

// The per-block claim bound is consensus only where it is WIRED into real
// chains. state.ApplyBlock enforces MaxClaimsPerBlock, but only against states
// it is handed; the single connection to chains a caller can run is the
// MaxClaimsPerBlock line in genesisState (chain.go). This test walks the
// caller's path - Open a chain from a genesis whose bound is K, then Build AND
// Append a block carrying K+1 genuinely valid claims - and demands the CHAIN
// rejects it with state.ErrTooManyClaims. Deleting the genesisState wiring
// line still compiles: the state layer keeps its hand-made-state tests, every
// real chain silently runs with bound 0 ("not engaged"), and the over-bound
// block below is accepted instead. Only this test goes red, which is exactly
// the silent inertness it exists to make loud.
func TestChainRejectsABlockOverTheGenesisClaimBound(t *testing.T) {
	// An explicit bound, not the shared 8: a small fixture, and proof that the
	// enforced bound is the genesis PARAMETER rather than any constant.
	g := *genesis.Devnet()
	g.Params.MaxClaimsPerBlock = 2
	// Small claim amount: every claim below is individually payable, so the
	// bound is the ONLY thing in the transition that can reject the block.
	g.Params.ClaimAmountSparks = 100
	bound := g.Params.MaxClaimsPerBlock
	c, err := Open(&g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	valPub, valPriv := genesis.DevValidatorKey()

	// bound+1 claims from bound+1 distinct fresh keys, each with a genuine
	// signature and a genuine puzzle for epoch 1 (block 1 at the devnet's
	// EpochBlocks). Nothing about them is invalid except their NUMBER.
	txs := make([]types.Tx, 0, bound+1)
	for i := uint64(0); i <= bound; i++ {
		claimantPub, key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		pow, ok := faucet.Solve(claimantPub, 1, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, 1_000_000)
		if !ok {
			t.Fatalf("claim %d: could not solve the devnet puzzle", i)
		}
		tx := &types.Tx{Type: types.TxFaucetClaim, From: types.AddressFromPub(claimantPub), PubKey: claimantPub,
			Nonce: 0, Epoch: 1, PowNonce: pow}
		sigHash := tx.SigningHash(c.Genesis().Hash())
		tx.Sig = crypto.Sign(key, sigHash[:])
		txs = append(txs, *tx)
	}

	// Fixture guard: the faucet (genesis mint plus block 1's emission, credited
	// by the transition) must be able to pay every claim individually. Without
	// it, a deleted wiring line could fail below on ErrFaucetEmpty instead of
	// demonstrating acceptance, and the mutant proof would rest on the wrong
	// error.
	faucetAddress := g.FaucetAddress()
	if got := c.State().Get(faucetAddress).Balance; got < (bound+1)*g.Params.ClaimAmountSparks {
		t.Fatalf("fixture error: faucet holds %d, needs to cover %d claims of %d each",
			got, bound+1, g.Params.ClaimAmountSparks)
	}

	// The honest proposer's path: Build runs the same transition Append runs
	// (advanceLocked -> state.ApplyBlock) and must stop the over-bound block
	// before it exists. Build returns no block on rejection, so the rejection
	// here leaves nothing to Append - the hostile path below covers Append.
	b, err := c.Build(valPriv, txs, 1_700_000_100)
	switch {
	case errors.Is(err, state.ErrTooManyClaims):
		// The bound fired: this is the whole test.
	case err == nil:
		// Concrete acceptance, so an unwired bound fails THIS test with a
		// message naming the inertness rather than a bare "no error".
		if err := c.Append(b); err != nil {
			t.Fatalf("the over-bound block built, but could not append: %v", err)
		}
		t.Fatalf("a block carrying %d claims against a genesis bound of %d was ACCEPTED through Build+Append (chain now at height %d) - the claim bound is not wired into the chain (genesisState's MaxClaimsPerBlock line)",
			len(txs), bound, c.Height())
	default:
		t.Fatalf("expected state.ErrTooManyClaims for %d claims against a genesis bound of %d, got %v",
			len(txs), bound, err)
	}

	// The validator's path: a hostile proposer can still hand every validator a
	// structurally valid, correctly signed block over the SAME over-bound
	// claims, claiming whatever root it likes. Append must reject it at the
	// count check - which state.ApplyBlock runs BEFORE any transaction is even
	// verified, so the fabricated root below is never reached - and not accept
	// the block or fail on anything else.
	hostile := &types.Block{
		Header: types.Header{
			Height:     c.Height() + 1,
			ParentHash: c.Head().ID(),
			StateRoot:  [32]byte{}, // fabricated; the count check must fire first
			TxRoot:     types.ComputeTxRoot(txs),
			Timestamp:  1_700_000_101,
			Proposer:   valPub,
		},
		Txs: txs,
	}
	headerHash := hostile.Header.SigningHash()
	hostile.Sig = crypto.Sign(valPriv, headerHash[:])
	if err := c.Append(hostile); !errors.Is(err, state.ErrTooManyClaims) {
		t.Fatalf("Append must reject an over-bound block at the count check, got %v", err)
	}
}

// Only CLAIMS count against the per-block bound. A mutant that counts every
// transaction as a claim survives the suite: it would reject any block
// carrying more than the bound transfers. This pins the count to
// types.TxFaucetClaim specifically through the chain path - more ordinary
// transfers than the genesis bound, zero claims, and the block must be
// accepted.
func TestTransfersDoNotCountAgainstTheClaimBound(t *testing.T) {
	c, priv := devChain(t)
	g := c.Genesis()
	bound := g.Params.MaxClaimsPerBlock
	// More ordinary transfers than the bound: only the tx TYPE can still let
	// this block through.
	n := int(bound) + 4

	fromPub := g.DevAccounts[0].PubKey
	from := types.AddressFromPub(fromPub)
	to := types.AddressFromPub(g.DevAccounts[1].PubKey)
	devPriv := devPrivateKey(t)

	txs := make([]types.Tx, 0, n)
	for i := 0; i < n; i++ {
		tx := &types.Tx{
			Type:   types.TxTransfer,
			From:   from,
			PubKey: fromPub,
			Nonce:  uint64(i),
			Fee:    g.Params.MinFeeSparks,
			To:     to,
			Amount: 1,
		}
		sigHash := tx.SigningHash(c.Genesis().Hash())
		tx.Sig = crypto.Sign(devPriv, sigHash[:])
		txs = append(txs, *tx)
	}

	// Fixture guard: this block must exceed the bound, or the test stops
	// distinguishing "only claims count" from "transactions count".
	if len(txs) <= int(bound) {
		t.Fatalf("fixture error: %d transfers do not exceed the genesis bound of %d", len(txs), bound)
	}

	b, err := c.Build(priv, txs, 1_700_000_100)
	if err != nil {
		t.Fatalf("a block of %d transfers with zero claims must build under a genesis bound of %d: %v",
			len(txs), bound, err)
	}
	if err := c.Append(b); err != nil {
		t.Fatalf("a block of %d transfers with zero claims must append under a genesis bound of %d: %v",
			len(txs), bound, err)
	}
	if c.Height() != 1 {
		t.Fatalf("height after the transfers-only block = %d, want 1", c.Height())
	}
}

// ---- Pre-vote block validation (audit C-1) ----
//
// The consensus engine's validation seam calls ValidateNext before prevoting
// a proposal. The seam's content must be EXACTLY what Append demands, so this
// test pins the two against each other: every way a block can be refused at
// append time must already be refused by ValidateNext, the valid case must
// pass, and no refusal may mutate the chain.

// pristineHeadPlusOne builds a block that is valid for this chain's head+1:
// signed by the devnet validator through the chain's own Build. It is the
// table's shared base; each case corrupts exactly one thing of its own, so a
// corruptor that does nothing fails loudly against the valid-case expectation.
func pristineHeadPlusOne(t *testing.T, c *Chain) *types.Block {
	t.Helper()
	_, priv := devKey()
	b, err := c.Build(priv, nil, 1_700_000_100)
	if err != nil {
		t.Fatalf("fixture Build: %v", err)
	}
	return b
}

func TestValidateNextAcceptsExactlyWhatAppendAccepts(t *testing.T) {
	c, _ := devChain(t)

	// The valid case: the block Build produces must pass ValidateNext
	// unchanged, and passing must not move the chain.
	valid := pristineHeadPlusOne(t, c)
	heightBefore, headBefore := c.Height(), c.Head().ID()
	if err := c.ValidateNext(valid); err != nil {
		t.Fatalf("ValidateNext refused a block Build signed for head+1: %v", err)
	}
	if c.Height() != heightBefore || c.Head().ID() != headBefore {
		t.Fatal("ValidateNext mutated the chain on a passing block")
	}

	// Case table: every refusal Append makes. Each case asserts the REFUSAL
	// by its named sentinel (not any error), so a wrong check failing on the
	// wrong defect cannot pass as this test's evidence.
	cases := []struct {
		name    string
		corrupt func(b *types.Block)
		want    error
	}{
		{
			name:    "wrong parent",
			corrupt: func(b *types.Block) { b.Header.ParentHash = crypto.HashParts([]byte("not-the-parent")) },
			want:    ErrBadParent,
		},
		{
			name:    "wrong height",
			corrupt: func(b *types.Block) { b.Header.Height = b.Header.Height + 7 },
			want:    ErrBadHeight,
		},
		{
			name:    "tx root mismatch",
			corrupt: func(b *types.Block) { b.Header.TxRoot = crypto.HashParts([]byte("not-the-tx-root")) },
			want:    types.ErrTxRootMismatch,
		},
		{
			name: "non-validator proposer",
			corrupt: func(b *types.Block) {
				_, strangerKey, _ := crypto.GenerateKey()
				b.Header.Proposer = strangerKey.Public().(ed25519.PublicKey)
				hh := b.Header.SigningHash()
				b.Sig = crypto.Sign(strangerKey, hh[:])
			},
			want: ErrNotValidator,
		},
		{
			name:    "missing proposer signature",
			corrupt: func(b *types.Block) { b.Sig = nil },
			want:    ErrBadProposerSig,
		},
		{
			name: "bad proposer signature",
			corrupt: func(b *types.Block) {
				b.Sig = append([]byte(nil), b.Sig...)
				b.Sig[3] ^= 0xff
			},
			want: ErrBadProposerSig,
		},
		{
			name: "garbage state root",
			corrupt: func(b *types.Block) {
				// The attack exactly as audit C-1 describes it: the proposer
				// builds a normal block, overwrites Header.StateRoot with
				// garbage and RE-SIGNS. The signature then verifies - it was
				// made over the tampered header - and the refusal must come
				// from the recomputed root, not from the signature.
				b.Header.StateRoot = [32]byte{0xde, 0xad, 0xbe, 0xef}
				_, key := devKey()
				hh := b.Header.SigningHash()
				b.Sig = crypto.Sign(key, hh[:])
			},
			want: ErrBadStateRoot,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := pristineHeadPlusOne(t, c)
			tc.corrupt(b)
			heightBefore, headBefore := c.Height(), c.Head().ID()
			if err := c.ValidateNext(b); !errors.Is(err, tc.want) {
				t.Fatalf("ValidateNext err = %v, want %v", err, tc.want)
			}
			// For the re-signed case the signature must genuinely verify: a
			// refusal named for the state-root sentinel would not name it if
			// the block were merely unsigned - this pins the attack shape.
			if tc.name == "garbage state root" {
				hh := b.Header.SigningHash()
				if !crypto.Verify(b.Header.Proposer, hh[:], b.Sig) {
					t.Fatal("fixture: the re-signed attack block does not verify; the case would not name the state-root check")
				}
			}
			if c.Height() != heightBefore || c.Head().ID() != headBefore {
				t.Fatal("ValidateNext mutated the chain on a refused block")
			}
			// Append must refuse the SAME block with the SAME sentinel: the
			// two entries to the one policy cannot drift apart.
			if err := c.Append(b); !errors.Is(err, tc.want) {
				t.Fatalf("Append err = %v, want %v (the seam and the gate disagree)", err, tc.want)
			}
		})
	}
}

// Audit O-6: Build must return an error, not panic, for a proposer key that
// cannot be used. ed25519.PrivateKey.Public() indexes the key and panics on a
// short one, so a nil wiring bug used to crash the node.
func TestBuildRefusesANilProposerInsteadOfPanicking(t *testing.T) {
	c, _ := devChain(t)
	for _, key := range []ed25519.PrivateKey{nil, {}} {
		if _, err := c.Build(key, nil, 1_700_000_100); !errors.Is(err, ErrUnknownProposer) {
			t.Fatalf("Build with a %d-byte proposer gave %v, want ErrUnknownProposer", len(key), err)
		}
	}
}

// Audit O-5: a data directory belongs to one genesis. Opening it with another
// must be reported as a genesis mismatch BEFORE any block is replayed, not as
// an opaque "replay diverged" after the fact.
func TestOpenRefusesADifferentGenesisUpFront(t *testing.T) {
	dir := t.TempDir()
	g := genesis.Devnet()
	_, priv := devKey()
	c, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Build(priv, nil, 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append(b); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	if c2, err := Open(genesis.Testnet(), dir); err == nil {
		_ = c2.Close()
		t.Fatal("opening a devnet directory with the testnet genesis must fail")
	} else if !errors.Is(err, ErrWrongGenesis) {
		t.Fatalf("wrong genesis reported as %v, want ErrWrongGenesis", err)
	} else if errors.Is(err, ErrGenesisReplay) {
		t.Fatal("a wrong genesis must not be reported as a replay divergence")
	}
}

// Audit S-14 evidence: a stray/duplicated segment does NOT silently renumber
// the chain. The store numbers heights by record count, but replay refuses a
// stored block whose own header does not claim its position, so the extra
// copy fails Open instead of shifting every later height.
func TestOpenRefusesADuplicatedSegment(t *testing.T) {
	dir := t.TempDir()
	g := genesis.Devnet()
	_, priv := devKey()
	c, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	for h := 1; h <= 3; h++ {
		b, err := c.Build(priv, nil, int64(1_700_000_000+h))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	// A stray copy sorted AFTER the real segment: its three records are
	// re-indexed as heights 4..6 while still claiming heights 1..3.
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%08d.seg", 1)), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if c2, err := Open(g, dir); err == nil {
		_ = c2.Close()
		t.Fatal("a duplicated segment silently renumbered the chain")
	} else if !errors.Is(err, ErrGenesisReplay) {
		t.Fatalf("a duplicated segment reported as %v, want ErrGenesisReplay", err)
	}
}

// Audit O-8: /status reads the head height, ID and root from one critical
// section. The invariant is checked while blocks are appended concurrently:
// every snapshot's ID and root must belong to a real block at that height.
// The outcome does not depend on interleaving, so it cannot flake.
func TestHeadSnapshotIsConsistentUnderAppends(t *testing.T) {
	dir := t.TempDir()
	g := genesis.Devnet()
	c, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := devKey()

	stop := make(chan struct{})
	checked := make(chan struct{})
	go func() {
		defer close(checked)
		for {
			select {
			case <-stop:
				return
			default:
			}
			height, id, stateRoot := c.HeadSnapshot()
			blk, err := c.BlockAt(height)
			if err != nil {
				t.Errorf("BlockAt(%d) after HeadSnapshot: %v", height, err)
				return
			}
			if got := blk.ID(); got != id {
				t.Errorf("head snapshot height %d: ID %x does not match the block at that height (%x)", height, id[:8], got[:8])
				return
			}
			if blk.Header.StateRoot != stateRoot {
				t.Errorf("head snapshot height %d: state root %x does not match the block at that height", height, stateRoot[:8])
				return
			}
		}
	}()
	for h := 1; h <= 60; h++ {
		b, err := c.Build(priv, nil, c.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	<-checked
}
