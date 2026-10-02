package chain

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
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
			To:     to,
			Amount: uint64(h) * genesis.SparksPerB10,
		}
		sigHash := tx.SigningHash()
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
		To:     to,
		Amount: 250 * genesis.SparksPerB10,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(devPriv, sigHash[:])

	b, err := c.Build(priv, []types.Tx{*tx}, 1_700_000_100)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := c.Append(b); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if got := c.State().Get(from).Balance; got != startFrom-250*genesis.SparksPerB10 {
		t.Fatalf("sender balance = %d, want %d", got, startFrom-250*genesis.SparksPerB10)
	}
	if got := c.State().Get(to).Balance; got != startTo+250*genesis.SparksPerB10 {
		t.Fatalf("recipient balance = %d, want %d", got, startTo+250*genesis.SparksPerB10)
	}
}

// Total supply must be conserved by transfers.
// Total supply must be conserved BY A REAL TRANSFER: value moves between
// accounts and none is created. The original version of this test built a
// block with the dev ACCOUNT key, discarded it, and asserted supply was
// unchanged - and since Build never mutates state, it could not fail for the
// reason it named.
func TestTotalSupplyIsConserved(t *testing.T) {
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
		To:     types.AddressFromPub(toPub),
		Amount: 123 * genesis.SparksPerB10,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(devPrivateKey(t), sigHash[:])

	b, err := c.Build(priv, []types.Tx{*tx}, 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append(b); err != nil {
		t.Fatal(err)
	}
	if got := c.State().TotalBalance(); got != before {
		t.Fatalf("supply changed across a transfer: %d -> %d", before, got)
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

func devPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv := genesis.DevAccountKey(0)
	return priv
}
