package types

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

func testBlock(t *testing.T, txs ...Tx) *Block {
	t.Helper()
	pub, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := &Block{
		Header: Header{
			Height:     1,
			ParentHash: crypto.HashParts([]byte("parent")),
			StateRoot:  crypto.HashParts([]byte("state")),
			Timestamp:  1_700_000_000,
			Proposer:   pub,
		},
		Txs: txs,
	}
	b.Header.TxRoot = ComputeTxRoot(txs)
	return b
}

func TestBlockEncodeDecodeRoundTrip(t *testing.T) {
	b := testBlock(t, *signedTransfer(t, 1, 50))
	got, err := DecodeBlock(b.Encode())
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if got.ID() != b.ID() {
		t.Fatal("round trip changed the block ID")
	}
	if len(got.Txs) != 1 || got.Txs[0].ID() != b.Txs[0].ID() {
		t.Fatal("round trip lost transactions")
	}
	if string(got.Header.Proposer) != string(b.Header.Proposer) {
		t.Fatal("round trip lost the proposer")
	}
}

// The block ID must commit to the header only. If it covered the
// transactions, a block's ID would change when its body was re-sent.
func TestBlockIDIsHeaderOnly(t *testing.T) {
	b := testBlock(t, *signedTransfer(t, 1, 5))
	before := b.ID()
	b.Txs = append(b.Txs, *signedTransfer(t, 2, 6))
	if b.ID() != before {
		t.Fatal("block ID changed when only the body changed")
	}
}

func TestBlockIDChangesWithHeader(t *testing.T) {
	b := testBlock(t)
	before := b.ID()
	b.Header.Height = 2
	if b.ID() == before {
		t.Fatal("block ID ignored a header change")
	}
}

func TestValidateStructureAcceptsWellFormedBlock(t *testing.T) {
	if err := testBlock(t, *signedTransfer(t, 1, 5)).ValidateStructure(); err != nil {
		t.Fatalf("valid block rejected: %v", err)
	}
	if err := testBlock(t).ValidateStructure(); err != nil {
		t.Fatalf("empty block rejected: %v", err)
	}
}

func TestValidateStructureRejectsWrongProposerLength(t *testing.T) {
	b := testBlock(t)
	b.Header.Proposer = []byte{1, 2, 3}
	if err := b.ValidateStructure(); !errors.Is(err, ErrBadProposer) {
		t.Fatalf("expected ErrBadProposer, got %v", err)
	}
}

func TestValidateStructureRejectsTxRootMismatch(t *testing.T) {
	b := testBlock(t, *signedTransfer(t, 1, 5))
	b.Header.TxRoot = crypto.HashParts([]byte("wrong"))
	if err := b.ValidateStructure(); !errors.Is(err, ErrTxRootMismatch) {
		t.Fatalf("expected ErrTxRootMismatch, got %v", err)
	}
}

func TestValidateStructureRejectsDuplicateTx(t *testing.T) {
	tx := signedTransfer(t, 1, 5)
	b := testBlock(t, *tx, *tx)
	if err := b.ValidateStructure(); !errors.Is(err, ErrDuplicateTx) {
		t.Fatalf("expected ErrDuplicateTx, got %v", err)
	}
}

func TestValidateStructureRejectsZeroTimestamp(t *testing.T) {
	b := testBlock(t)
	b.Header.Timestamp = 0
	if err := b.ValidateStructure(); err == nil {
		t.Fatal("expected an error for a zero timestamp")
	}
}

func TestValidateStructureRejectsTooManyTxs(t *testing.T) {
	b := testBlock(t)
	b.Txs = make([]Tx, MaxTxsPerBlock+1)
	b.Header.TxRoot = ComputeTxRoot(b.Txs)
	if err := b.ValidateStructure(); !errors.Is(err, ErrBlockTooLarge) {
		t.Fatalf("expected ErrBlockTooLarge, got %v", err)
	}
}
