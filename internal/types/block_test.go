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

// The signature must not change the block ID: signing does not mutate the
// header, so a block keeps its identity when the proposer signs it.
func TestBlockSigDoesNotAffectBlockID(t *testing.T) {
	b := testBlock(t)
	before := b.ID()
	b.Sig = []byte("a-signature")
	if b.ID() != before {
		t.Fatal("signature must not change the block ID")
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

// A structurally clean block whose canonical ENCODING exceeds MaxBlockBytes
// must also be rejected: the byte bound, not just the transaction-count
// bound, is what keeps every block processable on a Raspberry Pi within one
// block interval. The transactions stay under MaxTxsPerBlock so the failure
// can only come from the byte guard.
func TestValidateStructureRejectsOversizedCanonicalEncoding(t *testing.T) {
	b := testBlock(t)
	sig := make([]byte, 64) // filler: ValidateStructure checks no signature
	for len(b.Encode()) <= MaxBlockBytes {
		for i := 0; i < 256 && len(b.Txs) < MaxTxsPerBlock; i++ {
			b.Txs = append(b.Txs, Tx{
				Type:  TxTransfer,
				Nonce: uint64(len(b.Txs)), // distinct nonce -> distinct ID, so the duplicate rule never fires first
				Sig:   sig,
			})
		}
		if len(b.Txs) == MaxTxsPerBlock {
			break
		}
	}
	b.Header.TxRoot = ComputeTxRoot(b.Txs)

	if len(b.Txs) > MaxTxsPerBlock {
		t.Fatalf("test setup: %d transactions would trip the count bound, not the byte bound", len(b.Txs))
	}
	if size := len(b.Encode()); size <= MaxBlockBytes {
		t.Fatalf("test setup: canonical encoding is %d bytes, want > %d", size, MaxBlockBytes)
	}
	if err := b.ValidateStructure(); !errors.Is(err, ErrBlockTooLarge) {
		t.Fatalf("expected ErrBlockTooLarge, got %v", err)
	}
}

// A block that DECLARES more transactions than MaxTxsPerBlock is rejected at
// the declared count, before a single transaction body is parsed: nothing
// over the bound is ever decoded.
func TestDecodeBlockRejectsTxCountOverTheLimit(t *testing.T) {
	e := NewEncoder()
	e.U64(1)
	e.Fixed32([32]byte{}) // parent hash
	e.Fixed32([32]byte{}) // state root
	e.Fixed32([32]byte{}) // tx root
	e.I64(1_700_000_100)
	e.VarBytes(make([]byte, 32)) // proposer
	e.Len(MaxTxsPerBlock + 1)    // the over-limit declared count
	// The decoder bounds a declared count against the remaining buffer, so
	// the bytes must exist for the MaxTxsPerBlock guard to be the thing that
	// fires; they are never parsed as transactions.
	e.Raw(make([]byte, MaxTxsPerBlock+1))
	if _, err := DecodeBlock(e.Bytes()); !errors.Is(err, ErrBlockTooLarge) {
		t.Fatalf("expected ErrBlockTooLarge, got %v", err)
	}
}
