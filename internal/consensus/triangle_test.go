package consensus

// THE FRAME / BLOCK / WINDOW TRIANGLE (audit S-2 and S-3).
//
// Three numbers shipped that nothing compared: the block ceiling
// (types.MaxBlockBytes), the transport frame bound (wire.MaxFrameBytes) and the
// sync window (MaxBlocksPerResponse units of block + certificate). They live in
// four packages, and each pair that got out of step was a silent, permanent
// failure:
//
//   - a legal max-size block's PROPOSAL envelope encoded past one frame, so it
//     was built, signed, and discarded by every receiver (S-2 consequence A);
//   - a sync response carrying a window of legal blocks encoded past one
//     frame, so transport.skipOversized drained it, the puller read the
//     silence as "caught up", and a validator behind on a real chain could
//     never catch up again (S-2 consequence B);
//   - the pool could hand the producer more applicable transactions than a
//     block could hold in bytes, so chain.Build refused the block AFTER a full
//     state transition and node.Run exited the process (S-3).
//
// One test, one place, so that a change to any of the three numbers has to face
// the other two. It is deliberately not split up: the finding is that these
// numbers are only meaningful TOGETHER.

import (
	"crypto/ed25519"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/node"
	"github.com/cti97/b10coincom/internal/relay"
	"github.com/cti97/b10coincom/internal/transport/tcp"
	"github.com/cti97/b10coincom/internal/types"
	"github.com/cti97/b10coincom/internal/wire"
)

// maxSeats is genesis.maxCommitteeSize: the committee ceiling a certificate can
// be sized against. It is written here because the constant is unexported; the
// envelope assertion below is what turns it into a frame requirement.
const maxSeats = 255

// maxVoteBytes is one encoded precommit in a certificate: type(1) + height(8) +
// round(4) + blockID(32) + validator(1+32) + sig(1+64), as EncodeVote writes
// it, plus the two-byte varint prefix the certificate record frames it with.
const maxVoteBytes = 145

// triangleTransfers builds the state S-3 is about, by construction: `senders`
// genesis-funded accounts, each with the pool's maximum number of pending
// transfers (nonces 0..MaxPendingTransfersPerSender-1), so every one of them is
// applicable at head+1. Nothing here depends on timing, a race or a buffer.
func triangleTransfers(t *testing.T, senders int) (*genesis.Genesis, *chain.Chain, []types.Tx) {
	t.Helper()
	g := fourValGenesis(t)
	g.DevAccounts = nil
	type funder struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}
	funders := make([]funder, senders)
	for i := range funders {
		pub, priv, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		funders[i] = funder{pub: pub, priv: priv}
		g.DevAccounts = append(g.DevAccounts, genesis.DevAccount{PubKey: pub, BalanceSparks: 1_000_000})
	}
	// Sign only once the genesis is COMPLETE: the chain identifier a signature
	// binds is the hash of every genesis field, including the account list.
	genesisHash := g.Hash()
	var recipient types.Address
	recipient[0] = 0x5E
	txs := make([]types.Tx, 0, senders*mempool.MaxPendingTransfersPerSender)
	for _, f := range funders {
		from := types.AddressFromPub(f.pub)
		for nonce := 0; nonce < mempool.MaxPendingTransfersPerSender; nonce++ {
			tx := types.Tx{
				Type: types.TxTransfer, From: from, PubKey: f.pub,
				Nonce: uint64(nonce), Fee: g.Params.MinFeeSparks,
				To: recipient, Amount: 1,
			}
			h := tx.SigningHash(genesisHash)
			tx.Sig = crypto.Sign(f.priv, h[:])
			txs = append(txs, tx)
		}
	}
	ch, err := chain.Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	return g, ch, txs
}

// assertWireLegal checks the two things a block must be for its bytes to
// travel at all: legal by the chain's rules, and decodable from its SIGNED
// encoding (ValidateStructure measures an unsigned block; DecodeBlock enforces
// the bound on the signed one).
func assertWireLegal(t *testing.T, b *types.Block, where string) {
	t.Helper()
	signed := b.Encode()
	if len(signed) > types.MaxBlockBytes {
		t.Fatalf("%s encodes to %d signed bytes, above the %d-byte block bound", where, len(signed), types.MaxBlockBytes)
	}
	if len(b.Txs) > types.MaxTxsPerBlock {
		t.Fatalf("%s carries %d transactions, above MaxTxsPerBlock %d", where, len(b.Txs), types.MaxTxsPerBlock)
	}
	if _, err := types.DecodeBlock(signed); err != nil {
		t.Fatalf("%s does not decode from its signed encoding: %v", where, err)
	}
	if err := b.ValidateStructure(); err != nil {
		t.Fatalf("%s is not a legal block: %v", where, err)
	}
}

// TestTheBlockFrameWindowTriangle is the invariant audit section 7's first
// blindspot asks for: the only place the block ceiling, the frame bound and the
// sync window are compared to each other.
func TestTheBlockFrameWindowTriangle(t *testing.T) {
	// ---------------------------------------------------------------- bounds
	// One frame bound, not three. A transport stricter than the others severs
	// exactly the max-size blocks the others accept, and the reconnect churn
	// that follows looks like flapping peers rather than a bound that is one
	// number too small.
	if tcp.DefaultMaxFrameBytes != wire.MaxFrameBytes {
		t.Fatalf("the tcp transport's frame bound is %d, wire.MaxFrameBytes is %d: a frame one accepts the other drops",
			tcp.DefaultMaxFrameBytes, wire.MaxFrameBytes)
	}
	if relay.DefaultMaxFrameBytes != wire.MaxFrameBytes {
		t.Fatalf("the relay's frame bound is %d, wire.MaxFrameBytes is %d: the relay would sever frames the validators accept",
			relay.DefaultMaxFrameBytes, wire.MaxFrameBytes)
	}
	// The frame bound must carry the block bound PLUS the largest thing a
	// message wraps around one block: a commit certificate at the committee
	// ceiling (a sync unit's, or a re-proposal's justification), plus the
	// framing of the message carrying it. This is the assertion that fires when
	// anyone lowers the headroom or raises the seat ceiling.
	const envelopeSlack = 1 << 10 // message framing around the certificate
	if headroom := wire.MaxFrameBytes - types.MaxBlockBytes; headroom < maxSeats*maxVoteBytes+envelopeSlack {
		t.Fatalf("the frame bound leaves %d bytes over a max-size block; a %d-seat certificate plus framing needs %d",
			headroom, maxSeats, maxSeats*maxVoteBytes+envelopeSlack)
	}

	// -------------------------------------------------------------- producer
	// S-3: the pool hands the producer 100 x 64 = 6,400 applicable transfers,
	// which is 6,400 x 165 + 212 = 1,056,212 bytes - past the 1 MiB block
	// bound and inside the 10,000-transaction count bound. Before the byte
	// budget this built an oversized block, chain.Build returned
	// ErrBlockTooLarge after a full state transition, and node.Run exited the
	// process.
	const senders = 200
	const pooled = 100 * mempool.MaxPendingTransfersPerSender
	g, ch, txs := triangleTransfers(t, senders)
	mp := mempool.New(pooled+1_000, g.Hash(), ch.AdmissionHead)
	for i, err := range mp.Add(txs[:pooled]) {
		if err != nil {
			t.Fatalf("fixture: pooled transaction %d was refused: %v", i, err)
		}
	}
	n := node.New(ch, testCommitteeKey(0), mp)

	b1, err := n.RunOnce(g.Time + 1)
	if err != nil {
		t.Fatalf("RunOnce over a pool of %d applicable transfers failed: %v (the producer must be able to build what the pool hands it)", pooled, err)
	}
	assertWireLegal(t, b1, "the produced block")
	if got := len(b1.Txs); got < 6_000 || got >= pooled {
		t.Fatalf("the produced block carries %d of %d transfers; want a byte-full block that is not the whole pool", got, pooled)
	}
	// Nothing is lost: the transfers Take removed and the byte budget excluded
	// are back in the pool they came from, waiting for the next block.
	if want, got := pooled-len(b1.Txs), mp.Len(); got != want {
		t.Fatalf("after the block the pool holds %d transactions, want %d: the ones the byte budget excluded were not returned to the pool",
			got, want)
	}

	// ---------------------------------------------- S-2 consequence A + B
	// A second max-size block, built directly from senders the first block did
	// not touch, so the chain holds two full units - the situation a 64-height
	// window of max-size legal blocks is made of. Two units exceed one frame by
	// construction, so every assertion below is about the composition, not a
	// size the fixture chose.
	second := txs[pooled : pooled+len(b1.Txs)]
	b2, err := ch.Build(testCommitteeKey(0), second, g.Time+2)
	if err != nil {
		t.Fatalf("building a second max-size block failed: %v", err)
	}
	if err := ch.Append(b2); err != nil {
		t.Fatalf("appending a second max-size block failed: %v", err)
	}
	assertWireLegal(t, b2, "the second block")
	blocks := []*types.Block{b1, b2}

	// S-2 consequence A: the PROPOSAL envelope of such a block - the block,
	// its height and round, a re-proposal justification, and both signatures -
	// must fit one frame. Otherwise it is built, signed and discarded by every
	// receiver, and its height can never be decided.
	proposal := func(b *types.Block) *Proposal {
		return &Proposal{
			Height: b.Header.Height, Round: 0, ValidRound: -1,
			Block:     *b,
			Validator: testCommitteeKey(0).Public().(ed25519.PublicKey),
			Sig:       make([]byte, ed25519.SignatureSize),
		}
	}
	if got := len(EncodeProposal(proposal(blocks[0]))); got > wire.MaxFrameBytes {
		t.Fatalf("the proposal envelope of a max-size legal block is %d bytes, above the %d-byte frame bound: no peer would ever decode it",
			got, wire.MaxFrameBytes)
	}
	worst := proposal(blocks[0])
	worst.Justification = make([]byte, maxSeats*maxVoteBytes)
	if got := len(EncodeProposal(worst)); got > wire.MaxFrameBytes {
		t.Fatalf("the proposal envelope of a max-size legal block with a %d-seat justification is %d bytes, above the %d-byte frame bound",
			maxSeats, got, wire.MaxFrameBytes)
	}

	// S-2 consequence B: a 64-height sync window over max-size blocks. The
	// answer MUST serve the shorter range it can deliver, and what it serves
	// must encode under the bound, because a frame past it is drained and
	// discarded while the puller reads the silence as "caught up".
	srv := NewSyncer(ch, nil, testCommitteeKey(1))
	for i, b := range blocks {
		h := uint64(i + 1)
		srv.RecordCommit(h, 2, quorumCertFor(t, b, h, 2))
	}
	units := make([]wire.BlockSyncUnit, 0, len(blocks))
	for i := range blocks {
		h := uint64(i + 1)
		blk, err := ch.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		rec, ok := srv.certificateAt(h)
		if !ok {
			t.Fatalf("fixture: no certificate archived for height %d", h)
		}
		units = append(units, wire.BlockSyncUnit{Block: blk.Encode(), Round: rec.round, Votes: rec.encoded})
	}
	if got := len(wire.EncodeBlockSyncResp(&wire.BlockSyncResp{Nonce: 1, Units: units})); got <= wire.MaxFrameBytes {
		t.Fatalf("the fixture does not exercise the answer budget: %d units of max-size blocks encode to %d bytes, inside the %d-byte frame bound",
			len(units), got, wire.MaxFrameBytes)
	}
	resp, err := srv.Answer(syncSignReq(t, testCommitteeKey(0), 1, srv.MaxBlocksPerResponse))
	if err != nil {
		t.Fatalf("a window of max-size blocks was refused outright: %v", err)
	}
	if len(resp.Units) == 0 {
		t.Fatal("the answer served no units at all: a serveable chain must always serve at least one")
	}
	if uint64(len(resp.Units)) >= srv.MaxBlocksPerResponse {
		t.Fatalf("the answer served the whole %d-unit window, but two max-size units already exceed a frame", len(resp.Units))
	}
	if served := wire.EncodeBlockSyncResp(resp); len(served) > wire.MaxFrameBytes {
		t.Fatalf("the served window encodes to %d bytes, above the %d-byte frame bound: transport.skipOversized would discard it and the pull would read that as caught up",
			len(served), wire.MaxFrameBytes)
	}
}

// TestAByteBudgetedAnswerLetsThePullConvergeInWaves is the claim the S-2 fix
// rests on, checked rather than assumed: `served < win` ends a pull cleanly, and
// the next wave resumes from the new head. The answerer's budget is lowered so
// every answer is a SHORT window, and the puller still reaches the peer's
// height without an error - which is what makes "serve fewer units" safe
// instead of a new way to stall.
func TestAByteBudgetedAnswerLetsThePullConvergeInWaves(t *testing.T) {
	c := newCommitteeRig(t, 3, 5)
	defer c.halt()
	// A little over one unit of a small block fits; a five-block window does
	// not, so every answer is short.
	c.servers[0].MaxResponseBytes = 1_200
	c.rig.start()

	waves := 0
	for c.pullCh.Height() < c.chains[0].Height() {
		if err := c.pull.PullAndAdopt(c.pullCh.Height() + 1); err != nil {
			t.Fatalf("wave %d of a byte-budgeted pull failed: %v", waves+1, err)
		}
		waves++
		if waves > 10 {
			t.Fatalf("the pull made no progress over %d waves at height %d of %d", waves, c.pullCh.Height(), c.chains[0].Height())
		}
	}
	c.halt()
	c.assertConverged("after byte-budgeted waves")
	if waves < 2 {
		t.Fatalf("the pull converged in %d wave(s): the budget did not shorten any answer, so the fixture proves nothing", waves)
	}
}
