// Wallet history: GET /history, the second read the M6 wallet needs.
//
// There is no transaction index in the store and M6 does not add one (design
// decision 2). What this handler does instead is a SERVER-SIDE BACKWARD SCAN
// over the blocks the caller asked for: it reads at most MaxHistoryBlocks
// blocks back from the head, keeps at most maxHistoryEntries matching entries,
// newest first, and reports the window it actually scanned. `from`, `to`,
// `blocks` and `truncated` are the honest answer to "how far back does this
// go" - the wallet did not download a chain, and it did not see everything.
package rpc

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/cti97/b10coincom/internal/types"
)

const (
	// defaultHistoryBlocks is what a client gets without asking: one hundred
	// blocks back from the head.
	defaultHistoryBlocks = 100
	// MaxHistoryBlocks bounds ONE request. This endpoint is unauthenticated
	// and outside the /tx limiter, so its work must not be a function of the
	// chain: a request may never ask for more than this, whatever it sends.
	// Every block is a disk read, and the HTTP server's write timeout is 10 s.
	MaxHistoryBlocks = 500
	// maxHistoryEntries bounds the reply itself, independently of the window:
	// an address with thousands of transactions in the scanned window would
	// otherwise turn a bounded number of block reads into an unbounded JSON
	// body. When the cap drops matches, `truncated` says so.
	maxHistoryEntries = 200
)

// historyEntry is one transaction as the wallet sees it. Amounts are sparks
// (uint64) and travel as JSON numbers, never b10 and never a float, exactly as
// /account's do. To is empty for every type that carries no recipient, so a
// bond's zero address is never reported as somebody's account.
type historyEntry struct {
	TxID   string `json:"txid"`
	Height uint64 `json:"height"`
	Type   string `json:"type"` // "transfer" | "faucet claim" | "bond" | "unbond" | "withdraw"
	From   string `json:"from"`
	To     string `json:"to,omitempty"`
	Amount uint64 `json:"amount"` // sparks; 0 where the type carries none
	Fee    uint64 `json:"fee"`    // sparks
}

// historyResponse is one scanned window. Txs is always a list, never null: a
// client iterating it should not have to special-case "nothing matched".
type historyResponse struct {
	Address   string         `json:"address,omitempty"`
	Head      uint64         `json:"head"`
	From      uint64         `json:"from"` // lowest height scanned
	To        uint64         `json:"to"`   // == Head
	Blocks    int            `json:"blocks"`
	Truncated bool           `json:"truncated"`
	Txs       []historyEntry `json:"txs"` // newest first, never null
}

// historyBlocks parses `blocks`. The rule is unbondingWindow's (audit ST-4's
// "cap or paginate"): absent takes the default, a non-numeric or zero value is
// a client error rather than a silently different window, and a value above
// the maximum is CLAMPED, not refused - the client asked for "as much as
// allowed", and the reply's `blocks` reports what it actually got.
//
// THE PARSE IS AT 64 BITS, then clamped (audit S-14). It used to parse at 31
// bits, so 2^31 and above failed the PARSE and were answered with "must be a
// positive integer" about a positive integer - a 400 the help text promised
// would be clamped. Parsing a uint64 and clamping afterwards makes the promise
// true for every value a client can send; the only refusals left are the ones
// the sentence describes (zero, non-numeric, negative, or above 2^64-1, which
// does not "fit in 64 bits" and so is not a count this endpoint accepts).
func historyBlocks(q url.Values) (blocks int, err error) {
	blocks = defaultHistoryBlocks
	if raw := q.Get("blocks"); raw != "" {
		v, perr := strconv.ParseUint(raw, 10, 64)
		if perr != nil || v == 0 {
			return 0, errors.New("blocks must be a positive integer that fits in 64 bits")
		}
		if v > MaxHistoryBlocks {
			v = MaxHistoryBlocks
		}
		blocks = int(v)
	}
	return blocks, nil
}

// historyWindow turns the head and the requested block count into the height
// window [from, to] a scan covers. Height 0 is the genesis block, which carries
// no transactions (chain.genesisBlock), so the window starts at height 1: a
// seven-block chain asks for 1..7 and scans seven blocks, not eight. An empty
// chain (head 0) has an empty window, from == to == 0 and zero blocks.
func historyWindow(head uint64, blocks int) (from, to uint64) {
	if head == 0 || blocks <= 0 {
		return 0, 0
	}
	n := uint64(blocks)
	if n > head {
		n = head
	}
	return head - n + 1, head
}

// historyTypeLabel names a transaction type for a reader. These are the same
// words the CLI's transaction preview uses (cmd/b10coin txTypeLabel); the
// wallet prints them verbatim.
func historyTypeLabel(t types.TxType) string {
	switch t {
	case types.TxTransfer:
		return "transfer"
	case types.TxFaucetClaim:
		return "faucet claim"
	case types.TxBond:
		return "bond"
	case types.TxUnbond:
		return "unbond"
	case types.TxWithdraw:
		return "withdraw"
	}
	return "unknown"
}

// historyEntryOf renders one transaction at one height. It reads only the
// decoded transaction: the store has no index, so no state is consulted and
// the same bytes always produce the same entry.
func historyEntryOf(h uint64, tx *types.Tx) historyEntry {
	id := tx.ID()
	e := historyEntry{
		TxID:   hex.EncodeToString(id[:]),
		Height: h,
		Type:   historyTypeLabel(tx.Type),
		From:   tx.From.String(),
		Amount: tx.Amount,
		Fee:    tx.Fee,
	}
	// To is TxTransfer-only on the wire, so a bond, unbond, claim or withdraw
	// decodes it as the zero address. Reporting that as a recipient would tell
	// a reader the money went to account zero.
	if tx.Type == types.TxTransfer {
		e.To = tx.To.String()
	}
	return e
}

// historyMatches reports whether one transaction belongs to addr. A
// transaction matches on its sender for every type (a bond is something its
// signer did, and it must show up in that signer's history); it matches on its
// recipient only for a transfer, and never through a zero address - a zero To
// is "no recipient", not an account.
func historyMatches(tx *types.Tx, addr types.Address) bool {
	if tx.From == addr {
		return true
	}
	return tx.Type == types.TxTransfer && tx.To != (types.Address{}) && tx.To == addr
}

// handleHistory serves the wallet's history read.
//
// `address` is optional: without it the scan returns every transaction in the
// window, which is the explorer's feed. With it, only that address's
// transactions are returned, newest first.
//
// BOUNDS (this endpoint is unauthenticated and outside the /tx limiter):
//   - at most MaxHistoryBlocks block reads, whatever `blocks` says;
//   - at most maxHistoryEntries entries, whatever the window holds;
//   - the reply's `from`/`to`/`blocks` describe the window actually scanned and
//     `truncated` is true when the entry cap dropped matches.
//
// The scan calls BlockAt once per height and lets it take the chain's read lock
// per call, so an append can interleave: it must not try to hold a lock across
// the loop, and it must not call State() per block. A block that cannot be read
// is a generic 500 - never a short list (which would look like "no history")
// and never a filesystem path (audit O-8's rule for /block).
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"method not allowed"})
		return
	}
	// The scan bucket is charged before anything is parsed or read (audit
	// R-1): a refused request costs one map lookup.
	if !s.scanLimiter.allow(sourceHost(r.RemoteAddr)) {
		writeJSON(w, http.StatusTooManyRequests, errorResponse{"too many scans from this source"})
		return
	}
	q := r.URL.Query()
	var want types.Address
	filtered := false
	if raw := q.Get("address"); raw != "" {
		addr, err := types.ParseAddress(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{"address must be a canonical b10 address"})
			return
		}
		want = addr
		filtered = true
	}
	blocks, err := historyBlocks(q)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	release, ok := s.acquireScanSlot()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{"the node is busy scanning for other clients; retry shortly"})
		return
	}
	defer release()
	// One head read, once: the window is fixed before the scan, so appends
	// during the scan cannot make the reply describe two different chains.
	out, err := s.scanHistory(r.Context(), s.chain.Height(), want, filtered, blocks, maxHistoryEntries, nil)
	if err != nil {
		if r.Context().Err() != nil {
			// The client is gone (audit R-1): there is nobody to answer, and
			// the scan stopped at the first block it would have read for them.
			return
		}
		// Never echo err.Error(): a store failure names the data
		// directory, the segment file and an offset.
		writeJSON(w, http.StatusInternalServerError, errorResponse{"internal error: history unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// scanHistory is THE one backward scan over a bounded block window. /history
// and the explorer both call it, so the window arithmetic, the entry cap and
// the `from`/`to`/`blocks`/`truncated` semantics exist exactly once: the
// explorer grows no second source of truth about how far back it looked
// (design decision 2 - there is no index, so the scanned window is the honest
// answer).
//
// head is a PARAMETER and is never read here. A caller that displays a head
// must scan the head it displayed: if this function took its own Height()
// reading, a block committed between the caller's read and the scan would make
// the reply describe a chain the caller's own page does not show - the torn
// pair Task 2 removed from the faucet page.
//
// Bounds are the caller's: `blocks` is the window, `maxEntries` is the reply
// cap. Both callers pass a constant or a clamped `blocks`, so the work per
// request is never a function of the chain's length.
//
// visit, when non-nil, sees every block the scan reads, newest first, before
// its transactions are filtered: the explorer builds its block table from the
// same pass instead of reading the window twice (audit R-4).
func (s *Server) scanHistory(ctx context.Context, head uint64, want types.Address, filtered bool, blocks, maxEntries int, visit func(uint64, *types.Block)) (historyResponse, error) {
	from, to := historyWindow(head, blocks)
	out := historyResponse{Head: head, From: from, To: to, Txs: []historyEntry{}}
	if filtered {
		out.Address = want.String()
	}
	if from == 0 && to == 0 {
		return out, nil
	}
	out.Blocks = int(to - from + 1)
	dropped := 0
	for h := to; ; h-- {
		// A client that has gone is not read for (audit R-1): the scan is
		// up to MaxHistoryBlocks disk reads and decodes, and WriteTimeout
		// only ends the connection, never the goroutine doing them.
		if err := ctx.Err(); err != nil {
			return historyResponse{}, err
		}
		b, err := s.chain.BlockAt(h)
		if err != nil {
			// The caller turns this into a generic failure: err.Error() names
			// the data directory, the segment file and an offset.
			return historyResponse{}, err
		}
		if visit != nil {
			visit(h, b)
		}
		for i := range b.Txs {
			if filtered && !historyMatches(&b.Txs[i], want) {
				continue
			}
			if len(out.Txs) >= maxEntries {
				dropped++
				continue
			}
			out.Txs = append(out.Txs, historyEntryOf(h, &b.Txs[i]))
		}
		if h == from {
			break
		}
	}
	out.Truncated = dropped > 0
	return out, nil
}
