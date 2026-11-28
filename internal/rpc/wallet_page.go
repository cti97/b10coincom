// The wallet page: GET /wallet/{address}, a read of one account.
//
// It exists because the chain had no human view of an account. The JSON at
// /account/{address} is for clients, and the explorer page is about blocks;
// neither answers "what does this address hold, and what has it been doing".
// This page answers exactly that, from the node's committed state and the same
// scan /history uses.
//
// It signs nothing and submits nothing: the node holds no key for the visitor,
// and a page that could spend would be a wallet with the wrong custodian. The
// signing client is the CLI today and the extension later, both of which keep
// the key where the page cannot reach it.
package rpc

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/cti97/b10coincom/internal/types"
)

// walletScanBlocks is how far back the transaction table looks. The fixture
// chain produces ~15 blocks/s, so 20000 blocks is roughly twenty minutes of
// history: enough to see a transfer you just made, and honest about the fact
// that a bounded scan cannot show everything ever.
const walletScanBlocks = 20000

type walletPageView struct {
	ChainID      string
	Address      string
	AddressShort string
	Height       uint64
	Balance      uint64
	Nonce        uint64
	Bonded       uint64
	Unbonding    []walletUnbondingRow
	Head         uint64
	ScanFrom     uint64
	ScanTo       uint64
	Truncated    bool
	TxCap        int
	Txs          []walletTxRow
}

type walletUnbondingRow struct {
	Amount        uint64
	ReleaseHeight uint64
	BlocksToGo    uint64
	Mature        bool
}

type walletTxRow struct {
	Height       uint64
	Type         string
	Direction    string
	Amount       uint64
	HasAmount    bool
	Counterparty string
	Fee          uint64
}

func shortAddress(a types.Address) string {
	s := a.String()
	if len(s) <= 14 {
		return s
	}
	return s[:8] + "…" + s[len(s)-4:]
}

func (s *Server) handleWalletPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The page is a /history scan under another name, so it draws on the same
	// per-source bucket (audit R-1): one address view must not become a way to
	// scan for free.
	if !s.scanLimiter.allow(sourceHost(r.RemoteAddr)) {
		http.Error(w, "too many scans from this source", http.StatusTooManyRequests)
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/wallet/")
	if raw == "" {
		http.Error(w, "give an address: GET /wallet/{address}", http.StatusBadRequest)
		return
	}
	addr, err := types.ParseAddress(raw)
	if err != nil {
		http.Error(w, "address must be a canonical b10 address", http.StatusBadRequest)
		return
	}
	release, ok := s.acquireScanSlot()
	if !ok {
		http.Error(w, "the node is busy scanning for other clients; retry shortly", http.StatusServiceUnavailable)
		return
	}
	defer release()

	head, _, _ := s.chain.HeadSnapshot()
	st := s.chain.State()
	acc := st.Get(addr)
	bond, _ := st.BondOf(addr)
	recs := st.UnbondingOf(addr)

	v := walletPageView{
		ChainID:      s.chain.Genesis().ChainID,
		Address:      addr.String(),
		AddressShort: shortAddress(addr),
		Height:       head,
		Balance:      acc.Balance,
		Nonce:        acc.Nonce,
		Bonded:       bond.Amount,
		Head:         head,
		TxCap:        maxHistoryEntries,
	}
	for _, rec := range recs {
		row := walletUnbondingRow{Amount: rec.Amount, ReleaseHeight: rec.ReleaseHeight}
		if rec.ReleaseHeight <= head {
			row.Mature = true
		} else {
			row.BlocksToGo = rec.ReleaseHeight - head
		}
		v.Unbonding = append(v.Unbonding, row)
	}

	hist, err := s.scanHistory(r.Context(), head, addr, true, walletScanBlocks, maxHistoryEntries, nil)
	if err != nil {
		if r.Context().Err() != nil {
			return // the client is gone; the scan stopped for them (audit R-1)
		}
		// Never the error text: a store failure names the data directory.
		http.Error(w, "the wallet page is unavailable on this node", http.StatusInternalServerError)
		return
	}
	v.ScanFrom, v.ScanTo, v.Truncated = hist.From, hist.To, hist.Truncated
	for _, e := range hist.Txs {
		row := walletTxRow{Height: e.Height, Type: e.Type, Amount: e.Amount, Fee: e.Fee, HasAmount: e.Amount > 0}
		switch {
		case e.From == addr.String():
			row.Direction = "out"
			row.Counterparty = e.To
		case e.To == addr.String():
			row.Direction = "in"
			row.Counterparty = e.From
		default:
			row.Direction = "—"
		}
		if row.Direction == "out" && e.To == "" {
			row.Direction = "out" // bond/unbond/withdraw have no counterparty
		}
		v.Txs = append(v.Txs, row)
	}

	// Render into a buffer, then write once: a reader sees the whole document
	// or a clean error, never a truncated page.
	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, walletTemplateName, v); err != nil {
		http.Error(w, "the wallet page could not be rendered", http.StatusInternalServerError)
		return
	}
	pageHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
}
