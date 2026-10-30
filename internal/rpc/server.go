// Package rpc exposes a small read/write HTTP API for the node.
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

// statusResponse is ADDITIVE by contract (M5 Task 6): a client that ignores
// unknown fields must keep working, so the M5 fields are appended and no
// existing field is renamed or repurposed.
type statusResponse struct {
	ChainID   string `json:"chain_id"`
	Height    uint64 `json:"height"`
	HeadHash  string `json:"head_hash"`
	StateRoot string `json:"state_root"`
	Mempool   int    `json:"mempool"`

	// M5: the chain identity a signature is bound to, and the stake
	// parameters a client must know before it can build a valid staking
	// transaction. GenesisHash is the SAME value tx.SigningHash takes; a
	// client that signs against it produces a transaction this chain can
	// verify, and one that signs against a compiled-in assumption produces a
	// useless one.
	GenesisHash     string `json:"genesis_hash"`
	MinFeeSparks    uint64 `json:"min_fee_sparks"`
	MinStakeSparks  uint64 `json:"min_stake_sparks"`
	EpochBlocks     uint64 `json:"epoch_blocks"`
	UnbondingEpochs uint64 `json:"unbonding_epochs"`
	CommitteeSize   int    `json:"committee_size"`
}

// accountResponse is the /account/{address} view: the spendable account plus
// the two locked-stake records the staking verbs must know about. Amounts are
// sparks (uint64), never b10 and never a float.
//
// Unbonding is always a JSON list, never null: a client iterating it should
// not have to special-case "no records". UnbondingTotal is the number of
// records that exist, so a client reading a windowed reply can tell whether it
// saw them all; BondUnfunded is the part of Bonded that is a genesis grant and
// therefore NOT withdrawable (audit ST-3), which the unstake verb reports so an
// operator is not promised a payout that will not come.
type accountResponse struct {
	Address        string              `json:"address"`
	Balance        uint64              `json:"balance"`
	Nonce          uint64              `json:"nonce"`
	Bonded         uint64              `json:"bonded"`
	BondUnfunded   uint64              `json:"bond_unfunded"`
	Unbonding      []unbondingResponse `json:"unbonding"`
	UnbondingTotal int                 `json:"unbonding_total"`
}

// unbondingResponse is one record in that list.
type unbondingResponse struct {
	Amount        uint64 `json:"amount"`
	ReleaseHeight uint64 `json:"release_height"`
}

const (
	// defaultUnbondingLimit is the window a client gets without asking. It is
	// far above the state's own bound (UnbondingEpochs+2, four records on the
	// shipped params), so an ordinary read never sees a partial list.
	defaultUnbondingLimit = 64
	// maxUnbondingLimit bounds one reply. This endpoint is unauthenticated and
	// outside the /tx limiter, so its reply size must not be a function of the
	// state: a request may never ask for more than this, whatever it sends.
	maxUnbondingLimit = 256
)

// unbondingWindow parses limit/offset. Absent values take the defaults; a
// non-numeric, zero limit or an offset that is not a number is a client error
// rather than a silently different window. A limit above maxUnbondingLimit is
// clamped, not refused: the client asked for "as much as allowed".
func unbondingWindow(q url.Values) (offset, limit int, err error) {
	limit = defaultUnbondingLimit
	if raw := q.Get("limit"); raw != "" {
		v, perr := strconv.ParseUint(raw, 10, 31)
		if perr != nil || v == 0 {
			return 0, 0, errors.New("limit must be a positive integer")
		}
		if v > maxUnbondingLimit {
			v = maxUnbondingLimit
		}
		limit = int(v)
	}
	if raw := q.Get("offset"); raw != "" {
		v, perr := strconv.ParseUint(raw, 10, 31)
		if perr != nil {
			return 0, 0, errors.New("offset must be a non-negative integer")
		}
		offset = int(v)
	}
	return offset, limit, nil
}

// windowUnbonding returns the [offset, offset+limit) slice of recs and the
// total it was taken from. The slice is always non-nil (an empty window
// serialises as [], not null) and an offset past the end is an empty window,
// not an error: "there is nothing after these" is a valid answer.
func windowUnbonding(recs []unbondingResponse, offset, limit int) ([]unbondingResponse, int) {
	total := len(recs)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total || end < offset {
		end = total
	}
	out := make([]unbondingResponse, 0, end-offset)
	out = append(out, recs[offset:end]...)
	return out, total
}

type blockResponse struct {
	Height    uint64 `json:"height"`
	Hash      string `json:"hash"`
	Parent    string `json:"parent"`
	StateRoot string `json:"state_root"`
	Timestamp int64  `json:"timestamp"`
	Txs       int    `json:"tx_count"`
}

type txResponse struct {
	TxID string `json:"txid"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// Per-source /tx allowance (audit R-1). The pool's per-sender caps bound what
// one KEY can hold, but a source can submit from unlimited keys, so a token
// bucket per remote address bounds the request rate as well. The numbers are a
// local courtesy, not consensus: a burst of 256 and 64/s is far above any
// honest client and well below what it takes to fill the pool, and the bucket
// map is bounded so the limiter cannot itself become a memory sink. This is
// deliberately NOT the primary bound - many addresses behind one NAT share a
// bucket, and a distributed source has many buckets - so the stateful pool caps
// remain the safety net.
const (
	txRateBurst      = 256
	txRatePerSecond  = 64
	txRateMaxSources = 4096

	// maxTxBodyBytes bounds one POST /tx body (audit O-8). A canonical valid
	// transaction is at most ~163 bytes (a transfer: type, 20-byte address,
	// 33-byte framed 32-byte key, two u64s, 20-byte recipient, u64 amount,
	// 65-byte framed 64-byte signature); 4096 bytes is 25x that, so no legal
	// transaction is refused, while the previous 1 MiB let one request make
	// every handler read 5,000 transactions' worth of bytes to reject one.
	maxTxBodyBytes = 4096
)

type txBucket struct {
	tokens float64
	last   time.Time
}

// sourceLimiter is a bounded token-bucket rate limiter keyed by source address.
// now is a field so a test can drive it without a sleep or a timing race.
type sourceLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	burst   float64
	rate    float64
	max     int
	buckets map[string]*txBucket
	order   []string
}

func newSourceLimiter(burst, rate float64, max int) *sourceLimiter {
	return &sourceLimiter{
		now:     time.Now,
		burst:   burst,
		rate:    rate,
		max:     max,
		buckets: make(map[string]*txBucket),
	}
}

// allow reports whether src may spend one token now, refilling at the
// configured rate. A source not seen before starts full. The bucket map is
// bounded: at the cap the oldest-registered source is forgotten, so an
// attacker cycling through addresses cannot grow the map without limit.
func (l *sourceLimiter) allow(src string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[src]
	if !ok {
		if l.max > 0 && len(l.buckets) >= l.max {
			old := l.order[0]
			l.order = l.order[1:]
			delete(l.buckets, old)
		}
		b = &txBucket{tokens: l.burst, last: now}
		l.buckets[src] = b
		l.order = append(l.order, src)
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sourceHost reduces an http.Request's RemoteAddr to its host, so two ports
// from one address share a bucket. It falls back to the raw string when it is
// not host:port.
func sourceHost(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}

// Server binds the chain and mempool to HTTP handlers.
type Server struct {
	chain     *chain.Chain
	mempool   *mempool.Mempool
	txLimiter *sourceLimiter
}

func NewServer(c *chain.Chain, mp *mempool.Mempool) *Server {
	return &Server{
		chain:     c,
		mempool:   mp,
		txLimiter: newSourceLimiter(txRateBurst, txRatePerSecond, txRateMaxSources),
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Handler returns the routing table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/block/", s.handleBlock)
	mux.HandleFunc("/account/", s.handleAccount)
	mux.HandleFunc("/tx", s.handleTx)
	return mux
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"method not allowed"})
		return
	}
	// One snapshot, one lock (audit O-8): reading Head() then Height()
	// separately let a commit in between pair the new height with the old
	// head's hash and root. Genesis is immutable, so it needs no such care.
	height, headID, stateRoot := s.chain.HeadSnapshot()
	g := s.chain.Genesis()
	genesisHash := g.Hash()
	writeJSON(w, http.StatusOK, statusResponse{
		ChainID:   g.ChainID,
		Height:    height,
		HeadHash:  hex.EncodeToString(headID[:]),
		StateRoot: hex.EncodeToString(stateRoot[:]),
		Mempool:   s.mempool.Len(),

		GenesisHash:     hex.EncodeToString(genesisHash[:]),
		MinFeeSparks:    g.Params.MinFeeSparks,
		MinStakeSparks:  g.Params.MinStakeSparks,
		EpochBlocks:     g.Params.EpochBlocks,
		UnbondingEpochs: g.Params.UnbondingEpochs,
		CommitteeSize:   g.Params.CommitteeSize,
	})
}

// handleAccount reports the spendable account plus its bond and unbonding
// records for one address.
//
// An unknown address is a 200 with zeroes, not a 404: "this key holds
// nothing" is exactly what a staking client needs to know, and a 404 would
// make a fresh key (every key, before its first claim) look like a broken
// node. The address in the URL is echoed back so a client can check it is
// reading the account it asked for.
//
// The unbonding list is WINDOWED (audit ST-4's "cap or paginate"): `limit` and
// `offset` select a slice of it, `unbonding_total` reports how many records
// exist, and no reply ever serialises more than maxUnbondingLimit records. The
// state itself now bounds an address to UnbondingEpochs+2 records (the
// unmatured window plus one collapsed matured record), so the window is a
// backstop rather than the primary bound - but it is the backstop that keeps
// this unauthenticated endpoint's reply size independent of any state a future
// bug could build.
//
// The read is served from the chain's published state snapshot, which is
// immutable until the next Append replaces it: no lock is held across the
// JSON encode and a commit cannot interleave a half-updated account.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"method not allowed"})
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/account/")
	addr, err := types.ParseAddress(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"address must be a canonical b10 address"})
		return
	}
	offset, limit, err := unbondingWindow(r.URL.Query())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	st := s.chain.State()
	acc := st.Get(addr)
	bond, _ := st.BondOf(addr)
	recs := st.UnbondingOf(addr)
	all := make([]unbondingResponse, 0, len(recs))
	for _, rec := range recs {
		all = append(all, unbondingResponse{Amount: rec.Amount, ReleaseHeight: rec.ReleaseHeight})
	}
	out := accountResponse{
		Address:      addr.String(),
		Balance:      acc.Balance,
		Nonce:        acc.Nonce,
		Bonded:       bond.Amount,
		BondUnfunded: bond.Unfunded,
	}
	out.Unbonding, out.UnbondingTotal = windowUnbonding(all, offset, limit)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"method not allowed"})
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/block/")
	height, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"height must be an unsigned integer"})
		return
	}
	if height > s.chain.Height() {
		writeJSON(w, http.StatusNotFound, errorResponse{"height not found"})
		return
	}
	// Only the head is held in memory; earlier blocks are read from disk.
	b := s.chain.Head()
	if height != b.Header.Height {
		blk, err := s.chain.BlockAt(height)
		if err != nil {
			// Never echo err.Error() here (audit O-8): a store failure names
			// the data directory, the segment file and an offset - filesystem
			// paths a remote client has no business learning. The 404 above
			// already covers "no such height"; anything left is an internal
			// failure and is reported generically.
			writeJSON(w, http.StatusInternalServerError, errorResponse{"internal error: block unavailable"})
			return
		}
		b = blk
	}
	id := b.ID()
	writeJSON(w, http.StatusOK, blockResponse{
		Height:    b.Header.Height,
		Hash:      hex.EncodeToString(id[:]),
		Parent:    hex.EncodeToString(b.Header.ParentHash[:]),
		StateRoot: hex.EncodeToString(b.Header.StateRoot[:]),
		Timestamp: b.Header.Timestamp,
		Txs:       len(b.Txs),
	})
}

// handleTx admits ONE transaction to the mempool. A 200 means the transaction
// was ADMITTED, not that it will be included (audit O-7): a transaction whose
// nonce is ahead of the chain's is held until its predecessors land, and if
// they never do the pool drops it when a block's filter finds it inapplicable.
// There is deliberately no /tx/{id} on this milestone, so a client cannot poll
// that outcome; it learns it by observing the chain's nonce.
func (s *Server) handleTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"method not allowed"})
		return
	}
	// Per-source admission limit (audit R-1): refuse before reading the body or
	// touching the chain, so a flood costs one map lookup per request.
	if !s.txLimiter.allow(sourceHost(r.RemoteAddr)) {
		writeJSON(w, http.StatusTooManyRequests, errorResponse{"too many transactions from this source"})
		return
	}
	defer r.Body.Close()
	// Accept either a bare hex body or a JSON-quoted hex string: read once,
	// trim whitespace and surrounding quotes, then hex-decode. Read one byte
	// past the bound so an oversized body is detected rather than silently
	// truncated (audit O-8).
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTxBodyBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"cannot read body"})
		return
	}
	if len(body) > maxTxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{"transaction body too large"})
		return
	}
	enc := strings.Trim(string(body), " \t\r\n\"")
	if enc == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"expected hex-encoded transaction bytes"})
		return
	}
	raw, err := hex.DecodeString(enc)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid hex"})
		return
	}
	tx, err := types.DecodeTx(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	if err := s.mempool.Add([]types.Tx{*tx})[0]; err != nil {
		// A full pool is a transient CAPACITY condition, not a malformed
		// request: 503 tells a client to retry, 400 would tell it to fix its
		// bytes (audit O-8). Malformed/refused transactions stay 400.
		code := http.StatusBadRequest
		if errors.Is(err, mempool.ErrFull) || errors.Is(err, mempool.ErrClaimPoolFull) {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, errorResponse{err.Error()})
		return
	}
	id := tx.ID()
	writeJSON(w, http.StatusOK, txResponse{TxID: hex.EncodeToString(id[:])})
}
