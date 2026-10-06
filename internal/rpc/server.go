// Package rpc exposes a small read/write HTTP API for the node.
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

type statusResponse struct {
	ChainID   string `json:"chain_id"`
	Height    uint64 `json:"height"`
	HeadHash  string `json:"head_hash"`
	StateRoot string `json:"state_root"`
	Mempool   int    `json:"mempool"`
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
	writeJSON(w, http.StatusOK, statusResponse{
		ChainID:   s.chain.Genesis().ChainID,
		Height:    height,
		HeadHash:  hex.EncodeToString(headID[:]),
		StateRoot: hex.EncodeToString(stateRoot[:]),
		Mempool:   s.mempool.Len(),
	})
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
