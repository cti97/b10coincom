// Package rpc exposes a small read/write HTTP API for the node.
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

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

// Server binds the chain and mempool to HTTP handlers.
type Server struct {
	chain   *chain.Chain
	mempool *mempool.Mempool
}

func NewServer(c *chain.Chain, mp *mempool.Mempool) *Server {
	return &Server{chain: c, mempool: mp}
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
	head := s.chain.Head()
	h := head.ID()
	sr := head.Header.StateRoot
	writeJSON(w, http.StatusOK, statusResponse{
		ChainID:   s.chain.Genesis().ChainID,
		Height:    s.chain.Height(),
		HeadHash:  hex.EncodeToString(h[:]),
		StateRoot: hex.EncodeToString(sr[:]),
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
			writeJSON(w, http.StatusInternalServerError, errorResponse{err.Error()})
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

func (s *Server) handleTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"method not allowed"})
		return
	}
	defer r.Body.Close()
	// Accept either a bare hex body or a JSON-quoted hex string: read once,
	// trim whitespace and surrounding quotes, then hex-decode.
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"cannot read body"})
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
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	id := tx.ID()
	writeJSON(w, http.StatusOK, txResponse{TxID: hex.EncodeToString(id[:])})
}
