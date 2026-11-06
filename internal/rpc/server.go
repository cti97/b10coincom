// Package rpc exposes a small read/write HTTP API for the node.
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

	// M6: the amount one faucet claim pays, in sparks. APPENDED, never a
	// rename or a repurposing, so a client written against M5 keeps parsing
	// this body - the contract stated above. The wallet's read commands do
	// not need it; the walkthrough and the faucet page do, and re-deriving it
	// from a compiled-in assumption is exactly the second source of truth
	// /status exists to prevent.
	ClaimAmountSparks uint64 `json:"claim_amount_sparks"`
}

// accountResponse is the /account/{address} view: the spendable account plus
// the two locked-stake records the staking verbs must know about. Amounts are
// sparks (uint64), never b10 and never a float. They travel as JSON NUMBERS,
// not strings, to keep the wire contract additive; every on-chain amount is
// below 2^53 because the supply cap is 2.1e15, so an IEEE-754 reader holds each
// one exactly, but a client doing arithmetic must use 64-bit integers (audit
// CL-4).
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
//
// THE LIST IS NOT A PER-EPOCH HISTORY, AND IT MUST NOT BE READ AS ONE (audit
// C-5). state.mergeUnbonding rewrites every record already MATURE at an unbond's
// applying height into one record at the EARLIEST of their release heights and
// the sum of their amounts. That is what bounds an address to at most
// UnbondingEpochs+2 records (audit ST-4), and it is indistinguishable to a
// Withdraw - which releases every record at or below its block's height, so
// already-mature records pay identically whenever they are merged. What it costs
// is exactly the archaeology: two epochs' records that have both matured show one
// entry, at the earlier release height, with the combined amount. A client that
// needs "which epoch did each unbond happen in" must read the blocks, not this
// endpoint.
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
	// maxUnbondingOffset bounds the parsed offset so the int conversion below
	// is safe on every platform Go builds for, including 32-bit ones. The
	// state bounds this list to UnbondingEpochs+2 records, so any offset this
	// large is already past the end and means "empty window"; clamping it
	// there loses no request a client could have meant, and it cannot wrap to
	// a negative index (audit S-14).
	maxUnbondingOffset = 1<<31 - 1
)

// unbondingWindow parses limit/offset. Absent values take the defaults; a
// non-numeric, zero limit or an offset that is not a number is a client error
// rather than a silently different window. A limit above maxUnbondingLimit is
// clamped, not refused: the client asked for "as much as allowed".
//
// BOTH FIELDS PARSE AT 64 BITS and are clamped afterwards (audit S-14). A
// 31-bit parse rejected 2^31 and above as "not a positive integer" - false
// about the value and contrary to the clamp promise above. With a uint64 parse
// the only refusals are values no count can be: zero limit, non-numeric,
// negative, or above 2^64-1. The offset is additionally clamped to
// maxUnbondingOffset so int(v) cannot overflow.
func unbondingWindow(q url.Values) (offset, limit int, err error) {
	limit = defaultUnbondingLimit
	if raw := q.Get("limit"); raw != "" {
		v, perr := strconv.ParseUint(raw, 10, 64)
		if perr != nil || v == 0 {
			return 0, 0, errors.New("limit must be a positive integer that fits in 64 bits")
		}
		if v > maxUnbondingLimit {
			v = maxUnbondingLimit
		}
		limit = int(v)
	}
	if raw := q.Get("offset"); raw != "" {
		v, perr := strconv.ParseUint(raw, 10, 64)
		if perr != nil {
			return 0, 0, errors.New("offset must be a non-negative integer that fits in 64 bits")
		}
		if v > maxUnbondingOffset {
			v = maxUnbondingOffset
		}
		offset = int(v)
	}
	return offset, limit, nil
}

// unbondingBounds clamps the [offset, offset+limit) window to a list of total
// records. It is bounds arithmetic only, so the handler can convert JUST the
// window instead of copying every record into a response struct and copying the
// page again (audit ST-10). An offset past the end is an empty window, not an
// error: "there is nothing after these" is a valid answer.
func unbondingBounds(total, offset, limit int) (lo, hi int) {
	if offset > total {
		offset = total
	}
	hi = offset + limit
	if hi > total || hi < offset {
		hi = total
	}
	return offset, hi
}

type blockResponse struct {
	Height    uint64 `json:"height"`
	Hash      string `json:"hash"`
	Parent    string `json:"parent"`
	StateRoot string `json:"state_root"`
	Timestamp int64  `json:"timestamp"`
	Txs       int    `json:"tx_count"`
}

// txResponse is one POST /tx reply: the admitted transaction's ID, and - when
// this server knows the key the node signs blocks with - whether that key holds
// a committee seat at the height the transaction would need (testrun S-2).
//
// BOTH FIELDS ARE APPENDED, never a rename: a client written against the M5
// shape keeps parsing this body. They are emitted together and only when the
// server can answer, because "seated" is a claim about a specific signing key;
// a server built without one (a test, an embedded reader) has nothing to say
// and says nothing rather than answering a question it was not asked.
//
// A `seated: false` reply is still a 200. The transaction WAS admitted, and a
// status code that said otherwise would be a lie about what happened; what an
// operator needs to know is that admission is the end of it on this node. See
// handleTx.
type txResponse struct {
	TxID    string `json:"txid"`
	Seated  *bool  `json:"seated,omitempty"`
	Warning string `json:"warning,omitempty"`
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

	// The scan endpoints (/history and /explorer, audit R-1) get their own,
	// smaller bucket: one request is up to maxHistoryBlocks disk reads and
	// decodes, so a source is allowed a few windows per second, not sixty-four.
	// Sources are bounded the same way as the transaction limiter's.
	scanRateBurst     = 16
	scanRatePerSecond = 4
	// maxConcurrentScans bounds how many block scans run at once across every
	// source (audit R-1). The limiter bounds the rate per source; this bounds
	// the work in flight, which is what a client that opens requests and drops
	// them would otherwise multiply: every historical read serialises on the
	// store, so N abandoned scans are N windows of reads queued on one mutex.
	// A refused request costs nothing and is told to retry (503).
	maxConcurrentScans = 4

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
	// scanLimiter bounds the per-source rate of block scans (audit R-1).
	scanLimiter *sourceLimiter
	// scanSlots holds one token per scan in flight; a send that would block
	// means every slot is busy and the request is refused, never queued.
	scanSlots chan struct{}
	// genesisHash is the chain's immutable genesis identifier, computed once
	// at construction (audit CL-4): /status used to re-hash the whole genesis
	// on every request. Genesis cannot change under a running chain, so the
	// hash cannot either.
	genesisHash [32]byte
	// seatKey is the validator public key this node signs blocks with, when it
	// has one (testrun S-2). It is a COPY: the caller's slice is not retained,
	// so a caller reusing its buffer cannot change what this server answers.
	// Empty means "this server does not sign for a chain", and then POST /tx
	// reports nothing about seats.
	seatKey []byte
}

// NewServer binds the chain and mempool to HTTP handlers for a server that does
// not sign blocks (a test, an embedded reader). POST /tx can admit a
// transaction but cannot say whether any block will ever carry it, so its reply
// carries no seat fields.
func NewServer(c *chain.Chain, mp *mempool.Mempool) *Server {
	return newServer(c, mp, nil)
}

// NewServerWithSigningKey is NewServer for a node that proposes blocks with
// seatKey. POST /tx then tells the client when that key holds no committee seat
// at the height the transaction would need (testrun S-2): a transaction reaches
// a block only when the node it was posted to proposes one, so on an unseated
// node "accepted" is the end of the story, and saying so is the difference
// between an operator who reposts to a seated validator and one who waits.
func NewServerWithSigningKey(c *chain.Chain, mp *mempool.Mempool, seatKey []byte) *Server {
	return newServer(c, mp, seatKey)
}

func newServer(c *chain.Chain, mp *mempool.Mempool, seatKey []byte) *Server {
	s := &Server{
		chain:       c,
		mempool:     mp,
		txLimiter:   newSourceLimiter(txRateBurst, txRatePerSecond, txRateMaxSources),
		scanLimiter: newSourceLimiter(scanRateBurst, scanRatePerSecond, txRateMaxSources),
		scanSlots:   make(chan struct{}, maxConcurrentScans),
		genesisHash: c.Genesis().Hash(),
	}
	if len(seatKey) > 0 {
		s.seatKey = append([]byte(nil), seatKey...)
	}
	return s
}

// acquireScanSlot takes a scan slot without waiting. ok is false when every
// slot is busy; otherwise release must be called when the scan is done.
func (s *Server) acquireScanSlot() (release func(), ok bool) {
	select {
	case s.scanSlots <- struct{}{}:
		return func() { <-s.scanSlots }, true
	default:
		return nil, false
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
	mux.HandleFunc("/history", s.handleHistory)
	// The pages (M6 Tasks 2 and 3) are HANDLERS on this same server: they add
	// no listener, no authentication and no write path, so the node's single
	// loopback-bound --http address serves them beside the JSON API.
	mux.HandleFunc("/faucet", s.handleFaucet)
	mux.HandleFunc("/explorer", s.handleExplorer)
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
	// head's hash and root. Genesis is immutable, so it needs no such care,
	// and its hash is cached at construction (audit CL-4).
	height, headID, stateRoot := s.chain.HeadSnapshot()
	g := s.chain.Genesis()
	genesisHash := s.genesisHash
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

		ClaimAmountSparks: g.Params.ClaimAmountSparks,
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
// ONE bounded clone-and-sort remains, and it is the accessor's contract rather
// than waste (audit ST-10): UnbondingOf returns a sorted COPY so the reply is
// ordered by release height and a caller cannot mutate committed state through
// it. It is O(UnbondingEpochs+2), not O(state): at most four records on the
// shipped parameters. What this handler no longer does is copy the whole list a
// SECOND time into response structs and then copy the page again; it converts
// only the records inside the window, so the per-request work is the sort plus
// at most maxUnbondingLimit conversions.
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
	lo, hi := unbondingBounds(len(recs), offset, limit)
	out := accountResponse{
		Address:      addr.String(),
		Balance:      acc.Balance,
		Nonce:        acc.Nonce,
		Bonded:       bond.Amount,
		BondUnfunded: bond.Unfunded,
	}
	out.Unbonding = make([]unbondingResponse, 0, hi-lo)
	for _, rec := range recs[lo:hi] {
		out.Unbonding = append(out.Unbonding, unbondingResponse{Amount: rec.Amount, ReleaseHeight: rec.ReleaseHeight})
	}
	out.UnbondingTotal = len(recs)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"method not allowed"})
		return
	}
	// /block performs the same store read as /history - one block, off the
	// same mutex, allocating up to MaxBlockBytes - so it charges the same
	// bucket and takes the same slot (audit R-1, S-8). The 429 and the 503
	// below are /history's own sentences, so the two endpoints present ONE
	// contract. The bucket is charged before the path is parsed or a block is
	// read, exactly as in /history: a refused request costs a map lookup.
	//
	// The allowance inherited is the scan bucket's: a burst of 16 and 4/s per
	// source, shared with /history and /explorer. That is far above an honest
	// client polling its own node (one lookup per commit is a fraction of
	// 4/s), and the endpoint is a per-height read, not the sync protocol -
	// catch-up is the P2P BLOCK_SYNC path. A client that wants a long run of
	// heights is exactly the amplification R-1 bounds, and it can pace itself.
	if !s.scanLimiter.allow(sourceHost(r.RemoteAddr)) {
		writeJSON(w, http.StatusTooManyRequests, errorResponse{"too many scans from this source"})
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
	// The in-flight bound, taken exactly as /history takes it: never queued,
	// so a busy node says 503 rather than piling another store read behind
	// three abandoned ones. The head is memory-only, but the slot is taken for
	// both paths so the bound covers the disk read a height behind head
	// performs without a special case to get wrong.
	release, ok := s.acquireScanSlot()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{"the node is busy scanning for other clients; retry shortly"})
		return
	}
	defer release()
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
//
// THE STRONGER REASON "admitted" is not "included" (testrun S-2): proposals are
// built from the LOCAL pool (consensus.Driver.build), and no transaction is
// gossiped, so a transaction reaches a block only through the node it was
// posted to and only in a round where that node is the proposer. On a node
// whose key holds no committee seat the pool never feeds a block at all - the
// live finding is an Unbond that waited 400 blocks in a displaced seat's pool
// and applied in 12 s when the same bytes were posted to a seated node. That is
// a property of the design, not a defect, so the fix is to say it: when this
// server knows the node's signing key it reports whether that key holds a seat
// at the height a transaction would need, and an unseated reply explains what
// the pool now means. The status stays 200 because the admission really did
// happen, and a refusal would read as "your bytes are wrong" to a client whose
// bytes are fine; the warning is in the body, and the CLI prints it beside the
// txid.
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
	resp := txResponse{TxID: hex.EncodeToString(id[:])}
	if len(s.seatKey) > 0 {
		// The height a transaction posted now would have to be carried at. The
		// chain decides head+1 next, so that is the height whose committee
		// matters - at an epoch boundary it is the NEXT epoch's set, which is
		// exactly the seat an operator needs to know about.
		height := s.chain.Height() + 1
		seated, warning := s.seatStatus(height)
		resp.Seated = &seated
		resp.Warning = warning
	}
	writeJSON(w, http.StatusOK, resp)
}

// seatStatus reports whether this node can propose at height h, and why not
// when it cannot. It is called only when the server knows the signing key.
//
// The question is asked of the chain, not kept in a field: IsSeatedAt is the
// chain's own read-locked membership test over the memoised epoch set - the one
// the router calls for every vote and proposal (audit RT-6) - so it allocates
// nothing on the seated path and adds no lock. The answer cannot be a stale
// read: an epoch's set is a pure function of the state at epoch*E-1, which is
// committed before any height in that epoch can be asked about and never
// changes afterwards, so a commit racing this reply can only make the answer
// NEWER than the height it names, never wrong for that height.
//
// IsSeatedAt answers false for "not seated" and for "this chain cannot derive a
// committee at h", and the two need different sentences, so the false case asks
// CommitteeAt - the diagnostic seam its own doc comment names - to tell them
// apart. That costs one copy of the seat set on the refusal path only.
func (s *Server) seatStatus(h uint64) (seated bool, warning string) {
	if s.chain.IsSeatedAt(h, s.seatKey) {
		return true, ""
	}
	if _, err := s.chain.CommitteeAt(h); err != nil {
		return false, fmt.Sprintf("this node cannot derive the committee that judges height %d (%v), so no proposal can carry the transaction yet; it is parked in this node's mempool. Post the same bytes to a node that is running and seated", h, err)
	}
	return false, fmt.Sprintf("this node's key holds no committee seat at height %d, so this node will not propose a block there and the transaction cannot be included until it holds one; it is parked in this node's mempool. A transaction reaches a block only through the node it was posted to: post the same bytes to a node that holds a seat (any validator that the committee lists at that height)", h)
}
