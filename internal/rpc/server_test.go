package rpc

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s := NewServer(c, mempool.New(100, c.Genesis().Hash(), c.AdmissionHead))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func TestStatusEndpoint(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ChainID != "b10coin-devnet-1" {
		t.Fatalf("chain ID = %q", body.ChainID)
	}
	if body.Height != 0 {
		t.Fatalf("height = %d, want 0", body.Height)
	}
}

func TestBlockEndpointReturnsGenesis(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/block/0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var b blockResponse
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	if b.Height != 0 {
		t.Fatalf("height = %d, want 0", b.Height)
	}
}

func TestBlockEndpointRejectsMissingHeight(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/block/99")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestTxEndpointRejectsGarbage(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Post(ts.URL+"/tx", "text/plain", strings.NewReader("not-hex"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// buildSignedTx returns a valid transfer signed by a fresh key. The RPC
// endpoint only decodes a transaction and verifies its signature - it never
// checks balances - so an unfunded key is sufficient here.
func buildSignedTx(t *testing.T) *types.Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, otherPub, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   types.AddressFromPub(pub),
		PubKey: pub,
		Nonce:  0,
		Fee:    1,
		To:     types.AddressFromPub(otherPub),
		Amount: 1,
	}
	sigHash := tx.SigningHash(genesis.Devnet().Hash())
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return tx
}

func TestTxEndpointAcceptsValidTx(t *testing.T) {
	_, ts := testServer(t)
	enc := hex.EncodeToString(buildSignedTx(t).Encode())
	resp, err := http.Post(ts.URL+"/tx", "text/plain", strings.NewReader(enc))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := make([]byte, 256)
		n, _ := resp.Body.Read(buf)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, buf[:n])
	}
	// A 200 must mean the transaction was actually stored, not merely decoded.
	// A handler that returned 200 without mempool.Add would pass the status
	// check alone.
	status, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer status.Body.Close()
	var body statusResponse
	if err := json.NewDecoder(status.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Mempool != 1 {
		t.Fatalf("mempool holds %d transactions after a 200 POST, want 1", body.Mempool)
	}
}

// The RPC server reads the chain while the node loop appends to it. Run the
// suite with -race and this fails loudly if the guards are ever removed.
func TestRPCReadsAreSafeDuringAppends(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ts := httptest.NewServer(NewServer(c, mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)).Handler())
	defer ts.Close()
	_, priv := genesis.DevValidatorKey()

	// /account reads the same published state snapshot /status does; the
	// concurrent arm covers both so a future lock-free read that is not
	// actually safe fails under -race.
	devPub, _ := genesis.DevAccountKey(0)
	accountURL := ts.URL + "/account/" + types.AddressFromPub(devPub).String()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 80; i++ {
			url := ts.URL + "/status"
			if i%2 == 0 {
				url = accountURL
			}
			resp, err := http.Get(url)
			if err == nil {
				resp.Body.Close()
			}
		}
	}()
	for i := 0; i < 80; i++ {
		// Strictly after the parent, as chain.Append now requires (audit S-8);
		// the test is about concurrent reads during appends, not timestamps.
		b, err := c.Build(priv, nil, c.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}

// Per-source /tx limiting (audit R-1). The clock is injected, so the test is a
// constructed state: no sleep, no kernel buffer, no timing race.
func TestTxEndpointRateLimitsOneSource(t *testing.T) {
	s, ts := testServer(t)
	fixed := time.Unix(1_700_000_000, 0)
	s.txLimiter.now = func() time.Time { return fixed }
	s.txLimiter.burst = 1
	s.txLimiter.rate = 0

	post := func() int {
		enc := hex.EncodeToString(buildSignedTx(t).Encode())
		resp, err := http.Post(ts.URL+"/tx", "text/plain", strings.NewReader(enc))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("first POST /tx = %d, want 200", code)
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("second POST /tx from one source with its burst spent = %d, want 429", code)
	}
	// Other endpoints are not rate limited by the /tx bucket.
	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /status after a rate-limited POST = %d, want 200", resp.StatusCode)
	}
}

func TestSourceLimiterIsPerSource(t *testing.T) {
	l := newSourceLimiter(1, 0, 8)
	l.now = func() time.Time { return time.Unix(0, 0) }
	if !l.allow("1.1.1.1") {
		t.Fatal("the first request from a source must be allowed")
	}
	if l.allow("1.1.1.1") {
		t.Fatal("a source with an empty bucket must be refused")
	}
	if !l.allow("2.2.2.2") {
		t.Fatal("a different source must have its own bucket")
	}
}

func TestSourceLimiterRefills(t *testing.T) {
	l := newSourceLimiter(1, 1, 8) // one token, refilled at one per second
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	if !l.allow("a") {
		t.Fatal("the first request must be allowed")
	}
	if l.allow("a") {
		t.Fatal("a source with an empty bucket must be refused")
	}
	now = now.Add(time.Second)
	if !l.allow("a") {
		t.Fatal("a token should have refilled after one second")
	}
}

func TestSourceLimiterBoundsItsMap(t *testing.T) {
	l := newSourceLimiter(10, 0, 3)
	l.now = func() time.Time { return time.Unix(0, 0) }
	for _, s := range []string{"a", "b", "c", "d", "e"} {
		l.allow(s)
	}
	if len(l.buckets) != 3 {
		t.Fatalf("limiter tracks %d sources, want the bound 3: an address-cycling attacker must not grow the map", len(l.buckets))
	}
}

// Audit O-8: a full pool is a transient capacity condition, not malformed
// input, so POST /tx must answer 503, not 400.
func TestTxEndpointMapsAFullPoolToServiceUnavailable(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	mp := mempool.New(1, c.Genesis().Hash(), c.AdmissionHead)
	srv := httptest.NewServer(NewServer(c, mp).Handler())
	t.Cleanup(srv.Close)

	post := func() int {
		enc := hex.EncodeToString(buildSignedTx(t).Encode())
		resp, err := http.Post(srv.URL+"/tx", "text/plain", strings.NewReader(enc))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("first POST /tx = %d, want 200", code)
	}
	if code := post(); code != http.StatusServiceUnavailable {
		t.Fatalf("a second, distinct transaction into a full pool = %d, want 503 (capacity, not bad input)", code)
	}
}

// Audit O-8: a 500 from the block path must not echo the store's error, which
// names data-directory paths and segment files. The state is constructed by
// deleting the segment an historical read needs, so no timing is involved.
func TestBlockEndpointDoesNotLeakFilesystemPaths(t *testing.T) {
	dir := t.TempDir()
	c, err := chain.Open(genesis.Devnet(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_, priv := genesis.DevValidatorKey()
	for h := 1; h <= 2; h++ {
		b, err := c.Build(priv, nil, c.Head().Header.Timestamp+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	seg := filepath.Join(dir, "00000000.seg")
	if err := os.Remove(seg); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(c, mempool.New(100, c.Genesis().Hash(), c.AdmissionHead)).Handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/block/1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET /block/1 with its segment removed = %d, want 500", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, leak := range []string{dir, "00000000.seg", "no such file"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("500 body leaked %q: %s", leak, body)
		}
	}
}

// Audit O-8: the /tx body bound is a small multiple of a transaction, not
// 1 MiB, and an oversized body is refused as 413 rather than silently
// truncated.
func TestTxEndpointRejectsAnOversizedBody(t *testing.T) {
	_, ts := testServer(t)
	big := strings.Repeat("a", maxTxBodyBytes+1)
	resp, err := http.Post(ts.URL+"/tx", "text/plain", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized POST /tx = %d, want 413", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// M5 Task 6: the node reads a staking client needs
// ---------------------------------------------------------------------------

// TestStatusReportsTheGenesisHashAndTheStakeParams pins the ADDITIVE contract:
// every new field is present and equal to genesis.Devnet's value, and every
// pre-M5 field is still present under its original name. The map decode is the
// point - a renamed key (rather than an added one) would still satisfy a typed
// struct decode, but not the key set.
func TestStatusReportsTheGenesisHashAndTheStakeParams(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	g := genesis.Devnet()
	hash := g.Hash()
	for _, key := range []string{"chain_id", "height", "head_hash", "state_root", "mempool",
		"genesis_hash", "min_fee_sparks", "min_stake_sparks", "epoch_blocks", "unbonding_epochs", "committee_size"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("/status is missing the %q field (add fields, rename none); body: %s", key, raw)
		}
	}

	var got statusResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.GenesisHash != hex.EncodeToString(hash[:]) {
		t.Errorf("genesis_hash = %q, want %x", got.GenesisHash, hash)
	}
	if got.MinFeeSparks != g.Params.MinFeeSparks ||
		got.MinStakeSparks != g.Params.MinStakeSparks ||
		got.EpochBlocks != g.Params.EpochBlocks ||
		got.UnbondingEpochs != g.Params.UnbondingEpochs ||
		got.CommitteeSize != g.Params.CommitteeSize {
		t.Errorf("stake params = (fee %d, stake %d, epoch %d, unbonding %d, committee %d), want genesis (%d, %d, %d, %d, %d)",
			got.MinFeeSparks, got.MinStakeSparks, got.EpochBlocks, got.UnbondingEpochs, got.CommitteeSize,
			g.Params.MinFeeSparks, g.Params.MinStakeSparks, g.Params.EpochBlocks, g.Params.UnbondingEpochs, g.Params.CommitteeSize)
	}
	if got.MinStakeSparks != 1_000*genesis.SparksPerB10 {
		t.Errorf("min_stake_sparks = %d, want MIN_STAKE (10^11)", got.MinStakeSparks)
	}
}

// appendBlock builds one block containing txs with the devnet proposer key and
// appends it, failing the test on any error. It is how these tests construct a
// REAL committed state (a bond, then an unbond) instead of mutating the live
// state behind the chain's back.
func appendBlock(t *testing.T, c *chain.Chain, txs []types.Tx, timestamp int64) {
	t.Helper()
	_, valPriv := genesis.DevValidatorKey()
	blk, err := c.Build(valPriv, txs, timestamp)
	if err != nil {
		t.Fatalf("Build block at %d: %v", c.Height()+1, err)
	}
	if err := c.Append(blk); err != nil {
		t.Fatalf("Append block at %d: %v", c.Height()+1, err)
	}
}

// signTx signs a transaction with priv against the chain's genesis hash - the
// same binding the node checks and the same one the staking verbs use.
func signTx(t *testing.T, c *chain.Chain, tx *types.Tx, priv ed25519.PrivateKey) {
	t.Helper()
	hash := tx.SigningHash(c.Genesis().Hash())
	tx.Sig = crypto.Sign(priv, hash[:])
}

// TestAccountReportsBondAndUnbonding constructs a real bond and a real
// unbonding record through two committed blocks and reads them back from
// /account. The release height is asserted as a HEIGHT derived from the chain's
// own params (the epoch boundary at or after h +
// UnbondingEpochs*EpochBlocks), not as a duration.
func TestAccountReportsBondAndUnbonding(t *testing.T) {
	s, ts := testServer(t)
	c := s.chain
	g := c.Genesis()
	devPub, devPriv := genesis.DevAccountKey(0)
	addr := types.AddressFromPub(devPub)
	const minStake = 1_000 * genesis.SparksPerB10
	// 1,400 b10 bonded so the 400 b10 exit below leaves exactly MIN_STAKE:
	// audit ST-1 refuses a partial exit that would leave a sub-minimum bond.
	const bonded = 1_400 * genesis.SparksPerB10

	bond := &types.Tx{
		Type: types.TxBond, From: addr, PubKey: devPub,
		Nonce: 0, Fee: g.Params.MinFeeSparks, Amount: bonded,
	}
	signTx(t, c, bond, devPriv)
	appendBlock(t, c, []types.Tx{*bond}, g.Time+1)
	if c.Height() != 1 {
		t.Fatalf("height = %d, want 1", c.Height())
	}

	unbond := &types.Tx{
		Type: types.TxUnbond, From: addr, PubKey: devPub,
		Nonce: 1, Fee: 0, Amount: 400 * genesis.SparksPerB10,
	}
	signTx(t, c, unbond, devPriv)
	appendBlock(t, c, []types.Tx{*unbond}, g.Time+2)
	if c.Height() != 2 {
		t.Fatalf("height = %d, want 2", c.Height())
	}

	resp, err := http.Get(ts.URL + "/account/" + addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /account = %d, want 200", resp.StatusCode)
	}
	var got accountResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Address != addr.String() {
		t.Errorf("address = %q, want %q", got.Address, addr.String())
	}
	wantBalance := 1_000_000*genesis.SparksPerB10 - bonded - g.Params.MinFeeSparks
	if got.Balance != wantBalance {
		t.Errorf("balance = %d, want %d", got.Balance, wantBalance)
	}
	if got.Nonce != 2 {
		t.Errorf("nonce = %d, want 2", got.Nonce)
	}
	if want := uint64(minStake); got.Bonded != want {
		t.Errorf("bonded = %d, want %d (1,400 less the 400 b10 exit is exactly MIN_STAKE)", got.Bonded, want)
	}
	// This bond was created by a Bond transaction, so none of it is a genesis
	// grant: the whole of it is withdrawable (audit ST-3).
	if got.BondUnfunded != 0 {
		t.Errorf("bond_unfunded = %d, want 0 for a bond a transaction funded", got.BondUnfunded)
	}
	// The release height is the epoch boundary at or after the cooldown's floor
	// (audit ST-4): 2 + 2*1,000 = 2,002, rounded up to 3,000 on the devnet's
	// 1,000-block epochs. Never earlier than the floor.
	floor := uint64(2) + g.Params.UnbondingEpochs*g.Params.EpochBlocks
	if len(got.Unbonding) != 1 {
		t.Fatalf("unbonding = %+v, want one record", got.Unbonding)
	}
	if got.Unbonding[0].Amount != 400*genesis.SparksPerB10 {
		t.Errorf("unbonding amount = %d, want %d", got.Unbonding[0].Amount, 400*genesis.SparksPerB10)
	}
	if got.Unbonding[0].ReleaseHeight != 3_000 {
		t.Errorf("release_height = %d, want 3000 (the epoch boundary at or after %d = height 2 + %d epochs x %d blocks)",
			got.Unbonding[0].ReleaseHeight, floor, g.Params.UnbondingEpochs, g.Params.EpochBlocks)
	}
	if got.UnbondingTotal != 1 {
		t.Errorf("unbonding_total = %d, want 1", got.UnbondingTotal)
	}
}

// TestAccountForAFreshKeyIsZeroesNotEmpty404: the staking verbs read /account
// for a key that may never have transacted, so "holds nothing" must be a
// readable zero record - and the unbonding list must be [], not null.
func TestAccountForAFreshKeyIsZeroesNotEmpty404(t *testing.T) {
	_, ts := testServer(t)
	pub, _ := genesis.DevAccountKey(1) // the zero-balance recipient fixture
	addr := types.AddressFromPub(pub)
	resp, err := http.Get(ts.URL + "/account/" + addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /account for a fresh key = %d, want 200", resp.StatusCode)
	}
	var got accountResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Balance != 0 || got.Nonce != 0 || got.Bonded != 0 || len(got.Unbonding) != 0 {
		t.Errorf("fresh account = %+v, want all zero", got)
	}
	raw, _ := json.Marshal(got)
	if !strings.Contains(string(raw), `"unbonding":[]`) {
		t.Errorf("unbonding must encode as [] for a key with none: %s", raw)
	}

	bad, err := http.Get(ts.URL + "/account/not-an-address")
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /account with a malformed address = %d, want 400", bad.StatusCode)
	}
}

// TestAccountReportsAGenesisBondsUnfundedPart is /account's half of audit ST-3:
// a genesis seat's bond is reported as bonded (it votes) and as unfunded (it is
// not money). The devnet fixture's genesis validator is the shape every
// committee-file seat has - Amount = Power from no account.
func TestAccountReportsAGenesisBondsUnfundedPart(t *testing.T) {
	_, ts := testServer(t)
	g := genesis.Devnet()
	addr := types.AddressFromPub(g.Validators[0].PubKey)

	resp, err := http.Get(ts.URL + "/account/" + addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got accountResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if want := g.Validators[0].Power; got.Bonded != want || got.BondUnfunded != want {
		t.Fatalf("bonded = %d, bond_unfunded = %d, want both %d (a genesis seat's whole bond is unfunded)",
			got.Bonded, got.BondUnfunded, want)
	}
}

// TestAccountUnbondingWindow: the unbonding list is windowed so no reply size
// is a function of the state (audit ST-4). A one-record chain is enough to pin
// the offset/limit arithmetic and every rejection path.
func TestAccountUnbondingWindow(t *testing.T) {
	s, ts := testServer(t)
	c := s.chain
	g := c.Genesis()
	devPub, devPriv := genesis.DevAccountKey(0)
	addr := types.AddressFromPub(devPub)
	const minStake = 1_000 * genesis.SparksPerB10

	bond := &types.Tx{Type: types.TxBond, From: addr, PubKey: devPub, Nonce: 0, Fee: g.Params.MinFeeSparks, Amount: minStake}
	signTx(t, c, bond, devPriv)
	appendBlock(t, c, []types.Tx{*bond}, g.Time+1)
	unbond := &types.Tx{Type: types.TxUnbond, From: addr, PubKey: devPub, Nonce: 1, Fee: 0, Amount: minStake}
	signTx(t, c, unbond, devPriv)
	appendBlock(t, c, []types.Tx{*unbond}, g.Time+2)

	get := func(query string) (accountResponse, int) {
		t.Helper()
		resp, err := http.Get(ts.URL + "/account/" + addr.String() + query)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body accountResponse
		if resp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
		}
		return body, resp.StatusCode
	}

	for _, tc := range []struct {
		name      string
		query     string
		status    int
		wantLen   int
		wantTotal int
	}{
		{"no window", "", http.StatusOK, 1, 1},
		{"limit covers it", "?limit=4", http.StatusOK, 1, 1},
		{"limit one", "?limit=1", http.StatusOK, 1, 1},
		{"offset past the end", "?offset=1", http.StatusOK, 0, 1},
		{"offset and limit", "?offset=0&limit=1", http.StatusOK, 1, 1},
		{"huge limit is clamped", "?limit=999999", http.StatusOK, 1, 1},
		{"zero limit is refused", "?limit=0", http.StatusBadRequest, 0, 0},
		{"non-numeric limit is refused", "?limit=x", http.StatusBadRequest, 0, 0},
		{"non-numeric offset is refused", "?offset=-1", http.StatusBadRequest, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, status := get(tc.query)
			if status != tc.status {
				t.Fatalf("GET /account%s = %d, want %d", tc.query, status, tc.status)
			}
			if status != http.StatusOK {
				return
			}
			if len(body.Unbonding) != tc.wantLen || body.UnbondingTotal != tc.wantTotal {
				t.Fatalf("unbonding = %d records (total %d), want %d (total %d)",
					len(body.Unbonding), body.UnbondingTotal, tc.wantLen, tc.wantTotal)
			}
			if body.Unbonding == nil {
				t.Fatal("unbonding is null, want []")
			}
		})
	}
}

// TestWindowUnbondingIsBoundedByTheLimit is the reply-size bound directly: the
// handler never serialises more than maxUnbondingLimit records, whatever the
// state holds and whatever the client asks for.
func TestWindowUnbondingIsBoundedByTheLimit(t *testing.T) {
	all := make([]unbondingResponse, 300)
	for i := range all {
		all[i] = unbondingResponse{Amount: uint64(i + 1), ReleaseHeight: uint64(1000 * (i + 1))}
	}

	offset, limit, err := unbondingWindow(url.Values{"limit": {"999999"}})
	if err != nil {
		t.Fatalf("parsing a huge limit: %v", err)
	}
	if limit != maxUnbondingLimit {
		t.Fatalf("limit = %d, want it clamped to %d", limit, maxUnbondingLimit)
	}
	page, total := windowUnbonding(all, offset, limit)
	if total != len(all) || len(page) != maxUnbondingLimit {
		t.Fatalf("window = %d of %d, want %d of %d", len(page), total, maxUnbondingLimit, len(all))
	}
	if page[0].Amount != all[0].Amount || page[len(page)-1].Amount != all[maxUnbondingLimit-1].Amount {
		t.Fatal("the window is not the prefix it claims to be")
	}

	// Offset arithmetic, including an offset past the end.
	page, total = windowUnbonding(all, 295, 64)
	if total != 300 || len(page) != 5 || page[0].Amount != all[295].Amount {
		t.Fatalf("offset window = %d records from offset 295 of %d, want 5", len(page), total)
	}
	page, total = windowUnbonding(all, 400, 64)
	if total != 300 || len(page) != 0 || page == nil {
		t.Fatalf("past-the-end window = %d of %d (nil %v), want an empty, non-nil window", len(page), total, page == nil)
	}
	// No limit can make the reply larger than the bound.
	for _, ask := range []string{"1", "64", "256", "257", "999999999"} {
		_, limit, err := unbondingWindow(url.Values{"limit": {ask}})
		if err != nil {
			t.Fatalf("limit %s: %v", ask, err)
		}
		if limit > maxUnbondingLimit {
			t.Fatalf("limit %s parsed to %d, above the %d bound", ask, limit, maxUnbondingLimit)
		}
	}
}
