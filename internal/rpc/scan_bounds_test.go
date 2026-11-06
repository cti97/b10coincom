package rpc

// Audit R-1 (2026-11-01): the /history scan, and the explorer that shares it,
// must stop when the client is gone, must not run unboundedly many times at
// once, and must cost a source something per request. Each test pins one of
// the three bounds against the handler, not the helper.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// growChain appends n empty blocks so a scan has something to read.
func growChain(t *testing.T, s *Server, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		appendBlock(t, s.chain, nil, s.chain.Head().Header.Timestamp+1)
	}
}

func TestHistoryWritesNothingForARequestTheClientAbandoned(t *testing.T) {
	s, _ := testServer(t)
	growChain(t, s, 8)
	h := s.Handler()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client is gone before the scan starts
	gone := httptest.NewRecorder()
	h.ServeHTTP(gone, httptest.NewRequest(http.MethodGet, "/history?blocks=8", nil).WithContext(ctx))
	if gone.Body.Len() != 0 {
		t.Fatalf("a request whose client had gone was scanned and answered anyway (%d body bytes): the scan does not watch the request context (audit R-1)", gone.Body.Len())
	}

	// The control: the same request with a live client is answered in full.
	live := httptest.NewRecorder()
	h.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/history?blocks=8", nil))
	if live.Code != http.StatusOK || live.Body.Len() == 0 {
		t.Fatalf("the live request was not answered: %d %q", live.Code, live.Body.String())
	}
}

func TestScansAreRateLimitedPerSource(t *testing.T) {
	s, _ := testServer(t)
	growChain(t, s, 3)
	h := s.Handler()
	get := func(path, from string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = from
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// One source, a tight loop: well before a thousand requests the bucket
	// must run dry and stay dry.
	limited := 0
	for i := 0; i < 1000; i++ {
		if get("/history?blocks=3", "203.0.113.9:4242") == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("a thousand /history scans from one source were all served: the scan endpoints sit outside any per-source limit (audit R-1)")
	}
	if code := get("/history?blocks=3", "203.0.113.9:4242"); code != http.StatusTooManyRequests {
		t.Fatalf("the exhausted source was served again (%d): the limit refilled a whole burst within the loop", code)
	}
	// The explorer draws on the same bucket: it is the same scan.
	if code := get("/explorer", "203.0.113.9:4242"); code != http.StatusTooManyRequests {
		t.Fatalf("/explorer from the exhausted source was served (%d): the two scan endpoints do not share a limit", code)
	}
	// Another source is unaffected.
	if code := get("/history?blocks=3", "198.51.100.7:4242"); code != http.StatusOK {
		t.Fatalf("a second source was refused (%d): the limit is not per source", code)
	}
}

// withoutScanLimit lifts the per-source scan bucket on a test server whose
// subject is something other than the limit (a page's content, read safety
// during appends): those tests fire more requests from one address than a
// real source is allowed, and the limit has its own test above.
func withoutScanLimit(s *Server) {
	s.scanLimiter = newSourceLimiter(1<<30, 1<<30, txRateMaxSources)
}

func TestScansRefuseWhenEverySlotIsBusy(t *testing.T) {
	s, _ := testServer(t)
	withoutScanLimit(s) // the slot bound is the subject, not the bucket
	growChain(t, s, 3)
	h := s.Handler()
	get := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}

	// Occupy every scan slot as in-flight scans would.
	for i := 0; i < maxConcurrentScans; i++ {
		s.scanSlots <- struct{}{}
	}
	if code := get("/history?blocks=3"); code != http.StatusServiceUnavailable {
		t.Fatalf("/history with every scan slot busy = %d, want 503: nothing bounds how many scans run at once (audit R-1)", code)
	}
	if code := get("/explorer"); code != http.StatusServiceUnavailable {
		t.Fatalf("/explorer with every scan slot busy = %d, want 503", code)
	}
	// A refused request must not have consumed a slot it never held.
	<-s.scanSlots
	if code := get("/history?blocks=3"); code != http.StatusOK {
		t.Fatalf("/history after one slot freed = %d, want 200", code)
	}
	// And a served request returns its slot.
	if code := get("/history?blocks=3"); code != http.StatusOK {
		t.Fatalf("/history a second time after one slot freed = %d, want 200: the served scan kept its slot", code)
	}
	// The faucet page scans nothing and is unaffected by busy slots.
	for len(s.scanSlots) < maxConcurrentScans {
		s.scanSlots <- struct{}{}
	}
	if code := get("/faucet"); code != http.StatusOK {
		t.Fatalf("/faucet with every scan slot busy = %d, want 200: it reads no blocks", code)
	}
}

// Audit S-8: /block performs the same store read as /history - serialised on
// the store mutex, allocating the block - so it must charge the same bucket.
// The assertions are over the endpoint's codes and sentences, and the shared
// bucket is proven from the OTHER side: /block's flood exhausts /history.
func TestBlockIsRateLimitedPerSource(t *testing.T) {
	s, _ := testServer(t)
	growChain(t, s, 3)
	h := s.Handler()
	get := func(path, from string) (int, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = from
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// One source, a tight loop: the bucket runs dry and stays dry.
	limited := 0
	for i := 0; i < 1000; i++ {
		if code, _ := get("/block/1", "203.0.113.9:4242"); code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("a thousand /block reads from one source were all served: /block sits outside the scan limit (audit S-8)")
	}
	// The 429 is the scan endpoints' own sentence, not a new one.
	code, body := get("/block/1", "203.0.113.9:4242")
	if code != http.StatusTooManyRequests {
		t.Fatalf("/block from the exhausted source = %d, want 429", code)
	}
	if want := (errorResponse{"too many scans from this source"}); body != "{\"error\":\""+want.Error+"\"}\n" {
		t.Fatalf("/block's 429 body = %q, want the scan endpoints' own sentence", body)
	}
	// The bucket is SHARED: the same source is now refused /history too.
	if code, _ := get("/history?blocks=3", "203.0.113.9:4242"); code != http.StatusTooManyRequests {
		t.Fatalf("/history from the source that exhausted /block = %d, want 429: /block does not charge the scan bucket", code)
	}
	// Another source is unaffected.
	if code, _ := get("/block/1", "198.51.100.7:4242"); code != http.StatusOK {
		t.Fatalf("a second source's /block = %d, want 200: the limit is not per source", code)
	}
}

// TestBlockRefusesWhenEverySlotIsBusy pins the in-flight half: /block takes a
// scan slot, refuses with /history's 503 when none is free, and returns the
// slot it took.
func TestBlockRefusesWhenEverySlotIsBusy(t *testing.T) {
	s, _ := testServer(t)
	withoutScanLimit(s) // the slot bound is the subject, not the bucket
	growChain(t, s, 3)
	h := s.Handler()
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}

	for i := 0; i < maxConcurrentScans; i++ {
		s.scanSlots <- struct{}{}
	}
	code, body := get("/block/1")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("/block with every scan slot busy = %d, want 503: nothing bounds how many block reads run at once (audit S-8)", code)
	}
	if want := (errorResponse{"the node is busy scanning for other clients; retry shortly"}); body != "{\"error\":\""+want.Error+"\"}\n" {
		t.Fatalf("/block's 503 body = %q, want the scan endpoints' own sentence", body)
	}
	// A refused request must not have consumed a slot it never held.
	if len(s.scanSlots) != maxConcurrentScans {
		t.Fatalf("the refused /block left %d slots held, want %d", len(s.scanSlots), maxConcurrentScans)
	}
	for i := 0; i < maxConcurrentScans; i++ {
		<-s.scanSlots
	}
	if code, _ := get("/block/1"); code != http.StatusOK {
		t.Fatalf("/block after every slot freed = %d, want 200", code)
	}
	if n := len(s.scanSlots); n != 0 {
		t.Fatalf("a served /block kept %d scan slots, want 0: it must release what it took", n)
	}
	// The head path is slot-bounded too (the handler's shape has no special
	// case), and /history's own contract is untouched by this test.
	if code, _ := get("/history?blocks=3"); code != http.StatusOK {
		t.Fatalf("/history after the slots freed = %d, want 200", code)
	}
}

// TestBlockAllowsAnHonestPollRate is the S-8 honesty half: a client polling
// its own node once a second for a minute is never refused. The clock is the
// limiter's own seam, so this is a constructed minute, not a slow test.
func TestBlockAllowsAnHonestPollRate(t *testing.T) {
	s, _ := testServer(t)
	growChain(t, s, 5)
	now := time.Now()
	s.scanLimiter.now = func() time.Time { return now }
	h := s.Handler()

	for i := 0; i < 60; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/block/1", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("poll %d of a one-per-second honest client = %d, want 200: /block is unusably strict (%q)",
				i+1, rec.Code, rec.Body.String())
		}
		now = now.Add(time.Second)
	}
}
