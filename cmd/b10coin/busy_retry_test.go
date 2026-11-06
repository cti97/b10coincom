package main

// The wallet CLI's half of the 503 story (testrun 2026-11-06, Info): the
// node's four-slot scan semaphore answers a read with "the node is busy
// scanning for other clients; retry shortly", which is the throttle working as
// designed (audit R-1/S-8). A single CLI invocation must treat that as "wait
// and ask again", not as a failure: with 20 parallel mixed requests, 4 of 5
// `b10coin history` runs exited 1 on it.
//
// The state is CONSTRUCTED with an httptest handler that counts calls and
// answers 503 a fixed number of times, so the retry is proven by the call
// count and the eventual value - never by hoping a real node is busy.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const busySentence = "the node is busy scanning for other clients; retry shortly"

// busyThenOK serves 503 for its first `busy` requests, then one JSON object.
func busyThenOK(t *testing.T, busy int32, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= busy {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, busySentence+"\n")
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestGetJSONRetriesABusyNodeInsteadOfFailing(t *testing.T) {
	srv, calls := busyThenOK(t, 2, `{"height":42}`)
	var got struct {
		Height uint64 `json:"height"`
	}
	if err := getJSON(srv.URL+"/history", &got); err != nil {
		t.Fatalf("a 503 that cleared on the third attempt was reported as a failure: %v", err)
	}
	if got.Height != 42 {
		t.Fatalf("the retried read decoded height %d, want 42", got.Height)
	}
	if n := calls.Load(); n != 3 {
		t.Fatalf("the handler was called %d times, want 3 (two 503s, one success)", n)
	}
}

func TestGetJSONGivesUpOnAPersistentBusyNode(t *testing.T) {
	srv, calls := busyThenOK(t, 1<<30, `{}`)
	err := getJSON(srv.URL+"/history", &struct{}{})
	if err == nil {
		t.Fatal("a node that stays busy was reported as a success")
	}
	// The node's own sentence survives the retries: the operator is told
	// "retry shortly", not given a synthetic timeout.
	for _, want := range []string{"503", "retry shortly"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the final error does not carry %q: %v", want, err)
		}
	}
	if n := calls.Load(); n != busyRetries+1 {
		t.Fatalf("the handler was called %d times, want %d (one attempt plus %d retries)", n, busyRetries+1, busyRetries)
	}
}

func TestGetJSONDoesNotRetryAReadThatIsNotBusy(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "no such height", http.StatusNotFound)
	}))
	defer srv.Close()
	err := getJSON(srv.URL+"/block", &struct{}{})
	if err == nil {
		t.Fatal("a 404 was reported as a success")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("the error does not name the status: %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("a 404 was retried %d times; only a 503 is the throttle's signal", n)
	}
}
