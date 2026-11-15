package relay

import (
	"strings"
	"testing"
	"time"
)

// TestRelayStatsReportTheSocketLifecycleNotJustTheRegistry pins the three
// connection numbers apart, on a real relay and a real socket: conns is the
// registry's length, handshaking is accepted sockets that are not registered,
// and live is accepted minus closed. A line that folded them together could
// report the registry's belief as an observed socket count - the 2026-11-15
// misdiagnosis.
func TestRelayStatsReportTheSocketLifecycleNotJustTheRegistry(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 16, MaxConnsPerIP: 16, WriteQueueBytes: 1 << 16})
	addr := r.Addr().String()

	// One live, registered connection: 1 slot, 1 socket, 0 silence.
	a := dial(t, addr)
	waitRegistered(t, r, 1, "the dial did not register")
	writeFrame(t, a, []byte("hello"))
	st := r.Stats()
	if st.Conns != 1 || st.Handshaking != 0 || st.Live != 1 || st.Accepted != 1 || st.Closed != 0 {
		t.Fatalf("with one live connection: conns=%d handshaking=%d live=%d accepted=%d closed=%d; want 1/0/1/1/0",
			st.Conns, st.Handshaking, st.Live, st.Accepted, st.Closed)
	}
	if msg, bad := r.ConnBookkeepingIssue(); bad {
		t.Fatalf("a healthy relay reported a bookkeeping issue: %s", msg)
	}

	// A gated socket still presenting its token is a SOCKET but not a REGISTERED
	// connection: the caps count it, the registry must not, and the two
	// numbers must say so instead of hiding it.
	gr := startRelay(t, Options{
		MaxFrameBytes: 4096, MaxConns: 16, MaxConnsPerIP: 16, WriteQueueBytes: 1 << 16,
		AccessToken: testLeakToken, AccessTimeout: 5 * time.Second,
	})
	silent := dial(t, gr.Addr().String())
	waitFor(t, func() bool { return gr.Stats().Handshaking == 1 }, "the silent gated dial did not hold a handshake slot")
	if gst := gr.Stats(); gst.Conns != 0 || gst.Live != 1 || gst.Handshaking != 1 {
		t.Fatalf("with one socket mid-handshake: conns=%d handshaking=%d live=%d; want 0/1/1", gst.Conns, gst.Handshaking, gst.Live)
	}
	silent.Close()
	waitQuiescent(t, gr, "the gated dial")

	// Everything gone: the registry is empty, no socket is held, nothing is
	// silent, and the books agree.
	a.Close()
	waitQuiescent(t, r, "the single connection")
	if st := r.Stats(); st.Accepted != 1 || st.Closed != 1 || st.Live != 0 || st.LongestSilence != 0 {
		t.Fatalf("after the client disconnected: accepted=%d closed=%d live=%d silence=%s; want 1/1/0/0",
			st.Accepted, st.Closed, st.Live, st.LongestSilence)
	}
	if msg, bad := r.ConnBookkeepingIssue(); bad {
		t.Fatalf("an idle relay reported a bookkeeping issue: %s", msg)
	}
}

// TestRelayConnBookkeepingIssueNamesTheIncidentsShape constructs the state the
// production report describes - the registry holding a connection the process
// has no socket for - and requires the check to NAME it, with the direction.
// This is the line that was missing for two days: the stats line said
// conns=3 and nothing could contradict it.
func TestRelayConnBookkeepingIssueNamesTheIncidentsShape(t *testing.T) {
	r := New(Options{ReadTimeout: time.Minute})
	// Accepted and closed: the socket is gone. Registered anyway: the slot is
	// still held. Exactly "3 conns, 0 sockets", one connection's worth.
	r.accepted.Add(1)
	r.closedSockets.Add(1)
	c := &conn{nc: &progressConn{closed: make(chan struct{})}, dead: make(chan struct{}), srcGroup: "192.0.2.0/24"}
	c.lastFrame.Store(time.Now().UnixNano())
	r.mu.Lock()
	r.conns[c] = struct{}{}
	r.perGroup[c.srcGroup]++
	r.mu.Unlock()

	st := r.Stats()
	if st.Conns != 1 || st.Live != 0 {
		t.Fatalf("the constructed state reads conns=%d live=%d; want the registry holding 1 and no socket live", st.Conns, st.Live)
	}
	msg, bad := r.ConnBookkeepingIssue()
	if !bad {
		t.Fatalf("a registry holding a connection whose socket was already closed (conns=%d live=%d) reported NO bookkeeping issue", st.Conns, st.Live)
	}
	if !strings.Contains(msg, "1 slot(s) more than sockets") {
		t.Fatalf("the issue does not name the direction (a slot outliving its socket): %s", msg)
	}
	// ... and the reverse, the under-count that would weaken a cap.
	r.accepted.Add(3) // three sockets the registry has no slot for
	msg, bad = r.ConnBookkeepingIssue()
	if !bad {
		t.Fatal("a socket count above the slot count reported NO bookkeeping issue")
	}
	if !strings.Contains(msg, "released twice") {
		t.Fatalf("the issue does not name the under-count direction: %s", msg)
	}
}

// TestRelayConnBookkeepingIssueNamesAWedgedReader pins the second comparison:
// a registered connection that has delivered no frame for longer than its own
// read deadline allows. Every reader arms that deadline, so this state means
// the reader is not reading - the registry is holding a connection that is not
// there - and the check must say so rather than let conns stand alone.
func TestRelayConnBookkeepingIssueNamesAWedgedReader(t *testing.T) {
	r := New(Options{ReadTimeout: 40 * time.Millisecond})
	r.accepted.Add(1)
	c := &conn{nc: &progressConn{closed: make(chan struct{})}, dead: make(chan struct{}), srcGroup: "198.51.100.0/24"}
	c.lastFrame.Store(time.Now().Add(-time.Second).UnixNano()) // a whole second of silence
	r.mu.Lock()
	r.conns[c] = struct{}{}
	r.perGroup[c.srcGroup]++
	r.mu.Unlock()

	st := r.Stats()
	if st.Conns != 1 || st.Live != 1 {
		t.Fatalf("the constructed state reads conns=%d live=%d; want 1/1 (the books agree, only the traffic does not)", st.Conns, st.Live)
	}
	if st.LongestSilence < 2*40*time.Millisecond {
		t.Fatalf("LongestSilence = %s, want at least twice the 40ms read timeout", st.LongestSilence)
	}
	msg, bad := r.ConnBookkeepingIssue()
	if !bad {
		t.Fatalf("a registered connection silent for %s (read timeout 40ms) reported NO issue", st.LongestSilence)
	}
	if !strings.Contains(msg, "no frame") {
		t.Fatalf("the issue does not name the silence: %s", msg)
	}
}
