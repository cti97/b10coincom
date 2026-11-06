package relay

// Audit S-9: a panic in ONE connection's read loop must cost that connection,
// not the relay every validator behind it depends on. The panic is injected
// through the net.Conn seam - a connection whose Read panics - so the test
// CONSTRUCTS it; there is no race to provoke.

import (
	"net"
	"testing"
	"time"
)

// panicConn is a net.Conn whose first Read panics. Everything else is inert so
// the reader's setup and finish can run.
type panicConn struct{}

type panicAddr string

func (a panicAddr) Network() string { return "tcp" }
func (a panicAddr) String() string  { return string(a) }

func (panicConn) Read([]byte) (int, error)         { panic("injected read panic (audit S-9 containment test)") }
func (panicConn) Write(p []byte) (int, error)      { return len(p), nil }
func (panicConn) Close() error                     { return nil }
func (panicConn) LocalAddr() net.Addr              { return panicAddr("127.0.0.1:1") }
func (panicConn) RemoteAddr() net.Addr             { return panicAddr("203.0.113.77:4242") }
func (panicConn) SetDeadline(time.Time) error      { return nil }
func (panicConn) SetReadDeadline(time.Time) error  { return nil }
func (panicConn) SetWriteDeadline(time.Time) error { return nil }

func TestAReaderPanicCostsOneConnectionNotTheRelay(t *testing.T) {
	r := startRelay(t, Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16})
	a := dial(t, r.Addr().String())
	b := dial(t, r.Addr().String())
	waitRegistered(t, r, 2, "the two honest peers to register")

	// The relay is healthy before the injection, both ways.
	writeFrame(t, a, []byte("before"))
	if got := readFrame(t, b, 4096); string(got) != "before" {
		t.Fatalf("b read %q before the panic, want %q", got, "before")
	}

	// CONSTRUCT the panicking connection and run the real reader on it, with
	// its accept-time slot accounted exactly as admit would leave it.
	bad := &conn{
		nc:       panicConn{},
		q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
		srcGroup: "203.0.113.0/24",
		dead:     make(chan struct{}),
	}
	r.mu.Lock()
	r.conns[bad] = struct{}{}
	r.perGroup[bad.srcGroup]++
	r.mu.Unlock()
	r.wg.Add(1)
	go r.reader(bad)

	waitFor(t, func() bool { return r.ReaderPanics() == 1 },
		"the reader panic to be recovered (the process is still running, so the test got here)")
	// finish ran: the panicking connection is out of the registry and its
	// accept-time slot is back.
	waitFor(t, func() bool { return r.Stats().Conns == 2 },
		"the panicking connection to leave the registry")
	r.mu.Lock()
	slotBack := r.perGroup[bad.srcGroup] == 0
	r.mu.Unlock()
	if !slotBack {
		t.Fatal("the panicking connection kept its accept-time slot: finish did not run")
	}

	// The survivors still forward, in the direction that did not carry the
	// earlier proof, after the panic.
	writeFrame(t, b, []byte("after"))
	if got := readFrame(t, a, 4096); string(got) != "after" {
		t.Fatalf("a read %q after the panic, want %q - the relay stopped forwarding", got, "after")
	}
	if got := r.ReaderPanics(); got != 1 {
		t.Fatalf("ReaderPanics = %d after the survivors forwarded again, want 1", got)
	}
}
