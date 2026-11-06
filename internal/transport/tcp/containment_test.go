package tcp

// Audit S-9: a panic in ONE connection's read loop must cost that connection,
// not the node. The injection is deterministic and goes through a real seam -
// Options.Admit, the node-supplied admission policy the reader calls on every
// gated frame - so the test constructs the panic instead of racing one.

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

// gatedDial completes the transport's ID plus socket-nonce handshake as an
// accepted (gated) connection and returns it with its buffered reader.
func gatedDial(t *testing.T, addr, id string) (net.Conn, *bufio.Reader) {
	t.Helper()
	nc := rawDial(t, addr)
	if err := wire.WriteFrame(nc, []byte(id)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(nc)
	if _, err := wire.ReadFrame(br, maxHandshakeIDBytes); err != nil {
		t.Fatal(err)
	}
	rawAnswerNonce(t, nc, br)
	return nc, br
}

func TestAReaderPanicCostsOneConnectionNotTheNode(t *testing.T) {
	const boom = "inject-reader-panic"
	delivered := make(chan string, 8)
	tp := listen(t, Options{
		LocalID: "validator",
		Admit: func(frame []byte, _ []byte) bool {
			if string(frame) == boom {
				// The seam: a node-supplied admission policy that panics. The
				// reader calls it on this goroutine, inside the loop.
				panic("injected panic (audit S-9 containment test)")
			}
			return true
		},
	})
	tp.OnMessage(func(m transport.Message) { delivered <- string(m.Data) })

	// A completes the handshake and then sends the frame that panics Admit.
	a, _ := gatedDial(t, tp.Addr().String(), "conn-a")
	waitFor(t, "the panicking connection to install", 5*time.Second, func() bool {
		tp.mu.Lock()
		defer tp.mu.Unlock()
		return len(tp.conns) == 1
	})
	if err := wire.WriteFrame(a, []byte(boom)); err != nil {
		t.Fatal(err)
	}

	// The read loop recovered, closed A, and the PROCESS is still here: this
	// test is still running and the counter names exactly one containment.
	waitFor(t, "the reader panic to be recovered", 5*time.Second, func() bool {
		return tp.ReaderPanics() == 1
	})
	// A refused frame never reaches OnMessage, and the panicking connection was
	// closed on its own side.
	waitClosedConn(t, a, "the connection whose reader panicked")
	waitFor(t, "the panicking connection to leave the registry", 5*time.Second, func() bool {
		tp.mu.Lock()
		defer tp.mu.Unlock()
		return len(tp.conns) == 0
	})
	select {
	case got := <-delivered:
		t.Fatalf("the panicking frame reached OnMessage: %q", got)
	default:
	}

	// The OTHER connection still works end to end: handshake, admission,
	// dispatch. One reader's panic did not take the transport down.
	b, _ := gatedDial(t, tp.Addr().String(), "conn-b")
	waitFor(t, "the second connection to install", 5*time.Second, func() bool {
		tp.mu.Lock()
		defer tp.mu.Unlock()
		return len(tp.conns) == 1
	})
	if err := wire.WriteFrame(b, []byte("after-the-panic")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-delivered:
		if got != "after-the-panic" {
			t.Fatalf("the surviving connection delivered %q, want %q", got, "after-the-panic")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a connection opened after the panic never reached OnMessage")
	}
	if got := tp.ReaderPanics(); got != 1 {
		t.Fatalf("ReaderPanics = %d after a healthy second connection, want 1", got)
	}
}
