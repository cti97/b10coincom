package tcp

// Audit N-3: the A-2 fix widened the HELLO's socket binding from one 32-byte
// challenge to two (64 bytes), and a node on either side of that change never
// admits the other on a gated socket and never records it as a catch-up
// source. Before this there was NO observable except the GatedFrames counter:
// no log line, no version field. A mixed-version deployment that fails
// silently is worse than one that fails loudly, so a gated HELLO whose binding
// width is the OLD one-challenge form logs the two widths once per connection,
// and the connection is marked so a HELLO every wave cannot flood the log.
//
// The test constructs the shape directly: a gated (accepted) connection, the
// transport's real ID + commit-then-reveal handshake from a raw peer, and then
// HELLO frames carrying a 32-byte nonce. Only the FIRST frame of each
// connection is noticed; a second connection is a second notice. The second
// half covers the other entry point: an ADMITTED connection (a configured dial)
// never passes through the gate, so the node layer reports the same mismatch
// through NoteBindingVintage and must get the same once-per-connection line.

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/wire"
)

func TestAnOldBindingWidthIsNoticedOncePerConnection(t *testing.T) {
	buf := captureLog(t)
	tp := listen(t, Options{LocalID: "v0", Admit: func([]byte, []byte) bool { return false }})

	// A well-framed HELLO of the OLD vintage: one 32-byte challenge, which is
	// exactly what a pre-A-2 build signs. The policy refuses it (as it refuses
	// everything here); the notice is about WHY the width cannot ever match.
	old := wire.EncodeHello(&wire.Hello{
		ChainID:   "b10coin-devnet",
		Validator: bytes.Repeat([]byte{0x01}, 32),
		Height:    1,
		Nonce:     bytes.Repeat([]byte{0x02}, connectionNonceBytes),
		Sig:       []byte{0x03},
	})

	// connect completes the raw peer's side of the transport's handshake, so
	// the frames that follow reach the admission gate.
	connect := func(tp *TcpTransport, id string) net.Conn {
		t.Helper()
		c := rawDial(t, tp.Addr().String())
		if err := wire.WriteFrame(c, []byte(id)); err != nil {
			t.Fatalf("writing the raw ID: %v", err)
		}
		br := bufio.NewReader(c)
		if _, err := wire.ReadFrame(br, maxHandshakeIDBytes); err != nil {
			t.Fatalf("reading the transport's ID: %v", err)
		}
		rawAnswerNonce(t, c, br)
		return c
	}

	// One connection, two old-vintage HELLOs: ONE notice, two gated frames.
	c1 := connect(tp, "old1")
	for i := 0; i < 2; i++ {
		if err := wire.WriteFrame(c1, old); err != nil {
			t.Fatalf("sending the old-vintage HELLO: %v", err)
		}
	}
	waitFor(t, "both old-vintage HELLOs to be gated", 5*time.Second, func() bool {
		return tp.GatedFrames() >= 2
	})
	if got := tp.BindingVintages(); got != 1 {
		t.Fatalf("BindingVintages = %d after two HELLOs on one connection, want 1 (once per connection)", got)
	}
	if got := strings.Count(buf.String(), "audit N-3"); got != 1 {
		t.Fatalf("the N-3 notice was logged %d times for one connection, want once: %q", got, buf.String())
	}
	if !strings.Contains(buf.String(), "32-byte socket binding") {
		t.Fatalf("the notice does not name the old width: %q", buf.String())
	}

	// A second connection is a second notice: "once per connection", not once
	// per process.
	c2 := connect(tp, "old2")
	if err := wire.WriteFrame(c2, old); err != nil {
		t.Fatalf("sending the old-vintage HELLO on the second connection: %v", err)
	}
	waitFor(t, "the second connection's notice", 5*time.Second, func() bool {
		return tp.BindingVintages() >= 2
	})
	if got := strings.Count(buf.String(), "audit N-3"); got != 2 {
		t.Fatalf("the N-3 notice was logged %d times after two connections, want 2", got)
	}

	// A NEW-vintage HELLO must not be misdiagnosed as a vintage split. The
	// policy still refuses it (nothing here is admitted), but no third notice is
	// produced for a width that is this connection's own.
	newVintage := wire.EncodeHello(&wire.Hello{
		ChainID:   "b10coin-devnet",
		Validator: bytes.Repeat([]byte{0x01}, 32),
		Height:    1,
		Nonce:     bytes.Repeat([]byte{0x04}, 2*connectionNonceBytes),
		Sig:       []byte{0x05},
	})
	gatedBefore := tp.GatedFrames()
	if err := wire.WriteFrame(c2, newVintage); err != nil {
		t.Fatalf("sending a current-vintage HELLO: %v", err)
	}
	waitFor(t, "the current-vintage HELLO to be gated", 5*time.Second, func() bool {
		return tp.GatedFrames() > gatedBefore
	})
	if got := tp.BindingVintages(); got != 2 {
		t.Fatalf("BindingVintages = %d after a current-width HELLO, want 2 (no notice for a matching width)", got)
	}

	// An ADMITTED connection never passes through the gate, so a mixed-version
	// peer there is refused by observeHello's equality and the node layer
	// reports the width through NoteBindingVintage. It must produce the same
	// line, once, and nothing for a current-width HELLO.
	tp2 := listen(t, Options{LocalID: "v1"}) // no Admit: every connection is admitted
	_ = connect(tp2, "adm")
	tp2.NoteBindingVintage("adm", connectionNonceBytes)
	tp2.NoteBindingVintage("adm", connectionNonceBytes) // second HELLO, same connection
	tp2.NoteBindingVintage("adm", 2*connectionNonceBytes)
	if got := tp2.BindingVintages(); got != 1 {
		t.Fatalf("BindingVintages = %d for one admitted connection, want 1: the node-layer path is not once per connection", got)
	}
	if got := strings.Count(buf.String(), "audit N-3"); got != 3 {
		t.Fatalf("the N-3 notice was logged %d times in total, want 3 (two gated connections plus one admitted)", got)
	}
}
