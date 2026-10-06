package tcp

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
	"github.com/cti97/b10coincom/internal/transport"
	"github.com/cti97/b10coincom/internal/wire"
)

// The tests in this file are the fourth review round's pins for
//
//	new issue 1 - the per-connection rate limit throttling the SHARED relay
//	               link, which made one flooder at the relay drop every honest
//	               validator's votes; and
//	new issue 2 - the relay access token being sent to a relay that never asked
//	               for one, which forwarded the operator's secret to every peer.
//
// Both are constructed, never provoked: the rate-limit pins run over net.Pipe
// with an exact frame count, and the token pins drive a socket whose
// termination is an event (the node closes it), not a deadline.

// TestTheSharedRelayLinkIsNotShedByThePerConnectionBucket pins new issue 1 in
// the direction that matters: a flood arriving on the relay connection must not
// cost the honest frames that share that socket.
//
// Every member's traffic arrives on ONE relay:<addr> connection, so a bucket on
// that connection drops whatever frame is next - honest or not - once its
// tokens are gone. The flood below is the finding's shape exactly: 50 one-byte
// frames against a burst of 4. With the exemption, all 50 are dispatched and
// nothing is shed; without it, 46 honest frames are discarded.
//
// The honest frame AFTER the flood is sent and asserted separately, because
// "the validator's next vote survives a stranger at the relay" is the property
// the finding is about, and it is the frame the pre-fix bucket drops.
func TestTheSharedRelayLinkIsNotShedByThePerConnectionBucket(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	tp, err := New(Options{
		LocalID: "validator", RateLimitPerSec: 1, RateLimitBurst: 4,
		IdleReadTimeout: time.Hour, WriteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tp.Close()

	var mu sync.Mutex
	var payloads [][]byte
	tp.OnMessage(func(m transport.Message) {
		mu.Lock()
		payloads = append(payloads, append([]byte(nil), m.Data...))
		mu.Unlock()
	})

	addr := "relay.example.net:7001"
	c, err := tp.install(server, addr, true, RelayPeerName(addr))
	if err != nil {
		t.Fatal(err)
	}
	if !c.relayMode {
		t.Fatal("a dialled relay:<addr> connection was not marked relay-mode; the bucket is charged to the shared link")
	}

	flood := []byte{0xAA}
	go func() {
		for i := 0; i < 50; i++ {
			if err := wire.WriteFrame(client, flood); err != nil {
				return
			}
		}
		_ = wire.WriteFrame(client, []byte("honest-vote"))
	}()

	waitFor(t, "all 50 flood frames and the honest frame to be dispatched over the relay link", 10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(payloads) >= 51
	})
	mu.Lock()
	defer mu.Unlock()
	if n := c.rateLimited.Load(); n != 0 {
		t.Fatalf("%d frames were shed on the shared relay connection: an honest member's votes are dropped for a stranger's flood", n)
	}
	if !bytes.Equal(payloads[50], []byte("honest-vote")) {
		t.Fatalf("the honest frame after the flood was not the 51st dispatched: got %q", payloads[50])
	}
}

// TestADirectFlooderIsStillShedSoItCannotDelayHonestDispatch keeps the property
// the limiter exists for. The relay exemption must not leak into direct
// connections, where the connection IS the sender: the bucket is what stops a
// direct flooder from monopolising the single dispatch callback every reader
// serialises behind.
//
// The scenario is exact, not timed. Two directly installed connections, a
// flooder and an honest peer. The flooder's 50 frames are the burst (4) plus 46
// shed; the assertion is that its frames reach the callback AT MOST the burst,
// which is what bounds the honest peer's delay. Then the honest peer's frame is
// sent and must be dispatched. A mutant that removes the bucket from the direct
// path dispatches all 50 and fails the bound.
func TestADirectFlooderIsStillShedSoItCannotDelayHonestDispatch(t *testing.T) {
	tp, err := New(Options{
		LocalID: "validator", RateLimitPerSec: 1, RateLimitBurst: 4,
		IdleReadTimeout: time.Hour, WriteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tp.Close()

	var mu sync.Mutex
	fromFlooder, fromHonest := 0, 0
	tp.OnMessage(func(m transport.Message) {
		mu.Lock()
		defer mu.Unlock()
		switch m.From {
		case "flooder":
			fromFlooder++
		case "honest":
			fromHonest++
		}
	})

	floodSrv, floodCli := net.Pipe()
	defer floodCli.Close()
	honestSrv, honestCli := net.Pipe()
	defer honestCli.Close()
	fl, err := tp.install(floodSrv, "flooder", true, "flooder")
	if err != nil {
		t.Fatal(err)
	}
	if fl.relayMode {
		t.Fatal("a direct connection was marked relay-mode: the exemption is not restricted to the shared relay link")
	}
	if _, err := tp.install(honestSrv, "honest", true, "honest"); err != nil {
		t.Fatal(err)
	}

	go func() {
		for i := 0; i < 50; i++ {
			if err := wire.WriteFrame(floodCli, []byte{0xBB}); err != nil {
				return
			}
		}
	}()

	// Wait for the flooder's share to be fully accounted for: dispatched plus
	// shed reaches 50. Only then is the honest frame sent, so its dispatch
	// cannot be confused with the flood still in flight.
	waitFor(t, "the flooder's 50 frames to be dispatched or shed", 10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return fromFlooder+int(fl.rateLimited.Load()) >= 50
	})
	if err := wire.WriteFrame(honestCli, []byte("honest-vote")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the honest peer's frame to be dispatched while the flooder's are shed", 10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return fromHonest >= 1
	})
	mu.Lock()
	dispatched, shed := fromFlooder, fl.rateLimited.Load()
	mu.Unlock()
	if shed == 0 {
		t.Fatal("no frame was shed on a direct connection: the flooder is free to occupy the dispatch callback for all 50 frames")
	}
	if dispatched > 8 {
		t.Fatalf("a direct flooder got %d of 50 frames through the dispatch callback (burst 4); the bound is what keeps an honest peer's frame from queuing behind the flood", dispatched)
	}
}

// TestTheAccessTokenIsNotSentToARelayThatDoesNotGate is new issue 2's
// reproduction, BEFORE and AFTER, as one deterministic scenario.
//
// The relay here is the misconfigured one from the finding: it has NO token, so
// it sends no greeting and treats the first frame it receives as ordinary
// payload it forwards to every registered connection. The node IS configured
// with a token. Pre-fix the node wrote the token immediately, so this fake
// relay read the operator's secret; the test then fails with the secret in the
// message. Post-fix the node waits for the greeting, does not get one, refuses
// to send the token, logs the refusal and closes the socket - the fake relay's
// read ends having received nothing, which is an EVENT (the close) and not a
// deadline, so the assertion cannot pass by waiting.
func TestTheAccessTokenIsNotSentToARelayThatDoesNotGate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	accepted := make(chan struct{})
	got := make(chan []byte, 1)
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		close(accepted)
		defer nc.Close()
		_ = nc.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, errRead := wire.ReadFrame(nc, 1<<16)
		if errRead != nil {
			got <- nil // nothing was sent: the node refused to part with the secret
			return
		}
		got <- frame
	}()

	token := []byte("sixteen-byte-tok")
	logs := captureLog(t)
	tp := listen(t, Options{
		LocalID: "v0", RelayAccessToken: token,
		HandshakeTimeout: 150 * time.Millisecond,
		BackoffBase:      time.Hour, BackoffMax: time.Hour, // exactly one dial
		Rand: rand.New(rand.NewSource(7)),
	})
	if err := tp.AddRelay(addr); err != nil {
		t.Fatalf("AddRelay: %v", err)
	}

	select {
	case <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("the node never dialled the relay")
	}
	var frame []byte
	select {
	case frame = <-got:
	case <-time.After(30 * time.Second):
		t.Fatal("the node neither sent a frame nor closed the socket: the handshake did not terminate")
	}
	if frame != nil {
		t.Fatalf("the node sent %q to a relay that never announced the token gate; a relay without a token forwards that frame to EVERY registered peer, strangers included", frame)
	}
	// The refusal must be LOUD: before this fix a token-configured node
	// redialled in silence and the failure was visible only in the relay's
	// unauthorized counter.
	waitFor(t, "the node-side log line naming the refused relay handshake", 5*time.Second, func() bool {
		s := logs.String()
		return strings.Contains(s, "b10coin: relay "+addr) && strings.Contains(s, "access-token gate")
	})
	if peers := tp.Peers(); len(peers) != 0 {
		t.Fatalf("the refused relay dial was installed as a peer: %v", peers)
	}
}

// TestAWrongTokenIsLoggedNodeSide is the other half of the node-side log line:
// the relay DOES gate, the node presents a token the relay refuses, and the
// node must name the handshake death instead of redialling in silence. The
// relay's own unauthorized counter is the only pre-fix evidence, and it lives on
// the other machine.
func TestAWrongTokenIsLoggedNodeSide(t *testing.T) {
	rl := relay.New(relay.Options{AccessToken: []byte("the-relays-real-token")})
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer rl.Close()
	addr := rl.Addr().String()

	logs := captureLog(t)
	tp := listen(t, Options{
		LocalID: "v0", RelayAccessToken: []byte("a-different-wrong-token"),
		HandshakeTimeout: 2 * time.Second,
		BackoffBase:      time.Hour, BackoffMax: time.Hour,
		Rand: rand.New(rand.NewSource(11)),
	})
	if err := tp.AddRelay(addr); err != nil {
		t.Fatalf("AddRelay: %v", err)
	}
	waitFor(t, "the relay counting the refused token", 10*time.Second, func() bool {
		return rl.Stats().Unauthorized >= 1
	})
	waitFor(t, "the node-side log line for the refused token", 10*time.Second, func() bool {
		s := logs.String()
		return strings.Contains(s, "b10coin: relay "+addr) && strings.Contains(s, "accepting the token")
	})
	if peers := tp.Peers(); len(peers) != 0 {
		t.Fatalf("a token-refused dial was installed as a peer: %v", peers)
	}
}

// TestAShortRelayAccessTokenIsRefusedAtConstruction pins the minimum length on
// the node side. A token is the relay's only credential and its check is one
// comparison per dial, so a short one is brute-forced at network speed: 256
// dials for one byte. The floor is enforced where the operator learns about it,
// before any socket exists, and identically in the relay (relay.Listen) and both
// CLIs.
func TestAShortRelayAccessTokenIsRefusedAtConstruction(t *testing.T) {
	for _, n := range []int{1, 4, 8, wire.MinRelayAccessTokenBytes - 1} {
		token := bytes.Repeat([]byte{'t'}, n)
		if _, err := New(Options{LocalID: "v0", RelayAccessToken: token}); err == nil {
			t.Fatalf("a %d-byte relay access token was accepted; the floor is %d", n, wire.MinRelayAccessTokenBytes)
		}
	}
	if _, err := New(Options{LocalID: "v0", RelayAccessToken: bytes.Repeat([]byte{'t'}, wire.MinRelayAccessTokenBytes)}); err != nil {
		t.Fatalf("a token of exactly the minimum length was refused: %v", err)
	}
}

// TestTheNodeGateHandshakeCompletesAgainstAGatingRelay pins the positive path:
// node and relay configured with the same token register the relay link, with
// the two fixed gate frames exchanged in the fixed order and the token consumed
// rather than forwarded. Without this the negative tests above could pass by
// refusing EVERYTHING.
func TestTheNodeGateHandshakeCompletesAgainstAGatingRelay(t *testing.T) {
	token := []byte("a-shared-sixteen-byte-token")
	rl := relay.New(relay.Options{AccessToken: token})
	if err := rl.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer rl.Close()
	addr := rl.Addr().String()

	tp := listen(t, Options{
		LocalID: "v0", RelayAccessToken: token,
		BackoffBase: 10 * time.Millisecond, BackoffMax: 100 * time.Millisecond,
		Rand: rand.New(rand.NewSource(3)),
	})
	tp.OnMessage(func(transport.Message) {})
	if err := tp.AddRelay(addr); err != nil {
		t.Fatalf("AddRelay: %v", err)
	}
	waitPeersIs(t, tp, fmt.Sprintf("[%s]", RelayPeerName(addr)))
	if got := rl.Stats().Unauthorized; got != 0 {
		t.Fatalf("the relay counted %d unauthorized dials from a token holder", got)
	}
}

// captureLog redirects the standard logger into a buffer for one test and
// restores it afterwards. The transport logs a relay handshake death there
// (relayHandshakeFailed) because that failure is otherwise invisible: the
// maintainer treats it as an ordinary failure and redials with backoff.
func captureLog(t *testing.T) *logBuffer {
	t.Helper()
	buf := &logBuffer{}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return buf
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
