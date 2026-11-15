package relay

import (
	"bytes"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/wire"
)

// bookkeeping is a snapshot of the relay's connection bookkeeping under the
// registry lock: the registered connections, the sockets still presenting the
// access token, and the per-source-prefix slot counts. The three TOGETHER are
// the contract - the accept cap counts conns+handshaking, and the per-prefix
// cap counts perGroup - so a leak is any state where a count outlives the
// socket that justified it.
type bookkeeping struct {
	conns       int
	handshaking int
	perGroup    map[string]int
	groups      int // sum of perGroup, i.e. the slots the cap will see taken
}

func (r *Relay) bookkeeping() bookkeeping {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := bookkeeping{
		conns:       len(r.conns),
		handshaking: len(r.handshaking),
		perGroup:    make(map[string]int, len(r.perGroup)),
	}
	for g, n := range r.perGroup {
		b.perGroup[g] = n
		b.groups += n
	}
	return b
}

// waitQuiescent waits until every client has disconnected and the relay's
// bookkeeping has returned to zero. It reports the LAST observed state so a
// failure names the number that did not come back.
func waitQuiescent(t *testing.T, r *Relay, what string) {
	t.Helper()
	var last bookkeeping
	deadline := time.Now().Add(10 * time.Second)
	for {
		last = r.bookkeeping()
		if last.conns == 0 && last.handshaking == 0 && last.groups == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: after every client disconnected the relay still holds conns=%d handshaking=%d perGroup=%v (sum=%d); want 0/0/{}",
				what, last.conns, last.handshaking, last.perGroup, last.groups)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// testLeakToken is a token of the minimum legal width, so a gated relay starts
// and the handshake paths can be driven.
var testLeakToken = bytes.Repeat([]byte{0x5A}, wire.MinRelayAccessTokenBytes)

// reset closes a client socket with SO_LINGER 0, so the relay sees an RST
// instead of a FIN: the "peer vanished" case a home Pi's wifi loss looks like.
func reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

// TestRelayConnectDisconnectCyclesReleaseEverySlot drives ONE exit path per
// subtest, in a loop, and asserts after every cycle that the relay's conns
// count and its per-prefix group accounting both returned to 0. A loop rather
// than a single cycle because the production leak was rare per event (three
// connections over ~12 million frames and 23 hours of reconnects) and
// systematic over many.
func TestRelayConnectDisconnectCyclesReleaseEverySlot(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		run  func(t *testing.T, r *Relay, token []byte)
	}{
		{
			name: "clean dial, clean close",
			opts: Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16},
			run: func(t *testing.T, r *Relay, _ []byte) {
				c := dial(t, r.Addr().String())
				waitRegistered(t, r, 1, "the dial did not reach the registry")
				c.Close()
			},
		},
		{
			name: "dial, one frame, abrupt reset",
			opts: Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16},
			run: func(t *testing.T, r *Relay, _ []byte) {
				c := dial(t, r.Addr().String())
				writeFrame(t, c, []byte("hello"))
				reset(c)
			},
		},
		{
			name: "dial, half-close (FIN, no RST)",
			opts: Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16},
			run: func(t *testing.T, r *Relay, _ []byte) {
				c := dial(t, r.Addr().String())
				writeFrame(t, c, []byte("hello"))
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				c.Close()
			},
		},
		{
			name: "gated: full handshake then reset",
			opts: Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16, AccessToken: testLeakToken},
			run: func(t *testing.T, r *Relay, token []byte) {
				c := dial(t, r.Addr().String())
				expectGateGreeting(t, c)
				challenge := expectGateChallenge(t, c)
				proof := gateAnswer(token, challenge)
				writeFrame(t, c, proof)
				expectGateAccepted(t, c, token, challenge, proof)
				writeFrame(t, c, []byte("vote"))
				reset(c)
			},
		},
		{
			name: "gated: client vanishes mid-gate",
			opts: Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16, AccessToken: testLeakToken, AccessTimeout: 300 * time.Millisecond},
			run: func(t *testing.T, r *Relay, _ []byte) {
				c := dial(t, r.Addr().String())
				expectGateGreeting(t, c)
				reset(c)
			},
		},
		{
			name: "gated: wrong proof refused",
			opts: Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16, AccessToken: testLeakToken, AccessTimeout: 2 * time.Second},
			run: func(t *testing.T, r *Relay, _ []byte) {
				c := dial(t, r.Addr().String())
				expectGateGreeting(t, c)
				_ = expectGateChallenge(t, c)
				writeFrame(t, c, bytes.Repeat([]byte{0xAB}, wire.RelayGateMACBytes))
				waitClosed(t, c, "a dial with a wrong gate proof")
				c.Close()
			},
		},
		{
			name: "gated: silent dial times out",
			opts: Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16, AccessToken: testLeakToken, AccessTimeout: 150 * time.Millisecond},
			run: func(t *testing.T, r *Relay, _ []byte) {
				c := dial(t, r.Addr().String())
				// Read the greeting and challenge, answer nothing: the gate's
				// own deadline ends it.
				expectGateGreeting(t, c)
				_ = expectGateChallenge(t, c)
				waitClosed(t, c, "a silent dial against the gate")
				c.Close()
			},
		},
		{
			name: "gated: dial and close without reading the greeting",
			opts: Options{MaxFrameBytes: 4096, MaxConns: 64, MaxConnsPerIP: 64, WriteQueueBytes: 1 << 16, AccessToken: testLeakToken, AccessTimeout: 2 * time.Second},
			run: func(t *testing.T, r *Relay, _ []byte) {
				c := dial(t, r.Addr().String())
				reset(c)
			},
		},
	}

	const cycles = 60
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := startRelay(t, tc.opts)
			for i := 0; i < cycles; i++ {
				tc.run(t, r, testLeakToken)
				waitQuiescent(t, r, tc.name)
			}
			if st := r.Stats(); st.Conns != 0 {
				t.Fatalf("%s: Stats().Conns = %d after %d cycles", tc.name, st.Conns, cycles)
			}
		})
	}
}

// TestRelayConcurrentChurnLeavesNoBookkeeping drives all the exit paths at
// once, from several goroutines, and checks the invariant the caps depend on -
// sum(perGroup) == len(conns) + len(handshaking) - during the churn as well as
// after it. Races between admit, finish and releaseHandshake are exactly where
// a slot is double-released (an under-count, which lets more than the cap in)
// or never released (an over-count, which is the production symptom).
func TestRelayConcurrentChurnLeavesNoBookkeeping(t *testing.T) {
	token := testLeakToken
	r := startRelay(t, Options{
		MaxFrameBytes:   4096,
		MaxConns:        64,
		MaxConnsPerIP:   64,
		WriteQueueBytes: 1 << 16,
		AccessToken:     token,
		AccessTimeout:   200 * time.Millisecond,
	})
	addr := r.Addr().String()

	stop := make(chan struct{})
	var invariantErr error
	var invMu sync.Mutex
	var invWG sync.WaitGroup
	invWG.Add(1)
	go func() {
		defer invWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b := r.bookkeeping()
			if b.groups != b.conns+b.handshaking {
				invMu.Lock()
				if invariantErr == nil {
					invariantErr = &invariantViolation{b}
				}
				invMu.Unlock()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	var wg sync.WaitGroup
	const workers, cycles = 8, 40
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < cycles; i++ {
				c, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					continue
				}
				switch (w + i) % 5 {
				case 0: // clean dial, immediate close
					c.Close()
				case 1: // read the gate, then vanish mid-handshake
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					if _, err := wire.ReadFrame(c, 1<<16); err == nil {
						_, _ = wire.ReadFrame(c, wire.MaxRelayGateChallengeBytes)
					}
					reset(c)
				case 2: // wrong proof
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					challenge := []byte{}
					if _, err := wire.ReadFrame(c, 1<<16); err == nil {
						challenge, _ = wire.ReadFrame(c, wire.MaxRelayGateChallengeBytes)
					}
					_ = challenge
					_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					_ = wire.WriteFrame(c, bytes.Repeat([]byte{0x11}, wire.RelayGateMACBytes))
					time.Sleep(time.Millisecond)
					reset(c)
				case 3: // full handshake, one frame, then a clean close
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					if _, err := wire.ReadFrame(c, 1<<16); err == nil {
						if challenge, err := wire.ReadFrame(c, wire.MaxRelayGateChallengeBytes); err == nil {
							proof := wire.RelayGateProof(token, challenge)
							_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
							if err := wire.WriteFrame(c, proof); err == nil {
								_, _ = wire.ReadFrame(c, 1<<16) // confirmation
								_ = wire.WriteFrame(c, []byte("vote"))
							}
						}
					}
					c.Close()
				case 4: // silent dial: the gate's deadline must reap it
					time.Sleep(2 * time.Millisecond)
					reset(c)
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	invWG.Wait()

	invMu.Lock()
	bad := invariantErr
	invMu.Unlock()
	if bad != nil {
		t.Fatalf("%v", bad)
	}
	waitQuiescent(t, r, "concurrent churn")
	if st := r.Stats(); st.Conns != 0 {
		t.Fatalf("after %d concurrent connect/disconnect cycles the relay still reports conns=%d", workers*cycles, st.Conns)
	}
}

type invariantViolation struct{ b bookkeeping }

func (v *invariantViolation) Error() string {
	return "the accept caps' arithmetic and the per-prefix account disagree: sum(perGroup)=" +
		strconv.Itoa(v.b.groups) + " but conns+handshaking=" + strconv.Itoa(v.b.conns+v.b.handshaking) +
		" (conns=" + strconv.Itoa(v.b.conns) + " handshaking=" + strconv.Itoa(v.b.handshaking) + ")"
}

// drainUntilClosed reads whatever the relay managed to write before it ended
// the connection and then requires the socket to be closed: unlike
// waitClosed, data already in flight is expected here, because the receiver
// was wedged AFTER the relay wrote to it.
func drainUntilClosed(t *testing.T, c net.Conn, what string) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("%s: set read deadline: %v", what, err)
	}
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("%s: the relay left the connection open (read timed out instead of closing)", what)
			}
			return
		}
	}
}

// TestRelayWedgedReceiverReapReleasesItsSlot drives the ONE finish path that is
// not the reader's deferred teardown: the writer calling finish because a
// receiver's queue failed to drain (receiverStalled). It is constructed rather
// than provoked through a socket on purpose - whether a real sink's kernel
// buffers ever fill is a host property, not a relay property (the same reason
// audit N-1/N-2's socket-flood shapes were replaced with constructed ones) -
// and the assertion is the bookkeeping: after the reap the connection is gone
// from the registry AND the per-prefix count, the socket close is counted, and
// the books still agree.
func TestRelayWedgedReceiverReapReleasesItsSlot(t *testing.T) {
	const writeTimeout = 100 * time.Millisecond
	r := New(Options{
		MaxFrameBytes:    4096,
		MaxConns:         8,
		MaxConnsPerIP:    8,
		WriteQueueBytes:  1 << 20,
		WriteQueueFrames: 64,
		WriteTimeout:     writeTimeout,
	})
	// A sink that accepts every frame but too slowly for the queue to clear: a
	// 20ms write against a 100ms queue deadline makes progress on every write
	// (so no single write times out) while the backlog never empties - the
	// receiver-owned backlog receiverStalled exists for (audit N-2/F3).
	nc := &progressConn{writeDelay: 20 * time.Millisecond, closed: make(chan struct{})}
	c := &conn{
		nc:       nc,
		q:        newSendQ(r.opts.WriteQueueBytes, r.opts.MaxFrameBytes, r.opts.WriteQueueFrames),
		dead:     make(chan struct{}),
		srcGroup: "192.0.2.0/24",
	}
	c.lastFrame.Store(time.Now().UnixNano())
	r.accepted.Add(1) // stand in for the accept loop: this is a live socket
	r.mu.Lock()
	r.conns[c] = struct{}{}
	r.perGroup[c.srcGroup]++
	r.mu.Unlock()

	// One sender account, far below the frame cap, so neither the fair share
	// nor the entry ring can be what ends this connection.
	for i := 0; i < 50; i++ {
		if !c.q.push(c, []byte{byte(i)}, 1) {
			t.Fatalf("frame %d of 50 was refused while the queue was far below its cap - the wedged state never formed", i)
		}
	}
	if b := r.bookkeeping(); b.conns != 1 || b.groups != 1 {
		t.Fatalf("the constructed wedged connection is not registered: conns=%d perGroup=%v", b.conns, b.perGroup)
	}
	r.wg.Add(1)
	go r.writer(c)

	select {
	case <-c.dead:
	case <-time.After(5 * time.Second):
		t.Fatalf("the wedged receiver was never reaped: its queue stayed non-empty past --write-timeout while every write made progress (audit N-2's slow sink)")
	}
	waitQuiescent(t, r, "the wedged receiver")
	if st := r.Stats(); st.Conns != 0 || st.Live != 0 || st.Accepted != 1 || st.Closed != 1 {
		t.Fatalf("after the writer reaped its wedged receiver: conns=%d live=%d accepted=%d closed=%d; want 0/0/1/1",
			st.Conns, st.Live, st.Accepted, st.Closed)
	}
	if msg, bad := r.ConnBookkeepingIssue(); bad {
		t.Fatalf("the writer-initiated teardown left the books disagreeing: %s", msg)
	}
}

// TestRelayMaxConnsStillHoldsUnderConcurrentAdmission is the OTHER direction of
// the same accounting: a slot released twice would under-count, and the cap
// would then admit more sockets than --max-conns at once. With a token
// configured every dial is held in handshake, so the reserved slots are
// observable for as long as the test wants them.
func TestRelayMaxConnsStillHoldsUnderConcurrentAdmission(t *testing.T) {
	const cap = 3
	r := startRelay(t, Options{
		MaxFrameBytes: 4096, MaxConns: cap, MaxConnsPerIP: 64,
		WriteQueueBytes: 1 << 16,
		AccessToken:     testLeakToken, AccessTimeout: 10 * time.Second,
	})
	addr := r.Addr().String()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var clients []net.Conn
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return
			}
			mu.Lock()
			clients = append(clients, c)
			mu.Unlock()
		}()
	}
	wg.Wait()
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	// Every dial is reserved or refused synchronously at accept, so once the
	// refusals are counted the classification is final.
	if len(clients) != 40 {
		t.Fatalf("%d of 40 dials connected", len(clients))
	}
	waitFor(t, func() bool { return r.Stats().RefusedConns == 40-cap },
		"the cap did not refuse exactly the dials beyond --max-conns")
	b := r.bookkeeping()
	if held := b.conns + b.handshaking; held > cap {
		t.Fatalf("the relay holds %d sockets (conns=%d handshaking=%d) with --max-conns=%d: a slot was released more than once, so the cap no longer bounds anything",
			held, b.conns, b.handshaking, cap)
	}
	if b.groups != cap {
		t.Fatalf("per-group accounting is %d with %d sockets held and a per-prefix cap of 64; want %d - a slot was released twice",
			b.groups, b.conns+b.handshaking, cap)
	}
	// Close everything the relay admitted (and the refused ones too): the
	// bookkeeping must go back to nothing, not below it.
	for _, c := range clients {
		_ = c.Close()
	}
	waitQuiescent(t, r, "concurrent admission at the cap")
	if b := r.bookkeeping(); b.groups != 0 {
		t.Fatalf("per-group accounting ended at %d after every socket closed", b.groups)
	}
}

// TestRelaySoakOfConnectDisconnectCyclesLeavesNothing is the long form of the
// cycle test, opt-in because it runs for tens of seconds: thousands of
// connect/disconnect cycles across every exit path at once, with a watchdog
// asserting the cap arithmetic's invariant (sum(perGroup) ==
// conns + handshaking) throughout, and quiescence plus a goroutine count at the
// end. It exists to give a production-only race a place to reproduce: the
// incident's shape (three sockets over 23 hours of reconnects) is one leak per
// tens of thousands of events, which no single-cycle test can see.
//
// Skipped unless RELAY_SOAK=1: `RELAY_SOAK=1 go test -race -run
// TestRelaySoakOfConnectDisconnectCyclesLeavesNothing ./internal/relay/`.
func TestRelaySoakOfConnectDisconnectCyclesLeavesNothing(t *testing.T) {
	if os.Getenv("RELAY_SOAK") == "" {
		t.Skip("set RELAY_SOAK=1 to run the connect/disconnect soak")
	}
	r := startRelay(t, Options{
		MaxFrameBytes:   4096,
		MaxConns:        64,
		MaxConnsPerIP:   64,
		WriteQueueBytes: 1 << 16,
		AccessToken:     testLeakToken,
		AccessTimeout:   100 * time.Millisecond,
		ReadTimeout:     200 * time.Millisecond,
	})
	addr := r.Addr().String()

	stop := make(chan struct{})
	var invWG sync.WaitGroup
	var violation atomic.Value
	invWG.Add(1)
	go func() {
		defer invWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b := r.bookkeeping()
			if b.groups != b.conns+b.handshaking {
				violation.CompareAndSwap(nil, &invariantViolation{b})
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	baseline := runtime.NumGoroutine()
	var admitted atomic.Int64
	var wg sync.WaitGroup
	const workers, cycles = 16, 250
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < cycles; i++ {
				c, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					continue
				}
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				switch (w + i) % 7 {
				case 0: // clean dial, immediate close
					c.Close()
				case 1: // read the greeting, vanish mid-handshake
					_, _ = wire.ReadFrame(c, 1<<16)
					reset(c)
				case 2: // short first frame: a tokenless node's transport ID
					_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					_ = wire.WriteFrame(c, []byte("v0"))
					time.Sleep(time.Millisecond)
					reset(c)
				case 3: // wrong proof
					_, _ = wire.ReadFrame(c, 1<<16)
					_, _ = wire.ReadFrame(c, wire.MaxRelayGateChallengeBytes)
					_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					_ = wire.WriteFrame(c, bytes.Repeat([]byte{0x11}, wire.RelayGateMACBytes))
					time.Sleep(time.Millisecond)
					reset(c)
				case 4: // full handshake, one frame, clean close
					if challenge, err := relayGateChallenge(c); err == nil {
						proof := wire.RelayGateProof(testLeakToken, challenge)
						_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
						if err := wire.WriteFrame(c, proof); err == nil {
							if _, err := wire.ReadFrame(c, 1<<16); err == nil {
								admitted.Add(1)
								_ = wire.WriteFrame(c, []byte("vote"))
							}
						}
					}
					c.Close()
				case 5: // silent dial: the gate's deadline reaps it
					time.Sleep(3 * time.Millisecond)
					reset(c)
				case 6: // half-close: FIN without RST
					if challenge, err := relayGateChallenge(c); err == nil {
						proof := wire.RelayGateProof(testLeakToken, challenge)
						_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
						if err := wire.WriteFrame(c, proof); err == nil {
							_, _ = wire.ReadFrame(c, 1<<16)
							if tc, ok := c.(*net.TCPConn); ok {
								_ = tc.CloseWrite()
							}
						}
					}
					c.Close()
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	invWG.Wait()
	waitQuiescent(t, r, "the connect/disconnect soak")
	if v := violation.Load(); v != nil {
		t.Fatalf("%v", v)
	}
	if n := admitted.Load(); n < workers*cycles/7 {
		t.Fatalf("only %d of %d cycles completed the gate and registered a connection - the soak did not exercise admission", n, workers*cycles)
	}
	waitForWithin(t, 10*time.Second, func() bool { return runtime.NumGoroutine() <= baseline+1 },
		"the soak leaked goroutines behind the reaped connections")
}

// relayGateChallenge reads the gate greeting and the challenge, returning the
// challenge bytes exactly as the relay sent them.
func relayGateChallenge(c net.Conn) ([]byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := wire.ReadFrame(c, 1<<16); err != nil {
		return nil, err
	}
	return wire.ReadFrame(c, wire.MaxRelayGateChallengeBytes)
}

// TestRelayCloseReleasesEveryHandshakeReservation pins the shutdown path: a
// socket still presenting its access token is NOT in the registry, so Close's
// conns snapshot misses it - it closes those sockets instead and relies on each
// handshake goroutine to release its own accept-time reservation before it
// exits. Close waits for those goroutines, so when Close returns the
// handshaking set and every per-prefix slot must be empty.
func TestRelayCloseReleasesEveryHandshakeReservation(t *testing.T) {
	r := New(Options{
		MaxFrameBytes: 4096, MaxConns: 32, MaxConnsPerIP: 32,
		WriteQueueBytes: 1 << 16,
		AccessToken:     testLeakToken, AccessTimeout: 10 * time.Second,
	})
	if err := r.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	addr := r.Addr().String()

	clients := make([]net.Conn, 0, 16)
	for i := 0; i < 16; i++ {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("silent gated dial %d: %v", i, err)
		}
		clients = append(clients, c)
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()
	waitFor(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.handshaking) == len(clients)
	}, "the silent dials did not all reach the handshake set")

	r.Close()
	b := r.bookkeeping()
	if b.conns != 0 || b.handshaking != 0 || b.groups != 0 {
		t.Fatalf("after Close the relay still holds conns=%d handshaking=%d perGroup=%v - a reservation outlived the socket", b.conns, b.handshaking, b.perGroup)
	}
}

// TestRelayPerPrefixCapStillRefusesTheNPlusOnethSocket is the UNDER-count half
// of the same accounting, on the per-prefix cap: a slot released on the
// success path would leave the group's count under the number of sockets it
// holds, and the second dial from that prefix would be admitted beside the
// first. The refund direction matters just as much - once the first socket is
// gone its slot must come back, or the prefix can never reconnect.
func TestRelayPerPrefixCapStillRefusesTheNPlusOnethSocket(t *testing.T) {
	r := startRelay(t, Options{
		MaxFrameBytes: 4096, MaxConns: 8, MaxConnsPerIP: 1,
		WriteQueueBytes: 1 << 16,
	})
	addr := r.Addr().String()

	for cycle := 0; cycle < 10; cycle++ {
		a := dial(t, addr)
		waitRegistered(t, r, 1, "the first dial from the prefix was not admitted")
		// The N+1th concurrent socket from the SAME prefix must be refused.
		b := dial(t, addr)
		waitClosed(t, b, "the second concurrent dial from a prefix already holding its only slot")
		b.Close()
		if b := r.bookkeeping(); b.conns != 1 || b.groups != 1 {
			t.Fatalf("cycle %d: the relay holds conns=%d perGroup=%v while one socket is live and the per-prefix cap is 1",
				cycle, b.conns, b.perGroup)
		}
		// The slot must be refunded exactly once: one new dial is admitted.
		a.Close()
		waitQuiescent(t, r, "per-prefix cap cycle")
	}
}
