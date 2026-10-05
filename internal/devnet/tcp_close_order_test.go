package devnet

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/consensus"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/transport"
)

// The deterministic replacement for the probabilistic Close regression pin
// (Task 6 review, carry-forward). The old pin raced real committee traffic
// against a mid-flight Close and needed repeats under -race to observe the
// tear; the mutant that removed the closing gate passed 31 repeat runs. This
// test drives the SAME production path — a dispatch reaching route(), Close()
// with its flag-under-mu ordering, the refusal gate — with every interleaving
// pinned by explicit synchronization instead of traffic timing:
//
//   - CONTROL: an honest committee-signed frame passes route()'s checks and
//     reaches the dispatch callback. Without this leg the refusal assertion
//     below would be vacuous (a frame the router never accepted).
//   - IN-FLIGHT: a dispatch is entered and BLOCKED inside the callback (it
//     holds mu), Close() is called and must wait for it — no panic, the
//     chain still open while the dispatch completes — and then finish
//     cleanly. This is the "one dispatch already in flight finishes before
//     the flag is set" half of Close's ordered shutdown.
//   - REFUSAL: after Close, a new dispatch is refused by the closing gate —
//     never dispatched, and route() RETURNS (no hang). This kills the mutant
//     that removes the closing checks and the flag store in one run, with no
//     scheduling dependence.
//
// The validator idles while all this happens: a solo member of a four-seat
// committee with hour-long ticks and waves produces no block, no vote and no
// HELLO, so nothing but the test's own dispatches can touch the gate.
func TestValidatorCloseOrderingBlocksInFlightDispatchAndRefusesLaterOnes(t *testing.T) {
	v, err := StartValidator(ValidatorConfig{
		Dir:        t.TempDir(),
		Index:      0,
		Validators: 4,
		Listen:     "127.0.0.1:0",
		TickEvery:  time.Hour,
		WaveEvery:  time.Hour,
	})
	if err != nil {
		t.Fatalf("starting the idle validator: %v", err)
	}

	// A signed prevote by THIS validator's seat key: the frame the router must
	// verify and classify as consensus (Route() true). Each dispatch below
	// uses a DISTINCT height because the node now installs the dedup seen-set
	// (audit N-7): re-routing one identical frame would be refused as a
	// duplicate and never reach the callback this test exists to block, which
	// would make the close-gate assertions vacuous.
	probe := func(height uint64) transport.Message {
		vote := &consensus.Vote{
			Type:      consensus.MsgPrevote,
			Height:    height,
			Round:     3,
			Validator: v.pub,
		}
		sig := vote.SigningHash()
		vote.Sig = crypto.Sign(v.priv, sig[:])
		return transport.Message{From: transport.PeerID("close-ordering-probe"), Data: consensus.EncodeVote(vote)}
	}
	msg, msg2, msg3 := probe(7), probe(8), probe(9)

	// setDispatch swaps the driver's registered callback for a test one. The
	// seam is production state (the atomic slot rebuildDriver also swaps), so
	// a dispatched frame lands somewhere observable.
	var dispatched atomic.Int32
	setDispatch := func(fn func(transport.Message)) { v.drvTP.msg.Store(&fn) }
	runRoute := func(m transport.Message) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			v.route(m)
			close(done)
		}()
		return done
	}
	waitRouteDone := func(done <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: route() never returned - a gate that can hang is its own defect", what)
		}
	}

	// CONTROL: the gate open. The frame must trace check -> router -> dispatch.
	setDispatch(func(transport.Message) { dispatched.Add(1) })
	waitRouteDone(runRoute(msg), "the control dispatch")
	if dispatched.Load() != 1 {
		t.Fatalf("control dispatch reached the callback %d times - the probe frame is not passing the router, so the refusal assertions would be vacuous", dispatched.Load())
	}

	// IN-FLIGHT: a dispatch blocked INSIDE the callback, holding mu — the
	// exact state a socket reader can be in when Close begins. Close must
	// queue behind it (its first move takes mu), the dispatch completes
	// against an OPEN chain, and Close then finishes cleanly.
	inFlight := make(chan struct{})
	release := make(chan struct{})
	setDispatch(func(transport.Message) {
		close(inFlight)
		<-release
		dispatched.Add(1)
	})
	go v.route(msg2)
	<-inFlight

	closeErr := make(chan error, 1)
	go func() { closeErr <- v.Close() }()
	select {
	case err := <-closeErr:
		t.Fatalf("Close returned while a dispatch was still in flight (err %v) - it must wait for the dispatch holding mu, then tear down", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-closeErr:
		if err != nil {
			t.Fatalf("Close after the in-flight dispatch was released: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close never returned once the in-flight dispatch was released")
	}
	if got := dispatched.Load(); got != 2 {
		t.Fatalf("dispatch count after the blocked dispatch ran is %d, want 2 (control + in-flight)", got)
	}

	// REFUSAL: the flag is up (Close set it under mu). Any later dispatch is
	// refused by the closing gate - never dispatched, and route returns.
	before := dispatched.Load()
	setDispatch(func(transport.Message) { dispatched.Add(1) })
	waitRouteDone(runRoute(msg3), "the post-Close dispatch")
	if got := dispatched.Load(); got != before {
		t.Fatalf("a dispatch ran AFTER Close (%d -> %d at the callback) - the closing gate is gone and the chain was already closed", before, got)
	}
	// And Close stays idempotent once the tear-down ran.
	if err := v.Close(); err != nil {
		t.Fatalf("the second Close: %v", err)
	}
}
