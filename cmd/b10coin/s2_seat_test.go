package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

// captureStderr is captureStdout's other half, for the lines a verb puts on
// stderr on purpose: the seat warning (testrun S-2) is advice about a receipt
// that stays on stdout, so a test that captured stdout alone would see the
// receipt and none of the warning.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()
	fn()
	os.Stderr = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// TestSendPrintsTheNodesSeatWarning: a node that holds no seat admits the
// transfer and will never include it (testrun S-2). The txid stays on stdout
// because admission really happened; the warning goes to stderr and must carry
// the NODE's sentence plus the one thing the operator has to do - repost the
// same bytes to a seated validator.
func TestSendPrintsTheNodesSeatWarning(t *testing.T) {
	keyPath, _, to, stub := sendTestSetup(t, 5*genesis.SparksPerB10, 0)
	stub.setTxReply(200, `{"txid":"`+strings.Repeat("ab", 32)+`","seated":false,"warning":"this node's key holds no committee seat at height 12, so the transaction is parked"}`)

	var runErr error
	out := captureStdout(t, func() {
		stderr := captureStderr(t, func() {
			runErr = cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--yes"})
		})
		for _, want := range []string{
			"WARNING: this node's key holds no committee seat at height 12, so the transaction is parked",
			"nothing on this node will include it",
			"Post the same bytes to a seated validator",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr does not contain %q:\n%s", want, stderr)
			}
		}
	})
	if runErr != nil {
		t.Fatalf("cmdSend returned an error for an admitted transaction: %v", runErr)
	}
	// The receipt is still printed: the transaction was accepted, and the CLI
	// must not pretend otherwise.
	if !strings.Contains(out, "txid        "+strings.Repeat("ab", 32)) {
		t.Errorf("stdout lost the txid of the admitted transaction:\n%s", out)
	}
}

// TestSendSaysNothingWhenTheNodeReportsASeat: the warning must not appear on
// the honest path. Every shipped single-node run is this path.
func TestSendSaysNothingWhenTheNodeReportsASeat(t *testing.T) {
	keyPath, _, to, stub := sendTestSetup(t, 5*genesis.SparksPerB10, 0)
	stub.setTxReply(200, `{"txid":"`+strings.Repeat("ab", 32)+`","seated":true}`)

	out := captureStdout(t, func() {
		stderr := captureStderr(t, func() {
			if err := cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--yes"}); err != nil {
				t.Fatalf("cmdSend: %v", err)
			}
		})
		if strings.Contains(stderr, "WARNING") {
			t.Errorf("a seated node produced a warning:\n%s", stderr)
		}
	})
	if !strings.Contains(out, "txid        ") {
		t.Errorf("stdout lost the txid:\n%s", out)
	}
}

// TestSendIgnoresAWarningWithoutAnUnseatedVerdict: prose alone is not a
// verdict. A node that says seated=true and also sends a warning is
// contradicting itself, and the CLI refuses to invent a meaning for it - it
// prints no warning, because the one field that can be true or false says the
// transaction is fine.
func TestSendIgnoresAWarningWithoutAnUnseatedVerdict(t *testing.T) {
	keyPath, _, to, stub := sendTestSetup(t, 5*genesis.SparksPerB10, 0)
	stub.setTxReply(200, `{"txid":"`+strings.Repeat("ab", 32)+`","warning":"something went wrong"}`)

	captureStdout(t, func() {
		stderr := captureStderr(t, func() {
			if err := cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--yes"}); err != nil {
				t.Fatalf("cmdSend: %v", err)
			}
		})
		if strings.Contains(stderr, "something went wrong") {
			t.Errorf("a reply with no seated verdict printed its warning anyway:\n%s", stderr)
		}
	})
}

// TestTheSeatWarningIsSanitised: the warning is prose chosen by the node and
// printed on the operator's terminal, so the S-13 rule applies - no control
// bytes get through, and the ESC sequence arrives escaped.
func TestTheSeatWarningIsSanitised(t *testing.T) {
	keyPath, _, to, stub := sendTestSetup(t, 5*genesis.SparksPerB10, 0)
	stub.setTxReply(200, `{"txid":"`+strings.Repeat("ab", 32)+`","seated":false,"warning":"line one\n\u001b[2Jforged receipt"}`)

	captureStdout(t, func() {
		stderr := captureStderr(t, func() {
			if err := cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--yes"}); err != nil {
				t.Fatalf("cmdSend: %v", err)
			}
		})
		if strings.ContainsAny(stderr, "\x1b") {
			t.Errorf("an ESC byte from the node reached the terminal:\n%q", stderr)
		}
		if strings.Count(stderr, "\n") > 3 {
			t.Errorf("a newline inside the node's warning forged extra lines:\n%q", stderr)
		}
	})
}

// TestPostTxHexIgnoresSeatFieldsFromAnOlderNode: the fields are additive, so a
// node that does not report them must keep working exactly as before.
func TestPostTxHexIgnoresSeatFieldsFromAnOlderNode(t *testing.T) {
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{})
	stub.setTxReply(200, `{"txid":"`+strings.Repeat("ab", 32)+`"}`)

	rc, err := postTxHex(stub.url+"/tx", (&types.Tx{Type: types.TxTransfer}).Encode())
	if err != nil {
		t.Fatalf("postTxHex: %v", err)
	}
	if rc.TxID != strings.Repeat("ab", 32) {
		t.Errorf("txid = %q", rc.TxID)
	}
	if rc.Seated != nil {
		t.Errorf("seated = %v, want nil when the node did not report it", *rc.Seated)
	}
	if rc.Warning != "" {
		t.Errorf("warning = %q, want empty", rc.Warning)
	}
}
