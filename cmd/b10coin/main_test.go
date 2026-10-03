package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout swapped for a pipe and returns what
// fmt.Printf wrote. The devnet command reports through stdout only, so the
// wire format IS the observable surface the multi-path assertions pin.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()
	fn()
	os.Stdout = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// The --validators flag must swap the RUN, not decorate it: a multi-validator
// invocation drives the committee (per-validator heights, the agreement line),
// not the single-node faucet loop with a different number on the front.
//
// Killing mutant B (compiled): cmdDevnet ignores --validators and always takes
// the single-node path. Both subchecks catch it: the first finds no
// "validators   4" multi report (and finds the claims block the multi path
// never prints), the second finds --claims silently absorbed instead of
// refused.
func TestCmdDevnetMultiValidatorDrivesTheMultiPath(t *testing.T) {
	out := captureStdout(t, func() {
		if err := cmdDevnet([]string{"--validators", "4", "--blocks", "3", "--dir", t.TempDir()}); err != nil {
			t.Errorf("cmdDevnet multi: %v", err)
		}
	})
	for _, want := range []string{"validators   4", "heights", "agreed       yes", "OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("the multi-validator run's output is missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "claims paid") {
		t.Errorf("the multi-validator run printed the single-node faucet block; got:\n%s", out)
	}

	// An explicit --claims alongside a committee is refused, not silently
	// dropped: the claim scenario has no transaction path into a committee,
	// so honouring the run while ignoring the flag would print an empty
	// faucet report and look like a broken faucet.
	if err := cmdDevnet([]string{"--validators", "4", "--blocks", "2", "--claims", "1", "--dir", t.TempDir()}); err == nil {
		t.Error("--claims with --validators > 1 must fail the command, not drop the flag")
	}
}

// An EXPLICIT --validators always names the committee that gets run — the
// flag's ABSENCE is the only way to ask for the single-node run, so that
// `--validators 0` cannot silently become the single-node path and
// `--validators 1` really runs the one-member committee.
//
// Killing mutant (compiled): the multi-path condition reverts to
// `*validators > 1`. Then `--validators 0` exits 0 as a single-node run
// instead of failing, and `--validators 1` claims it ran the committee while
// printing `b10coin-devnet-1` with the faucet block.
func TestCmdDevnetExplicitValidatorsAlwaysMeansTheCommittee(t *testing.T) {
	if err := cmdDevnet([]string{"--validators", "0", "--blocks", "2", "--dir", t.TempDir()}); err == nil {
		t.Error("--validators 0 names an empty committee; it must fail, not fall back to the single-node run")
	}
	out := captureStdout(t, func() {
		if err := cmdDevnet([]string{"--validators", "1", "--blocks", "2", "--dir", t.TempDir()}); err != nil {
			t.Errorf("cmdDevnet --validators 1: %v", err)
		}
	})
	if !strings.Contains(out, "b10coin-simnet-1") || !strings.Contains(out, "validators   1") {
		t.Errorf("an explicit --validators 1 must run the one-member committee, got:\n%s", out)
	}
	if strings.Contains(out, "claims paid") {
		t.Errorf("an explicit --validators 1 ran the single-node faucet path, got:\n%s", out)
	}
}
