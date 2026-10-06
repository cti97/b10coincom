// Tests for the relay COMMAND - not the relay package (that package tests
// itself over real TCP). The command owns exactly three things and each is
// pinned: the flag -> relay.Options wiring, the exit codes (0 help/run,
// 1 listen failure, 2 bad invocation), and the brief-required trust text that
// every operator sees first. Everything here goes through run(), the
// extracted whole-command entry point, and asserts on the exit code plus the
// writers - the same observables os.Exit gives the shell.
package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
)

// TestRunHelpPrintsTheTrustTrade: the brief requires the trust trade in
// --help, and it must be CHECKED text, not read by eye once: cannot forge a
// vote, can only censor or delay - and, since F1, the two socket-level timers
// with their defaults and their expiry semantics stated where the operator
// reads them.
func TestRunHelpPrintsTheTrustTrade(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("--help exited %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("--help wrote %d bytes to stderr: %q", stderr.Len(), stderr.String())
	}
	for _, want := range []string{
		"cannot forge",
		"censor or delay",
		"--read-timeout (default 120)",
		"--write-timeout (default 30)",
		"--keepalive (default 15)",
		"--max-conns-per-ip (default 8)",
		"connection is closed and its registry slot released",
		"--write-queue-frames",
		"max-conns x (write-queue-bytes",
		"write-queue-frames x 32",
		"32 x (2 MiB + 4096 x 32 B + 2 x 1 MiB) = 32 x 4.125 MiB",
		"= 132 MiB",
		"--access-token-file",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("--help is missing %q - an operator would not see it", want)
		}
	}
}

// A bad invocation exits with the invocation code, prints the problem and the
// usage, and never reaches a listen.
func TestRunBadInvocationsExitTwo(t *testing.T) {
	cases := [][]string{
		{"--nope"}, // undefined flag
		{"extra"},  // unknown positional argument
		{"--max-conns", "not-a-number"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("run %v exited %d, want 2 (the invocation code)", args, code)
		}
		if stderr.Len() == 0 {
			t.Fatalf("run %v printed nothing to stderr - the operator would not know what was wrong", args)
		}
	}
}

// The flag wiring the tests exercise directly through run's parser: DEFAULTS
// must reach relay.Options exactly as documented (the operator-facing numbers
// also pinned relay-side by TestRelayOptionDefaultsPinTheOperatorNumbers), and
// every flag override must land on the right Options field.
func TestParseArgsWiresFlagsOntoRelayOptions(t *testing.T) {
	var stderr bytes.Buffer
	addr, opts, err := parseArgs(nil, &stderr)
	if err != nil {
		t.Fatalf("parseArgs() with no args: %v", err)
	}
	if addr != ":7001" {
		t.Fatalf("default --addr = %q, want \":7001\"", addr)
	}
	want := relay.Options{
		MaxFrameBytes:    1 << 20,
		MaxConns:         32,
		MaxConnsPerIP:    8,
		WriteQueueBytes:  2 << 20,
		WriteQueueFrames: 4096,
		WriteTimeout:     30 * time.Second,
		ReadTimeout:      2 * time.Minute,
		KeepAlive:        15 * time.Second,
	}
	if !reflect.DeepEqual(opts, want) {
		t.Fatalf("default Options drifted from the documented numbers: got %+v, want %+v", opts, want)
	}

	var stderr2 bytes.Buffer
	addr, opts, err = parseArgs([]string{
		"--addr", "127.0.0.1:7005",
		"--max-frame-bytes", "8192",
		"--max-conns", "7",
		"--max-conns-per-ip", "5",
		"--write-queue-bytes", "4096",
		"--write-queue-frames", "17",
		"--write-timeout", "6",
		"--read-timeout", "30",
		"--keepalive", "10",
	}, &stderr2)
	if err != nil {
		t.Fatalf("parseArgs(overrides): %v", err)
	}
	if addr != "127.0.0.1:7005" {
		t.Fatalf("--addr = %q, want \"127.0.0.1:7005\"", addr)
	}
	wantOverride := relay.Options{
		MaxFrameBytes:    8192,
		MaxConns:         7,
		MaxConnsPerIP:    5,
		WriteQueueBytes:  4096,
		WriteQueueFrames: 17,
		WriteTimeout:     6 * time.Second,
		ReadTimeout:      30 * time.Second,
		KeepAlive:        10 * time.Second,
	}
	if !reflect.DeepEqual(opts, wantOverride) {
		t.Fatalf("overrides did not reach Options: got %+v, want %+v", opts, wantOverride)
	}

	// A zero is a deliberate convention ("use the default", relay.Options'
	// contract) and must pass through untouched, not become some other value.
	_, opts, err = parseArgs([]string{"--read-timeout", "0", "--keepalive", "0", "--write-timeout", "0", "--max-conns-per-ip", "0", "--write-queue-bytes", "0", "--write-queue-frames", "0"}, &stderr2)
	if err != nil {
		t.Fatalf("parseArgs(zeros): %v", err)
	}
	if opts.ReadTimeout != 0 || opts.KeepAlive != 0 || opts.WriteTimeout != 0 || opts.MaxConnsPerIP != 0 || opts.WriteQueueBytes != 0 || opts.WriteQueueFrames != 0 {
		t.Fatalf("zero flags must pass through for the relay's default convention: got %+v", opts)
	}
}

// A listen failure exits 1: the address is checked the moment the relay
// starts, loudly, and nothing half-listens.
func TestRunBadAddrExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--addr", "not-a-socket"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("--addr not-a-socket exited %d, want 1 (the listen-failure code)", code)
	}
	if !strings.Contains(stderr.String(), "error:") {
		t.Fatalf("listen failure did not report the error on stderr: %q", stderr.String())
	}
}

// TestParseArgsReadsTheAccessTokenFile pins audit N-8's CLI wiring: the token
// is read from a FILE (not argv, where ps would show it), a trailing newline
// from an editor is trimmed, and an empty or missing file is a bad invocation
// rather than a silently disabled gate. The length floor is part of it (review,
// audit fix round 4): a token shorter than wire.MinRelayAccessTokenBytes is
// brute-forced by dialling, so the CLI refuses it before the relay can listen.
func TestParseArgsReadsTheAccessTokenFile(t *testing.T) {
	dir := t.TempDir()
	const goodToken = "shared-secret-enough"
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte(goodToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	_, opts, err := parseArgs([]string{"--access-token-file", tokenPath}, &stderr)
	if err != nil {
		t.Fatalf("parseArgs with a token file: %v", err)
	}
	if string(opts.AccessToken) != goodToken {
		t.Fatalf("AccessToken = %q, want %q (with the trailing newline trimmed)", opts.AccessToken, goodToken)
	}
	// One byte under the floor is refused, and the message names the floor.
	shortPath := filepath.Join(dir, "short")
	if err := os.WriteFile(shortPath, []byte("too-short-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseArgs([]string{"--access-token-file", shortPath}, &stderr); err == nil {
		t.Fatal("a 15-byte access token was accepted; it is brute-forced by dialling")
	} else if !strings.Contains(err.Error(), "at least") {
		t.Fatalf("the short-token refusal reads %q; it must name the minimum", err)
	}

	// A missing file is an error, not an open relay.
	if _, _, err := parseArgs([]string{"--access-token-file", filepath.Join(dir, "missing")}, &stderr); err == nil {
		t.Fatal("a missing access-token file was accepted, leaving the relay open")
	}
	// An empty file too: an empty token would compare equal to nothing and
	// disable the gate without saying so.
	emptyPath := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyPath, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseArgs([]string{"--access-token-file", emptyPath}, &stderr); err == nil {
		t.Fatal("an empty access-token file was accepted")
	}
}

// writerFunc adapts a function to io.Writer for the stats test's channel.
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// TestLogStatsSurfacesTheCountersOnTheTimerAndTheSignal pins audit N-9: the
// relay's Dropped and RefusedConns counters - the numbers that reveal the
// relay censoring - are printed on a timer AND on demand. The line is read
// off a channel, so the assertions are on produced output, not on a sleep.
func TestLogStatsSurfacesTheCountersOnTheTimerAndTheSignal(t *testing.T) {
	lines := make(chan string, 8)
	w := writerFunc(func(p []byte) (int, error) { lines <- string(p); return len(p), nil })
	r := relay.New(relay.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	go logStats(ctx, sig, r, w, 20*time.Millisecond)

	readLine := func(what string) string {
		t.Helper()
		select {
		case line := <-lines:
			return line
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: logStats wrote nothing", what)
			return ""
		}
	}
	timerLine := readLine("the timer path")
	for _, want := range []string{"conns=", "forwarded=", "dropped=", "refused=", "unauthorized="} {
		if !strings.Contains(timerLine, want) {
			t.Fatalf("the stats line omits %q, so a relay silently dropping frames would still look healthy: %q", want, timerLine)
		}
	}
	// The signal path writes one line per signal, immediately.
	sig <- os.Interrupt
	signalLine := readLine("the signal path")
	if !strings.Contains(signalLine, "b10coin-relay stats:") {
		t.Fatalf("the signal path wrote %q, not a stats line", signalLine)
	}
	cancel()
}

// TestRelayStatsLineReportsEveryCounter pins the exact fields of the line, so
// a future edit cannot quietly drop the two counters N-9 exists for.
func TestRelayStatsLineReportsEveryCounter(t *testing.T) {
	got := relayStatsLine(relay.Stats{Conns: 3, Forwarded: 11, Dropped: 2, RefusedConns: 5, Unauthorized: 7})
	want := "b10coin-relay stats: conns=3 forwarded=11 dropped=2 refused=5 unauthorized=7"
	if got != want {
		t.Fatalf("relayStatsLine = %q, want %q", got, want)
	}
}
