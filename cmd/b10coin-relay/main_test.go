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
		"max-conns x (write-queue-bytes + 2 x max-frame-bytes)",
		"32 x (2 MiB + 2 x 1 MiB) = 32 x 4 MiB = 128 MiB",
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
		MaxFrameBytes:   1 << 20,
		MaxConns:        32,
		MaxConnsPerIP:   8,
		WriteQueueBytes: 2 << 20,
		WriteTimeout:    30 * time.Second,
		ReadTimeout:     2 * time.Minute,
		KeepAlive:       15 * time.Second,
	}
	if opts != want {
		t.Fatalf("default Options drifted from the documented numbers: got %+v, want %+v", opts, want)
	}

	var stderr2 bytes.Buffer
	addr, opts, err = parseArgs([]string{
		"--addr", "127.0.0.1:7005",
		"--max-frame-bytes", "8192",
		"--max-conns", "7",
		"--max-conns-per-ip", "5",
		"--write-queue-bytes", "4096",
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
		MaxFrameBytes:   8192,
		MaxConns:        7,
		MaxConnsPerIP:   5,
		WriteQueueBytes: 4096,
		WriteTimeout:    6 * time.Second,
		ReadTimeout:     30 * time.Second,
		KeepAlive:       10 * time.Second,
	}
	if opts != wantOverride {
		t.Fatalf("overrides did not reach Options: got %+v, want %+v", opts, wantOverride)
	}

	// A zero is a deliberate convention ("use the default", relay.Options'
	// contract) and must pass through untouched, not become some other value.
	_, opts, err = parseArgs([]string{"--read-timeout", "0", "--keepalive", "0", "--write-timeout", "0", "--max-conns-per-ip", "0", "--write-queue-bytes", "0"}, &stderr2)
	if err != nil {
		t.Fatalf("parseArgs(zeros): %v", err)
	}
	if opts.ReadTimeout != 0 || opts.KeepAlive != 0 || opts.WriteTimeout != 0 || opts.MaxConnsPerIP != 0 || opts.WriteQueueBytes != 0 {
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
