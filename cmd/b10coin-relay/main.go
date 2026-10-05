// Command b10coin-relay is the public forwarder of the M4 network: one cheap
// VPS process that every home validator dials OUTBOUND to, so no validator
// needs a port forward - and, under CGNAT, could not have one.
//
// It forwards length-prefixed frames between every connected validator and
// does nothing else. It does not know what a vote is. That is the design, and
// the safety case for the whole topology: because every consensus message is
// signed with the sender's Ed25519 key, a malicious relay can censor or delay
// but cannot forge a vote or a proposal - safety is never at risk from the
// relay, only liveness is. THAT TRADE HOLDS ONLY FOR COMMITTEES OF HELD KEYS
// (--genesis + --key): the development fixture committee derives every
// member's private key from public seeds, so with it the claim is vacuous -
// anyone can sign as any seat, no relay required - and a fixture committee
// must never meet a relay reachable beyond the operator's own machines. If
// the relay ever "understood" the traffic it would become a place where
// consensus could be wrongly interpreted, so it is kept exactly as smart as a
// length prefix.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cti97/b10coincom/internal/relay"
)

const helpText = `b10coin-relay — the forwarder validators dial outbound to

Usage:
  b10coin-relay [--addr ADDR] [--max-frame-bytes N] [--max-conns N] [--write-queue N]
                [--read-timeout SECONDS] [--keepalive SECONDS]
  b10coin-relay --help

Every validator connects OUTBOUND to this relay (inbound to a home machine
is blocked by NAT/firewall, and CGNAT has no public IP to forward to at all;
outbound is almost never blocked). The relay keeps a registry of connected
peers and forwards every frame it receives to every OTHER peer. That is all
it does: it reads a frame's length, forwards the bytes, and parses nothing
beyond that length.

THE TRUST TRADE — read before running one

  Every consensus message is signed with the sender's Ed25519 key. A
  malicious relay can therefore censor or delay frames, but it cannot forge
  a vote or a proposal: consensus safety never depends on the relay, only
  liveness does (a relay that partitions the validator set stalls consensus).
  For a testnet this is an acceptable trade. If it ever stops being one, the
  design's mitigations are multiple relays and direct connections - never a
  smarter relay.

  THAT TRADE HOLDS ONLY FOR COMMITTEES OF HELD KEYS: validators started with
  --genesis (a shared committee file listing the members' public keys) and
  --key (b10coin keygen). The development fixture committee
  (--validators/--index) derives every member's private key from public
  seeds inside the source, so with it anyone can sign as ANY validator - and
  no property of the relay matters, because forging needs no relay at all.
  Never point the fixture committee at a relay reachable beyond your own
  machines.

  Because the relay authenticates nothing, it must bind everything a
  stranger controls: frame size (--max-frame-bytes, refused before
  allocation), connection count (--max-conns), per-connection buffering
  (--write-queue), and how long a connection may hold its slot without
  delivering a frame (--read-timeout). A frame over the bound ends its
  connection; a dial past the connection bound is closed at accept.

HOW LONG A STRANGER MAY HOLD A CONNECTION (both socket-level: nothing is
parsed to enforce them)

  --read-timeout (default 120) is a per-frame read deadline: armed before
  each frame's 4-byte header and refreshed at every completed frame, so a
  peer that is actively sending is never cut off. When it expires - a
  connection that delivered no complete frame for the whole period - the
  connection is closed and its registry slot released the same instant.
  The peer's outbound backoff redials it. A stranger can therefore pin at
  most max-conns x max-frame-bytes of memory and max-conns of slots, each
  for at most --read-timeout, never forever.

  --keepalive (default 15) is the TCP keepalive probe period: a HALF-OPEN
  connection (a peer that vanished without closing, e.g. a power cut) is
  reaped by the kernel after unanswered probes - minutes, by the OS's
  count - again without the relay looking at any byte.

Operation: run one instance per validator star, behind the VPS firewall
allowlisting the validator IPs - the relay itself is too dumb to have an
access policy, which is the point. Validators reconnect to it with
exponential backoff if it restarts. Bandwidth is kilobytes per second.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the whole command: parse the flags onto relay.Options, listen, and
// exit by CODE rather than by os.Exit so tests can call it. The two exit
// codes beyond zero: 1 for a listen failure, 2 for a bad invocation.
func run(args []string, stdout, stderr io.Writer) int {
	addr, opts, err := parseArgs(args, stderr)
	if errors.Is(err, errHelp) {
		fmt.Fprint(stdout, helpText)
		return 0
	}
	if err != nil {
		// parseArgs has already printed the problem and the usage.
		return 2
	}

	r := relay.New(opts)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := r.Listen(addr); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(stdout,
		"b10coin-relay forwarding on %s (max frame %d, max conns %d, queue %d, read timeout %s, keepalive %s)\n",
		r.Addr(), opts.MaxFrameBytes, opts.MaxConns, opts.WriteQueueSize, opts.ReadTimeout, opts.KeepAlive)

	<-ctx.Done()
	// Stop serving before draining: no new frames are accepted while the
	// wait below joins every reader and writer.
	r.Close()
	return 0
}

// errHelp is the sentinel parseArgs returns when the operator asked for
// help: run then prints the trust trade to stdout and exits 0.
var errHelp = errors.New("b10coin-relay: help requested")

// parseArgs maps the CLI flags onto the listen address and the relay Options
// (the wiring the tests exercise). It owns the usage printing on stderr for
// every rejected invocation and returns an error for them; --help anywhere in
// the arguments wins, and is signalled with errHelp.
func parseArgs(args []string, stderr io.Writer) (string, relay.Options, error) {
	// Detected before Parse: on a --help the flag package's own usage print
	// (below, through fs.Usage) would duplicate the copy run() sends to
	// stdout, so Usage suppresses itself for that one path.
	help := false
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" {
			help = true
			break
		}
	}
	fs := flag.NewFlagSet("b10coin-relay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		out := io.Writer(stderr)
		if help {
			out = io.Discard
		}
		fmt.Fprint(out, helpText)
	}
	addr := fs.String("addr", ":7001", "listen address (all interfaces; validators reach this one)")
	maxFrame := fs.Int("max-frame-bytes", relay.DefaultMaxFrameBytes, "largest frame any connection may send; a larger declared length ends that connection")
	maxConns := fs.Int("max-conns", relay.DefaultMaxConns, "maximum simultaneous connections; excess dials are closed at accept")
	queue := fs.Int("write-queue", relay.DefaultWriteQueueSize, "per-connection buffered frames before forwarding drops instead of blocking")
	readTimeout := fs.Int("read-timeout", int(relay.DefaultReadTimeout/time.Second), "seconds one frame may take to arrive; expiry closes that connection and releases its slot")
	keepAlive := fs.Int("keepalive", int(relay.DefaultKeepAlive/time.Second), "TCP keepalive probe period in seconds; half-open connections are reaped by the kernel after unanswered probes")

	err := fs.Parse(args)
	switch {
	case help:
		// Help wins wherever it appears in the arguments.
		return "", relay.Options{}, errHelp
	case errors.Is(err, flag.ErrHelp):
		return "", relay.Options{}, errHelp
	case err != nil:
		return "", relay.Options{}, err
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unknown argument %q\n\n", fs.Arg(0))
		fs.Usage()
		return "", relay.Options{}, fmt.Errorf("unknown argument %q", fs.Arg(0))
	}
	return *addr, relay.Options{
		MaxFrameBytes:  *maxFrame,
		MaxConns:       *maxConns,
		WriteQueueSize: *queue,
		ReadTimeout:    time.Duration(*readTimeout) * time.Second,
		KeepAlive:      time.Duration(*keepAlive) * time.Second,
	}, nil
}
