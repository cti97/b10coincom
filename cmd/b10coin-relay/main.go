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
  b10coin-relay [--addr ADDR] [--max-frame-bytes N] [--max-conns N]
                [--max-conns-per-ip N] [--write-queue-bytes N]
                [--write-timeout SECONDS] [--read-timeout SECONDS]
                [--keepalive SECONDS]
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
  stranger controls - with STRUCTURAL bounds only (byte budgets, socket
  deadlines, endpoint counts; it parses the frame length and nothing beyond
  it): frame size (--max-frame-bytes, refused before allocation), connection
  count in total (--max-conns) and per source IP (--max-conns-per-ip), the
  per-connection write queue in BYTES (--write-queue-bytes), and two
  per-frame socket deadlines (--read-timeout, --write-timeout). A frame over
  the bound ends its connection; a dial past either connection bound is
  closed at accept. (Zero or negative for any knob selects its default.)

HOW MUCH AND HOW LONG A STRANGER MAY PIN (derivable; nothing is parsed to
enforce any of it)

  --read-timeout (default 120) is a per-frame read deadline: armed before
  each frame's 4-byte header and refreshed at every completed frame, so a
  peer that is actively sending is never cut off. When it expires - a
  connection that delivered no complete frame for the whole period - the
  connection is closed and its registry slot released the same instant. The
  peer's outbound backoff redials it.

  --write-timeout (default 30) is a per-frame write deadline: a frame that
  cannot be written inside it - the connection's reader has stopped reading
  and the kernel is backpressuring - closes the connection the same way and
  releases the bytes queued behind the writer. This is the timer that keeps
  a sink that never reads from pinning its queue forever, WHATEVER keepalive
  frames it keeps sending: keepalives refresh only the READ deadline, so
  without a write deadline a sink could hold a full queue indefinitely (the
  N-2 attack); with it, the pin is bounded by the deadline whether or not
  the sink keeps talking.

  --keepalive (default 15) is the TCP keepalive probe period: a HALF-OPEN
  connection (a peer that vanished without closing, e.g. a power cut) is
  reaped by the kernel after unanswered probes - minutes, by the OS's count.

  THE MEMORY ARITHMETIC, derived rather than asserted. One connection can
  hold, at one instant, at most: its full write-queue byte budget
  (--write-queue-bytes), the one frame in its writer's hand (<=
  --max-frame-bytes), and the one frame in its reader's hand (<=
  --max-frame-bytes). The aggregate is therefore:

      max-conns x (write-queue-bytes + 2 x max-frame-bytes)

  At the defaults: 32 x (2 MiB + 2 x 1 MiB) = 32 x 4 MiB = 128 MiB. (The
  pre-fix claim in this space was wrong by the write-queue factor: 256
  conns could each queue 64 FRAMES x 1 MiB = 64 MiB - 16 GiB aggregate, not
  the 256 MiB documented - and hold it indefinitely, a sink that never
  reads having no write deadline to end it.) Slots are additionally bounded
  per source IP by --max-conns-per-ip (default 8), so one host cannot hold
  the registry.

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
		"b10coin-relay forwarding on %s (max frame %d, max conns %d (%d per IP), queue %d bytes, read timeout %s, write timeout %s, keepalive %s)\n",
		r.Addr(), opts.MaxFrameBytes, opts.MaxConns, opts.MaxConnsPerIP, opts.WriteQueueBytes, opts.ReadTimeout, opts.WriteTimeout, opts.KeepAlive)

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
	maxPerIP := fs.Int("max-conns-per-ip", relay.DefaultMaxConnsPerIP, "maximum simultaneous connections from one source IP; excess dials from that IP are closed at accept")
	queueBytes := fs.Int("write-queue-bytes", relay.DefaultWriteQueueBytes, "per-connection write-queue budget in PAYLOAD BYTES before forwarding drops instead of blocking (floored at max-frame-bytes)")
	writeTimeout := fs.Int("write-timeout", int(relay.DefaultWriteTimeout/time.Second), "seconds one frame may remain unwritten to a connection that has stopped reading; expiry closes that connection and releases its queued bytes and slot")
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
		MaxFrameBytes:   *maxFrame,
		MaxConns:        *maxConns,
		MaxConnsPerIP:   *maxPerIP,
		WriteQueueBytes: *queueBytes,
		WriteTimeout:    time.Duration(*writeTimeout) * time.Second,
		ReadTimeout:     time.Duration(*readTimeout) * time.Second,
		KeepAlive:       time.Duration(*keepAlive) * time.Second,
	}, nil
}
