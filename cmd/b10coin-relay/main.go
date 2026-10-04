// Command b10coin-relay is the public forwarder of the M4 network: one cheap
// VPS process that every home validator dials OUTBOUND to, so no validator
// needs a port forward - and, under CGNAT, could not have one.
//
// It forwards length-prefixed frames between every connected validator and
// does nothing else. It does not know what a vote is. That is the design, and
// the safety case for the whole topology: because every consensus message is
// signed with the sender's Ed25519 key, a malicious relay can censor or delay
// but cannot forge anything - safety is never at risk from the relay, only
// liveness is. If the relay ever "understood" the traffic it would become a
// place where consensus could be wrongly interpreted, so it is kept exactly
// as smart as a length prefix.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cti97/b10coincom/internal/relay"
)

const helpText = `b10coin-relay — the forwarder validators dial outbound to

Usage:
  b10coin-relay [--addr ADDR] [--max-frame-bytes N] [--max-conns N] [--write-queue N]
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

  Because the relay authenticates nothing, it must bind everything a
  stranger controls: frame size (--max-frame-bytes, refused before
  allocation), connection count (--max-conns), and per-connection buffering
  (--write-queue). A frame over the bound ends its connection; a dial past
  the connection bound is closed at accept.

Operation: run one instance per validator star, behind the VPS firewall
allowlisting the validator IPs - the relay itself is too dumb to have an
access policy, which is the point. Validators reconnect to it with
exponential backoff if it restarts. Bandwidth is kilobytes per second.
`

func main() {
	fs := flag.NewFlagSet("b10coin-relay", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), helpText) }
	addr := fs.String("addr", ":7001", "listen address (all interfaces; validators reach this one)")
	maxFrame := fs.Int("max-frame-bytes", relay.DefaultMaxFrameBytes, "largest frame any connection may send; a larger declared length ends that connection")
	maxConns := fs.Int("max-conns", relay.DefaultMaxConns, "maximum simultaneous connections; excess dials are closed at accept")
	queue := fs.Int("write-queue", relay.DefaultWriteQueueSize, "per-connection buffered frames before forwarding drops instead of blocking")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unknown argument %q\n\n", fs.Arg(0))
		fs.Usage()
		os.Exit(2)
	}

	r := relay.New(relay.Options{
		MaxFrameBytes:  *maxFrame,
		MaxConns:       *maxConns,
		WriteQueueSize: *queue,
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := r.Listen(*addr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("b10coin-relay forwarding on %s (max frame %d, max conns %d, queue %d)\n",
		r.Addr(), *maxFrame, *maxConns, *queue)

	<-ctx.Done()
	// Stop serving before draining: no new frames are accepted while the
	// wait below joins every reader and writer.
	r.Close()
}
