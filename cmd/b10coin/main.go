// Command b10coin is the b10coin node and tooling binary.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/devnet"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/keystore"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/node"
	"github.com/cti97/b10coincom/internal/rpc"
	"github.com/cti97/b10coincom/internal/types"
	"github.com/cti97/b10coincom/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "devnet":
		err = cmdDevnet(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "node":
		err = cmdNode(os.Args[2:])
	case "claim":
		err = cmdClaim(os.Args[2:])
	case "version":
		fmt.Println(version.Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `b10coin — a testnet cryptocurrency for small computers

Usage:
  b10coin devnet --blocks N [--validators N] [--dir PATH] [--claims N]   Build and verify a local chain (or, with --validators given, a consensus devnet over the FIXTURE committee)
  b10coin keygen [--out PATH]                                            Generate this validator's key file (owner-only permissions; refuses to overwrite)
  b10coin node   --dir PATH [--http ADDR] [--block-time DURATION]
                 [--peers ADDR,...] [--relay ADDR] [--listen ADDR]       Run the single-node devnet producer, or — with --peers/--relay/--listen — a consensus validator
                 --genesis PATH --key PATH                               (with both: a REAL member of the committee the genesis file lists)
                 --validators N --index I                                (fixture ONLY: the derived development committee, publicly derivable keys)
  b10coin claim  --node URL [--dir PATH]                Solve the faucet puzzle and send one claim
  b10coin version

A node with --peers/--relay/--listen runs the M4 consensus committee over real
TCP: --peers dials the other validators (or the relay), --relay dials the dumb
forwarder every home validator reaches outbound, --listen accepts direct
connections. HOW the committee is named decides whose keys sign:

  --genesis PATH --key PATH   the committee is the genesis file's list of
                              validator PUBLIC keys; this node signs with ITS
                              OWN held key and REFUSES TO START when that key
                              is not in the committee. This is the mode for
                              any node that reaches a shared network.
  --validators N --index I    FIXTURE COMMITTEE (development only): every
                              seat's private key is derived from the public
                              seed "b10coin-simnet-validator" plus the seat
                              number, so anyone with this repository can sign
                              proposals, prevotes and precommits for ANY seat,
                              and the chain ID b10coin-simnet-N publishes the
                              committee size. Never point this mode at a
                              network beyond your own machines.
Without any of those flags the node is the M1 producer: one chain, no round
protocol.

The claim command signs with an ephemeral key that is printed and never
stored: the key signs exactly this claim and is printed once so it can be
reused for a follow-up transfer.
`)
}

func cmdDevnet(args []string) error {
	fs := flag.NewFlagSet("devnet", flag.ExitOnError)
	blocks := fs.Uint64("blocks", 100, "number of blocks to produce")
	// Default 1: the acceptance check IS the milestone's proof, so the
	// faucet must be exercised without a flag. Every default run pays one
	// claim against a solved puzzle and proves the same-epoch double claim
	// refused. --claims 0 keeps the plain transfer-only runs available.
	claims := fs.Uint64("claims", 1, "faucet claim attempts to make after the block loop (single-node run only)")
	// Default 1: exactly the single-node acceptance check M0-M2 shipped.
	// An EXPLICIT value - 1 included - swaps the whole run for the
	// multi-validator consensus path (see validatorsSet below): `--validators
	// 1` deliberately runs a one-member committee. That is the acceptance
	// check the design named at M0
	// (`devnet --validators 4 --blocks 100`) and could not honour until M3,
	// because a single node needs no agreement.
	validators := fs.Uint64("validators", 1, "committee size; giving the flag at all — 1 included — runs a multi-validator consensus devnet (the faucet-claim scenario does not apply)")
	dir := fs.String("dir", "", "data directory (default: a fresh temporary directory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Whether --claims was given explicitly (its default is 1, so the flag's
	// value alone cannot tell "asked for claims" from "left the default").
	// The same applies to --validators: an EXPLICIT value — including
	// `--validators 1` — names the committee that gets run. Only the flag's
	// ABSENCE means the single-node run; otherwise `--validators 0` would
	// silently become the single-node path and the flag would lie.
	claimsSet := false
	validatorsSet := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "claims":
			claimsSet = true
		case "validators":
			validatorsSet = true
		}
	})

	if *dir == "" {
		d, err := os.MkdirTemp("", "b10coin-devnet-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(d)
		*dir = d
	}

	// The multi-validator path: a consensus committee over the simnet
	// harness, reported per validator, failing unless the validators hold one
	// history (--validators 0 fails inside RunMulti as ErrNoValidators). The
	// faucet-claim scenario is the SINGLE-NODE path's proof — a committee
	// accepts no transactions — so an explicit --claims there is a misuse to
	// refuse, not a value to drop on the floor.
	if *validators > 1 || validatorsSet {
		if claimsSet && *claims > 0 {
			return fmt.Errorf("--claims runs the single-node faucet scenario and does not apply to a --validators %d run; drop --claims (the single-node default still pays one)", *validators)
		}
		summary, err := devnet.RunMulti(devnet.Options{Dir: *dir, Blocks: *blocks, Validators: *validators})
		// Only a run that RAN (its summary names a committee) prints a report;
		// an option-validation failure returns an empty summary, and printing
		// `validators   0` ahead of its error would be noise, not diagnosis.
		if summary.Validators > 0 {
			printMultiDevnet(summary)
		}
		if err != nil {
			// The summary lines above are whatever the run produced — on a
			// stall or a disagreement they are the diagnosis.
			return err
		}
		fmt.Println("OK")
		return nil
	}

	summary, err := devnet.Run(devnet.Options{Dir: *dir, Blocks: *blocks, Claims: *claims})
	if err != nil {
		return err
	}
	fmt.Printf("chain        %s\n", summary.ChainID)
	fmt.Printf("height       %d\n", summary.Height)
	fmt.Printf("state root   %x\n", summary.StateRoot)
	fmt.Printf("txs included %d\n", summary.TxsIncluded)
	if *claims > 0 {
		fmt.Printf("claims paid  %d of %d attempts, %d sparks each\n",
			summary.Claimed, *claims, summary.ClaimAmount)
		fmt.Printf("double claims refused %d (one claim per key per epoch)\n", summary.DoubleClaimsRefused)
		fmt.Printf("claimant bal %d sparks\n", summary.ClaimedBalance)
		fmt.Printf("faucet bal   %d sparks (emitted %d sparks in total)\n",
			summary.FaucetBalance, summary.EmittedTotal)
	}
	// Every claim attempt takes exactly one following block, and the double
	// claim of every PAID attempt takes one more (RunOnce appends one block
	// per call — empty when the probe refuses the transaction), so the
	// expected final height is blocks plus attempts plus the refused double
	// claims the scenario proved.
	if summary.Height != *blocks+*claims+summary.DoubleClaimsRefused {
		return fmt.Errorf("expected height %d, got %d", *blocks+*claims+summary.DoubleClaimsRefused, summary.Height)
	}
	fmt.Println("OK")
	return nil
}

// printMultiDevnet prints the committee report of a multi-validator run:
// every validator's final height, and whether the validators hold one
// history. The run FAILS (no OK, exit 1) unless they agree — that check is
// RunMulti's, surfaced here as the error above.
func printMultiDevnet(s devnet.Summary) {
	fmt.Printf("chain        %s\n", s.ChainID)
	fmt.Printf("validators   %d\n", s.Validators)
	fmt.Printf("heights      %s\n", validatorHeightsLine(s.ValidatorHeights))
	agreed := "no"
	if s.Agreed {
		agreed = "yes"
	}
	fmt.Printf("agreed       %s\n", agreed)
}

// validatorHeightsLine renders the per-validator heights as v0=H v1=H ... in
// committee-index order.
func validatorHeightsLine(h map[int]uint64) string {
	indexes := make([]int, 0, len(h))
	for i := range h {
		indexes = append(indexes, i)
	}
	sort.Ints(indexes)
	parts := make([]string, 0, len(indexes))
	for _, i := range indexes {
		parts = append(parts, fmt.Sprintf("v%d=%d", i, h[i]))
	}
	return strings.Join(parts, " ")
}

// cmdKeygen generates one REAL validator key and writes it to a key file with
// owner-only permissions. It refuses to overwrite an existing file (audit
// A-1): a careless rerun derives a DIFFERENT key, and a validator that then
// loads the new file can no longer sign as the seat the genesis listed —
// while anyone holding the old file still can. Only the PUBLIC key travels:
// the printed value is what goes into the committee file (--genesis) the
// whole committee shares.
//
// The printed seat address is the account this key signs from
// (BLAKE3("b10coin-address") of the public key, rendered with its checksum),
// the same derivation every transaction's From field carries.
func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "./b10coin.key", "key file to write (created owner-only 0600; refuses to overwrite an existing file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unknown argument %q", fs.Arg(0))
	}
	_, priv, err := keystore.Generate(*out)
	if err != nil {
		return err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	fmt.Printf("key file     %s (owner-only 0600; regenerate elsewhere, never over this one)\n", *out)
	fmt.Printf("public key   %x\n", []byte(pub))
	fmt.Printf("seat address %s\n", types.AddressFromPub(pub))
	fmt.Println()
	fmt.Println("Add the public key line above to the committee file your validators share")
	fmt.Println("(--genesis). A node started with --key must find its public key there, or")
	fmt.Println("it refuses to start rather than signing for a seat it does not hold.")
	return nil
}

// claimHTTP bounds RPC round trips for the claim command; the puzzle itself
// is solved locally before anything is sent.
var claimHTTP = &http.Client{Timeout: 15 * time.Second}

// claimPuzzleAttempts bounds the local solve. The devnet's easy target needs
// about two attempts; a failure means the tuning changed, not that mining is
// slow.
const claimPuzzleAttempts = 1_000_000

// cmdClaim solves the faucet puzzle for a FRESH EPHEMERAL key and submits the
// signed claim to a node's /tx endpoint. There is no key file and no
// keystore: the key signs exactly this claim and is PRINTED, never stored,
// so it can be reused for a follow-up transfer if the operator chooses to
// copy it out. The claim is only queued by this command; the node pays it
// when its next block applies it (one claim per key per epoch).
func cmdClaim(args []string) error {
	fs := flag.NewFlagSet("claim", flag.ExitOnError)
	nodeURL := fs.String("node", "http://127.0.0.1:8645", "URL of the node's HTTP RPC to submit the claim to")
	// --dir keeps the command surface uniform with the other commands, but
	// claim reads NOTHING from disk: the devnet genesis it must agree with is
	// compiled in, and the key must never be written anywhere. The flag is
	// accepted so scripts built on the other commands keep working; its value
	// is deliberately never read here.
	fs.String("dir", "./b10coin-data", "the node's data directory (unused by the claim itself; the devnet genesis is compiled in)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// The puzzle's parameters are GENESIS state, not carried on the wire:
	// claimant and verifier must agree on them, so the command solves with
	// the same compiled-in devnet parameters an M2 node runs.
	g := genesis.Devnet()

	base := strings.TrimRight(*nodeURL, "/")
	var status struct {
		ChainID string `json:"chain_id"`
		Height  uint64 `json:"height"`
	}
	if err := getJSON(base+"/status", &status); err != nil {
		return fmt.Errorf("cannot read the node's status at %s: %w", base+"/status", err)
	}
	// The claim only verifies on the chain whose parameters solved it; a
	// different chain would refuse it anyway, so say so here.
	if status.ChainID != g.ChainID {
		return fmt.Errorf("the node at %s runs chain %q, not the devnet genesis %q", *nodeURL, status.ChainID, g.ChainID)
	}
	// The claim must carry the epoch of the block that will apply it: the
	// block at the node's head+1 (epoch(h) = h/EpochBlocks + 1).
	epoch := (status.Height+1)/g.Params.EpochBlocks + 1

	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	pow, ok := faucet.Solve(pub, epoch, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, claimPuzzleAttempts)
	if !ok {
		return fmt.Errorf("no solution found within %d attempts", claimPuzzleAttempts)
	}

	tx := &types.Tx{
		Type:     types.TxFaucetClaim,
		From:     types.AddressFromPub(pub),
		PubKey:   pub,
		Nonce:    0, // a fresh key has never transacted
		Epoch:    epoch,
		PowNonce: pow,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])

	txid, err := postTxHex(base+"/tx", tx.Encode())
	if err != nil {
		return err
	}

	fmt.Printf("claimant    %x\n", tx.From[:])
	fmt.Printf("public key  %x\n", pub)
	fmt.Printf("claim epoch %d\n", epoch)
	fmt.Printf("pow nonce   %d\n", pow)
	fmt.Printf("txid        %s\n", txid)
	fmt.Println("no key file, no keystore: the ephemeral signing key below cannot be recovered later.")
	fmt.Printf("ephemeral key %x  <- copy now only if you plan a follow-up transfer\n", priv)
	fmt.Println("the claim is queued on the node; it is paid when the node's next block applies it.")
	return nil
}

func getJSON(url string, into any) error {
	resp, err := claimHTTP.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
}

// postTxHex submits the canonical hex encoding of one transaction and
// returns the node's txid.
func postTxHex(url string, raw []byte) (string, error) {
	resp, err := claimHTTP.Post(url, "application/octet-stream", strings.NewReader(hex.EncodeToString(raw)))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		TxID  string `json:"txid"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("%s: unreadable reply: %w", resp.Status, err)
	}
	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return "", fmt.Errorf("%s: %s", resp.Status, out.Error)
		}
		return "", fmt.Errorf("%s", resp.Status)
	}
	if out.TxID == "" {
		return "", fmt.Errorf("%s: reply carried no txid", resp.Status)
	}
	return out.TxID, nil
}

func cmdNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	dir := fs.String("dir", "./b10coin-data", "data directory")
	addr := fs.String("http", "127.0.0.1:8645", "HTTP RPC listen address")
	blockTime := fs.Duration("block-time", 2*time.Second, "target block interval")
	// M4 networking. Giving ANY of these switches the node into the consensus
	// committee over real TCP; none given means the M1 producer exactly as
	// today, so every earlier acceptance run is untouched. --block-time is
	// refused with networking: a committee's cadence is the round-timeout
	// ladder, and a flag that was silently ignored would lie about the run.
	//
	// HOW the committee is named (audit A-1):
	//   - --genesis PATH --key PATH is the REAL mode: the committee is the
	//     JSON file's list of validator public keys (every member holds the
	//     same file), this node signs with ITS OWN key, and a key that is not
	//     in the committee refuses to start.
	//   - --validators N --index I is the FIXTURE mode: derived keys that
	//     anyone with the repository can reproduce, for development only.
	peers := fs.String("peers", "", "comma-separated peer addresses to dial")
	relay := fs.String("relay", "", "address of the dumb forwarder relay to dial")
	listen := fs.String("listen", "", "P2P listen address for direct connections (empty: dial only)")
	validators := fs.Int("validators", 0, "FIXTURE committee size (development mode; committee from --genesis otherwise)")
	index := fs.Int("index", 0, "FIXTURE committee seat (development mode; the seat of --key is derived from --genesis otherwise)")
	keyPath := fs.String("key", "", "this validator's key file (b10coin keygen); REQUIRED with --genesis")
	genesisPath := fs.String("genesis", "", "shared committee file listing the validators' public keys (required for any node a shared network can reach)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	networked := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "peers", "relay", "listen", "validators", "index", "genesis":
			networked = true
		}
	})
	if !networked {
		if *keyPath != "" {
			return fmt.Errorf("--key signs for a committee seat, but this node (no networking flags) is the single-node devnet producer and signs with its fixture key: give --genesis together with --key, or drop --key")
		}
		return runProducerNode(*dir, *addr, *blockTime)
	}
	return runNetworkedNode(fs, *dir, *addr, *listen, *peers, *relay, *keyPath, *genesisPath, *validators, *index)
}

// runProducerNode is the M1 single-node path, unchanged by M4 and unchanged
// by A-1: the devnet fixture chain, one unilateral block producer on the
// fixture key, no round protocol. It takes no key: there is exactly one
// honest chain identity here (the devnet genesis) and its one key is part of
// that fixture, so a --key flag here could only make a flag lie.
func runProducerNode(dir, httpAddr string, blockTime time.Duration) error {
	// M1 nodes run the devnet genesis. The testnet genesis has no validator
	// keys yet, so there is nothing to sign blocks with until M4.
	c, err := chain.Open(genesis.Devnet(), dir)
	if err != nil {
		return err
	}
	defer c.Close()

	_, priv := genesis.DevValidatorKey()
	mp := mempool.New(10_000)
	n := node.New(c, priv, mp)
	srv := rpc.NewServer(c, mp)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Timeouts suit a local-node API serving small JSON bodies to trusted
	// LAN clients: header reading is the untrusted window, reads and writes
	// never take longer than a slow client, and idle keep-alives are
	// reaped so a vanished peer cannot hold a connection forever.
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = httpSrv.Close()
	}()

	fmt.Printf("b10coin %s listening on http://%s (chain %s, height %d)\n",
		version.Version, httpAddr, c.Genesis().ChainID, c.Height())

	// A failed listen must reach the shell as a failure, not as exit 0: the
	// goroutine delivers its error into the buffered channel BEFORE calling
	// stop(), so by the time n.Run returns from that cancellation the error
	// is already available to be read below — no window in which a failure is
	// visible only to the node loop.
	serveErr := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "http:", err)
			serveErr <- err
			stop()
		}
	}()

	if err := n.Run(ctx, blockTime); err != nil && ctx.Err() == nil {
		return err
	}
	// A cancelled context is either a clean SIGINT shutdown — success — or
	// the consequence of a failed listen, which must fail the process. The
	// buffered serve error is guaranteed present in the latter case and
	// absent in the former, so the read is non-blocking in both.
	select {
	case err := <-serveErr:
		return err
	default:
		return nil
	}
}

// runNetworkedNode is the M4 consensus path of the `node` command: one
// validator of a consensus committee over the real transport, running the same
// consensus stack the in-process TCP integration test drives. The single-node
// body (runProducerNode) is deliberately UNTOUCHED and reachable only with
// none of the networking flags: the M3 acceptance runs must be byte-identical.
//
// Since the audit's A-1 fix there are two ways to name the committee, and the
// difference is who holds the keys:
//
//   - GENESIS-FILE MODE (--genesis --key): the committee is the shared file's
//     list of PUBLIC keys; this node signs with its own key file and refuses
//     to start when that key is nowhere in the committee. The chain ID is the
//     file's, chosen by the operators — nothing about it publishes the
//     committee size, and nobody can reproduce a member key from this repo.
//   - FIXTURE MODE (--validators --index): the committee is derived from the
//     size flag and every seat signs a publicly derivable fixture key. This
//     is development-only, and it says so — on stderr, in the usage text, in
//     the README and in the deploy recipe — because a warning the operator
//     never sees cannot protect anything.
//
// --block-time is refused with networking: a committee's cadence is its
// round-timeout ladder, and the flag only drives the single-node producer.
func runNetworkedNode(fs *flag.FlagSet, dir, httpAddr, listen, peers, relay, keyPath, genesisPath string, committee, seat int) error {
	vSet, iSet, genSet, keySet, blockTimeSet := false, false, false, false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "validators":
			vSet = true
		case "index":
			iSet = true
		case "genesis":
			genSet = true
		case "key":
			keySet = true
		case "block-time":
			blockTimeSet = true
		}
	})
	if blockTimeSet {
		return fmt.Errorf("--block-time drives the single-node block producer and does not apply to a consensus committee; drop it")
	}

	var (
		g       *genesis.Genesis
		priv    ed25519.PrivateKey
		keyDesc string
	)
	switch {
	case genSet:
		// Genesis-file mode. The fixture flags are meaningless here and
		// refusing them keeps a mismatched committee-size flag from looking
		// like it did something.
		if vSet || iSet {
			return fmt.Errorf("--validators/--index name the fixture committee and mean nothing alongside --genesis (the committee is the file's public-key list); drop the fixture flags, or drop --genesis for the development fixture")
		}
		if !keySet {
			return fmt.Errorf("a node on the genesis-file committee %q must say who signs for it: give --key PATH (b10coin keygen creates the file)", genesisPath)
		}
		gFile, err := genesis.LoadCommitteeJSON(genesisPath)
		if err != nil {
			return err
		}
		priv, err = keystore.Load(keyPath)
		if err != nil {
			return err
		}
		// Passes through the membership gate inside StartValidator: a key
		// that is not in the committee file REFUSES to start.
		g = gFile
		keyDesc = fmt.Sprintf("key file %s", keyPath)
	default:
		// Fixture mode (development). --key has no place here: the fixture
		// derives every seat's key, so a supplied key could only be refused
		// by the membership gate — refusing it at the flag is clearer.
		if keySet {
			return fmt.Errorf("--key does not apply to the fixture committee (--validators/--index derive every seat's key from public seeds, so there is no key file to load); use --genesis <committee file> --key <key file> for a committee of held keys")
		}
		if !vSet || !iSet {
			return fmt.Errorf("the fixture committee is devnet-only and must be named explicitly: give --validators N and --index I (or, for a real committee, --genesis <file> --key <key file>)")
		}
		g = nil // StartValidator derives simnet.Committee(committee) in fixture mode
		priv = nil
		keyDesc = "derived fixture key (public knowledge)"
	}

	dial := make([]string, 0, 8)
	if s := strings.TrimSpace(peers); s != "" {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				dial = append(dial, p)
			}
		}
	}
	// The relay is kept out of the direct dial list: its connection runs the
	// transport's RELAY dial mode (no ID read, fixed relay:<addr> name -
	// audit N-1), which a plain peer address must not hit.
	relayDial := make([]string, 0, 1)
	if r := strings.TrimSpace(relay); r != "" {
		relayDial = append(relayDial, r)
	}
	committeeSize := committee
	seatName := fmt.Sprintf("seat %d", seat)
	if g != nil {
		committeeSize = len(g.Validators)
		seatName = fmt.Sprintf("seat %d, %s", seatFromKey(g, priv), keyDesc)
	}
	if len(dial) == 0 && len(relayDial) == 0 && listen == "" && committeeSize > 1 && g == nil {
		// Fixture mode can be refused before anything starts. Genesis-file
		// mode's membership refusal must come FIRST — a non-member key hears
		// the refusal, not the peers hint — so StartValidator runs first for
		// it and this guard is re-checked after that failure path.
		return fmt.Errorf("a committee of %d needs reachable peers: give --peers, --relay, or --listen for the others to dial", committeeSize)
	}

	var v *devnet.Validator
	var err error
	if g != nil {
		v, err = devnet.StartValidator(devnet.ValidatorConfig{Dir: dir, Genesis: g, Key: priv, Listen: listen})
	} else {
		v, err = devnet.StartValidator(devnet.ValidatorConfig{Dir: dir, Index: seat, Validators: committee, Listen: listen})
	}
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()
	if g != nil && len(dial) == 0 && len(relayDial) == 0 && listen == "" && committeeSize > 1 {
		// The genesis-file mode's re-run of the guard: StartValidator has now
		// vetted the key against the committee (a non-member key was already
		// refused above), so this failure is exactly the peers hint.
		_ = v.Close()
		return fmt.Errorf("a committee of %d needs reachable peers: give --peers, --relay, or --listen for the others to dial", committeeSize)
	}
	if err := v.Connect(dial...); err != nil {
		return err
	}
	if err := v.ConnectRelay(relayDial...); err != nil {
		return err
	}
	if g == nil {
		// The audit-mandated fixture warning. It stands directly between the
		// operator and the committee they just started, printed to stderr
		// where systemd captures it: a fixture this derivable must never be
		// mistaken for a network with held keys.
		fmt.Fprintln(os.Stderr, strings.Repeat("=", 72))
		fmt.Fprintln(os.Stderr, "WARNING: FIXTURE COMMITTEE — the keys are PUBLIC KNOWLEDGE.")
		fmt.Fprintf(os.Stderr, "Every member of committee b10coin-simnet-%d derives its private key from the\n", committeeSize)
		fmt.Fprintln(os.Stderr, "public seed \"b10coin-simnet-validator\" plus the seat number, and the chain ID")
		fmt.Fprintln(os.Stderr, "publishes the committee size: anyone with this repository can sign proposals,")
		fmt.Fprintln(os.Stderr, "prevotes and precommits for ANY seat. Do not expose this committee to any")
		fmt.Fprintln(os.Stderr, "network beyond your own machines. For a committee of held keys, start every")
		fmt.Fprintln(os.Stderr, "member with --genesis <committee file> --key <key file> (see b10coin keygen).")
		fmt.Fprintln(os.Stderr, strings.Repeat("=", 72))
	}

	srv := rpc.NewServer(v.Chain(), v.Pool())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The same HTTP shape the single node runs (same timeouts, same failure
	// plumbing) so a networked node's RPC behaves identically.
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = httpSrv.Close()
	}()

	fmt.Printf("b10coin %s listening on http://%s (chain %s, height %d)\n",
		version.Version, httpAddr, v.Chain().Genesis().ChainID, v.Height())
	dialDesc := "listening for inbound connections"
	if len(dial) > 0 {
		dialDesc = "dialled " + strings.Join(dial, " ")
	}
	if g == nil {
		seatName = fmt.Sprintf("seat %d (%s)", seat, keyDesc)
	}
	fmt.Printf("consensus    committee of %d, %s, %s\n", committeeSize, seatName, dialDesc)

	serveErr := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "http:", err)
			serveErr <- err
			stop()
		}
	}()

	<-ctx.Done()
	// Same semantics as the single node: a clean SIGINT is success; a failed
	// listen must fail the process.
	select {
	case err := <-serveErr:
		return err
	default:
		return nil
	}
}

// seatFromKey finds the committee position a key signs as, or -1. The CLI uses
// it only inside the seat-name banner; the hard refusal lives in
// StartValidator, so a non-member key never gets this far.
func seatFromKey(g *genesis.Genesis, priv ed25519.PrivateKey) int {
	pub, _ := priv.Public().(ed25519.PublicKey)
	return genesis.SeatOfPubKey(g.Validators, pub)
}
