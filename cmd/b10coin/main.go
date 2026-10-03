// Command b10coin is the b10coin node and tooling binary.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/devnet"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
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
  b10coin devnet --blocks N [--dir PATH] [--claims N]   Build and verify a local chain
  b10coin node   --dir PATH [--http ADDR] [--block-time DURATION]
  b10coin claim  --node URL [--dir PATH]                Solve the faucet puzzle and send one claim
  b10coin version

The claim command signs with an ephemeral key that is printed and never
stored: there is no key file and no keystore.
`)
}

func cmdDevnet(args []string) error {
	fs := flag.NewFlagSet("devnet", flag.ExitOnError)
	blocks := fs.Uint64("blocks", 100, "number of blocks to produce")
	claims := fs.Uint64("claims", 0, "faucet claim attempts to make after the block loop")
	dir := fs.String("dir", "", "data directory (default: a fresh temporary directory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		d, err := os.MkdirTemp("", "b10coin-devnet-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(d)
		*dir = d
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
		fmt.Printf("claimant bal %d sparks\n", summary.ClaimedBalance)
		fmt.Printf("faucet bal   %d sparks (emitted %d sparks in total)\n",
			summary.FaucetBalance, summary.EmittedTotal)
	}
	// Every claim attempt takes exactly one following block (RunOnce appends
	// one block per call, empty when its claim is refused), so the expected
	// final height is blocks plus attempts.
	if summary.Height != *blocks+*claims {
		return fmt.Errorf("expected height %d, got %d", *blocks+*claims, summary.Height)
	}
	fmt.Println("OK")
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	// M1 nodes run the devnet genesis. The testnet genesis has no validator
	// keys yet, so there is nothing to sign blocks with until M4.
	c, err := chain.Open(genesis.Devnet(), *dir)
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
		Addr:              *addr,
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
		version.Version, *addr, c.Genesis().ChainID, c.Height())

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

	if err := n.Run(ctx, *blockTime); err != nil && ctx.Err() == nil {
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
