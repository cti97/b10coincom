// Command b10coin is the b10coin node and tooling binary.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
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
	"github.com/cti97/b10coincom/internal/wire"
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
	case "balance":
		err = cmdBalance(os.Args[2:])
	case "history":
		err = cmdHistory(os.Args[2:])
	case "send":
		err = cmdSend(os.Args[2:])
	case "stake":
		err = cmdStake(os.Args[2:])
	case "unstake":
		err = cmdUnstake(os.Args[2:])
	case "withdraw":
		err = cmdWithdraw(os.Args[2:])
	case "version":
		err = cmdVersion(os.Args[2:])
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

// cmdVersion prints the build identity: the semantic version plus, whenever
// the build carries one, the VCS revision and the modification state. That
// full line is the SAME token the node startup banner prints, so an operator
// comparing three Pis can diff the two outputs character for character instead
// of deciding whether two renderings name the same build (audit S-10).
//
// --short prints only the semantic version, and it exists for exactly one
// caller: scripts/build-release.sh names every artifact with it. The version
// must keep coming from the binary — a second constant in a shell script would
// be the drift this repository keeps finding — but a change to the human
// display must not be able to rename the release files or break the semver
// assertion that guards them. A flag is the explicit interface; scraping the
// display string would be the fragile one.
func cmdVersion(args []string) error {
	switch {
	case len(args) == 0:
		fmt.Println(version.Build().String())
		return nil
	case len(args) == 1 && args[0] == "--short":
		fmt.Println(version.Version)
		return nil
	}
	return fmt.Errorf("usage: b10coin version [--short]")
}

func usage() {
	fmt.Fprint(os.Stderr, `b10coin — a testnet cryptocurrency for small computers

Usage:
  b10coin devnet --blocks N [--validators N] [--dir PATH] [--claims N]   Build and verify a local chain (or, with --validators given, a consensus devnet over the FIXTURE committee)
                 [--epoch-blocks N] [--rotate-demo] [--plot-nakamoto]   (epoch length, the rotation fixture, and the committed-state Nakamoto series)
  b10coin keygen [--out PATH]                                            Generate this validator's key file (owner-only permissions; refuses to overwrite)
  b10coin node   --dir PATH [--http ADDR] [--block-time DURATION]
                 [--peers ADDR,...] [--relay ADDR] [--listen ADDR]       Run the single-node devnet producer, or — with --peers/--relay/--listen — a consensus validator
                 [--advertise IP:PORT]                                  (the address peers should dial when --listen binds a wildcard, e.g. a forwarded port)
                 [--allow-local-peer-hints]                              (accept loopback/private peer hints: private-range and single-host networks only)
                 --genesis PATH --key PATH                               (with both: a REAL member of the committee the genesis file lists)
                 --validators N --index I                                (fixture ONLY: the derived development committee, publicly derivable keys)
  b10coin claim  --node URL [--key PATH] [--print-key] [--yes | --dry-run]
                                                        Solve the faucet puzzle and send one claim; with --key the coins land on a key you hold
  b10coin balance --node URL (--key PATH | --address ADDR)
                                                        Read one account's balance, nonce and bond from the node
  b10coin history --node URL (--key PATH | --address ADDR) [--blocks N]
                                                        List that account's transactions in the node's last N blocks
  b10coin send   --node URL --key PATH --to ADDRESS --amount 0.5 [--max-fee SPARKS] [--yes | --dry-run]
                                                        Transfer b10 from this key to another address (signed tx, printed first)
  b10coin stake  --node URL --key PATH --amount 1000 [--max-fee SPARKS] [--yes | --dry-run]
                                                        Bond b10 to this key's committee seat (signed tx, printed first)
  b10coin unstake --node URL --key PATH [--amount 1000] [--yes | --dry-run]
                                                        Unbond all or part of the bond; a partial exit must leave MIN_STAKE or nothing
  b10coin withdraw --node URL --key PATH [--yes | --dry-run]
                                                        Release matured unbonding records to the spendable balance
  b10coin version [--short]                             Print the build identity (version + VCS revision);
                                                        --short prints only the semantic version, for scripts

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

Without --key, the claim command signs with an ephemeral key that is never
stored and, by default, never printed: stdout is captured by shells, CI logs
and journalctl, and a claim you intend to spend from should use --key. Pass
--print-key to print the key once for a follow-up transfer; the claimant
address is printed either way.
With --key PATH the claim signs for that key file, through the same
print-confirm-sign envelope as the staking verbs, so its coins are spendable by
a key you hold (claim --dry-run prints the transaction and stops).

The claim FOLLOWS THE GENESIS OF THE NODE IT IS POINTED AT: it reads /status for
that chain's genesis hash and epoch length, signs over the hash the node
reports, and derives the claim's epoch from the epoch length the node reports.
A committee-file chain and a simnet committee are therefore claimable exactly as
the devnet is, and a claim can never be signed over a hash this CLI assumed.
The puzzle's TUNING (Argon2id cost and target) is the one parameter that is not
on the wire; every chain a node of this build can open carries the devnet
fixture's tuning (the devnet genesis, the simnet committee and the committee-file
loader all start from it), and the node is the verifier: the state machine
re-derives the digest with its own parameters, so a claim solved against another
tuning cannot apply and is dropped by the proposer's applicability filter rather
than riding a block.

balance and history are READ verbs: clients of the node, not a second chain.
balance is one /status read plus one /account/{address} read; history is one
/history read. Neither opens a data directory, a store or a block file, and
neither signs or posts anything. BALANCE is what the node reports, in sparks
with the exact b10 render beside it (an integer division, never a float).

HISTORY IS A BOUNDED BACKWARD SCAN, NOT AN ACCOUNT LEDGER. There is no
transaction index in the store, so history scans at most --blocks blocks back
from the node's head (default 100, maximum 500). Above 500 this verb REFUSES,
here, before the node is asked (exit 1) - the 500 is the node's per-request
bound, and a hand-written client that asks for more has its request clamped to
500 rather than served; the header reports what the node actually scanned.
What it prints is therefore activity inside that window - not the account's
whole past.
A window with no transfers does not prove an account never transacted, and a
transaction older than the window cannot be reached by asking for more than
500 blocks; run the verb again later, or read the blocks. The window line and
the no-index sentence are printed on every run, not only when the reply was
cut short. The numbers themselves come from the node: the CLI has no
independent copy of the chain and cannot check them.

The staking verbs are ORDINARY signed transactions, not a side channel: they
read /status for the chain's genesis hash and stake parameters and
/account/{address} for the nonce, balance and bond, then POST to /tx - the
same signing, genesis-hash binding, fee rule and mempool admission as a
transfer, and the state machine judges them at execution time. A bond needs
MIN_STAKE (1,000 b10 = 10^11 sparks) and takes effect at the next epoch
boundary. No shipped genesis funds a fresh key with MIN_STAKE: the faucet pays
one claim per key per epoch (1 b10 on the devnet parameters, 100 b10 on the
testnet parameters), so reaching the floor means 1,001 claims from 1,001 keys
plus 1,001 transfers (~2,002 blocks of emission) - claim --key and send walk
that path, and it is long. See README "Staking" for the arithmetic and for the
one pre-funded fixture account a local devnet ships.

Every staking verb BUILDS the transaction, prints its fields and its canonical
bytes, and only then signs - after a confirmation: type "yes" at the prompt,
or pass --yes when stdin is not an interactive terminal. --dry-run prints the
transaction and stops without signing and without posting; if --yes and
--dry-run are given together, --dry-run wins and --yes is inert (nothing is
signed either way). The fee ceiling
defaults to 1 spark because that is min_fee_sparks on every shipped genesis and
a fee above it buys nothing: the mempool admits on nonce and state rather than
on price, and applyBond/applyTransfer burn the whole fee. --max-fee SPARKS raises the
ceiling; a node asking for more than one spark is refused by default.
WHAT THIS DOES NOT FIX: the nonce, balance, bond and genesis hash still come
from the node the verb is pointed at, and the CLI has no independent copy of
them. The printed transaction makes them visible instead of silent, so a lying
node can still delay a bond with a future nonce, turn a full exit into a
partial one by under-reporting the bond, or make the transaction invalid by
misreporting the genesis hash - but it can no longer choose the fee, and the
default ceiling bounds that loss to one spark. There is deliberately no
--chain-id expectation: the genesis hash IS the chain binding, so a signature
made for a different node's chain is useless there and invalid on the chain
the operator meant - useless, not dangerous. HTTP redirects are refused for
the same reason.

A TRANSACTION IS NOT GOSSIPED, and that decides where you post it. The wire
carries proposals, votes, HELLOs, block sync and peer exchange; no message
carries a transaction between nodes. A block is built from the LOCAL mempool of
the validator whose turn it is to propose, so a transaction reaches the chain
only through the node you posted it to, and only when that node's turn comes:
on a SEATED validator it waits for that turn (one height in the committee size,
roughly one in ten at ten seats), and on an UNSEATED node it waits forever -
the pool of a node whose key holds no committee seat never feeds a block. The
2026-11-06 ten-node run measured it: an Unbond posted to a displaced seat sat in
that node's mempool for 400 blocks, and the same bytes posted to a seated
validator applied in 12 seconds. Every signing verb therefore prints the node's
own verdict beside the txid: POST /tx reports "seated": true|false for the
node's signing key at the height the transaction would have to be carried at
(head+1), and when that is false it adds a warning sentence naming the height,
which these verbs print on stderr. "seated": false is still a 200 - the
transaction was admitted, and the txid is a receipt for admission only. Post
the same bytes to a seated validator.
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
	epochBlocks := fs.Uint64("epoch-blocks", 0, "epoch length in blocks for BOTH the committee epoch (0-based) and the faucet claim epoch (1-based), overridden in the genesis before hashing (0 = the compiled-in value); a --dir built at another length is refused by the store, not silently reused")
	rotateDemo := fs.Bool("rotate-demo", false, "rotation fixture: one seat unbonds mid-epoch through an ordinary Unbond transaction and leaves at the boundary (needs --validators >= 5, --epoch-blocks >= 4, --blocks > --epoch-blocks; not with --claims)")
	plotNakamoto := fs.Bool("plot-nakamoto", false, "print the Nakamoto coefficient per epoch boundary plus the head, from committed state (needs --validators; the threshold is 1/3, the BFT figure, not 1/2)")
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

	// The two committee-only flags must not be silently dropped on the
	// single-node path: Run has one validator and no series, and a flag that
	// asked for a plot and printed nothing would look like an empty result
	// rather than a misuse.
	multi := *validators > 1 || validatorsSet
	if *plotNakamoto && !multi {
		return fmt.Errorf("--plot-nakamoto reports a committee's coefficient from committed state; give --validators N (the single-node run has no committee to plot)")
	}
	if *rotateDemo && !multi {
		return fmt.Errorf("--rotate-demo is the committee rotation fixture; give --validators N (at least 5)")
	}

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
		summary, err := devnet.RunMulti(devnet.Options{
			Dir: *dir, Blocks: *blocks, Validators: *validators,
			EpochBlocks: *epochBlocks, RotateDemo: *rotateDemo, PlotNakamoto: *plotNakamoto,
		})
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

	summary, err := devnet.Run(devnet.Options{Dir: *dir, Blocks: *blocks, Claims: *claims, EpochBlocks: *epochBlocks})
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
	// The acceptance artefact, when it was asked for. A blank line separates
	// the run report from the series so the table is readable on its own.
	if len(s.Nakamoto) > 0 {
		fmt.Println()
		fmt.Print(devnet.FormatNakamoto(s.Nakamoto))
	}
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
//
// Redirects are REFUSED (audit CL-4). net/http follows up to ten by default,
// so a node - or an on-path party that can answer the configured address -
// could move the staking verbs' /status and /account reads to a different
// server and back a preview with another node's claims. The configured URL is
// the trust boundary; a redirect is a request to leave it, so it fails closed.
var claimHTTP = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("the RPC endpoint redirected to %s; refusing to follow a redirect (the staking verbs sign what the configured node reports)", req.URL)
	},
}

// claimPuzzleAttempts bounds the local solve. The reference claimant solves the
// cheap outer puzzle (16 leading zero bits) as well as the devnet's easy
// Argon2id target, so the expected scan is about 2^17 nonces; a failure means
// the tuning changed, not that mining is slow.
const claimPuzzleAttempts = 1 << 24

// cmdClaim solves the faucet puzzle and submits the signed claim to a node's
// /tx endpoint.
//
// Without --key it signs with a FRESH EPHEMERAL key: there is no key file and
// no keystore, the key signs exactly this claim and is PRINTED, never stored,
// and the claim is only queued by this command; the node pays it when its next
// block applies it (one claim per key per epoch).
//
// With --key PATH the claim signs with THAT key file, through the same envelope
// send and the staking verbs use (claimWithKey in wallet.go): the claimed coins
// then land on an address the operator can sign a transfer with, which the
// ephemeral path never could. The flag is an addition; without it the output
// and behaviour above are unchanged.
func cmdClaim(args []string) error {
	fs := flag.NewFlagSet("claim", flag.ExitOnError)
	nodeURL := fs.String("node", "http://127.0.0.1:8645", "URL of the node's HTTP RPC to submit the claim to")
	// --dir keeps the command surface uniform with the other commands, but
	// claim reads NOTHING from disk: the devnet genesis it must agree with is
	// compiled in, and the key must never be written anywhere. The flag is
	// accepted so scripts built on the other commands keep working; its value
	// is deliberately never read here.
	fs.String("dir", "./b10coin-data", "the node's data directory (unused by the claim itself; the devnet genesis is compiled in)")
	// Printing the key is the documented default (kept for compatibility),
	// but stdout is captured by shells, CI and journalctl, so the opt-out is
	// the safe choice for any run that does not intend a follow-up transfer
	// (audit O-10). The claimant ADDRESS is printed either way.
	printKey := fs.Bool("print-key", false, "print the ephemeral signing key to stdout (off by default, so the secret stays out of shell history, CI logs and journalctl; without it the key is unrecoverable and no follow-up transfer from this claimant is possible - use --key for a claim you intend to spend from). No effect with --key, whose key is already a file")
	keyPath := fs.String("key", "", "sign the claim with this key file (b10coin keygen) so the claimed coins land on an address you hold; absent, the claim signs with an ephemeral key it never saves and, unless --print-key is given, never prints")
	// The envelope's confirmation surface. It applies to --key only: the
	// ephemeral claim prints no preview and never asks, so a --yes or
	// --dry-run accepted there and ignored would be a flag that lies.
	yes, dryRun := addTxConfirmationFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *keyPath != "" {
		return claimWithKey(*nodeURL, *keyPath, *yes, *dryRun)
	}
	if *yes || *dryRun {
		return fmt.Errorf("--yes and --dry-run apply to --key: the ephemeral claim prints no preview and asks for no confirmation, so neither flag would mean anything. Give --key PATH to sign for a key file through the envelope")
	}

	// The puzzle's COST AND TARGET are genesis state and are the one thing on
	// this path that is not reported by /status, so the command solves with the
	// compiled-in fixture tuning. That is correct rather than assumed: every
	// chain a node of this build can open carries it (genesis.Devnet(), and
	// simnet.Committee and genesis.ParseCommitteeJSON, which both start from
	// Devnet() and override only the identity, the validator list and the seat
	// count - the committee-file loader deliberately keeps the monetary and
	// puzzle parameters). The chain is the verifier: the state machine
	// re-derives the digest with its own parameters, so a claim solved against
	// a different tuning cannot apply and is dropped by the proposer's
	// applicability filter instead of riding a block. Everything ELSE is the
	// node's (testrun S-3): the genesis hash
	// the signature binds to and the epoch length the claim's epoch is derived
	// from are read below, because signing over a compiled-in hash is exactly
	// what made this command refuse every chain but the devnet.
	g := genesis.Devnet()

	base := strings.TrimRight(*nodeURL, "/")
	// readStatus is the same read the staking verbs use: it reports the
	// chain's identity, its epoch length and its 32-byte genesis hash, and
	// refuses a node that does not report one (a node from before M5).
	status, genesisHash, err := readStatus(base)
	if err != nil {
		return err
	}
	// The claim must carry the epoch of the block that will apply it: the
	// block at the node's head+1 (epoch(h) = h/EpochBlocks + 1), at the
	// length the NODE reports - not at the compiled-in one, which on a chain
	// started with --epoch-blocks would name the wrong epoch.
	if status.EpochBlocks == 0 {
		return fmt.Errorf("the node at %s reports epoch_blocks 0: the claim's epoch cannot be derived", *nodeURL)
	}
	epoch := (status.Height+1)/status.EpochBlocks + 1

	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	// SolveClaim also satisfies the cheap outer puzzle a node's mempool now
	// requires at admission (audit R-1); Solve alone would be refused at the
	// door even though the block's Argon2id rule would have accepted it.
	pow, ok := faucet.SolveClaim(pub, epoch, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, claimPuzzleAttempts)
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
	// Signed over the hash the NODE reported (testrun S-3). This used to be
	// g.Hash(), the compiled-in devnet genesis, guarded by a chain-ID equality
	// check - so the command could only ever sign for one chain. The genesis
	// hash IS the chain binding, and reading it from the node is what the
	// --key path always did; the ephemeral path now does the same.
	sigHash := tx.SigningHash(genesisHash)
	tx.Sig = crypto.Sign(priv, sigHash[:])

	rc, err := postTxHex(base+"/tx", tx.Encode())
	if err != nil {
		return err
	}

	fmt.Printf("claimant    %x\n", tx.From[:])
	fmt.Printf("public key  %x\n", pub)
	fmt.Printf("claim epoch %d\n", epoch)
	fmt.Printf("pow nonce   %d\n", pow)
	fmt.Printf("txid        %s\n", rc.TxID)
	fmt.Println("no key file, no keystore: the ephemeral signing key cannot be recovered later.")
	if *printKey {
		fmt.Printf("ephemeral key %x  <- copy now only if you plan a follow-up transfer\n", priv)
	} else {
		fmt.Println("the signing key was not printed (pass --print-key to see it); no follow-up transfer from this claimant is possible without it")
	}
	printSeatWarning(rc)
	fmt.Println("the claim is queued on the node; it is paid when the node's next block applies it.")
	return nil
}

// The read paths retry a 503 (testrun 2026-11-06, Info). A 503 from this node
// is its own "the node is busy scanning for other clients; retry shortly",
// i.e. the four-slot scan semaphore working as designed (audit R-1/S-8), not a
// refusal of the request. The CLI used to surface it as exit 1: with 20
// parallel mixed requests to one node, 4 of 5 `b10coin history` runs failed on
// a reply that told them in so many words to retry. Only the GET paths use
// getJSON (the signing verbs' POST has postTxHex), and a GET is idempotent, so
// a bounded exponential backoff costs a delay and nothing else. No jitter: the
// caller is one CLI process, and the node's own slots are what it is waiting
// for.
const (
	busyRetries = 3
	busyBackoff = 50 * time.Millisecond
)

func getJSON(url string, into any) error {
	for attempt := 0; ; attempt++ {
		resp, err := claimHTTP.Get(url)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable && attempt < busyRetries {
			// Busy, not broken: back off outside the request's timeout and
			// ask again. The final attempt falls through to the error below,
			// so a node that stays busy is still reported with its own
			// sentence instead of being waited on forever.
			time.Sleep(busyBackoff << attempt)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			// The status line and the body are both the node's text: quote them so
			// a reply cannot clear the screen or forge a line of this CLI's output
			// on the read paths (/status, /account, /history) as well (audit S-13).
			return fmt.Errorf("%s: %s", safeText(resp.Status), safeText(strings.TrimSpace(string(body))))
		}
		if readErr != nil {
			return readErr
		}
		return json.NewDecoder(bytes.NewReader(body)).Decode(into)
	}
}

// txidHexLen is the length of a hex-encoded 32-byte transaction ID.
const txidHexLen = 64

// validTxID reports whether s is exactly the canonical hex form of a 32-byte
// transaction ID: 64 characters, all lowercase. This is not cosmetic. The txid
// is the only string a signing verb prints as a RECEIPT, and it is printed
// after the signature; the node chooses every byte of it. A node that returns
// ANSI escapes or a newline in that field can erase the lines the CLI just
// printed (including the ones saying what was signed) and write a forged
// receipt in their place (audit S-13, the class W-2 closed for /history rows).
// A value that is not a well-formed hash has no business being printed, and a
// receipt this CLI cannot check must not be presented as one.
func validTxID(s string) bool {
	if len(s) != txidHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// txReceipt is one POST /tx answer: the admitted transaction's id, and the
// node's word on whether it can ever be included (testrun S-2).
//
// Seated is a POINTER because "this node did not say" and "this node said
// false" are different facts, and only one of them is worth a warning. A node
// from before this milestone, or one built without a signing key, leaves it
// nil; Warning is non-empty exactly when the node explained a refusal to
// propose.
type txReceipt struct {
	TxID    string
	Seated  *bool
	Warning string
}

// printSeatWarning writes the node's own explanation when its /tx reply says it
// holds no seat at the height the transaction needed. It goes to STDERR, beside
// a txid that stays on stdout: the txid is a true receipt for what happened
// (admission), and the warning is the part an operator must not miss - the
// transaction is parked, and the same bytes posted to a seated validator are
// what reaches a block.
//
// The sentence is the NODE's, not this CLI's: the node knows the height it
// judged and whether it could derive a committee at all, and there is exactly
// one copy of that reasoning (internal/rpc's seatStatus). This function only
// frames it and says what to do with the bytes.
func printSeatWarning(rc txReceipt) {
	if rc.Warning == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "WARNING: %s\n", rc.Warning)
	fmt.Fprintln(os.Stderr, "WARNING: nothing on this node will include it; the txid above is not a promise. Post the same bytes to a seated validator (b10coin --node <that node's URL> with the same verb), or start a node whose key the committee seats.")
}

// postTxHex submits the canonical hex encoding of one transaction and returns
// the node's receipt.
//
// EVERY node-chosen string on this path is either validated or quoted. The
// txid must be a canonical 32-byte hash (validTxID) or the submission is
// refused; the error body and the HTTP status line (whose reason phrase the
// server also chooses) go through safeText, so a hostile node cannot move the
// cursor, clear the screen or start a new line inside an error message. There
// is no raw echo of node bytes left on this path (audit S-13).
//
// The seat fields are additive and optional: a node that does not report them
// yields Seated == nil and no warning, so an older node keeps working (M5's
// additive /status contract, applied to this reply).
func postTxHex(url string, raw []byte) (txReceipt, error) {
	resp, err := claimHTTP.Post(url, "application/octet-stream", strings.NewReader(hex.EncodeToString(raw)))
	if err != nil {
		return txReceipt{}, err
	}
	defer resp.Body.Close()
	var out struct {
		TxID    string `json:"txid"`
		Error   string `json:"error"`
		Seated  *bool  `json:"seated"`
		Warning string `json:"warning"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return txReceipt{}, fmt.Errorf("%s: unreadable reply: %w", safeText(resp.Status), err)
	}
	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return txReceipt{}, fmt.Errorf("%s: %s", safeText(resp.Status), safeText(out.Error))
		}
		return txReceipt{}, fmt.Errorf("%s", safeText(resp.Status))
	}
	if !validTxID(out.TxID) {
		// The bad value is quoted, never echoed: it is exactly the string that
		// must not reach the terminal raw, and quoting keeps its ESC/CR bytes
		// visible as escapes instead of executing them.
		return txReceipt{}, fmt.Errorf("%s: the node's reply carried a txid that is not 64 lowercase hex characters (%s); refusing to print it as a receipt",
			safeText(resp.Status), safeText(out.TxID))
	}
	// A warning is prose chosen by the node, printed on the operator's terminal:
	// same rule as every other node-supplied string here, one line, no control
	// bytes (safeText), and only when the node also said it is unseated - a
	// warning without `seated: false` is a contradiction this CLI will not
	// invent a meaning for.
	rc := txReceipt{TxID: out.TxID, Seated: out.Seated}
	if out.Seated != nil && !*out.Seated && out.Warning != "" {
		rc.Warning = safeText(out.Warning)
	}
	return rc, nil
}

// ---------------------------------------------------------------------------
// The staking verbs (M5 Task 6)
// ---------------------------------------------------------------------------
//
// These are CLIENTS, not a second transaction path. Each one reads the node's
// /status for the chain's genesis hash and stake parameters and
// /account/{address} for the nonce, balance and bond, then signs with the
// operator's key file and POSTs the canonical bytes to /tx - the same endpoint,
// the same signing hash and the same mempool admission a transfer uses. The
// node's state machine judges the transaction at execution time, exactly as it
// judges a transfer's balance, so nothing here needs (or is allowed) a bypass.
//
// The verbs do NOT wait for inclusion: a bond takes effect when a block applies
// it and a SEAT changes only at the next epoch boundary, so "nothing happened
// yet" is correct for up to an epoch. The txid is the receipt.

// ---------------------------------------------------------------------------
// The staking verbs (M5 Task 6)
// ---------------------------------------------------------------------------
//
// stake, unstake and withdraw are CLIENTS, not a second transaction path.
// They share the signing envelope in wallet.go: each reads the node's /status
// for the chain's genesis hash and stake parameters and /account/{address} for
// the nonce, balance and bond, then signs with the operator's key file and
// POSTs the canonical bytes to /tx - the same endpoint, the same signing hash
// and the same mempool admission a transfer uses. The node's state machine
// judges the transaction at execution time, exactly as it judges a transfer's
// balance, so nothing here needs (or is allowed) a bypass.
//
// The verbs do NOT wait for inclusion: a bond takes effect when a block applies
// it and a SEAT changes only at the next epoch boundary, so "nothing happened
// yet" is correct for up to an epoch. The txid is the receipt.

// stakingFundingNote is the honest answer to "where do I get MIN_STAKE?".
// It is returned at the point a verb refuses for lack of funds or stake, so an
// operator meets it with the command in hand rather than in a doc they have not
// opened yet.
const stakingFundingNote = "no shipped genesis gives an operator's key MIN_STAKE in spendable funds: the faucet pays one claim per key per epoch, so the path to this balance is 1,001 claims (b10coin claim --key) from 1,001 keys plus 1,001 transfers (b10coin send) into one address, ~2,002 blocks of emission (README \"Staking\" derives it), not a starting balance. claim follows the genesis of whichever node it is pointed at, so this path exists on a committee chain too - or list the key in the committee file and skip it"

// fundingNote returns the MIN_STAKE hint, prefixed for appending to a refusal,
// ONLY when the account's spendable balance is itself below MIN_STAKE.
//
// It used to be appended to every refusal, so an account holding a thousand
// times MIN_STAKE that was two sparks short of the FEE was told that no shipped
// genesis gives it MIN_STAKE at all (M5 Docker re-run, 2026-10-30: misleading,
// cosmetic, and exactly the kind of hint that sends an operator looking for a
// faucet they do not need). A balance at or above MIN_STAKE needs a correct
// top-up or a smaller bond; the funding lecture is false there.
func fundingNote(balance, minStake uint64) string {
	if minStake > 0 && balance >= minStake {
		return ""
	}
	return "; " + stakingFundingNote
}

// checkSpendable refuses a bond the account cannot cover, before submitting:
// the node would refuse it at execution, but the operator learns why here.
// minStake is the chain's MIN_STAKE, used only for the funding hint.
//
// It is the bond's half of the cover check: the arithmetic is coverError's
// (wallet.go), and the MIN_STAKE funding note is appended HERE so a transfer -
// which calls checkCover - never inherits the bond lecture. A sender short by a
// hundred sparks is not a bond short by a thousand b10.
func checkSpendable(balance, amount, fee, minStake uint64) error {
	if err := coverError("bond", balance, amount, fee); err != nil {
		return fmt.Errorf("%w%s", err, fundingNote(balance, minStake))
	}
	return nil
}

// cooldownBlocks is UnbondingEpochs x EpochBlocks with the overflow check the
// state machine applies. ok=false means the product does not fit in a uint64
// (unreachable on a validated genesis, but a node is not trusted input).
func cooldownBlocks(st stakingStatus) (uint64, bool) {
	if st.EpochBlocks == 0 || st.UnbondingEpochs > math.MaxUint64/st.EpochBlocks {
		return 0, false
	}
	return st.UnbondingEpochs * st.EpochBlocks, true
}

// ceilToEpoch rounds h UP to the next multiple of epochBlocks: the rule
// state.releaseHeightFor applies to an unbond's release height, mirrored here
// so the verb forecasts the height the chain will actually record (audit ST-4).
// ok=false on a zero epoch length or an overflow; the caller then prints no
// forecast rather than a wrong one.
func ceilToEpoch(h, epochBlocks uint64) (uint64, bool) {
	if epochBlocks == 0 {
		return 0, false
	}
	rem := h % epochBlocks
	if rem == 0 {
		return h, true
	}
	add := epochBlocks - rem
	if h > math.MaxUint64-add {
		return 0, false
	}
	return h + add, true
}

// splitUnbondExit mirrors state.applyUnbond's split for the preview: the bond's
// FUNDED part leaves first and is the sparks the address is owed, and only an
// exit larger than that reaches the seat's unfunded genesis power, which the
// state DESTROYS rather than records (audits ST-3 and C-1). The order is the
// whole of C-1: a genesis operator that topped up with its own coins recovers
// them through an ordinary partial exit, and loses only the grant.
//
// A hand-built /account reply with Unfunded above Bonded is not a state the chain
// can hold; like the state's own subtraction, this floors the funded part at zero
// rather than wrapping.
func splitUnbondExit(amount, bonded, unfunded uint64) (funded, destroyed uint64) {
	fundedInBond := uint64(0)
	if unfunded < bonded {
		fundedInBond = bonded - unfunded
	}
	funded = min(amount, fundedInBond)
	return funded, amount - funded
}

// releaseForecast is the "release" line cmdUnstake prints for the sparks the
// state will RECORD, as a function so the arithmetic is testable without
// capturing stdout. funded is that recorded amount (see splitUnbondExit); its
// release height is the epoch boundary at or after the earliest applying block
// (head+1) plus the cooldown. funded == 0 means the exit records nothing, and no
// height is forecast for it - printing one would promise a payout that cannot
// happen.
func releaseForecast(funded uint64, st stakingStatus, cooldown uint64) (string, bool) {
	if funded == 0 {
		return "", false
	}
	earliest := st.Height + 1
	if earliest == 0 { // head was MaxUint64; a wrapped "earliest" would forecast the past
		return "", false
	}
	if earliest > math.MaxUint64-cooldown {
		return "", false
	}
	release, ok := ceilToEpoch(earliest+cooldown, st.EpochBlocks)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("height %d at the earliest (submitted at head %d; the cooldown is %d epochs x %d blocks = %d blocks, and the release height is the epoch boundary at or after head+1+cooldown)",
		release, st.Height, st.UnbondingEpochs, st.EpochBlocks, cooldown), true
}

// unbondEffect is the consequence line cmdUnstake prints before the signature
// (audit CL-2), and audit C-1's other half: it is CONDITIONAL on the split, not
// on "is this exit bigger than the grant". The text used to say "the seat is gone
// from the committee and there is nothing to withdraw" for every exit no larger
// than the grant - which is wrong twice for a topped-up genesis seat, because the
// funded part now leaves first (so there IS something to withdraw) and a
// remainder at or above the floor keeps the seat.
func unbondEffect(amount, bonded, unfunded uint64, st stakingStatus) string {
	funded, destroyed := splitUnbondExit(amount, bonded, unfunded)
	var parts []string
	if funded > 0 {
		line := "the funded coins are neither spendable nor counted in the committee until the release height; `b10coin withdraw` releases them then"
		if cooldown, ok := cooldownBlocks(st); ok {
			if forecast, ok := releaseForecast(funded, st, cooldown); ok {
				line = forecast + "; " + line
			}
		}
		parts = append(parts, line)
	}
	if destroyed > 0 {
		parts = append(parts, fmt.Sprintf("%d sparks are the seat's unfunded genesis power and are destroyed, not released (audit ST-3)", destroyed))
	}
	if remainder := bonded - amount; remainder == 0 {
		parts = append(parts, "the whole bond leaves, so the seat is gone from the committee at the next epoch boundary")
	} else {
		parts = append(parts, fmt.Sprintf("%d sparks stay bonded, at the minimum or above, so the seat is RETAINED until a later exit takes it below the minimum", remainder))
	}
	return strings.Join(parts, "; ")
}

func cmdStake(args []string) error {
	fs := flag.NewFlagSet("stake", flag.ExitOnError)
	nodeURL := fs.String("node", "http://127.0.0.1:8645", "URL of the node's HTTP RPC")
	keyPath := fs.String("key", "", "key file to sign with (b10coin keygen); the bond seats THIS key")
	amountB10 := fs.String("amount", "", "amount to bond, in b10 as an exact decimal (the bond AFTER adding it must be at least MIN_STAKE, 1000 b10; a top-up below that is legal when the existing bond makes the result clear the floor)")
	maxFee := fs.Uint64("max-fee", defaultMaxFeeSparks, maxFeeHelp)
	yes, dryRun := addTxConfirmationFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unknown argument %q", fs.Arg(0))
	}
	if *amountB10 == "" {
		return fmt.Errorf("give --amount N in b10 (exact decimal; MIN_STAKE is 1000 b10 = 10^11 sparks)")
	}
	amount, err := genesis.ParseB10(*amountB10)
	if err != nil {
		return err
	}
	if amount == 0 {
		return fmt.Errorf("--amount %q is zero sparks; a bond must be positive", *amountB10)
	}
	t, err := connectWalletNode(*nodeURL, *keyPath)
	if err != nil {
		return err
	}
	if t.status.MinStakeSparks == 0 {
		return fmt.Errorf("the node reports min_stake_sparks 0: staking is not parameterised on that chain")
	}
	// A bond with fee 0 could never apply: every shipped genesis sets at least
	// one spark and genesis.Validate refuses a zero minimum, so a node
	// reporting 0 is either misconfigured or steering this verb into a
	// transaction the real chain will reject.
	if t.status.MinFeeSparks == 0 {
		return fmt.Errorf("the node reports min_fee_sparks 0: every shipped genesis sets at least 1 spark and genesis.Validate refuses a zero minimum, so a zero-fee bond could never apply")
	}
	// The floor is on the RESULTING bond, not on this transaction
	// (state.applyBond), so an existing bond may be topped up: 600 then 400 is
	// legal against a 1,000 floor while either alone is not. Checking only
	// --amount here would refuse a bond the chain accepts, which is exactly
	// the verb/consensus disagreement this pre-check exists to prevent.
	if t.account.Bonded > math.MaxUint64-amount {
		return fmt.Errorf("the existing bond %d plus --amount %d overflows a uint64", t.account.Bonded, amount)
	}
	resulting := t.account.Bonded + amount
	if resulting < t.status.MinStakeSparks {
		return fmt.Errorf("--amount %s b10 (%d sparks) would leave the bond at %s b10 (%d sparks), below this chain's MIN_STAKE %s b10 (%d sparks)%s",
			genesis.FormatB10(amount), amount, genesis.FormatB10(resulting), resulting,
			genesis.FormatB10(t.status.MinStakeSparks), t.status.MinStakeSparks,
			fundingNote(t.account.Balance, t.status.MinStakeSparks))
	}
	if err := checkSpendable(t.account.Balance, amount, t.status.MinFeeSparks, t.status.MinStakeSparks); err != nil {
		return err
	}

	tx := &types.Tx{
		Type:   types.TxBond,
		From:   t.addr,
		PubKey: t.pub,
		Nonce:  t.account.Nonce,
		Fee:    t.status.MinFeeSparks,
		Amount: amount,
	}
	// The consequence is part of the preview, not a receipt printed after the
	// irreversible POST (audit CL-2): the operator sees that the seat changes
	// only at a boundary before choosing "yes".
	effect := "the bond is applied when a block includes it; the seat it buys is considered at the next epoch boundary, never mid-epoch"
	if t.status.EpochBlocks > 0 {
		effect = fmt.Sprintf("the bond is applied when a block includes it; the seat it buys is considered at the next epoch boundary (every %d blocks as this node reports it), never mid-epoch", t.status.EpochBlocks)
	}
	rc, posted, err := t.submit(tx, txOptions{maxFee: *maxFee, yes: *yes, dryRun: *dryRun}, txProvenance{amount: "from --amount", effect: effect})
	if err != nil {
		return err
	}
	if posted {
		fmt.Printf("txid        %s\n", rc.TxID)
		printSeatWarning(rc)
	}
	return nil
}

func cmdUnstake(args []string) error {
	fs := flag.NewFlagSet("unstake", flag.ExitOnError)
	nodeURL := fs.String("node", "http://127.0.0.1:8645", "URL of the node's HTTP RPC")
	keyPath := fs.String("key", "", "key file that holds the bond (b10coin keygen)")
	amountB10 := fs.String("amount", "", "amount to unbond, in b10 as an exact decimal (default: the whole bond; a partial exit must leave at least MIN_STAKE bonded)")
	// No --max-fee here: state.applyUnbond requires fee 0 exactly, so there is
	// no fee for a ceiling to bound.
	yes, dryRun := addTxConfirmationFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unknown argument %q", fs.Arg(0))
	}
	t, err := connectWalletNode(*nodeURL, *keyPath)
	if err != nil {
		return err
	}
	if t.account.Bonded == 0 {
		return fmt.Errorf("the account %s holds no bond; there is nothing to unbond (a bond is created by `b10coin stake`)", t.addr)
	}
	amount := t.account.Bonded
	// Where the unbond amount came from is printed with the transaction: with
	// no --amount this verb cannot know the bond, and a node that under-reports
	// it turns a full exit into a partial one ONLY IF the operator cannot see
	// which number was signed. The preview names the source (audit CL-1).
	amountSource := "the WHOLE bond as this node reports it (no --amount given): an under-reporting node makes this a PARTIAL exit"
	if *amountB10 != "" {
		amountSource = "from --amount"
		amount, err = genesis.ParseB10(*amountB10)
		if err != nil {
			return err
		}
		if amount == 0 {
			return fmt.Errorf("--amount %q is zero sparks; omit --amount to unbond the whole bond", *amountB10)
		}
		if amount > t.account.Bonded {
			return fmt.Errorf("--amount %s b10 (%d sparks) is more than the bonded %s b10 (%d sparks)",
				genesis.FormatB10(amount), amount, genesis.FormatB10(t.account.Bonded), t.account.Bonded)
		}
	}
	// The state's candidacy floor, mirrored (audit ST-1): a partial exit must
	// leave the bond at zero or at MIN_STAKE or above, because any positive
	// bond is a committee candidate and the power cap equalises small seats
	// with large ones. A bond ALREADY under the floor (a genesis seat bonded at
	// `power` one spark) can only be exited in full, which is what this check
	// does without a special case: every partial remainder is below the bond,
	// so every partial remainder is below the floor.
	if remainder := t.account.Bonded - amount; remainder != 0 && remainder < t.status.MinStakeSparks {
		return fmt.Errorf("--amount %s b10 (%d sparks) would leave %s b10 (%d sparks) bonded, below this chain's MIN_STAKE %s b10 (%d sparks); unbond the whole bond, or leave at least the minimum",
			genesis.FormatB10(amount), amount, genesis.FormatB10(remainder), remainder,
			genesis.FormatB10(t.status.MinStakeSparks), t.status.MinStakeSparks)
	}

	// Fee 0 is a CONSENSUS rule for an exit (state.applyUnbond), not a
	// convenience: a validator may hold nothing spendable, and an exit that
	// needed a coin would be one a zero-balance operator could never make.
	tx := &types.Tx{
		Type:   types.TxUnbond,
		From:   t.addr,
		PubKey: t.pub,
		Nonce:  t.account.Nonce,
		Fee:    0,
		Amount: amount,
	}
	// The consequence is part of the preview, not a receipt printed after the
	// irreversible POST (audit CL-2). The applying block is at least head+1, so
	// the height is the EARLIEST release; the block that applies the unbond
	// sets the exact one, which is why the line says "at the earliest". The
	// wording is CONDITIONAL on the funded/grant split and on the remainder
	// (audit C-1): a partial exit can return coins AND keep the seat.
	effect := unbondEffect(amount, t.account.Bonded, t.account.BondUnfunded, t.status)
	// An exit carries fee 0 by consensus, so its ceiling is 0: any non-zero
	// fee this verb somehow built would be refused rather than signed.
	rc, posted, err := t.submit(tx, txOptions{maxFee: 0, yes: *yes, dryRun: *dryRun}, txProvenance{amount: amountSource, effect: effect})
	if err != nil {
		return err
	}
	if posted {
		fmt.Printf("txid        %s\n", rc.TxID)
		printSeatWarning(rc)
	}
	return nil
}

func cmdWithdraw(args []string) error {
	fs := flag.NewFlagSet("withdraw", flag.ExitOnError)
	nodeURL := fs.String("node", "http://127.0.0.1:8645", "URL of the node's HTTP RPC")
	keyPath := fs.String("key", "", "key file that holds the unbonding records (b10coin keygen)")
	yes, dryRun := addTxConfirmationFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unknown argument %q", fs.Arg(0))
	}
	t, err := connectWalletNode(*nodeURL, *keyPath)
	if err != nil {
		return err
	}
	// A windowed reply must not be mistaken for a complete one: a matured
	// record outside the window would be missed, and this verb signs one
	// Withdraw for every matured record the STATE holds (not one per record it
	// saw), so the count it reports has to come from the node's total.
	if t.account.UnbondingTotal > len(t.account.Unbonding) {
		return fmt.Errorf("the node reports %d unbonding record(s) but returned %d (a windowed reply; audit ST-4); this verb needs all of them - retry against a node whose reply is not truncated", t.account.UnbondingTotal, len(t.account.Unbonding))
	}
	if len(t.account.Unbonding) == 0 {
		return fmt.Errorf("the account %s has no unbonding record; there is nothing to withdraw (a record is created by `b10coin unstake`; a genesis seat's unfunded power is destroyed on unstake, not recorded)", t.addr)
	}
	// A transaction submitted now applies at head+1 at the earliest, so a
	// record releasing at head+1 is mature by the time it executes. Testing
	// against head alone would refuse that record for one block.
	next := t.status.Height + 1
	if next == 0 { // head was MaxUint64; a wrapped "next" would let an unmatured record through
		next = math.MaxUint64
	}
	var matured, total uint64
	var earliest uint64
	for _, rec := range t.account.Unbonding {
		if rec.ReleaseHeight <= next {
			if total > math.MaxUint64-rec.Amount {
				return fmt.Errorf("the node reports unbonding records that overflow a uint64; refusing to sign")
			}
			total += rec.Amount
			matured++
			continue
		}
		if earliest == 0 || rec.ReleaseHeight < earliest {
			earliest = rec.ReleaseHeight
		}
	}
	if matured == 0 {
		return fmt.Errorf("no unbonding record has matured at head %d: the next releases at height %d (%d block(s) to go); run withdraw again then",
			t.status.Height, earliest, earliest-next)
	}

	tx := &types.Tx{
		Type:   types.TxWithdraw,
		From:   t.addr,
		PubKey: t.pub,
		Nonce:  t.account.Nonce,
		Fee:    0,
	}
	// An exit carries fee 0 by consensus, so its ceiling is 0. The payout is
	// the state's (applyWithdraw derives it from every matured record), and the
	// node's count is shown as the node's claim, not as a field of the bytes.
	rc, posted, err := t.submit(tx, txOptions{maxFee: 0, yes: *yes, dryRun: *dryRun}, txProvenance{
		note: fmt.Sprintf("%d matured record(s), %s b10 (%d sparks), released to the spendable balance",
			matured, genesis.FormatB10(total), total),
	})
	if err != nil {
		return err
	}
	if posted {
		fmt.Printf("txid        %s\n", rc.TxID)
		printSeatWarning(rc)
		fmt.Printf("withdraw    %d matured record(s), %s b10 (%d sparks), back to the spendable balance\n", matured, genesis.FormatB10(total), total)
	}
	fmt.Println("withdraw releases EVERY record that is mature when the block applies; a second withdraw of the same record pays nothing.")
	return nil
}

// resumeLine is the startup note a validator prints when it comes back into an
// undecided height at a round other than 0, and "" when it starts at round 0.
//
// It names the trigger of the rolling-restart stall (M5 network re-run at
// 6d54215, 2026-10-30, diagnosed with a debug build): a restarted node resumes
// at the round it had reached before it stopped, which is BEHIND a committee
// that kept climbing rounds while it was down. It jumps forward only on
// evidence from enough of the committee (2 of 4 seats on a four-seat
// committee), so if the next node is stopped before this one has heard from
// two peers it keeps the gap, and only the timeout ladder closes it. The stall
// line (internal/devnet/stall.go) reports the symptom once the height is
// stuck; this line is the cause, printed at the moment it is created.
func resumeLine(height uint64, round uint32) string {
	if round == 0 {
		return ""
	}
	return fmt.Sprintf("consensus    resuming height %d at round %d, the round this node reached before it stopped; it catches up to a committee further ahead only once enough of the committee is heard from, so in a one-at-a-time restart stop the next node only after the chain has advanced (deploy README: rolling restart)", height, round)
}

// checkProducerBlockTime refuses an interval the single-node producer's clock
// cannot satisfy.
//
// The producer stamps every block with time.Now().Unix() - WHOLE SECONDS - and
// chain.Append requires each timestamp to be strictly greater than its
// parent's (audit S-8). Two blocks inside one second therefore kill the node at
// the second one with "chain: block timestamp is not valid for its parent";
// this was reproduced on a real node at height 1. A sub-second interval is
// refused instead of being accepted and then killing the node, because the
// walkthrough copies commands and a reader copying 500ms gets a dead node. The
// floor also keeps time.NewTicker away from a non-positive interval, which
// panics.
func checkProducerBlockTime(d time.Duration) error {
	if d >= time.Second {
		return nil
	}
	return fmt.Errorf("--block-time %s is below the 1s floor: the producer stamps each block with the wall clock in whole seconds (time.Now().Unix()) and the chain requires every block's timestamp to be strictly greater than its parent's, so two blocks inside one second stop the node with \"chain: block timestamp is not valid for its parent\". Use --block-time 1s or longer", d)
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
	relayTokenPath := fs.String("relay-access-token-file", "", "path to the relay's pre-shared access token (audit N-8; at least 16 bytes). The token is NEVER sent: the node answers the relay's per-connection challenge with HMAC-SHA-256(token, challenge) only after the relay announces its gate, and requires HMAC-SHA-256(token, challenge || answer) back, so a relay (or a stranger behind an ungated one) that does not hold the token is refused and logged (audit D-1). The exchange is in plaintext: use it over a trusted path")
	listen := fs.String("listen", "", "P2P listen address for direct connections (empty: dial only)")
	// The advertisement override (audit PX-8). A port-forwarded home node listens
	// on 0.0.0.0:7001, which names no endpoint a peer can dial, so PEER_EXCHANGE
	// used to advertise nothing and the operator had no clue why. --advertise is
	// the address the router forwards to; it must be a literal IP:port (a
	// hostname would move the target after a peer's checks) and it means nothing
	// without a listener to receive the dial it asks for.
	advertise := fs.String("advertise", "", "address PEER_EXCHANGE should advertise when --listen binds a wildcard (e.g. the public IP:port of a forwarded port); literal IP:port, requires --listen")
	// The PEER_EXCHANGE admission exception (audit M-2). A hint naming a
	// loopback, private or link-local address is refused by default, which is
	// the right policy for a network whose members have public listeners - and
	// the wrong one for a private-range deployment (a lab VLAN, a Docker
	// bridge, a home network on 10/8), where EVERY address a peer can advertise
	// is private, so peer exchange could never link anyone without it.
	allowLocalHints := fs.Bool("allow-local-peer-hints", false, "accept PEER_EXCHANGE hints naming loopback/private/link-local addresses (private-range and single-host deployments; never on a node reachable from the public internet)")
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
		case "peers", "relay", "listen", "advertise", "validators", "index", "genesis":
			networked = true
		}
	})
	if !networked {
		if *keyPath != "" {
			return fmt.Errorf("--key signs for a committee seat, but this node (no networking flags) is the single-node devnet producer and signs with its fixture key: give --genesis together with --key, or drop --key")
		}
		if *relayTokenPath != "" {
			return fmt.Errorf("--relay-access-token-file credentials a --relay connection, but no networking flag is set: give --relay ADDR together with it, or drop it")
		}
		if *allowLocalHints {
			// PEER_EXCHANGE only exists on a networked node, and a producer
			// that silently accepted a security-relevant switch it never
			// consults would be a flag that lies.
			return fmt.Errorf("--allow-local-peer-hints relaxes PEER_EXCHANGE admission, which only a networked node runs: give --peers, --relay or --listen together with it, or drop it")
		}
		if *advertise != "" {
			return fmt.Errorf("--advertise names what PEER_EXCHANGE should advertise, which only a networked node runs: give --listen together with it, or drop it")
		}
		if err := checkProducerBlockTime(*blockTime); err != nil {
			return err
		}
		return runProducerNode(*dir, *addr, *blockTime)
	}
	var relayToken []byte
	if *relayTokenPath != "" {
		data, err := os.ReadFile(*relayTokenPath)
		if err != nil {
			return fmt.Errorf("reading relay access-token file %q: %w", *relayTokenPath, err)
		}
		// A trailing newline is an editor artifact, not part of the token;
		// the relay trims the same way, so both ends agree on the bytes.
		relayToken = bytes.TrimRight(data, "\r\n")
		if len(relayToken) == 0 {
			return fmt.Errorf("relay access-token file %q is empty; remove the flag or give it at least one byte", *relayTokenPath)
		}
		// The same floor the relay enforces, refused here so the operator
		// learns about it before the node is listening rather than from a
		// relay that closes every dial. See wire.MinRelayAccessTokenBytes.
		if len(relayToken) < wire.MinRelayAccessTokenBytes {
			return fmt.Errorf("relay access-token file %q holds %d bytes; at least %d are required (a shorter token is brute-forced by dialling)",
				*relayTokenPath, len(relayToken), wire.MinRelayAccessTokenBytes)
		}
	}
	if *advertise != "" && *listen == "" {
		// A node with no listener cannot receive the dial an advertisement asks
		// for; accepting the flag would advertise an endpoint that refuses every
		// peer. The devnet layer refuses it too (it is the library entry point).
		return fmt.Errorf("--advertise names the address peers should dial, but this node has no --listen to receive them: give --listen ADDR (e.g. 0.0.0.0:7001) together with it")
	}
	return runNetworkedNode(fs, *dir, *addr, *listen, *advertise, *peers, *relay, *keyPath, *genesisPath, *validators, *index, relayToken, *allowLocalHints)
}

// runProducerNode is the M1 single-node path, unchanged by M4 and unchanged
// by A-1: the devnet fixture chain, one unilateral block producer on the
// fixture key, no round protocol. It takes no key: there is exactly one
// honest chain identity here (the devnet genesis) and its one key is part of
// that fixture, so a --key flag here could only make a flag lie.
// httpShutdownGrace bounds how long a shutdown waits for in-flight requests.
// It is a bound, not a hang: Shutdown stops accepting immediately and returns
// when active requests finish or this expires.
const httpShutdownGrace = 5 * time.Second

// shutdownHTTP drains in-flight requests instead of aborting them (audit
// O-10). http.Server.Close aborted every active request; Shutdown stops
// accepting, waits for the active ones up to the grace period, and returns.
func shutdownHTTP(s *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), httpShutdownGrace)
	defer cancel()
	_ = s.Shutdown(ctx)
}

// startupLine is the first line a node prints: the build identity, the listen
// address, the chain and the height. Both node paths — the single-node
// producer and the consensus validator — print exactly this line, through this
// function, so the identity an operator sees at startup cannot differ between
// the two (audit S-10). The identity comes from version.Build, which reads the
// toolchain's stamp; nothing here is a constant that could disagree with what
// `b10coin version` says about the same binary.
func startupLine(addr, chainID string, height uint64) string {
	return fmt.Sprintf("b10coin %s listening on http://%s (chain %s, height %d)",
		version.Build().String(), addr, chainID, height)
}

func runProducerNode(dir, httpAddr string, blockTime time.Duration) error {
	// M1 nodes run the devnet genesis. The testnet genesis has no validator
	// keys yet, so there is nothing to sign blocks with until M4.
	c, err := chain.Open(genesis.Devnet(), dir)
	if err != nil {
		return err
	}
	defer c.Close()

	pub, priv := genesis.DevValidatorKey()
	mp := mempool.New(10_000, c.Genesis().Hash(), c.AdmissionHead)
	n := node.New(c, priv, mp)
	// The producer signs every block and holds the chain's only seat, so its
	// POST /tx can say so (testrun S-2); a server built without the key would
	// have to stay silent, which on the one node that includes everything
	// would be the wrong kind of quiet.
	srv := rpc.NewServerWithSigningKey(c, mp, pub)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Bind before announcing, and drain rather than abort on the way out
	// (audit O-10). The banner used to print before ListenAndServe, so a
	// failed bind still claimed to be "listening"; a synchronous net.Listen
	// makes the failure an error and the banner true. On shutdown, Shutdown
	// (not Close) lets an in-flight request finish, and the caller waits for
	// it before returning so the process does not exit under one.
	ln, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownHTTP(httpSrv)
		close(shutdownDone)
	}()

	fmt.Println(startupLine(ln.Addr().String(), c.Genesis().ChainID, c.Height()))

	// A failed Serve must reach the shell as a failure, not as exit 0: the
	// goroutine delivers its error into the buffered channel BEFORE calling
	// stop(), so by the time n.Run returns from that cancellation the error
	// is already available to be read below — no window in which a failure is
	// visible only to the node loop.
	serveErr := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "http:", err)
			serveErr <- err
			stop()
		}
	}()

	if err := n.Run(ctx, blockTime); err != nil && ctx.Err() == nil {
		return err
	}
	// Wait for the HTTP drain before returning. On the clean-signal path this
	// is the drain; on a failed Serve path stop() has already fired, so it is
	// already complete.
	<-shutdownDone
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
func runNetworkedNode(fs *flag.FlagSet, dir, httpAddr, listen, advertise, peers, relay, keyPath, genesisPath string, committee, seat int, relayToken []byte, allowLocalHints bool) error {
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
		// A genesis seat is named by its position. A key that joined after
		// genesis has none (audit RT-1): its seat is a per-epoch property of
		// committed state, so the banner must not print "-1" as if it were a
		// position.
		if pos := seatFromKey(g, priv); pos >= 0 {
			seatName = fmt.Sprintf("seat %d, %s", pos, keyDesc)
		} else {
			seatName = fmt.Sprintf("rotated-in key (seated at head+1), %s", keyDesc)
		}
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
		v, err = devnet.StartValidator(devnet.ValidatorConfig{Dir: dir, Genesis: g, Key: priv, Listen: listen, Advertise: advertise, Relay: relayDial, RelayAccessToken: relayToken, AllowLocalPeerHints: allowLocalHints})
	} else {
		v, err = devnet.StartValidator(devnet.ValidatorConfig{Dir: dir, Index: seat, Validators: committee, Listen: listen, Advertise: advertise, Relay: relayDial, RelayAccessToken: relayToken, AllowLocalPeerHints: allowLocalHints})
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

	// The signing key goes in with the chain and the pool: POST /tx is where an
	// operator learns that a transaction posted here has nowhere to go, and
	// only this node can say whether its own key holds a seat (testrun S-2).
	srv := rpc.NewServerWithSigningKey(v.Chain(), v.Pool(), v.SigningKey())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The same HTTP shape the single node runs (same timeouts, same failure
	// plumbing, same bind-before-banner and drain-on-shutdown fixes: audit
	// O-10) so a networked node's RPC behaves identically.
	ln, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownHTTP(httpSrv)
		close(shutdownDone)
	}()

	fmt.Println(startupLine(ln.Addr().String(), v.Chain().Genesis().ChainID, v.Height()))
	dialDesc := "listening for inbound connections"
	if len(dial) > 0 {
		dialDesc = "dialled " + strings.Join(dial, " ")
	}
	if g == nil {
		seatName = fmt.Sprintf("seat %d (%s)", seat, keyDesc)
	}
	fmt.Printf("consensus    committee of %d, %s, %s\n", committeeSize, seatName, dialDesc)
	if line := resumeLine(v.Height()+1, v.Round()); line != "" {
		fmt.Println(line)
	}

	serveErr := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "http:", err)
			serveErr <- err
			stop()
		}
	}()

	<-ctx.Done()
	// Same semantics as the single node: a clean SIGINT is success; a failed
	// listen must fail the process. The drain is waited out so the process
	// does not exit under an in-flight request.
	<-shutdownDone
	select {
	case err := <-serveErr:
		return err
	default:
		return nil
	}
}

// seatFromKey finds the GENESIS committee position a key signs as, or -1. The
// CLI uses it only inside the seat-name banner; the admission decision lives in
// StartValidator, which admits a key seated at head+1 even though this returns
// -1 for it (a validator that bonded after genesis, audit RT-1).
func seatFromKey(g *genesis.Genesis, priv ed25519.PrivateKey) int {
	pub, _ := priv.Public().(ed25519.PublicKey)
	return genesis.SeatOfPubKey(g.Validators, pub)
}
