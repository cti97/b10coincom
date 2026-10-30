// Command b10coin is the b10coin node and tooling binary.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	case "stake":
		err = cmdStake(os.Args[2:])
	case "unstake":
		err = cmdUnstake(os.Args[2:])
	case "withdraw":
		err = cmdWithdraw(os.Args[2:])
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
                 [--epoch-blocks N] [--rotate-demo] [--plot-nakamoto]   (epoch length, the rotation fixture, and the committed-state Nakamoto series)
  b10coin keygen [--out PATH]                                            Generate this validator's key file (owner-only permissions; refuses to overwrite)
  b10coin node   --dir PATH [--http ADDR] [--block-time DURATION]
                 [--peers ADDR,...] [--relay ADDR] [--listen ADDR]       Run the single-node devnet producer, or — with --peers/--relay/--listen — a consensus validator
                 [--allow-local-peer-hints]                              (accept loopback/private peer hints: private-range and single-host networks only)
                 --genesis PATH --key PATH                               (with both: a REAL member of the committee the genesis file lists)
                 --validators N --index I                                (fixture ONLY: the derived development committee, publicly derivable keys)
  b10coin claim  --node URL [--dir PATH]                Solve the faucet puzzle and send one claim
  b10coin stake  --node URL --key PATH --amount 1000 [--max-fee SPARKS] [--yes | --dry-run]
                                                        Bond b10 to this key's committee seat (signed tx, printed first)
  b10coin unstake --node URL --key PATH [--amount 1000] [--yes | --dry-run]
                                                        Unbond all or part of the bond; a partial exit must leave MIN_STAKE or nothing
  b10coin withdraw --node URL --key PATH [--yes | --dry-run]
                                                        Release matured unbonding records to the spendable balance
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
reused for a follow-up transfer. Because stdout is captured by shells, CI
logs and journalctl, --print-key=false withholds the key: safe when
no follow-up transfer is planned, and the claimant address is still printed.

The staking verbs are ORDINARY signed transactions, not a side channel: they
read /status for the chain's genesis hash and stake parameters and
/account/{address} for the nonce, balance and bond, then POST to /tx - the
same signing, genesis-hash binding, fee rule and mempool admission as a
transfer, and the state machine judges them at execution time. A bond needs
MIN_STAKE (1,000 b10 = 10^11 sparks) and takes effect at the next epoch
boundary. No shipped genesis funds a fresh key with MIN_STAKE: the faucet pays
one claim per key per epoch (1 b10 on the devnet parameters, 100 b10 on the
testnet parameters), and claim signs with an ephemeral key it never saves. See
README "Staking" for the arithmetic and for the one pre-funded fixture account
a local devnet ships.

Every staking verb BUILDS the transaction, prints its fields and its canonical
bytes, and only then signs - after a confirmation: type "yes" at the prompt,
or pass --yes when stdin is not an interactive terminal. --dry-run prints the
transaction and stops without signing and without posting. The fee ceiling
defaults to 1 spark because that is min_fee_sparks on every shipped genesis and
a fee above it buys nothing: the mempool admits on nonce and state rather than
on price, and applyBond burns the whole fee. --max-fee SPARKS raises the
ceiling; a node asking for more than one spark is refused by default.
WHAT THIS DOES NOT FIX: the nonce, balance, bond and genesis hash still come
from the node the verb is pointed at, and the CLI has no independent copy of
them. The printed transaction makes them visible instead of silent, so a lying
node can still delay a bond with a future nonce, turn a full exit into a
partial one by under-reporting the bond, or make the transaction invalid by
misreporting the genesis hash - but it can no longer choose the fee, and the
default ceiling bounds that loss to one spark.
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
var claimHTTP = &http.Client{Timeout: 15 * time.Second}

// claimPuzzleAttempts bounds the local solve. The reference claimant solves the
// cheap outer puzzle (16 leading zero bits) as well as the devnet's easy
// Argon2id target, so the expected scan is about 2^17 nonces; a failure means
// the tuning changed, not that mining is slow.
const claimPuzzleAttempts = 1 << 24

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
	// Printing the key is the documented default (kept for compatibility),
	// but stdout is captured by shells, CI and journalctl, so the opt-out is
	// the safe choice for any run that does not intend a follow-up transfer
	// (audit O-10). The claimant ADDRESS is printed either way.
	printKey := fs.Bool("print-key", true, "print the ephemeral signing key to stdout; set --print-key=false to keep the secret out of shell history, CI logs and journalctl (the key is then unrecoverable and no follow-up transfer is possible)")
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
	sigHash := tx.SigningHash(g.Hash())
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
	fmt.Println("no key file, no keystore: the ephemeral signing key cannot be recovered later.")
	if *printKey {
		fmt.Printf("ephemeral key %x  <- copy now only if you plan a follow-up transfer\n", priv)
	} else {
		fmt.Println("ephemeral key withheld (--print-key=false); no follow-up transfer from this claimant is possible")
	}
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

// stakingStatus is the subset of GET /status the staking verbs need.
type stakingStatus struct {
	ChainID         string `json:"chain_id"`
	Height          uint64 `json:"height"`
	GenesisHash     string `json:"genesis_hash"`
	MinFeeSparks    uint64 `json:"min_fee_sparks"`
	MinStakeSparks  uint64 `json:"min_stake_sparks"`
	EpochBlocks     uint64 `json:"epoch_blocks"`
	UnbondingEpochs uint64 `json:"unbonding_epochs"`
	CommitteeSize   int    `json:"committee_size"`
}

// stakingAccount is GET /account/{address}'s body. BondUnfunded is the part of
// Bonded that came from the genesis grant and is therefore not withdrawable
// (audit ST-3); UnbondingTotal is how many records the node holds, so the
// verb can tell a windowed reply from a complete one (audit ST-4).
type stakingAccount struct {
	Address        string                `json:"address"`
	Balance        uint64                `json:"balance"`
	Nonce          uint64                `json:"nonce"`
	Bonded         uint64                `json:"bonded"`
	BondUnfunded   uint64                `json:"bond_unfunded"`
	Unbonding      []stakingUnbondingRec `json:"unbonding"`
	UnbondingTotal int                   `json:"unbonding_total"`
}

type stakingUnbondingRec struct {
	Amount        uint64 `json:"amount"`
	ReleaseHeight uint64 `json:"release_height"`
}

// defaultMaxFeeSparks is the ceiling on the fee a staking verb will sign unless
// --max-fee raises it. The number is DERIVED from the shipped chains, not
// rounded:
//
//   - every shipped genesis sets MinFeeSparks = 1 (genesis.sharedParams, which
//     the devnet and the testnet both use and every simnet genesis wraps), and
//     genesis.Validate refuses a zero minimum;
//   - one spark is the WHOLE admission price. internal/mempool judges a fee
//     only as "at least the state's minimum" (admitNonClaim) and Mempool.Take
//     hands transactions to a block in arrival order, so this milestone has no
//     fee market: a larger fee buys no earlier admission and no better
//     position;
//   - state.applyBond subtracts the fee from the sender's balance and credits
//     it to nobody, so every spark above the minimum is simply burned.
//
// An honest node therefore never charges more than one spark, and a node that
// asks for more is either misconfigured or running the CL-1 attack (report
// fee = balance - amount so the bond burns the whole spendable balance). A
// chain whose genesis really does set a higher minimum is usable with
// --max-fee SPARKS.
const defaultMaxFeeSparks uint64 = 1

// maxFeeHelp is shared by the verbs so the help text cannot drift from the
// ceiling's derivation.
const maxFeeHelp = "ceiling on the signed fee, in sparks (uint64, never b10). The default 1 is min_fee_sparks on every shipped genesis and is also the whole admission price (the mempool does not price transactions and applyBond burns the fee, so a higher fee buys nothing); a node that asks for more is refused unless this raises it"

// stakingTxOptions is the confirmation surface the three staking verbs share.
type stakingTxOptions struct {
	// maxFee is the ceiling on the signed fee, in sparks. An exit's fee is
	// fixed at 0 by consensus (state.applyUnbond, state.applyWithdraw), so
	// the exits pass 0: any non-zero fee they somehow built would be refused.
	maxFee uint64
	// yes is --yes: sign and post without asking, for a non-interactive run.
	yes bool
	// dryRun is --dry-run: build and print, then stop. Nothing is signed and
	// nothing is posted.
	dryRun bool
}

// addTxConfirmationFlags registers the two flags every verb shares.
func addTxConfirmationFlags(fs *flag.FlagSet) (yes, dryRun *bool) {
	yes = fs.Bool("yes", false, "confirm and sign without a terminal prompt; required when stdin is not an interactive terminal (a script, cron, CI)")
	dryRun = fs.Bool("dry-run", false, "build and print the transaction, then stop: nothing is signed and nothing is posted")
	return yes, dryRun
}

// stakingTarget is one node plus the key the verb signs with, already vetted:
// the key file loaded, the node's chain identity parsed, and the account read
// and checked to be the one this key signs as.
type stakingTarget struct {
	base    string
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	addr    types.Address
	status  stakingStatus
	account stakingAccount
	genesis [32]byte
}

// connectStakingNode loads the key file, reads the node's status and account,
// and refuses anything that would make the signature meaningless: no key, an
// unknown/malformed genesis hash (a node from before M5 cannot be signed for),
// or an account the node names as somebody else's.
func connectStakingNode(nodeURL, keyPath string) (*stakingTarget, error) {
	if keyPath == "" {
		return nil, fmt.Errorf("give --key PATH: a staking transaction is signed by a key file (b10coin keygen)")
	}
	priv, err := keystore.Load(keyPath)
	if err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key file %s holds no Ed25519 public key", keyPath)
	}
	addr := types.AddressFromPub(pub)
	base := strings.TrimRight(nodeURL, "/")

	var st stakingStatus
	if err := getJSON(base+"/status", &st); err != nil {
		return nil, fmt.Errorf("cannot read the node's status at %s: %w", base+"/status", err)
	}
	rawHash, err := hex.DecodeString(st.GenesisHash)
	if err != nil || len(rawHash) != 32 {
		return nil, fmt.Errorf("the node at %s reports genesis_hash %q; a staking transaction must be signed against the chain's 32-byte genesis hash (a node from before M5 does not report one, so it cannot be signed for)", nodeURL, st.GenesisHash)
	}
	var gh [32]byte
	copy(gh[:], rawHash)

	var acc stakingAccount
	if err := getJSON(base+"/account/"+addr.String(), &acc); err != nil {
		return nil, fmt.Errorf("cannot read the account for %s at %s: %w", addr, base+"/account/", err)
	}
	gotAddr, err := types.ParseAddress(acc.Address)
	if err != nil || gotAddr != addr {
		return nil, fmt.Errorf("the node reports account %q where this key signs as %s; refusing to sign for an account this key does not own", acc.Address, addr)
	}
	return &stakingTarget{base: base, priv: priv, pub: pub, addr: addr, status: st, account: acc, genesis: gh}, nil
}

// txProvenance records where the preview's non-byte facts came from, so the
// reader can tell an operator's own --amount from a node's claim.
type txProvenance struct {
	amount string // where a bond/unbond Amount came from
	note   string // an optional node-supplied fact worth showing (a withdraw payout)
}

// builtTx is one fully built transaction, read back from its own canonical
// bytes. submit builds it ONCE and both prints and signs THIS value, so the
// transaction a user reads is the transaction that receives the signature -
// never a re-rendered summary that could disagree with the signed bytes
// (audit CL-1).
type builtTx struct {
	raw []byte
	tx  *types.Tx // decoded from raw
}

// buildTx encodes tx once and decodes those bytes back. Everything printed and
// signed afterwards is derived from the decode, so a divergence between what
// is displayed and what is signed is not representable.
func buildTx(tx *types.Tx) (*builtTx, error) {
	raw := tx.Encode()
	back, err := types.DecodeTx(raw)
	if err != nil {
		return nil, fmt.Errorf("the transaction this verb built does not decode: %w", err)
	}
	return &builtTx{raw: raw, tx: back}, nil
}

// txTypeLabel names a transaction type for the preview.
func txTypeLabel(t types.TxType) string {
	switch t {
	case types.TxTransfer:
		return "transfer"
	case types.TxFaucetClaim:
		return "faucet claim"
	case types.TxBond:
		return "bond"
	case types.TxUnbond:
		return "unbond"
	case types.TxWithdraw:
		return "withdraw"
	}
	return "unknown"
}

// print writes the transaction that will be signed. Each field is read from
// b.tx (decoded from b.raw) and b.raw is printed verbatim, so the hex a reader
// can decode offline is the same byte string the signature will cover.
// genesisHash, node and prov are annotated as what they are - facts the NODE
// supplied, or the operator's own --amount - so a reader can tell which values
// this CLI could check and which it merely echoes.
func (b *builtTx) print(w io.Writer, genesisHash [32]byte, node string, prov txProvenance, maxFee uint64) {
	fmt.Fprintf(w, "transaction to sign (built, not yet signed):\n")
	fmt.Fprintf(w, "  type        %s (%d)\n", txTypeLabel(b.tx.Type), b.tx.Type)
	fmt.Fprintf(w, "  from        %s\n", b.tx.From)
	fmt.Fprintf(w, "  public key  %x\n", b.tx.PubKey)
	fmt.Fprintf(w, "  nonce       %d  (the node's claim)\n", b.tx.Nonce)
	if b.tx.Type == types.TxBond {
		fmt.Fprintf(w, "  fee         %d spark  (the node's claim; ceiling %d)\n", b.tx.Fee, maxFee)
	} else {
		// An exit's fee is not a node claim: state.applyUnbond and
		// state.applyWithdraw refuse anything but 0. Saying "the node's claim"
		// here would be false.
		fmt.Fprintf(w, "  fee         %d spark  (fixed at 0 by consensus: an exit is free)\n", b.tx.Fee)
	}
	if b.tx.Type == types.TxBond || b.tx.Type == types.TxUnbond {
		fmt.Fprintf(w, "  amount      %d sparks (%s b10)  (%s)\n",
			b.tx.Amount, genesis.FormatB10(b.tx.Amount), prov.amount)
	}
	if prov.note != "" {
		fmt.Fprintf(w, "  node says   %s\n", prov.note)
	}
	fmt.Fprintf(w, "  genesis     %x  (the node's claim; the signature is bound to it)\n", genesisHash)
	fmt.Fprintf(w, "  bytes       %x\n", b.raw)
	if b.tx.Type == types.TxBond {
		fmt.Fprintf(w, "  the nonce, fee and genesis above come from %s and this CLI cannot\n", node)
	} else {
		fmt.Fprintf(w, "  the nonce and genesis above come from %s and this CLI cannot\n", node)
	}
	fmt.Fprintf(w, "  check them: a node reporting a future nonce builds a bond that applies later,\n")
	fmt.Fprintf(w, "  and one under-reporting the bond makes an exit partial. Only --amount\n")
	fmt.Fprintf(w, "  (when given) and the signing key are yours.\n")
}

// errNoAnswer means the confirmation question had no answer: stdin is not an
// interactive terminal (a pipe, a file, cron) or it closed.
var errNoAnswer = errors.New("stdin is not an interactive terminal, or it closed before an answer")

// stdinIsTerminal reports whether f is an interactive terminal. A real terminal
// is a character device; /dev/null is one too (and is what `go test`, cron and
// CI hand a process), so identity with the null device is excluded explicitly.
// Reading is still what decides: an empty answer is a refusal whatever the
// device was, because EOF must never look like consent.
func stdinIsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if null, err := os.Stat(os.DevNull); err == nil && os.SameFile(fi, null) {
		return false
	}
	return true
}

// askConfirmation is the interactive half of the confirmation boundary, kept
// as a variable so a test can construct the TTY/no-TTY states instead of
// provoking them through a timing race.
var askConfirmation = func() (string, error) {
	if !stdinIsTerminal(os.Stdin) {
		return "", errNoAnswer
	}
	fmt.Fprint(os.Stderr, `Type "yes" to sign and post this transaction: `)
	// A partial line without a trailing newline is still an answer; an empty
	// line is a refusal whether the read returned EOF or nothing. Ignoring the
	// error here is deliberate, and it is why EOF (/dev/null, a closed pipe)
	// can never be mistaken for consent.
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if line == "" {
		return "", errNoAnswer
	}
	return line, nil
}

// confirmTransaction is the trust boundary the audit asked for: a staking
// transaction is not signed merely because a command line was typed. --yes
// states the confirmation explicitly; otherwise a terminal must answer "yes".
// Any other answer, or no terminal, refuses BEFORE Sign is called.
func confirmTransaction(yes bool) error {
	if yes {
		return nil
	}
	answer, err := askConfirmation()
	if err != nil {
		return fmt.Errorf("refusing to sign: nothing was signed because this run cannot confirm the transaction (%w). Re-run with --yes to confirm non-interactively, or with --dry-run to print it without signing", err)
	}
	if !strings.EqualFold(strings.TrimSpace(answer), "yes") {
		return fmt.Errorf("refusing to sign: nothing was signed; the answer was %q, not %q", strings.TrimSpace(answer), "yes")
	}
	return nil
}

// feeCeilingReason explains the ceiling in a refusal, with the number's origin.
func feeCeilingReason(maxFee uint64) string {
	if maxFee == defaultMaxFeeSparks {
		return fmt.Sprintf("the default ceiling of %d spark: every shipped genesis sets min_fee_sparks to 1, the mempool does not price transactions, and applyBond burns the whole fee, so a higher fee buys nothing", defaultMaxFeeSparks)
	}
	return fmt.Sprintf("the ceiling of %d spark this run set with --max-fee", maxFee)
}

// submit is the ONLY path from a built staking transaction to a signature. It
// builds the transaction once, prints those bytes, enforces the fee ceiling on
// the fee read back from them, honours --dry-run, and asks for confirmation -
// all before Sign. posted=false means nothing was signed and nothing was sent:
// either a dry run (no error) or a refusal (an error).
func (t *stakingTarget) submit(tx *types.Tx, o stakingTxOptions, prov txProvenance) (txid string, posted bool, err error) {
	built, err := buildTx(tx)
	if err != nil {
		return "", false, err
	}

	// PRINT BEFORE SIGNING, FROM THE SAME BYTES THAT WILL BE SIGNED.
	built.print(os.Stdout, t.genesis, t.base, prov, o.maxFee)

	// The ceiling is enforced on the fee read back from the printed bytes,
	// before any signature exists. It must not depend on the reported
	// min_fee_sparks being honest: the ceiling is this CLI's own number.
	if built.tx.Fee > o.maxFee {
		return "", false, fmt.Errorf("refusing to sign: the node at %s puts a fee of %d spark on this transaction, above %s. Re-run with --max-fee %d (sparks) only if you accept that cost",
			t.base, built.tx.Fee, feeCeilingReason(o.maxFee), built.tx.Fee)
	}

	if o.dryRun {
		fmt.Println("dry run: the transaction above was NOT signed and NOT posted.")
		return "", false, nil
	}

	if err := confirmTransaction(o.yes); err != nil {
		return "", false, err
	}

	// Sign the decoded transaction and post its canonical re-encoding. The
	// signature covers SigningHash(encodeBody), which is a function of the
	// same bytes printed above; the only bytes added are the signature.
	hash := built.tx.SigningHash(t.genesis)
	built.tx.Sig = crypto.Sign(t.priv, hash[:])
	txid, err = postTxHex(t.base+"/tx", built.tx.Encode())
	if err != nil {
		return "", false, err
	}
	return txid, true, nil
}

// stakingFundingNote is the honest answer to "where do I get MIN_STAKE?".
// It is returned at the point a verb refuses for lack of funds or stake, so an
// operator meets it with the command in hand rather than in a doc they have not
// opened yet.
const stakingFundingNote = "no shipped genesis gives an operator's key MIN_STAKE in spendable funds: the faucet pays one claim per key per epoch and `b10coin claim` signs with an ephemeral key it does not save, so a fresh operator has no shipped path to this balance; see README \"Staking\" for the claim arithmetic"

// checkSpendable refuses a bond the account cannot cover, before submitting:
// the node would refuse it at execution, but the operator learns why here.
func checkSpendable(balance, amount, fee uint64) error {
	if fee > math.MaxUint64-amount {
		return fmt.Errorf("the bond %d + fee %d overflows a uint64", amount, fee)
	}
	need := amount + fee
	if balance < need {
		return fmt.Errorf("the account holds %s b10 (%d sparks) but the bond plus the %d-spark fee needs %s b10 (%d sparks), short %d sparks; %s",
			genesis.FormatB10(balance), balance, fee, genesis.FormatB10(need), need, need-balance, stakingFundingNote)
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

// releaseForecast is the "release" line cmdUnstake prints, as a function so the
// arithmetic and the genesis-bond case are testable without capturing stdout.
//
// amount <= bondUnfunded means the whole exit is the seat's unfunded genesis
// power, which the state DESTROYS rather than records (audit ST-3): printing a
// release height for it would promise a payout that cannot happen. Otherwise
// the funded part is recorded, and its release height is the epoch boundary at
// or after the earliest applying block (head+1) plus the cooldown.
func releaseForecast(amount, bondUnfunded uint64, st stakingStatus, cooldown uint64) (string, bool) {
	if amount <= bondUnfunded {
		return fmt.Sprintf("nothing: all %d sparks of this exit are the seat's UNFUNDED genesis power, which an unbond destroys instead of releasing (audit ST-3)", amount), true
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

func cmdStake(args []string) error {
	fs := flag.NewFlagSet("stake", flag.ExitOnError)
	nodeURL := fs.String("node", "http://127.0.0.1:8645", "URL of the node's HTTP RPC")
	keyPath := fs.String("key", "", "key file to sign with (b10coin keygen); the bond seats THIS key")
	amountB10 := fs.String("amount", "", "amount to bond, in b10 as an exact decimal (at least MIN_STAKE, 1000 b10)")
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
	t, err := connectStakingNode(*nodeURL, *keyPath)
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
		return fmt.Errorf("--amount %s b10 (%d sparks) would leave the bond at %s b10 (%d sparks), below this chain's MIN_STAKE %s b10 (%d sparks); %s",
			genesis.FormatB10(amount), amount, genesis.FormatB10(resulting), resulting,
			genesis.FormatB10(t.status.MinStakeSparks), t.status.MinStakeSparks, stakingFundingNote)
	}
	if err := checkSpendable(t.account.Balance, amount, t.status.MinFeeSparks); err != nil {
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
	txid, posted, err := t.submit(tx, stakingTxOptions{maxFee: *maxFee, yes: *yes, dryRun: *dryRun}, txProvenance{amount: "from --amount"})
	if err != nil {
		return err
	}
	if posted {
		fmt.Printf("txid        %s\n", txid)
	}
	if t.status.EpochBlocks > 0 {
		fmt.Printf("the bond is applied when a block includes it; the seat it buys is considered at the next epoch boundary (every %d blocks), never mid-epoch.\n", t.status.EpochBlocks)
	} else {
		fmt.Println("the bond is applied when a block includes it; the seat it buys is considered at the next epoch boundary.")
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
	t, err := connectStakingNode(*nodeURL, *keyPath)
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
	// An exit carries fee 0 by consensus, so its ceiling is 0: any non-zero
	// fee this verb somehow built would be refused rather than signed.
	txid, posted, err := t.submit(tx, stakingTxOptions{maxFee: 0, yes: *yes, dryRun: *dryRun}, txProvenance{amount: amountSource})
	if err != nil {
		return err
	}
	if posted {
		fmt.Printf("txid        %s\n", txid)
	}
	if cooldown, ok := cooldownBlocks(t.status); ok {
		// The applying block is at least head+1, so this is the EARLIEST
		// release height; the block that actually applies the unbond sets the
		// exact one. Stated as an estimate rather than as a receipt.
		if line, ok := releaseForecast(amount, t.account.BondUnfunded, t.status, cooldown); ok {
			fmt.Printf("release     %s\n", line)
		}
	}
	if amount > t.account.BondUnfunded {
		if t.account.BondUnfunded > 0 {
			fmt.Printf("unfunded    %d sparks of this exit are the seat's unfunded genesis power and are destroyed, not released (audit ST-3)\n", t.account.BondUnfunded)
		}
		fmt.Println("the coins are neither spendable nor counted in the committee until the release height; `b10coin withdraw` releases them then.")
	} else {
		fmt.Println("the seat is gone from the committee and there is nothing to withdraw: a genesis grant was never funded (audit ST-3).")
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
	t, err := connectStakingNode(*nodeURL, *keyPath)
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
	txid, posted, err := t.submit(tx, stakingTxOptions{maxFee: 0, yes: *yes, dryRun: *dryRun}, txProvenance{
		note: fmt.Sprintf("%d matured record(s), %s b10 (%d sparks), released to the spendable balance",
			matured, genesis.FormatB10(total), total),
	})
	if err != nil {
		return err
	}
	if posted {
		fmt.Printf("txid        %s\n", txid)
		fmt.Printf("withdraw    %d matured record(s), %s b10 (%d sparks), back to the spendable balance\n", matured, genesis.FormatB10(total), total)
	}
	fmt.Println("withdraw releases EVERY record that is mature when the block applies; a second withdraw of the same record pays nothing.")
	return nil
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
	relayTokenPath := fs.String("relay-access-token-file", "", "path to the relay's pre-shared access token (audit N-8; at least 16 bytes). Sent only after the relay announces its gate with a fixed first frame, so a relay without a token never receives it; a refused token is logged and retried. Plaintext over TCP and replayable: use it over a trusted path")
	listen := fs.String("listen", "", "P2P listen address for direct connections (empty: dial only)")
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
		case "peers", "relay", "listen", "validators", "index", "genesis":
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
	return runNetworkedNode(fs, *dir, *addr, *listen, *peers, *relay, *keyPath, *genesisPath, *validators, *index, relayToken, *allowLocalHints)
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

func runProducerNode(dir, httpAddr string, blockTime time.Duration) error {
	// M1 nodes run the devnet genesis. The testnet genesis has no validator
	// keys yet, so there is nothing to sign blocks with until M4.
	c, err := chain.Open(genesis.Devnet(), dir)
	if err != nil {
		return err
	}
	defer c.Close()

	_, priv := genesis.DevValidatorKey()
	mp := mempool.New(10_000, c.Genesis().Hash(), c.AdmissionHead)
	n := node.New(c, priv, mp)
	srv := rpc.NewServer(c, mp)

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

	fmt.Printf("b10coin %s listening on http://%s (chain %s, height %d)\n",
		version.Version, ln.Addr(), c.Genesis().ChainID, c.Height())

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
func runNetworkedNode(fs *flag.FlagSet, dir, httpAddr, listen, peers, relay, keyPath, genesisPath string, committee, seat int, relayToken []byte, allowLocalHints bool) error {
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
		v, err = devnet.StartValidator(devnet.ValidatorConfig{Dir: dir, Genesis: g, Key: priv, Listen: listen, RelayAccessToken: relayToken, AllowLocalPeerHints: allowLocalHints})
	} else {
		v, err = devnet.StartValidator(devnet.ValidatorConfig{Dir: dir, Index: seat, Validators: committee, Listen: listen, RelayAccessToken: relayToken, AllowLocalPeerHints: allowLocalHints})
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

	fmt.Printf("b10coin %s listening on http://%s (chain %s, height %d)\n",
		version.Version, ln.Addr(), v.Chain().Genesis().ChainID, v.Height())
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
