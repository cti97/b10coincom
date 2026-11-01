// The wallet's signing envelope and its read verbs (M5 Task 6, moved here by
// M6 Task 1).
//
// ONE envelope, every verb. `stake`, `unstake`, `withdraw`, `send` and
// `claim --key` all reach the chain through submit: it builds the transaction
// once, prints those bytes, enforces the fee ceiling on the fee read back from
// them, honours --dry-run before the confirmation, and asks for confirmation
// before the signature. A verb that signed anywhere else would be a second
// transaction path, which is what CL-1 fixed.
//
// The read verbs (`balance`, `history`) are CLIENTS, not a second node. They
// read the node's /status and /account/{address} (balance) or /history
// (history) over HTTP - the same redirect-refusing client the claim and
// signing verbs use - and never open a data directory, never open a store and
// never scan a block locally. Design decision 2: a wallet that downloads the
// chain to show a balance is a second node, and this milestone does not build
// one.
//
// Money on the wire and on the screen is sparks (uint64). A b10 amount is
// rendered by genesis.FormatB10, which divides and takes the remainder of an
// integer - never a float: "0.29" written through a float64 round trip is
// 28,999,999 sparks, one spark short, and this file must not be able to print
// that.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/faucet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/keystore"
	"github.com/cti97/b10coincom/internal/types"
)

// readStatus reads GET /status and parses the one field a wallet cannot get
// anywhere else: the chain's 32-byte genesis hash (hex in the body). A node
// from before M5 does not report one, so it cannot be a wallet's target.
func readStatus(base string) (stakingStatus, [32]byte, error) {
	var st stakingStatus
	var gh [32]byte
	if err := getJSON(base+"/status", &st); err != nil {
		return st, gh, fmt.Errorf("cannot read the node's status at %s: %w", base+"/status", err)
	}
	raw, err := hex.DecodeString(st.GenesisHash)
	if err != nil || len(raw) != 32 {
		return st, gh, fmt.Errorf("the node at %s reports genesis_hash %q; this wallet needs the chain's 32-byte genesis hash (a node from before M5 does not report one)", base, st.GenesisHash)
	}
	copy(gh[:], raw)
	return st, gh, nil
}

// readAccount reads GET /account/{address} and refuses a reply for a different
// address. The node echoes the address for exactly this reason
// (internal/rpc/server.go's handleAccount); a client that ignores the echo lets
// a node answer for somebody else.
func readAccount(base string, addr types.Address) (stakingAccount, error) {
	var acc stakingAccount
	if err := getJSON(base+"/account/"+addr.String(), &acc); err != nil {
		return acc, fmt.Errorf("cannot read the account for %s at %s: %w", addr, base+"/account/", err)
	}
	got, err := types.ParseAddress(acc.Address)
	if err != nil || got != addr {
		return acc, fmt.Errorf("the node reports account %q where this read asked for %s; refusing to show a balance for an account that was not asked for", acc.Address, addr)
	}
	return acc, nil
}

// walletAddress resolves the address a read verb works on. --key and --address
// are ALTERNATIVES: exactly one must be given. With --key the address is
// derived from the key file's public half (the wallet never asks a node for
// it); with --address it is parsed canonically, checksum included.
func walletAddress(keyPath, addrFlag string) (types.Address, error) {
	var zero types.Address
	switch {
	case keyPath != "" && addrFlag != "":
		return zero, fmt.Errorf("give --key PATH or --address ADDR, not both: they name two different accounts and this verb reads one")
	case keyPath != "":
		priv, err := keystore.Load(keyPath)
		if err != nil {
			return zero, err
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return zero, fmt.Errorf("key file %s holds no Ed25519 public key", keyPath)
		}
		return types.AddressFromPub(pub), nil
	case addrFlag != "":
		addr, err := types.ParseAddress(addrFlag)
		if err != nil {
			return zero, fmt.Errorf("--address %q: %w", addrFlag, err)
		}
		return addr, nil
	}
	return zero, fmt.Errorf("give --key PATH (a key file from b10coin keygen) or --address ADDR: a read needs to know whose account to read")
}

// cmdBalance prints the node's view of one account.
//
// It is TWO reads and nothing else: /status for the chain identity and height,
// /account/{address} for the money and the nonce. It does not take a data
// directory, does not open a store and does not scan a block, so it cannot
// become a second node by accident.
//
// The output format is PINNED (the M6 walkthrough greps it): one
// space-aligned label per line, sparks first and the exact b10 render after.
func cmdBalance(args []string) error {
	fs := flag.NewFlagSet("balance", flag.ExitOnError)
	nodeURL := fs.String("node", "http://127.0.0.1:8645", "URL of the node's HTTP RPC (the balance is read from it; no data directory is opened)")
	keyPath := fs.String("key", "", "key file (b10coin keygen) whose address to read; an alternative to --address")
	addrFlag := fs.String("address", "", "b10 address to read; an alternative to --key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	addr, err := walletAddress(*keyPath, *addrFlag)
	if err != nil {
		return err
	}
	base := strings.TrimRight(*nodeURL, "/")
	st, _, err := readStatus(base)
	if err != nil {
		return err
	}
	acc, err := readAccount(base, addr)
	if err != nil {
		return err
	}
	fmt.Printf("%-11s %s\n", "address", addr)
	fmt.Printf("%-11s %d sparks (%s b10)\n", "balance", acc.Balance, genesis.FormatB10(acc.Balance))
	fmt.Printf("%-11s %d\n", "nonce", acc.Nonce)
	fmt.Printf("%-11s %d sparks (%s b10)\n", "bonded", acc.Bonded, genesis.FormatB10(acc.Bonded))
	fmt.Printf("%-11s %d records\n", "unbonding", acc.UnbondingTotal)
	fmt.Printf("%-11s %s\n", "chain", st.ChainID)
	fmt.Printf("%-11s %d\n", "height", st.Height)
	return nil
}

// walletHistory is GET /history's body as the CLI reads it. It mirrors the
// handler's shape but is its own type: the RPC's structs are unexported, and a
// client should pin the wire contract it depends on rather than import one.
type walletHistory struct {
	Address   string               `json:"address"`
	Head      uint64               `json:"head"`
	From      uint64               `json:"from"`
	To        uint64               `json:"to"`
	Blocks    int                  `json:"blocks"`
	Truncated bool                 `json:"truncated"`
	Txs       []walletHistoryEntry `json:"txs"`
}

type walletHistoryEntry struct {
	TxID   string `json:"txid"`
	Height uint64 `json:"height"`
	Type   string `json:"type"`
	From   string `json:"from"`
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
	Fee    uint64 `json:"fee"`
}

// defaultHistoryBlocks is the same window the node applies when a client asks
// for none. The verb sends it explicitly so the number it asked for and the
// number the node scanned can be compared.
const defaultHistoryBlocks = 100

// historyBlocksHelp is the one place the verb's window bound is described.
const historyBlocksHelp = "how many blocks back from the node's head to scan (default 100, maximum 500; the node clamps anything above 500 and the reply reports what it actually scanned)"

// cmdHistory prints one account's transactions inside a bounded block window.
//
// The verb does NOT ask the node for an account's whole past - there is no
// transaction index to ask (design decision 2), and M6 does not add one. It
// asks for a backward scan over at most --blocks blocks and prints the window
// the node reports, so the reader can tell "nothing happened" from "I did not
// look far enough". The no-index sentence is printed EVERY time, not only when
// the reply is truncated: a limit shown only sometimes is a limit a reader
// learns to miss.
func cmdHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	nodeURL := fs.String("node", "http://127.0.0.1:8645", "URL of the node's HTTP RPC (the history is read from it; no data directory is opened)")
	keyPath := fs.String("key", "", "key file (b10coin keygen) whose address to read; an alternative to --address")
	addrFlag := fs.String("address", "", "b10 address to read; an alternative to --key")
	blocks := fs.Uint64("blocks", defaultHistoryBlocks, historyBlocksHelp)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *blocks == 0 {
		return fmt.Errorf("--blocks 0 asks for no window: give at least 1")
	}
	addr, err := walletAddress(*keyPath, *addrFlag)
	if err != nil {
		return err
	}
	base := strings.TrimRight(*nodeURL, "/")
	// One read: /history's reply carries the head it scanned, so the verb
	// never asks /status and never asks for a genesis hash.
	q := url.Values{}
	q.Set("address", addr.String())
	q.Set("blocks", strconv.FormatUint(*blocks, 10))
	var h walletHistory
	if err := getJSON(base+"/history?"+q.Encode(), &h); err != nil {
		return fmt.Errorf("cannot read the history at %s: %w", base+"/history", err)
	}
	// The node echoes the address it answered for; a reply for another account
	// would make every line below a lie about this one.
	if h.Address != "" {
		got, perr := types.ParseAddress(h.Address)
		if perr != nil || got != addr {
			return fmt.Errorf("the node reports history for %q where this read asked for %s; refusing to show another account's history", h.Address, addr)
		}
	}

	if h.Blocks == 0 {
		fmt.Printf("history for %s (no blocks to scan: the chain is at height %d)\n", addr, h.Head)
	} else {
		fmt.Printf("history for %s (blocks %d..%d, scanned %d, newest first)\n", addr, h.From, h.To, h.Blocks)
	}
	for _, e := range h.Txs {
		// The party column names the OTHER side of the entry relative to the
		// account this read asked for: a transfer's recipient from the
		// sender's history, its sender from the recipient's. A non-transfer
		// carries no counterparty on the wire, so it shows none.
		party := "from -"
		if e.To != "" {
			if e.From == addr.String() {
				party = "to   " + e.To
			} else {
				party = "from " + e.From
			}
		}
		fmt.Printf("%6d  %-13s %10d sparks (%s b10)  fee %d  %s\n",
			e.Height, e.Type, e.Amount, genesis.FormatB10(e.Amount), e.Fee, party)
	}
	if h.Truncated {
		// No number here: the cap is the node's (internal/rpc
		// maxHistoryEntries), and repeating it in the CLI would be a second
		// source of truth for a fact the node owns.
		fmt.Println("truncated: the node capped this reply; older matches inside this window are not shown")
	}
	// Printed every time (design decision 5).
	if h.Blocks == 0 {
		fmt.Println("no transaction index: this is a backward scan of committed blocks, so there is nothing below height 1 to show.")
	} else {
		fmt.Printf("no transaction index: this is a backward scan over the %d block(s) above, not a complete account history - older activity is not shown. Raise --blocks to look further back (at most 500 per run).\n", h.Blocks)
	}
	return nil
}

// stakingStatus is the subset of GET /status the signing verbs need (the
// name is kept: the test suite references it, and a rename would churn it for
// no behaviour).
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

// defaultMaxFeeSparks is the ceiling on the fee a wallet verb will sign unless
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
//   - state.applyBond and state.applyTransfer subtract the fee from the
//     sender's balance and credit it to nobody, so every spark above the
//     minimum is simply burned.
//
// An honest node therefore never charges more than one spark, and a node that
// asks for more is either misconfigured or running the CL-1 attack (report
// fee = balance - amount so the transaction burns the whole spendable balance). A
// chain whose genesis really does set a higher minimum is usable with
// --max-fee SPARKS.
const defaultMaxFeeSparks uint64 = 1

// maxFeeHelp is shared by the verbs so the help text cannot drift from the
// ceiling's derivation.
const maxFeeHelp = "ceiling on the signed fee, in sparks (uint64, never b10). The default 1 is min_fee_sparks on every shipped genesis and is also the whole admission price (the mempool does not price transactions and applyBond/applyTransfer burn the fee, so a higher fee buys nothing); a node that asks for more is refused unless this raises it"

// txOptions is the confirmation surface the wallet verbs share.
type txOptions struct {
	// maxFee is the ceiling on the signed fee, in sparks. An exit's fee is
	// fixed at 0 by consensus (state.applyUnbond, state.applyWithdraw), so
	// the exits pass 0: any non-zero fee they somehow built would be refused.
	maxFee uint64
	// yes is --yes: sign and post without asking, for a non-interactive run.
	// With dryRun also set, dryRun wins and yes is inert: dry-run returns
	// before the confirmation is reached, so nothing is signed either way.
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

// walletTarget is one node plus the key the verb signs with, already vetted:
// the key file loaded, the node's chain identity parsed, and the account read
// and checked to be the one this key signs as.
type walletTarget struct {
	base    string
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	addr    types.Address
	status  stakingStatus
	account stakingAccount
	genesis [32]byte
}

// connectWalletNode loads the key file, reads the node's status and account,
// and refuses anything that would make the signature meaningless: no key, an
// unknown/malformed genesis hash (a node from before M5 cannot be signed for),
// or an account the node names as somebody else's.
func connectWalletNode(nodeURL, keyPath string) (*walletTarget, error) {
	if keyPath == "" {
		return nil, fmt.Errorf("give --key PATH: a transaction is signed by a key file (b10coin keygen)")
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
		return nil, fmt.Errorf("the node at %s reports genesis_hash %q; a transaction must be signed against the chain's 32-byte genesis hash (a node from before M5 does not report one, so it cannot be signed for)", nodeURL, st.GenesisHash)
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
	return &walletTarget{base: base, priv: priv, pub: pub, addr: addr, status: st, account: acc, genesis: gh}, nil
}

// txProvenance records where the preview's non-byte facts came from, so the
// reader can tell an operator's own --amount from a node's claim.
type txProvenance struct {
	amount string // where a bond/unbond/transfer Amount came from
	note   string // an optional node-supplied fact worth showing (a withdraw payout)
	// effect is what the transaction will do once applied, shown BEFORE the
	// confirmation so an irreversible bond or exit is understood, not merely
	// authorised (audit CL-2). It is derived from the node's reported
	// parameters, so the preview labels it a forecast where it depends on them.
	effect string
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
	// THREE fee cases, each a true statement to the signer. A bond and a
	// transfer pay the node-reported fee and the ceiling bounds it; an exit's
	// fee is 0 because state.applyUnbond and state.applyWithdraw refuse
	// anything else; a claim's fee is 0 because state.applyFaucetClaim refuses
	// a claim that carries one. "An exit is free" and "a claim may not carry a
	// fee" are different facts about different transactions.
	switch b.tx.Type {
	case types.TxBond, types.TxTransfer:
		fmt.Fprintf(w, "  fee         %d spark  (the node's claim; ceiling %d)\n", b.tx.Fee, maxFee)
	case types.TxFaucetClaim:
		fmt.Fprintf(w, "  fee         %d spark  (fixed at 0 by consensus: a claim may not carry a fee)\n", b.tx.Fee)
	default:
		fmt.Fprintf(w, "  fee         %d spark  (fixed at 0 by consensus: an exit is free)\n", b.tx.Fee)
	}
	switch b.tx.Type {
	case types.TxBond, types.TxUnbond, types.TxTransfer:
		fmt.Fprintf(w, "  amount      %d sparks (%s b10)  (%s)\n",
			b.tx.Amount, genesis.FormatB10(b.tx.Amount), prov.amount)
		if b.tx.Type == types.TxTransfer {
			// The recipient is part of the transaction a transfer signs; it is
			// printed from the decoded bytes, like every other field here.
			fmt.Fprintf(w, "  to          %s  (the operator's --to; the address this transfer credits)\n", b.tx.To)
		}
	case types.TxFaucetClaim:
		// The epoch is the transaction's only time binding and it is signed.
		// It is derived from the node's height, so the preview says whose
		// claim it is; the proof-of-work nonce is solved locally.
		fmt.Fprintf(w, "  epoch       %d  (the node's claim: the block at its head+1 decides it; it is signed)\n", b.tx.Epoch)
		fmt.Fprintf(w, "  pow nonce   %d  (this CLI solved the puzzle locally; the proof is signed)\n", b.tx.PowNonce)
	}
	if prov.note != "" {
		fmt.Fprintf(w, "  node says   %s\n", prov.note)
	}
	if prov.effect != "" {
		fmt.Fprintf(w, "  effect      %s\n", prov.effect)
	}
	fmt.Fprintf(w, "  genesis     %x  (the node's claim; the signature is bound to it)\n", genesisHash)
	fmt.Fprintf(w, "  bytes       %x\n", b.raw)
	switch b.tx.Type {
	case types.TxBond, types.TxTransfer:
		fmt.Fprintf(w, "  the nonce, fee and genesis above come from %s and this CLI cannot\n", node)
	case types.TxFaucetClaim:
		fmt.Fprintf(w, "  the nonce, epoch and genesis above come from %s and this CLI cannot\n", node)
	default:
		fmt.Fprintf(w, "  the nonce and genesis above come from %s and this CLI cannot\n", node)
	}
	switch b.tx.Type {
	case types.TxTransfer:
		fmt.Fprintf(w, "  check them: a node reporting a future nonce builds a transfer that applies later.\n")
		fmt.Fprintf(w, "  --to, --amount and the signing key are yours; the fee and nonce are not.\n")
	case types.TxFaucetClaim:
		fmt.Fprintf(w, "  check them: a node reporting a future nonce, or a height that picks another\n")
		fmt.Fprintf(w, "  epoch, builds a claim that applies later or not at all. The signing key is\n")
		fmt.Fprintf(w, "  yours; the puzzle proof was solved locally against the epoch shown.\n")
	default:
		fmt.Fprintf(w, "  check them: a node reporting a future nonce builds a bond that applies later,\n")
		fmt.Fprintf(w, "  and one under-reporting the bond makes an exit partial. Only --amount\n")
		fmt.Fprintf(w, "  (when given) and the signing key are yours.\n")
	}
	fmt.Fprintf(w, "  The signature cannot be withdrawn: once a node accepts these bytes this CLI\n")
	switch b.tx.Type {
	case types.TxTransfer:
		fmt.Fprintf(w, "  cannot cancel or replace the transaction, and a transfer is irreversible.\n")
	case types.TxFaucetClaim:
		fmt.Fprintf(w, "  cannot cancel or replace the transaction, and a claim is irreversible.\n")
	default:
		fmt.Fprintf(w, "  cannot cancel or replace the transaction, and a bond or exit is irreversible.\n")
	}
}

// errNoAnswer means the confirmation question had no answer: stdin is not an
// interactive terminal (a pipe, a file, cron) or it closed.
var errNoAnswer = errors.New("stdin is not an interactive terminal, or it closed before an answer")

// stdinIsTerminal reports whether f is an interactive terminal. The portable
// test is os.ModeCharDevice on f's stat: a pipe and a regular file are not
// character devices, and a console is. Comparing against os.DevNull instead
// (the pre-fix code) is NOT portable: on Windows a console handle and NUL both
// stat with volume serial and file index zero, so os.SameFile matched and every
// stake/unstake/withdraw without --yes was refused as non-interactive
// (audit E-1). /dev/null is itself a character device, so this returns true for
// it; that is safe because READING still decides - an empty line is a refusal,
// and EOF must never look like consent (askConfirmation).
func stdinIsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
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
		return fmt.Sprintf("the default ceiling of %d spark: every shipped genesis sets min_fee_sparks to 1, the mempool does not price transactions, and applyBond/applyTransfer burn the whole fee, so a higher fee buys nothing", defaultMaxFeeSparks)
	}
	return fmt.Sprintf("the ceiling of %d spark this run set with --max-fee", maxFee)
}

// submit is the ONLY path from a built transaction to a signature. It
// builds the transaction once, prints those bytes, enforces the fee ceiling on
// the fee read back from them, honours --dry-run, and asks for confirmation -
// all before Sign. posted=false means nothing was signed and nothing was sent:
// either a dry run (no error) or a refusal (an error).
func (t *walletTarget) submit(tx *types.Tx, o txOptions, prov txProvenance) (txid string, posted bool, err error) {
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
		return "", false, fmt.Errorf("refusing to sign: the node at %s puts a fee of %d spark on this transaction, above %s. Nothing was signed. If you deliberately accept a higher fee, raise --max-fee to a number YOU choose above %d; do not copy the fee the node reported",
			t.base, built.tx.Fee, feeCeilingReason(o.maxFee), o.maxFee)
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

// ---------------------------------------------------------------------------
// The cover check (M6 Task 1)
// ---------------------------------------------------------------------------

// coverError is the one arithmetic a spend verb uses before signing: amount +
// fee must fit in a uint64 and the account must hold it. noun names the
// transaction's amount, because the refusal is read by an operator who asked
// for a bond or a transfer and should be told which one could not be covered.
//
// It carries NO funding hint. checkSpendable appends the bond-only MIN_STAKE
// lecture, and a transfer short by a hundred sparks must not inherit it: the
// M5 Docker re-run (2026-10-30) found a bond refusal lecturing an account that
// needed a smaller bond, and telling a sender to go and fund a stake would be
// the same mistake pointing the other way.
func coverError(noun string, balance, amount, fee uint64) error {
	if fee > math.MaxUint64-amount {
		return fmt.Errorf("the %s %d + fee %d overflows a uint64", noun, amount, fee)
	}
	need := amount + fee
	if balance < need {
		return fmt.Errorf("the account holds %s b10 (%d sparks) but the %s plus the %d-spark fee needs %s b10 (%d sparks), short %d sparks",
			genesis.FormatB10(balance), balance, noun, fee, genesis.FormatB10(need), need, need-balance)
	}
	return nil
}

// checkCover is the transfer's cover check: the same arithmetic as a bond's,
// with no MIN_STAKE hint.
func checkCover(balance, amount, fee uint64) error {
	return coverError("amount", balance, amount, fee)
}

// ---------------------------------------------------------------------------
// send: the transfer verb (M6 Task 1)
// ---------------------------------------------------------------------------

// cmdSend builds ONE transfer and hands it to the shared envelope. The fee and
// nonce are the node's claim (t.status.MinFeeSparks, t.account.Nonce), exactly
// as cmdStake takes them; --amount and --to are the operator's own and are the
// only two values this verb can vouch for. The recipient is credited when a
// block includes the transaction; the fee is burned and the signature cannot be
// withdrawn, both stated in the preview before the confirmation.
func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	nodeURL := fs.String("node", "http://127.0.0.1:8645", "URL of the node's HTTP RPC")
	keyPath := fs.String("key", "", "key file that pays (b10coin keygen); the transfer is signed by it")
	toFlag := fs.String("to", "", "recipient b10 address (canonical and checksummed)")
	amountB10 := fs.String("amount", "", "amount to send, in b10 as an exact decimal (e.g. 0.5); sparks only, never a float")
	maxFee := fs.Uint64("max-fee", defaultMaxFeeSparks, maxFeeHelp)
	yes, dryRun := addTxConfirmationFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unknown argument %q", fs.Arg(0))
	}
	if *amountB10 == "" {
		return fmt.Errorf("give --amount N in b10 (exact decimal, e.g. 0.5)")
	}
	amount, err := genesis.ParseB10(*amountB10)
	if err != nil {
		return err
	}
	if amount == 0 {
		return fmt.Errorf("--amount %q is zero sparks; a transfer must be positive", *amountB10)
	}
	if *toFlag == "" {
		return fmt.Errorf("give --to ADDRESS: a transfer needs a recipient")
	}
	to, err := types.ParseAddress(*toFlag)
	if err != nil {
		return fmt.Errorf("--to %q: %w", *toFlag, err)
	}
	if *keyPath == "" {
		return fmt.Errorf("give --key PATH: a transfer is signed by a key file (b10coin keygen)")
	}
	// A self-transfer is refused BEFORE any network call: the sender's address
	// is a function of the key file alone, and state.applyTransfer refuses
	// From == To (ErrSelfTransfer), so asking a node about it could only
	// produce a transaction the chain rejects.
	priv, err := keystore.Load(*keyPath)
	if err != nil {
		return err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("key file %s holds no Ed25519 public key", *keyPath)
	}
	if from := types.AddressFromPub(pub); from == to {
		return fmt.Errorf("--to %s is the sending key's own address: state.applyTransfer refuses a transfer to self (ErrSelfTransfer), so nothing was signed and no node was asked", to)
	}

	t, err := connectWalletNode(*nodeURL, *keyPath)
	if err != nil {
		return err
	}
	// A zero-fee transfer could never apply: every shipped genesis sets at
	// least one spark and genesis.Validate refuses a zero minimum. A node
	// reporting 0 is either misconfigured or steering this verb into a
	// transaction the real chain will reject.
	if t.status.MinFeeSparks == 0 {
		return fmt.Errorf("the node reports min_fee_sparks 0: every shipped genesis sets at least 1 spark and genesis.Validate refuses a zero minimum, so a zero-fee transfer could never apply")
	}
	if err := checkCover(t.account.Balance, amount, t.status.MinFeeSparks); err != nil {
		return err
	}

	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   t.addr,
		PubKey: t.pub,
		Nonce:  t.account.Nonce,
		Fee:    t.status.MinFeeSparks,
		To:     to,
		Amount: amount,
	}
	effect := "the recipient is credited when a block includes the transaction; the fee is burned (it pays no one) and the signature cannot be withdrawn"
	txid, posted, err := t.submit(tx, txOptions{maxFee: *maxFee, yes: *yes, dryRun: *dryRun}, txProvenance{amount: "from --amount", effect: effect})
	if err != nil {
		return err
	}
	if posted {
		fmt.Printf("txid        %s\n", txid)
		// There is deliberately no /tx/{id} route to wait on: inclusion is a
		// property of a later block, and a wait loop here would hide that.
		fmt.Println("send does not wait for a block: the recipient's balance changes only when a block includes the transaction. Poll `b10coin balance --address` (there is no /tx/{id} route to wait on).")
	}
	return nil
}

// ---------------------------------------------------------------------------
// claim --key: the faucet claim through the same envelope (M6 Task 1)
// ---------------------------------------------------------------------------

// claimWithKey signs a faucet claim with a KEY FILE the operator holds, so the
// coins land on an address a transfer can sign for. Without it cmdClaim keeps
// its ephemeral path byte-for-byte; this path exists because the shipped claim
// used to fund an address nothing could sign for (keystore has no verb that
// turns a printed key into a file).
//
// The epoch is derived from the node's height and is the transaction's only
// time binding; the puzzle parameters are genesis state, so the chain ID must
// still be the compiled-in devnet's. The claim goes through submit: printed
// first, fee ceiling enforced on the decoded fee, --dry-run before the
// confirmation, confirmation before the signature.
func claimWithKey(nodeURL, keyPath string, yes, dryRun bool) error {
	g := genesis.Devnet()
	t, err := connectWalletNode(nodeURL, keyPath)
	if err != nil {
		return err
	}
	// The claim only verifies on the chain whose parameters solved it; a
	// different chain would refuse it anyway, so say so here.
	if t.status.ChainID != g.ChainID {
		return fmt.Errorf("the node at %s runs chain %q, not the devnet genesis %q", nodeURL, t.status.ChainID, g.ChainID)
	}
	if t.status.EpochBlocks == 0 {
		return fmt.Errorf("the node reports epoch_blocks 0: the claim's epoch cannot be derived")
	}
	// The claim must carry the epoch of the block that will apply it: the
	// block at the node's head+1 (epoch(h) = h/EpochBlocks + 1).
	epoch := (t.status.Height+1)/t.status.EpochBlocks + 1
	pow, ok := faucet.SolveClaim(t.pub, epoch, g.Params.FaucetPowTarget, g.Params.FaucetPowArgon2, claimPuzzleAttempts)
	if !ok {
		return fmt.Errorf("no solution found within %d attempts", claimPuzzleAttempts)
	}

	tx := &types.Tx{
		Type:     types.TxFaucetClaim,
		From:     t.addr,
		PubKey:   t.pub,
		Nonce:    t.account.Nonce,
		Fee:      0, // a claim may not carry a fee (state.ErrClaimCarriesFee)
		Epoch:    epoch,
		PowNonce: pow,
	}
	txid, posted, err := t.submit(tx, txOptions{maxFee: 0, yes: yes, dryRun: dryRun}, txProvenance{
		effect: "the claim is paid from the faucet when a block includes it; it is one claim per key per epoch, and the signature cannot be withdrawn",
	})
	if err != nil {
		return err
	}

	fmt.Printf("claimant    %x\n", t.addr[:])
	fmt.Printf("public key  %x\n", t.pub)
	fmt.Printf("claim epoch %d\n", epoch)
	fmt.Printf("pow nonce   %d\n", pow)
	if !posted {
		// A dry run queued nothing; saying "the claim is queued" here would be
		// a false receipt. submit already printed that nothing was signed or
		// posted.
		return nil
	}
	fmt.Printf("txid        %s\n", txid)
	fmt.Println("the claim is queued on the node; it is paid when the node's next block applies it.")
	return nil
}
