// The wallet's read verbs: `balance` and `history` (M6 Task 0).
//
// These are CLIENTS, not a second node. They read the node's /status and
// /account/{address} (balance) or /history (history) over HTTP - the same
// redirect-refusing client the claim and staking verbs use - and never open a
// data directory, never open a store and never scan a block locally. Design
// decision 2: a wallet that downloads the chain to show a balance is a second
// node, and this milestone does not build one.
//
// Money on the wire and on the screen is sparks (uint64). A b10 amount is
// rendered by genesis.FormatB10, which divides and takes the remainder of an
// integer - never a float: "0.29" written through a float64 round trip is
// 28,999,999 sparks, one spark short, and this file must not be able to print
// that.
//
// This file starts here and Task 1 moves the signing envelope into it; nothing
// in this task signs, posts or mutates anything.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"strconv"
	"strings"

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
