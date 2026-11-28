//go:build js && wasm

// Command b10coin-wasm exposes the repository's own transaction builder to
// JavaScript, for a browser wallet.
//
// The point is what it does NOT contain: a second encoder. A wallet written in
// JavaScript that re-implemented the transaction envelope would be a second
// definition of the wire format, and a field-order or width mistake there
// produces signatures that verify against a hash the node never computes. This
// binary compiles internal/wallet - the same code the CLI signs with - to
// WebAssembly, so the bytes a browser produces are the bytes the node already
// verifies, by construction.
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -o dist/b10coin-wasm.wasm ./cmd/b10coin-wasm
//	cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" dist/          # go1.24+
//
// Every call is one JSON string in, one JSON string out, so the JavaScript
// side needs no per-operation bindings:
//
//	const out = JSON.parse(b10coin.request(JSON.stringify({op: "newkey"})))
//
// ops: newkey | address | transfer | bond | unbond | withdraw
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"syscall/js"

	"github.com/cti97/b10coincom/internal/types"
	"github.com/cti97/b10coincom/internal/wallet"
)

// request is one operation. Amounts are SPARKS, as they are everywhere on the
// wire: a wallet that accepted "0.5" here would be inventing a float unit the
// chain does not have.
type request struct {
	Op         string `json:"op"`
	Seed       string `json:"seed,omitempty"`     // 32-byte Ed25519 seed, hex
	PrivateKey string `json:"private_key,omitempty"` // 64-byte form the CLI's key file holds
	Genesis    string `json:"genesis_hash,omitempty"`
	To         string `json:"to,omitempty"`
	Amount     uint64 `json:"amount,omitempty"`
	Fee        uint64 `json:"fee,omitempty"`
	Nonce      uint64 `json:"nonce,omitempty"`
}

type response struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Address    string `json:"address,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	TxHex      string `json:"tx_hex,omitempty"`
	TxID       string `json:"tx_id,omitempty"`
}

func fail(err error) string {
	b, _ := json.Marshal(response{Error: err.Error()})
	return string(b)
}

func okAddress(k wallet.Key, seedHex string) string {
	b, _ := json.Marshal(response{
		OK:         true,
		Address:    k.Address.String(),
		PublicKey:  hex.EncodeToString(k.Pub),
		PrivateKey: seedHex,
	})
	return string(b)
}

func key(r request) (wallet.Key, error) {
	switch {
	case r.Seed != "":
		seed, err := hex.DecodeString(r.Seed)
		if err != nil {
			return wallet.Key{}, err
		}
		return wallet.KeyFromSeed(seed)
	case r.PrivateKey != "":
		priv, err := hex.DecodeString(r.PrivateKey)
		if err != nil {
			return wallet.Key{}, err
		}
		return wallet.KeyFromPrivate(priv)
	}
	return wallet.Key{}, errors.New("wallet: give seed (32 bytes, hex) or private_key (64 bytes, hex)")
}

func genesisHash(r request) ([32]byte, error) {
	var g [32]byte
	if r.Genesis == "" {
		return g, errors.New("wallet: genesis_hash is required: every signature covers it")
	}
	b, err := hex.DecodeString(r.Genesis)
	if err != nil {
		return g, err
	}
	if len(b) != 32 {
		return g, errors.New("wallet: genesis_hash must be 32 bytes of hex")
	}
	copy(g[:], b)
	return g, nil
}

func toAddress(r request) (types.Address, error) {
	var a types.Address
	if r.To == "" {
		return a, errors.New("wallet: give to (a b10 address)")
	}
	return types.ParseAddress(r.To)
}

// request handles one operation and returns the JSON response. It never
// panics: a panic inside a js.Func would take the whole page down.
func handle(r request) (out string) {
	defer func() {
		if rec := recover(); rec != nil {
			out = fail(errors.New("wallet: internal error"))
		}
	}()

	switch r.Op {
	case "newkey":
		k, err := wallet.NewKey()
		if err != nil {
			return fail(err)
		}
		return okAddress(k, hex.EncodeToString(k.Seed()))

	case "address":
		k, err := key(r)
		if err != nil {
			return fail(err)
		}
		return okAddress(k, hex.EncodeToString(k.Seed()))

	case "transfer", "bond", "unbond", "withdraw":
		k, err := key(r)
		if err != nil {
			return fail(err)
		}
		g, err := genesisHash(r)
		if err != nil {
			return fail(err)
		}
		var tx *types.Tx
		switch r.Op {
		case "transfer":
			to, err := toAddress(r)
			if err != nil {
				return fail(err)
			}
			tx, err = wallet.Transfer(k, g, to, r.Amount, r.Fee, r.Nonce)
			if err != nil {
				return fail(err)
			}
		case "bond":
			tx, err = wallet.Bond(k, g, r.Amount, r.Fee, r.Nonce)
			if err != nil {
				return fail(err)
			}
		case "unbond":
			tx, err = wallet.Unbond(k, g, r.Amount, r.Fee, r.Nonce)
			if err != nil {
				return fail(err)
			}
		case "withdraw":
			tx, err = wallet.Withdraw(k, g, r.Fee, r.Nonce)
			if err != nil {
				return fail(err)
			}
		}
		id := wallet.ID(tx)
		b, _ := json.Marshal(response{
			OK:      true,
			Address: k.Address.String(),
			TxHex:   wallet.Hex(tx),
			TxID:    hex.EncodeToString(id[:]),
		})
		return string(b)

	default:
		return fail(errors.New("wallet: unknown op " + r.Op))
	}
}

func main() {
	api := map[string]any{
		"request": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 {
				return fail(errors.New("wallet: request takes one JSON string"))
			}
			var r request
			if err := json.Unmarshal([]byte(args[0].String()), &r); err != nil {
				return fail(err)
			}
			return handle(r)
		}),
	}
	js.Global().Set("b10coin", api)
	// Keep the Go runtime alive: the page calls in through js.Func values.
	select {}
}
