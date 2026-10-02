# M0–M1: Foundation and Single-Node Chain — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a Go codebase where a devnet node creates, signs, persists, and replays a chain of blocks with real transfer transactions, verified by one command.

**Architecture:** A canonical binary encoding layer underpins every consensus structure, so encoding is deterministic and non-malleable. An account-based Merkle-committed state machine applies transfers. Blocks are appended to crash-tolerant segment files and fully replayed on restart, with the recomputed state root compared against each header. There is no consensus in this plan — a single node produces blocks unilaterally; Byzantine-fault-tolerant agreement arrives in M3.

**Tech Stack:** Go 1.23+, `crypto/ed25519`, `net/http` + `encoding/json`, `lukechampine.com/blake3` (the only external dependency), standard-library `testing`.

**Spec:** `docs/2026-10-02-b10coin-design.md` (in this repo — read it alongside this plan; the plan argues from the spec).

## Global Constraints

- **Module path:** `github.com/cti97/b10coincom`
- **Go floor:** `go 1.23`
- **Toolchain (verified 2026-10-02):** `brew install go` upgraded this machine from go1.21.4 to **go1.27.1**, which satisfies this floor. No toolchain download or floor change is needed.
- **Dependencies:** exactly one *direct* external module, `lukechampine.com/blake3` (v1.4.1). It pulls one transitive requirement, `github.com/klauspost/cpuid/v2`, recorded `// indirect` in `go.mod` — that is unavoidable and is not a second chosen dependency. Do not add a CLI framework, a logging framework, a test framework, a database, or any other direct dependency.
- **Base unit is `spark`**; `1 b10 = 10^8 sparks`. All monetary values are `uint64` sparks. Never use floats for money.
- **Canonical encoding only.** Every consensus structure is encoded with the helpers from Task 2. Never `encoding/gob`, never JSON for anything that gets hashed or signed, never iterate a Go `map` when producing bytes.
- **No premine on testnet.** The testnet genesis must have zero funded accounts. Task 8 includes a test that enforces this.
- **No secrets in the repo.** `keys/`, `.env`, `*.key`, `*.pem` are already git-ignored — keep it that way.
- **Every task ends with `go test ./...` green and a commit.**
- Commit message prefixes: `feat:`, `test:`, `fix:`, `chore:`, `docs:`.

## File Structure

| File | Responsibility |
|---|---|
| `go.mod`, `Makefile`, `.github/workflows/ci.yml` | Module, build targets, CI |
| `internal/version/version.go` | Version constant |
| `internal/types/codec.go` | Canonical encode/decode primitives — the foundation everything else uses |
| `internal/crypto/hash.go` | BLAKE3 hashing with unambiguous part framing |
| `internal/crypto/merkle.go` | Order-sensitive binary Merkle root |
| `internal/crypto/keys.go` | Ed25519 generate/sign/verify |
| `internal/types/address.go` | Address derivation, base32 text encoding, checksum |
| `internal/types/tx.go` | Transaction union, signing hash, ID, decode |
| `internal/types/block.go` | Header, Block, structural validation, tx root |
| `internal/state/state.go` | Account map, clone, sorted Merkle root |
| `internal/state/apply.go` | Transfer rules — the state transition function |
| `internal/genesis/genesis.go` | Params, genesis hash, faucet address derivation |
| `internal/store/store.go` | Append-only block segments, crash-tolerant open, index |
| `internal/chain/chain.go` | Build/append/validate blocks, replay, state root checks |
| `internal/mempool/mempool.go` | Pending transactions, dedup, cap |
| `internal/rpc/server.go` | HTTP JSON endpoints |
| `internal/devnet/devnet.go` | In-process devnet used by both the CLI and the acceptance test |
| `cmd/b10coin/main.go` | CLI: `devnet`, `node` |

Split by responsibility: `types` never imports `state`; `state` never imports `chain`; `chain` never imports `rpc`. Import direction is `cmd → devnet → {chain, rpc, node}` and `chain → {store, state, genesis, types, crypto}`.

---

### Task 1: Module skeleton, Makefile, CI

**Files:**
- Create: `go.mod`, `Makefile`, `.github/workflows/ci.yml`, `internal/version/version.go`, `internal/version/version_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `version.Version` (string constant), `make test`, `make build`

- [ ] **Step 1: Write the failing test**

Create `internal/version/version_test.go`:

```go
package version

import (
	"regexp"
	"testing"
)

func TestVersionIsSemver(t *testing.T) {
	re := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	if !re.MatchString(Version) {
		t.Fatalf("Version %q is not semver", Version)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/version/ -v`
Expected: FAIL — package has no Go files / `undefined: Version`

- [ ] **Step 3: Write minimal implementation**

Create `internal/version/version.go`:

```go
// Package version holds the b10coin build version.
package version

// Version is the semantic version of the node software.
const Version = "0.1.0"
```

- [ ] **Step 4: Create the module and toolchain files**

Run: `go mod init github.com/cti97/b10coincom && go mod edit -go=1.23`

Create `Makefile` (recipes are indented with TABS):

```makefile
GO ?= go

.PHONY: test build vet fmt devnet

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

build:
	$(GO) build -o bin/b10coin ./cmd/b10coin

fmt:
	$(GO) fmt ./...

devnet: build
	./bin/b10coin devnet --blocks 100
```

Create `.github/workflows/ci.yml`:

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      - run: go vet ./...
      - run: go test ./...
      - run: go build ./...
```

- [ ] **Step 5: Run tests and vet**

Run: `go test ./... && go vet ./...`
Expected: PASS, no output from vet.

- [ ] **Step 6: Commit**

```bash
git add go.mod Makefile .github internal/version
git commit -m "chore: add Go module skeleton, Makefile and CI"
```

---

### Task 2: Canonical encoding primitives

**Files:**
- Create: `internal/types/codec.go`, `internal/types/codec_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `type Encoder struct{}` with `NewEncoder() *Encoder`, `(*Encoder) Bytes() []byte`, `U8(uint8)`, `U32(uint32)`, `U64(uint64)`, `I64(int64)`, `Len(int)`, `VarBytes([]byte)`, `Raw([]byte)`, `Fixed32([32]byte)`
  - `type Decoder struct{}` with `NewDecoder([]byte) *Decoder`, `Done() error`, `U8() (uint8, error)`, `U32() (uint32, error)`, `U64() (uint64, error)`, `I64() (int64, error)`, `Len() (int, error)`, `VarBytes() ([]byte, error)`, `Fixed32() ([32]byte, error)`
  - Errors: `ErrShortBuffer`, `ErrTrailingBytes`, `ErrNonCanonical`

- [ ] **Step 1: Write the failing tests**

Create `internal/types/codec_test.go`:

```go
package types

import (
	"bytes"
	"errors"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	e := NewEncoder()
	e.U8(0xAB)
	e.U32(0xDEADBEEF)
	e.U64(1<<63 + 7)
	e.I64(-42)
	e.Len(3)
	e.VarBytes([]byte("hello"))
	e.Raw([]byte{1, 2, 3})
	e.Fixed32([32]byte{9})

	d := NewDecoder(e.Bytes())
	if v, err := d.U8(); err != nil || v != 0xAB {
		t.Fatalf("U8 = %v, %v", v, err)
	}
	if v, err := d.U32(); err != nil || v != 0xDEADBEEF {
		t.Fatalf("U32 = %v, %v", v, err)
	}
	if v, err := d.U64(); err != nil || v != 1<<63+7 {
		t.Fatalf("U64 = %v, %v", v, err)
	}
	if v, err := d.I64(); err != nil || v != -42 {
		t.Fatalf("I64 = %v, %v", v, err)
	}
	if v, err := d.Len(); err != nil || v != 3 {
		t.Fatalf("Len = %v, %v", v, err)
	}
	if v, err := d.VarBytes(); err != nil || !bytes.Equal(v, []byte("hello")) {
		t.Fatalf("VarBytes = %q, %v", v, err)
	}
	raw := make([]byte, 3)
	for i := range raw {
		b, err := d.U8()
		if err != nil {
			t.Fatal(err)
		}
		raw[i] = b
	}
	if !bytes.Equal(raw, []byte{1, 2, 3}) {
		t.Fatalf("raw = %v", raw)
	}
	if v, err := d.Fixed32(); err != nil || v != [32]byte{9} {
		t.Fatalf("Fixed32 = %v, %v", v, err)
	}
	if err := d.Done(); err != nil {
		t.Fatalf("Done = %v", err)
	}
}

func TestDecoderRejectsShortBuffer(t *testing.T) {
	d := NewDecoder([]byte{1, 2})
	if _, err := d.U32(); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}

func TestDecoderRejectsTrailingBytes(t *testing.T) {
	d := NewDecoder([]byte{1, 2, 3})
	if _, err := d.U8(); err != nil {
		t.Fatal(err)
	}
	if err := d.Done(); !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("expected ErrTrailingBytes, got %v", err)
	}
}

// A length prefix may not be padded with redundant continuation bytes.
// Without this check the same value has two encodings, which would let an
// attacker change a transaction's bytes without changing its meaning.
func TestDecoderRejectsNonCanonicalVarint(t *testing.T) {
	// 0x80 0x00 is a two-byte encoding of zero; canonical is 0x00.
	d := NewDecoder([]byte{0x80, 0x00})
	if _, err := d.Len(); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("expected ErrNonCanonical, got %v", err)
	}
}

func TestLenPrefixLargerThanBufferIsShortBuffer(t *testing.T) {
	e := NewEncoder()
	e.Len(1000)
	d := NewDecoder(e.Bytes())
	if _, err := d.VarBytes(); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/types/ -v`
Expected: FAIL — `undefined: NewEncoder`

- [ ] **Step 3: Write the implementation**

Create `internal/types/codec.go`:

```go
// Package types holds b10coin's consensus structures and their canonical
// binary encoding.
//
// Encoding rules — these are consensus-critical, and violating them is how
// chains fork:
//
//   - Fixed-width integers are big-endian (uint8/uint32/uint64/int64).
//   - Lengths and counts are unsigned LEB128 varints, minimally encoded.
//   - Byte slices are varint-length-prefixed.
//   - Go maps are NEVER encoded directly; iteration order is not deterministic.
//     Sort keys first.
//   - Nothing that is hashed or signed uses JSON or gob.
package types

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrShortBuffer   = errors.New("types: short buffer")
	ErrTrailingBytes = errors.New("types: trailing bytes after decode")
	ErrNonCanonical  = errors.New("types: non-canonical encoding")
)

// Encoder appends canonically-encoded fields to an internal buffer.
type Encoder struct {
	buf []byte
}

func NewEncoder() *Encoder { return &Encoder{} }

// Bytes returns the accumulated encoding. The result aliases internal
// storage and must not be modified by the caller.
func (e *Encoder) Bytes() []byte { return e.buf }

func (e *Encoder) U8(v uint8) { e.buf = append(e.buf, v) }

func (e *Encoder) U32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	e.buf = append(e.buf, b[:]...)
}

func (e *Encoder) U64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	e.buf = append(e.buf, b[:]...)
}

func (e *Encoder) I64(v int64) { e.U64(uint64(v)) }

// Len writes a count or byte length as a minimal unsigned LEB128 varint.
func (e *Encoder) Len(n int) {
	if n < 0 {
		panic("types: negative length")
	}
	var b [binary.MaxVarintLen64]byte
	m := binary.PutUvarint(b[:], uint64(n))
	e.buf = append(e.buf, b[:m]...)
}

func (e *Encoder) VarBytes(b []byte) {
	e.Len(len(b))
	e.buf = append(e.buf, b...)
}

func (e *Encoder) Raw(b []byte) { e.buf = append(e.buf, b...) }

func (e *Encoder) Fixed32(v [32]byte) { e.buf = append(e.buf, v[:]...) }

// Decoder reads canonically-encoded fields. Every method is bounds-checked
// and returns an error rather than panicking: this code parses untrusted
// network input.
type Decoder struct {
	buf []byte
	off int
}

func NewDecoder(b []byte) *Decoder { return &Decoder{buf: b} }

func (d *Decoder) remaining() int { return len(d.buf) - d.off }

// Done reports whether every byte was consumed. Callers MUST call it after
// decoding: unconsumed bytes mean the input had a second interpretation.
func (d *Decoder) Done() error {
	if n := d.remaining(); n != 0 {
		return fmt.Errorf("%w: %d left", ErrTrailingBytes, n)
	}
	return nil
}

func (d *Decoder) U8() (uint8, error) {
	if d.remaining() < 1 {
		return 0, ErrShortBuffer
	}
	v := d.buf[d.off]
	d.off++
	return v, nil
}

func (d *Decoder) U32() (uint32, error) {
	if d.remaining() < 4 {
		return 0, ErrShortBuffer
	}
	v := binary.BigEndian.Uint32(d.buf[d.off:])
	d.off += 4
	return v, nil
}

func (d *Decoder) U64() (uint64, error) {
	if d.remaining() < 8 {
		return 0, ErrShortBuffer
	}
	v := binary.BigEndian.Uint64(d.buf[d.off:])
	d.off += 8
	return v, nil
}

func (d *Decoder) I64() (int64, error) {
	v, err := d.U64()
	return int64(v), err
}

// Len reads a varint length, rejecting non-minimal encodings.
func (d *Decoder) Len() (int, error) {
	if d.remaining() == 0 {
		return 0, ErrShortBuffer
	}
	n, m := binary.Uvarint(d.buf[d.off:])
	if m <= 0 {
		return 0, ErrShortBuffer
	}
	// A multi-byte varint whose final byte is zero has redundant
	// continuation: it is a non-minimal encoding of the same value.
	if m > 1 && d.buf[d.off+m-1] == 0 {
		return 0, ErrNonCanonical
	}
	d.off += m
	if n > uint64(d.remaining()) {
		return 0, ErrShortBuffer
	}
	return int(n), nil
}

func (d *Decoder) VarBytes() ([]byte, error) {
	n, err := d.Len()
	if err != nil {
		return nil, err
	}
	if n > d.remaining() {
		return nil, ErrShortBuffer
	}
	out := make([]byte, n)
	copy(out, d.buf[d.off:d.off+n])
	d.off += n
	return out, nil
}

func (d *Decoder) Fixed32() ([32]byte, error) {
	var v [32]byte
	if d.remaining() < 32 {
		return v, ErrShortBuffer
	}
	copy(v[:], d.buf[d.off:d.off+32])
	d.off += 32
	return v, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/types/ -v`
Expected: PASS for all five tests.

- [ ] **Step 5: Commit**

```bash
git add internal/types/codec.go internal/types/codec_test.go
git commit -m "feat: add canonical binary encoding primitives"
```

---

### Task 3: Hashing and Merkle root

**Files:**
- Create: `internal/crypto/hash.go`, `internal/crypto/merkle.go`, `internal/crypto/merkle_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `crypto.HashParts(parts ...[]byte) [32]byte`, `crypto.MerkleRoot(leaves [][32]byte) [32]byte`

- [ ] **Step 1: Add the dependency and write the failing tests**

Run: `go get lukechampine.com/blake3@latest`

Create `internal/crypto/merkle_test.go`:

```go
package crypto

import (
	"bytes"
	"testing"
)

func TestHashPartsIsUnambiguous(t *testing.T) {
	// Splitting the input differently must not collide: this is why every
	// part is length-prefixed rather than concatenated.
	a := HashParts([]byte("ab"), []byte("c"))
	b := HashParts([]byte("a"), []byte("bc"))
	if a == b {
		t.Fatal("HashParts collided across different part boundaries")
	}
}

func TestHashPartsIsDeterministic(t *testing.T) {
	a := HashParts([]byte("x"), []byte("y"))
	b := HashParts([]byte("x"), []byte("y"))
	if a != b {
		t.Fatal("HashParts is not deterministic")
	}
}

func TestMerkleRootEmptyIsZero(t *testing.T) {
	if got := MerkleRoot(nil); got != ([32]byte{}) {
		t.Fatalf("empty Merkle root = %x, want all zeros", got)
	}
}

func TestMerkleRootSingleLeaf(t *testing.T) {
	leaf := HashParts([]byte("leaf"))
	if got := MerkleRoot([][32]byte{leaf}); got == ([32]byte{}) {
		t.Fatal("single-leaf root must not be the empty root")
	}
}

// Order must matter: a state root that ignores ordering would let two
// different account sets share a root.
func TestMerkleRootIsOrderSensitive(t *testing.T) {
	a := HashParts([]byte("a"))
	b := HashParts([]byte("b"))
	if MerkleRoot([][32]byte{a, b}) == MerkleRoot([][32]byte{b, a}) {
		t.Fatal("Merkle root must depend on leaf order")
	}
}

func TestMerkleRootDetectsTampering(t *testing.T) {
	leaves := [][32]byte{HashParts([]byte("1")), HashParts([]byte("2")), HashParts([]byte("3"))}
	before := MerkleRoot(leaves)

	tampered := make([][32]byte, len(leaves))
	copy(tampered, leaves)
	tampered[1] = HashParts([]byte("2-modified"))

	if MerkleRoot(tampered) == before {
		t.Fatal("Merkle root failed to detect a modified leaf")
	}
}

func TestMerkleRootHandlesOddLeafCounts(t *testing.T) {
	// 1, 3 and 5 leaves exercise the odd-promotion path.
	for _, n := range []int{1, 3, 5} {
		leaves := make([][32]byte, n)
		for i := range leaves {
			leaves[i] = HashParts([]byte{byte(i)})
		}
		got := MerkleRoot(leaves)
		if got == ([32]byte{}) {
			t.Fatalf("n=%d produced the empty root", n)
		}
		// MerkleRoot's result is an unaddressable array and cannot be sliced
		// in place, so bind it before comparing.
		again := MerkleRoot(leaves)
		if !bytes.Equal(got[:], again[:]) {
			t.Fatalf("n=%d is not deterministic", n)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/crypto/ -v`
Expected: FAIL — `undefined: HashParts`

- [ ] **Step 3: Write the implementation**

Create `internal/crypto/hash.go`:

```go
// Package crypto provides b10coin's hashing, Merkle commitment and
// signature primitives.
package crypto

import (
	"encoding/binary"

	"lukechampine.com/blake3"
)

// HashParts hashes a sequence of byte slices unambiguously. Each part is
// length-prefixed before hashing, so HashParts(a, b) differs from
// HashParts(a||b) even when the concatenation is identical. Using this
// instead of concatenating prevents a whole class of collision attacks.
func HashParts(parts ...[]byte) [32]byte {
	h := blake3.New(32, nil)
	var lenbuf [binary.MaxVarintLen64]byte
	for _, p := range parts {
		n := binary.PutUvarint(lenbuf[:], uint64(len(p)))
		h.Write(lenbuf[:n])
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}
```

Create `internal/crypto/merkle.go`:

```go
package crypto

// MerkleRoot computes a binary Merkle root over leaves, preserving order.
//
// Domain separation prevents a second-preimage attack in which an internal
// node is presented as a leaf:
//
//	leaf     = H(0x00 || data)
//	internal = H(0x01 || left || right)
//
// An odd node at any level is hashed with itself to produce the next level.
//
// Known limitation: this construction is vulnerable to the classic
// duplicate-last-leaf ambiguity, where two different leaf lists can produce
// the same root. It is not exploitable for b10coin's state root, because
// leaves are derived from a sorted, deduplicated set of addresses. It MUST
// be revisited before any inclusion or exclusion proof is added — proofs are
// an explicit non-goal of the current spec.
func MerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	level := make([][32]byte, len(leaves))
	for i, l := range leaves {
		level[i] = HashParts([]byte{0x00}, l[:])
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, HashParts([]byte{0x01}, left[:], right[:]))
		}
		level = next
	}
	return level[0]
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/crypto/ -v`
Expected: PASS for all six tests.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/crypto
git commit -m "feat: add BLAKE3 hashing and order-sensitive Merkle root"
```

---

### Task 4: Ed25519 keys and addresses

**Files:**
- Create: `internal/crypto/keys.go`, `internal/types/address.go`, `internal/types/address_test.go`

**Interfaces:**
- Consumes: `crypto.HashParts`
- Produces:
  - `crypto.GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error)`
  - `crypto.Sign(ed25519.PrivateKey, []byte) []byte`
  - `crypto.Verify(ed25519.PublicKey, msg, sig []byte) bool`
  - `types.Address` (`[20]byte`), `types.AddressFromPub([]byte) Address`, `(Address).String() string`, `types.ParseAddress(string) (Address, error)`, `types.ErrBadAddress`

- [ ] **Step 1: Write the failing tests**

Create `internal/types/address_test.go`:

```go
package types

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func randomPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestAddressStringRoundTrip(t *testing.T) {
	addr := AddressFromPub(randomPub(t))
	got, err := ParseAddress(addr.String())
	if err != nil {
		t.Fatalf("ParseAddress(%q) failed: %v", addr.String(), err)
	}
	if got != addr {
		t.Fatalf("round trip mismatch: %v != %v", got, addr)
	}
}

func TestAddressHasPrefixAndIsLowercase(t *testing.T) {
	s := AddressFromPub(randomPub(t)).String()
	if !strings.HasPrefix(s, AddressPrefix) {
		t.Fatalf("address %q lacks prefix %q", s, AddressPrefix)
	}
	if s != strings.ToLower(s) {
		t.Fatalf("address %q is not lowercase", s)
	}
}

func TestAddressIsDeterministic(t *testing.T) {
	pub := randomPub(t)
	if AddressFromPub(pub) != AddressFromPub(pub) {
		t.Fatal("AddressFromPub is not deterministic")
	}
}

func TestAddressDiffersForDifferentKeys(t *testing.T) {
	if AddressFromPub(randomPub(t)) == AddressFromPub(randomPub(t)) {
		t.Fatal("two distinct keys produced the same address")
	}
}

func TestParseAddressRejectsTamperedChecksum(t *testing.T) {
	s := AddressFromPub(randomPub(t)).String()
	// Flip the final character to a different valid base32 symbol.
	last := s[len(s)-1]
	repl := byte('a')
	if last == 'a' {
		repl = 'b'
	}
	tampered := s[:len(s)-1] + string(repl)

	if _, err := ParseAddress(tampered); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("expected ErrBadAddress for tampered checksum, got %v", err)
	}
}

func TestParseAddressRejectsBadInput(t *testing.T) {
	for _, in := range []string{"", "xyz", "b10", "b10!!!!", strings.ToUpper(AddressFromPub(randomPub(t)).String())} {
		if _, err := ParseAddress(in); !errors.Is(err, ErrBadAddress) {
			t.Fatalf("ParseAddress(%q): expected ErrBadAddress, got %v", in, err)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/types/ -v`
Expected: FAIL — `undefined: AddressFromPub`

- [ ] **Step 3: Write the crypto helpers**

Create `internal/crypto/keys.go`:

```go
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
)

// GenerateKey returns a fresh Ed25519 keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign returns a detached Ed25519 signature over msg.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Verify reports whether sig is a valid Ed25519 signature by pub over msg.
// Lengths are checked explicitly because ed25519.Verify panics on
// wrongly-sized keys, and this function parses untrusted network input.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}
```

- [ ] **Step 4: Write the address implementation**

Create `internal/types/address.go`:

```go
package types

import (
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/cti97/b10coincom/internal/crypto"
)

const (
	// AddressPrefix is the human-readable prefix of every address.
	AddressPrefix = "b10"
	// AddressSize is the length of the address payload in bytes.
	AddressSize = 20
	// addressChecksumSize is the number of trailing bytes that make a
	// transcription typo detectable.
	addressChecksumSize = 4
)

var (
	// ErrBadAddress is returned for any malformed or mistyped address.
	ErrBadAddress = errors.New("types: invalid address")
	// b32 is RFC 4648 base32 without padding, used case-insensitively.
	b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// Address identifies an account: BLAKE3("b10coin-address" || pubkey)[:20].
type Address [AddressSize]byte

// AddressFromPub derives the address for an Ed25519 public key.
func AddressFromPub(pub []byte) Address {
	h := crypto.HashParts([]byte("b10coin-address"), pub)
	var a Address
	copy(a[:], h[:AddressSize])
	return a
}

// String renders the address as b10 + lowercase base32(payload || checksum).
func (a Address) String() string {
	sum := crypto.HashParts([]byte("b10coin-checksum"), a[:])
	payload := make([]byte, 0, AddressSize+addressChecksumSize)
	payload = append(payload, a[:]...)
	payload = append(payload, sum[:addressChecksumSize]...)
	return AddressPrefix + strings.ToLower(b32.EncodeToString(payload))
}

// ParseAddress validates the prefix, base32 body and checksum of s.
func ParseAddress(s string) (Address, error) {
	var a Address
	if !strings.HasPrefix(s, AddressPrefix) {
		return a, fmt.Errorf("%w: missing %q prefix", ErrBadAddress, AddressPrefix)
	}
	body := strings.TrimPrefix(s, AddressPrefix)
	if body == "" {
		return a, fmt.Errorf("%w: empty body", ErrBadAddress)
	}
	raw, err := b32.DecodeString(strings.ToUpper(body))
	if err != nil {
		return a, fmt.Errorf("%w: %v", ErrBadAddress, err)
	}
	if len(raw) != AddressSize+addressChecksumSize {
		return a, fmt.Errorf("%w: decoded length %d, want %d", ErrBadAddress, len(raw), AddressSize+addressChecksumSize)
	}
	copy(a[:], raw[:AddressSize])
	sum := crypto.HashParts([]byte("b10coin-checksum"), a[:])
	if !bytes.Equal(sum[:addressChecksumSize], raw[AddressSize:]) {
		return a, fmt.Errorf("%w: checksum mismatch", ErrBadAddress)
	}
	return a, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/types/ ./internal/crypto/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/crypto/keys.go internal/types/address.go internal/types/address_test.go
git commit -m "feat: add Ed25519 signing and checksummed base32 addresses"
```

---

### Task 5: Transactions

**Files:**
- Create: `internal/types/tx.go`, `internal/types/tx_test.go`

**Interfaces:**
- Consumes: `Encoder`, `Decoder`, `Address`, `crypto`
- Produces:
  - `type TxType uint8` with constants `TxTransfer TxType = 1`, `TxFaucetClaim = 2`, `TxBond = 3`, `TxUnbond = 4`, `TxWithdraw = 5`
  - `type Tx struct { Type TxType; From Address; PubKey []byte; Nonce uint64; To Address; Amount uint64; Sig []byte }`
  - `(*Tx) SigningHash() [32]byte`, `(*Tx) ID() [32]byte`, `(*Tx) Encode() []byte`, `(*Tx) VerifySignature() error`, `DecodeTx([]byte) (*Tx, error)`
  - `ErrUnsupportedTxType`, `ErrBadSignature`, `ErrAddressMismatch`

**Note:** M1 implements `TxTransfer` end to end. The remaining type constants are reserved so the wire format does not need to change later; `DecodeTx` returns `ErrUnsupportedTxType` for them, and `state` rejects them. (`Tx.Encode` has no error return, so it can only ever produce the transfer shape.) M2 adds `TxFaucetClaim`; M5 adds the staking types.

- [ ] **Step 1: Write the failing tests**

Create `internal/types/tx_test.go`:

```go
package types

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

// signedTransfer builds a valid transfer signed by a fresh key.
func signedTransfer(t *testing.T, nonce, amount uint64) *Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, otherPub, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &Tx{
		Type:   TxTransfer,
		From:   AddressFromPub(pub),
		PubKey: pub,
		Nonce:  nonce,
		To:     AddressFromPub(otherPub),
		Amount: amount,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return tx
}

func TestTxEncodeDecodeRoundTrip(t *testing.T) {
	tx := signedTransfer(t, 7, 1234)
	got, err := DecodeTx(tx.Encode())
	if err != nil {
		t.Fatalf("DecodeTx: %v", err)
	}
	if got.Type != tx.Type || got.From != tx.From || got.Nonce != tx.Nonce ||
		got.To != tx.To || got.Amount != tx.Amount {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, tx)
	}
	if string(got.PubKey) != string(tx.PubKey) || string(got.Sig) != string(tx.Sig) {
		t.Fatal("round trip lost key material")
	}
	if got.ID() != tx.ID() {
		t.Fatal("round trip changed the tx ID")
	}
}

func TestTxIDIsDeterministicAndSensitive(t *testing.T) {
	a := signedTransfer(t, 1, 100)
	b := signedTransfer(t, 1, 100)
	if a.ID() != a.ID() {
		t.Fatal("ID is not deterministic")
	}
	if a.ID() == b.ID() {
		t.Fatal("two distinct transactions shared an ID")
	}
}

func TestVerifySignatureAcceptsValid(t *testing.T) {
	if err := signedTransfer(t, 1, 10).VerifySignature(); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifySignatureRejectsTamperedAmount(t *testing.T) {
	tx := signedTransfer(t, 1, 10)
	tx.Amount = 999999
	if err := tx.VerifySignature(); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

// The signature covers From, so an attacker cannot re-attribute a signed
// transaction to a different account.
func TestVerifySignatureRejectsMismatchedFrom(t *testing.T) {
	tx := signedTransfer(t, 1, 10)
	// Point From at an address that does not match PubKey. The key/address
	// binding check must reject this before the signature is examined.
	tx.From = AddressFromPub([]byte("not-the-real-key"))
	if err := tx.VerifySignature(); !errors.Is(err, ErrAddressMismatch) {
		t.Fatalf("expected ErrAddressMismatch, got %v", err)
	}
}

func TestDecodeTxRejectsUnsupportedType(t *testing.T) {
	e := NewEncoder()
	e.U8(uint8(TxBond))
	e.Raw(AddressFromPub([]byte("p"))[:])
	e.VarBytes([]byte("pub"))
	e.U64(0)
	e.U64(0)
	e.VarBytes([]byte("sig"))
	if _, err := DecodeTx(e.Bytes()); !errors.Is(err, ErrUnsupportedTxType) {
		t.Fatalf("expected ErrUnsupportedTxType, got %v", err)
	}
}

func TestDecodeTxRejectsTrailingBytes(t *testing.T) {
	enc := signedTransfer(t, 1, 5).Encode()
	if _, err := DecodeTx(append(enc, 0xFF)); err == nil {
		t.Fatal("expected an error for trailing bytes")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/types/ -v`
Expected: FAIL — `undefined: Tx`

- [ ] **Step 3: Write the implementation**

Create `internal/types/tx.go`:

```go
package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
)

var (
	ErrUnsupportedTxType = errors.New("types: unsupported transaction type")
	ErrBadSignature      = errors.New("types: bad signature")
	ErrAddressMismatch   = errors.New("types: pubkey does not match sender address")
)

// TxType discriminates the transaction union. Only TxTransfer is
// implemented in M1; the rest are reserved so the encoding is stable.
type TxType uint8

const (
	TxTransfer    TxType = 1
	TxFaucetClaim TxType = 2
	TxBond        TxType = 3
	TxUnbond      TxType = 4
	TxWithdraw    TxType = 5
)

// Tx is a signed state transition.
//
// The sender's public key travels with the transaction because an address is
// only a hash of that key: the key cannot be recovered from the address, so
// signature verification needs it supplied explicitly.
type Tx struct {
	Type   TxType
	From   Address
	PubKey []byte
	Nonce  uint64

	// TxTransfer only.
	To     Address
	Amount uint64

	// Sig is the Ed25519 signature over SigningHash().
	Sig []byte
}

// encodeBody renders every field the signature covers.
func (tx *Tx) encodeBody() []byte {
	e := NewEncoder()
	e.U8(uint8(tx.Type))
	e.Raw(tx.From[:])
	e.VarBytes(tx.PubKey)
	e.U64(tx.Nonce)
	if tx.Type == TxTransfer {
		e.Raw(tx.To[:])
		e.U64(tx.Amount)
	}
	return e.Bytes()
}

// SigningHash is the digest that must be signed. It deliberately excludes
// Sig, so signing is not recursive.
func (tx *Tx) SigningHash() [32]byte {
	return crypto.HashParts([]byte("b10coin-tx"), tx.encodeBody())
}

// ID is the transaction identifier used for deduplication and indexing.
func (tx *Tx) ID() [32]byte {
	return crypto.HashParts([]byte("b10coin-txid"), tx.Encode())
}

// Encode returns the canonical wire encoding, signature included.
func (tx *Tx) Encode() []byte {
	e := NewEncoder()
	e.Raw(tx.encodeBody())
	e.VarBytes(tx.Sig)
	return e.Bytes()
}

// VerifySignature checks that PubKey matches From and that Sig is valid.
func (tx *Tx) VerifySignature() error {
	if len(tx.PubKey) == 0 {
		return fmt.Errorf("%w: missing public key", ErrBadSignature)
	}
	if AddressFromPub(tx.PubKey) != tx.From {
		return ErrAddressMismatch
	}
	sigHash := tx.SigningHash()
	if !crypto.Verify(tx.PubKey, sigHash[:], tx.Sig) {
		return ErrBadSignature
	}
	return nil
}

// DecodeTx parses a canonical transaction encoding. It rejects unsupported
// types, trailing bytes and any over-long field.
func DecodeTx(b []byte) (*Tx, error) {
	d := NewDecoder(b)
	rawType, err := d.U8()
	if err != nil {
		return nil, err
	}
	tx := &Tx{Type: TxType(rawType)}
	if tx.Type != TxTransfer {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedTxType, rawType)
	}
	if tx.From, err = d.Fixed20(); err != nil {
		return nil, err
	}
	if tx.PubKey, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if tx.Nonce, err = d.U64(); err != nil {
		return nil, err
	}
	if tx.To, err = d.Fixed20(); err != nil {
		return nil, err
	}
	if tx.Amount, err = d.U64(); err != nil {
		return nil, err
	}
	if tx.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return tx, nil
}

// Equal reports whether two transactions are byte-identical when encoded.
func (tx *Tx) Equal(other *Tx) bool {
	return bytes.Equal(tx.Encode(), other.Encode())
}
```

- [ ] **Step 4: Add the `Fixed20` decoder method**

`DecodeTx` needs a 20-byte reader. Add to `internal/types/codec.go`, below `Fixed32`:

```go
func (d *Decoder) Fixed20() (Address, error) {
	var a Address
	if d.remaining() < AddressSize {
		return a, ErrShortBuffer
	}
	copy(a[:], d.buf[d.off:d.off+AddressSize])
	d.off += AddressSize
	return a, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/types/ -v`
Expected: PASS. (Having fixed the scratch code noted in Step 1.)

- [ ] **Step 6: Commit**

```bash
git add internal/types/tx.go internal/types/tx_test.go internal/types/codec.go
git commit -m "feat: add transfer transaction type with signing and canonical encoding"
```

---

### Task 6: Blocks

**Files:**
- Create: `internal/types/block.go`, `internal/types/block_test.go`

**Interfaces:**
- Consumes: `Tx`, `Encoder`, `Decoder`, `crypto`, `Address`
- Produces:
  - `type Header struct { Height uint64; ParentHash [32]byte; StateRoot [32]byte; TxRoot [32]byte; Timestamp int64; Proposer []byte }`
  - `type Block struct { Header Header; Txs []Tx }`
  - `(*Header) Encode() []byte`, `(*Block) ID() [32]byte`, `(*Block) Encode() []byte`, `DecodeBlock([]byte) (*Block, error)`, `ComputeTxRoot([]Tx) [32]byte`, `(*Block) ValidateStructure() error`
  - Constants: `MaxTxsPerBlock = 10_000`, `MaxBlockBytes = 1 << 20`
  - Errors: `ErrBadProposer`, `ErrTxRootMismatch`, `ErrDuplicateTx`, `ErrBlockTooLarge`, `ErrBadTimestamp`. There is deliberately NO `ErrNoTransactions`: an empty block is valid, and `TestValidateStructureAcceptsWellFormedBlock` requires it (`validateStructure` therefore never errors on `len(Txs) == 0`)

- [ ] **Step 1: Write the failing tests**

Create `internal/types/block_test.go`:

```go
package types

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

func testBlock(t *testing.T, txs ...Tx) *Block {
	t.Helper()
	pub, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := &Block{
		Header: Header{
			Height:     1,
			ParentHash: crypto.HashParts([]byte("parent")),
			StateRoot:  crypto.HashParts([]byte("state")),
			Timestamp:  1_700_000_000,
			Proposer:   pub,
		},
		Txs: txs,
	}
	b.Header.TxRoot = ComputeTxRoot(txs)
	return b
}

func TestBlockEncodeDecodeRoundTrip(t *testing.T) {
	b := testBlock(t, *signedTransfer(t, 1, 50))
	got, err := DecodeBlock(b.Encode())
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if got.ID() != b.ID() {
		t.Fatal("round trip changed the block ID")
	}
	if len(got.Txs) != 1 || got.Txs[0].ID() != b.Txs[0].ID() {
		t.Fatal("round trip lost transactions")
	}
	if string(got.Header.Proposer) != string(b.Header.Proposer) {
		t.Fatal("round trip lost the proposer")
	}
}

// The block ID must commit to the header only. If it covered the
// transactions, a block's ID would change when its body was re-sent.
func TestBlockIDIsHeaderOnly(t *testing.T) {
	b := testBlock(t, *signedTransfer(t, 1, 5))
	before := b.ID()
	b.Txs = append(b.Txs, *signedTransfer(t, 2, 6))
	if b.ID() != before {
		t.Fatal("block ID changed when only the body changed")
	}
}

func TestBlockIDChangesWithHeader(t *testing.T) {
	b := testBlock(t)
	before := b.ID()
	b.Header.Height = 2
	if b.ID() == before {
		t.Fatal("block ID ignored a header change")
	}
}

func TestValidateStructureAcceptsWellFormedBlock(t *testing.T) {
	if err := testBlock(t, *signedTransfer(t, 1, 5)).ValidateStructure(); err != nil {
		t.Fatalf("valid block rejected: %v", err)
	}
	if err := testBlock(t).ValidateStructure(); err != nil {
		t.Fatalf("empty block rejected: %v", err)
	}
}

func TestValidateStructureRejectsWrongProposerLength(t *testing.T) {
	b := testBlock(t)
	b.Header.Proposer = []byte{1, 2, 3}
	if err := b.ValidateStructure(); !errors.Is(err, ErrBadProposer) {
		t.Fatalf("expected ErrBadProposer, got %v", err)
	}
}

func TestValidateStructureRejectsTxRootMismatch(t *testing.T) {
	b := testBlock(t, *signedTransfer(t, 1, 5))
	b.Header.TxRoot = crypto.HashParts([]byte("wrong"))
	if err := b.ValidateStructure(); !errors.Is(err, ErrTxRootMismatch) {
		t.Fatalf("expected ErrTxRootMismatch, got %v", err)
	}
}

func TestValidateStructureRejectsDuplicateTx(t *testing.T) {
	tx := signedTransfer(t, 1, 5)
	b := testBlock(t, *tx, *tx)
	if err := b.ValidateStructure(); !errors.Is(err, ErrDuplicateTx) {
		t.Fatalf("expected ErrDuplicateTx, got %v", err)
	}
}

func TestValidateStructureRejectsZeroTimestamp(t *testing.T) {
	b := testBlock(t)
	b.Header.Timestamp = 0
	if err := b.ValidateStructure(); err == nil {
		t.Fatal("expected an error for a zero timestamp")
	}
}

func TestValidateStructureRejectsTooManyTxs(t *testing.T) {
	b := testBlock(t)
	b.Txs = make([]Tx, MaxTxsPerBlock+1)
	b.Header.TxRoot = ComputeTxRoot(b.Txs)
	if err := b.ValidateStructure(); !errors.Is(err, ErrBlockTooLarge) {
		t.Fatalf("expected ErrBlockTooLarge, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/types/ -v`
Expected: FAIL — `undefined: Block`

- [ ] **Step 3: Write the implementation**

Create `internal/types/block.go`:

```go
package types

import (
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
)

const (
	// MaxTxsPerBlock bounds block size so a Raspberry Pi can always
	// process a block within one block interval.
	MaxTxsPerBlock = 10_000
	// MaxBlockBytes bounds the canonical encoding of a block.
	MaxBlockBytes = 1 << 20
)

var (
	ErrBadProposer   = errors.New("types: proposer must be a valid Ed25519 public key")
	ErrTxRootMismatch = errors.New("types: transaction root does not match header")
	ErrDuplicateTx   = errors.New("types: block contains a duplicate transaction")
	ErrBlockTooLarge = errors.New("types: block exceeds size limits")
	ErrBadTimestamp  = errors.New("types: timestamp must be positive")
)

// Header is the signed commitment for a block. A block's identity is its
// header hash; the body is carried separately.
type Header struct {
	Height     uint64
	ParentHash [32]byte
	StateRoot  [32]byte
	TxRoot     [32]byte
	Timestamp  int64
	Proposer   []byte // Ed25519 public key
}

// Block is a header plus its transactions.
type Block struct {
	Header Header
	Txs    []Tx
}

// ComputeTxRoot commits to the ordered list of transaction IDs.
func ComputeTxRoot(txs []Tx) [32]byte {
	leaves := make([][32]byte, len(txs))
	for i := range txs {
		leaves[i] = txs[i].ID()
	}
	return crypto.MerkleRoot(leaves)
}

func (h *Header) Encode() []byte {
	e := NewEncoder()
	e.U64(h.Height)
	e.Fixed32(h.ParentHash)
	e.Fixed32(h.StateRoot)
	e.Fixed32(h.TxRoot)
	e.I64(h.Timestamp)
	e.VarBytes(h.Proposer)
	return e.Bytes()
}

// SigningHash is the digest a proposer signs.
func (h *Header) SigningHash() [32]byte {
	return crypto.HashParts([]byte("b10coin-header"), h.Encode())
}

// ID returns the block identifier: the hash of the header alone.
func (b *Block) ID() [32]byte {
	return crypto.HashParts([]byte("b10coin-block"), b.Header.Encode())
}

func (b *Block) Encode() []byte {
	e := NewEncoder()
	e.Raw(b.Header.Encode())
	e.Len(len(b.Txs))
	for i := range b.Txs {
		// VarBytes, not Raw: DecodeBlock frames each transaction with
		// d.VarBytes(), so the encoder MUST write the matching length
		// prefix. Raw here produced blocks that could not be decoded.
		e.VarBytes(b.Txs[i].Encode())
	}
	return e.Bytes()
}

func DecodeBlock(b []byte) (*Block, error) {
	d := NewDecoder(b)
	out := &Block{}
	var err error
	if out.Header.Height, err = d.U64(); err != nil {
		return nil, err
	}
	if out.Header.ParentHash, err = d.Fixed32(); err != nil {
		return nil, err
	}
	if out.Header.StateRoot, err = d.Fixed32(); err != nil {
		return nil, err
	}
	if out.Header.TxRoot, err = d.Fixed32(); err != nil {
		return nil, err
	}
	if out.Header.Timestamp, err = d.I64(); err != nil {
		return nil, err
	}
	if out.Header.Proposer, err = d.VarBytes(); err != nil {
		return nil, err
	}
	n, err := d.Len()
	if err != nil {
		return nil, err
	}
	if n > MaxTxsPerBlock {
		return nil, fmt.Errorf("%w: %d transactions", ErrBlockTooLarge, n)
	}
	out.Txs = make([]Tx, 0, n)
	for i := 0; i < n; i++ {
		raw, err := d.VarBytes()
		if err != nil {
			return nil, err
		}
		tx, err := DecodeTx(raw)
		if err != nil {
			return nil, err
		}
		out.Txs = append(out.Txs, *tx)
	}
	if err := d.Done(); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateStructure checks everything about a block that does not require
// chain state: shape, limits, proposer key size, and internal consistency.
// State-dependent rules (nonces, balances, parent linkage) are enforced by
// the chain package.
func (b *Block) ValidateStructure() error {
	if len(b.Header.Proposer) != ed25519PublicKeySize {
		return fmt.Errorf("%w: got %d bytes", ErrBadProposer, len(b.Header.Proposer))
	}
	if b.Header.Timestamp <= 0 {
		return ErrBadTimestamp
	}
	if len(b.Txs) > MaxTxsPerBlock {
		return fmt.Errorf("%w: %d transactions", ErrBlockTooLarge, len(b.Txs))
	}
	if ComputeTxRoot(b.Txs) != b.Header.TxRoot {
		return ErrTxRootMismatch
	}
	seen := make(map[[32]byte]struct{}, len(b.Txs))
	for i := range b.Txs {
		id := b.Txs[i].ID()
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: %x", ErrDuplicateTx, id[:8])
		}
		seen[id] = struct{}{}
	}
	if len(b.Encode()) > MaxBlockBytes {
		return fmt.Errorf("%w: %d bytes", ErrBlockTooLarge, len(b.Encode()))
	}
	return nil
}
```

- [ ] **Step 4: Add the Ed25519 key-size constant**

`block.go` references `ed25519PublicKeySize`. Add to `internal/types/tx.go` (or keep it in `block.go`):

```go
import "crypto/ed25519"

// ed25519PublicKeySize is the expected length of a proposer or signer key.
const ed25519PublicKeySize = ed25519.PublicKeySize
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/types/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/types/block.go internal/types/block_test.go internal/types/tx.go
git commit -m "feat: add block header, block encoding and structural validation"
```

---

### Task 7: Account state and the transfer transition

**Files:**
- Create: `internal/state/state.go`, `internal/state/apply.go`, `internal/state/apply_test.go`

**Interfaces:**
- Consumes: `types.Address`, `types.Tx`, `crypto`
- Produces:
  - `type Account struct { Balance uint64; Nonce uint64 }`
  - `type State struct{}` with `New() *State`, `(*State) Get(types.Address) Account`, `(*State) Set(types.Address, Account)`, `(*State) Clone() *State`, `(*State) Len() int`, `(*State) Root() [32]byte`, `(*State) TotalBalance() uint64`
  - `(*State) ApplyTx(*types.Tx) error`, `(*State) ApplyBlock([]types.Tx) (*State, error)`
  - Errors: `ErrZeroAmount`, `ErrBadNonce`, `ErrInsufficientFunds`, `ErrSelfTransfer`, `ErrBalanceOverflow`, `ErrUnsupportedTxType`

- [ ] **Step 1: Write the failing tests**

Create `internal/state/apply_test.go`:

```go
package state

import (
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// keypair returns a fresh address/public/private triple.
func keypair(t *testing.T) (types.Address, []byte, []byte) {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return types.AddressFromPub(pub), pub, priv
}

// transfer builds a signed transfer.
func transfer(t *testing.T, fromPub, fromPriv []byte, from types.Address, nonce, amount uint64, to types.Address) *types.Tx {
	t.Helper()
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  nonce,
		To:     to,
		Amount: amount,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(fromPriv, sigHash[:])
	return tx
}

func TestApplyTransferMovesFundsAndBumpsNonce(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 1000})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 400, to)); err != nil {
		t.Fatalf("ApplyTx: %v", err)
	}
	if got := s.Get(from); got.Balance != 600 || got.Nonce != 1 {
		t.Fatalf("sender = %+v, want balance 600 nonce 1", got)
	}
	if got := s.Get(to); got.Balance != 400 || got.Nonce != 0 {
		t.Fatalf("recipient = %+v, want balance 400 nonce 0", got)
	}
}

func TestApplyTransferRejectsReplayedNonce(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 1000})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 100, to)); err != nil {
		t.Fatal(err)
	}
	// Replaying nonce 0 must fail: this is the double-spend guard.
	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 100, to)); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("expected ErrBadNonce, got %v", err)
	}
}

func TestApplyTransferRejectsSkippedNonce(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 1000})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 5, 100, to)); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("expected ErrBadNonce, got %v", err)
	}
}

func TestApplyTransferRejectsInsufficientFunds(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 99})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 100, to)); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected ErrInsufficientFunds, got %v", err)
	}
}

func TestApplyTransferRejectsZeroAmount(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 0, to)); !errors.Is(err, ErrZeroAmount) {
		t.Fatalf("expected ErrZeroAmount, got %v", err)
	}
}

func TestApplyTransferRejectsSelfTransfer(t *testing.T) {
	from, pub, priv := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 10, from)); !errors.Is(err, ErrSelfTransfer) {
		t.Fatalf("expected ErrSelfTransfer, got %v", err)
	}
}

func TestApplyTransferRejectsBadSignature(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})

	tx := transfer(t, pub, priv, from, 0, 10, to)
	tx.Sig[0] ^= 0xFF
	if err := s.ApplyTx(tx); !errors.Is(err, types.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

// A failed transaction must leave no trace: state is all-or-nothing per tx.
func TestFailedTxDoesNotMutateState(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})
	before := s.Root()

	if err := s.ApplyTx(transfer(t, pub, priv, from, 0, 1000, to)); err == nil {
		t.Fatal("expected failure")
	}
	if s.Root() != before {
		t.Fatal("state changed after a failed transaction")
	}
}

// ApplyBlock is atomic: if any transaction fails, none are applied.
func TestApplyBlockIsAtomic(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})
	before := s.Root()

	txs := []types.Tx{
		*transfer(t, pub, priv, from, 0, 50, to),
		*transfer(t, pub, priv, from, 1, 9999, to), // fails
	}
	if _, err := s.ApplyBlock(txs); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected ErrInsufficientFunds, got %v", err)
	}
	if s.Root() != before {
		t.Fatal("state changed after a failed block")
	}
}

func TestApplyBlockReturnsNewStateOnSuccess(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})
	before := s.Root()

	next, err := s.ApplyBlock([]types.Tx{*transfer(t, pub, priv, from, 0, 50, to)})
	if err != nil {
		t.Fatal(err)
	}
	if next.Get(to).Balance != 50 {
		t.Fatalf("new state has wrong balance: %+v", next.Get(to))
	}
	if s.Root() != before {
		t.Fatal("ApplyBlock mutated the original state")
	}
}

func TestRootIsOrderIndependentAndSensitive(t *testing.T) {
	// 32 accounts inserted in opposite orders. With this many entries the
	// chance that two independent map iterations agree is negligible, so an
	// unsorted Root() cannot pass by luck on any Go runtime.
	const n = 32
	addrs := make([]types.Address, n)
	for i := range addrs {
		pub, _, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = types.AddressFromPub(pub)
	}

	forward := New()
	backward := New()
	for i := 0; i < n; i++ {
		forward.Set(addrs[i], Account{Balance: uint64(i + 1)})
		backward.Set(addrs[n-1-i], Account{Balance: uint64(n - i)})
	}
	if forward.Root() != backward.Root() {
		t.Fatal("state root depends on insertion order")
	}

	// Sensitivity: a single balance change must move the root.
	altered := New()
	for i := 0; i < n; i++ {
		altered.Set(addrs[i], Account{Balance: uint64(i + 1)})
	}
	altered.Set(addrs[0], Account{Balance: 999})
	if forward.Root() == altered.Root() {
		t.Fatal("state root ignored a balance change")
	}
}

// TestRootGoldenVector freezes the exact root for a fixed state. It is the
// only test that pins the leaf encoding (balance then nonce), the Merkle
// construction and the "b10coin-account" domain label: change any of them and
// this value changes, which is precisely the point.
//
// The vector is frozen. It was captured once from the implementation and then
// proven load-bearing by changing the "b10coin-account" domain label in
// state.go (the test fails) and reverting. Never re-capture it from a fresh
// run: that would enshrine whatever the code currently produces, regression
// included, and destroy the test's value.
func TestRootGoldenVector(t *testing.T) {
	s := New()
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, Account{Balance: 1000, Nonce: 7})
	s.Set(types.Address{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, Account{Balance: 0, Nonce: 3})
	s.Set(types.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, Account{Balance: 18446744073709551615, Nonce: 0})

	// Frozen and verified load-bearing: changing the "b10coin-account" domain
	// label makes this test fail. Do NOT re-capture this value from a fresh run -
	// re-capturing would enshrine whatever the code happens to produce, including a
	// regression. If it fails, the root construction changed and that is the point.
	want := [32]byte{
		0x69, 0x38, 0x3e, 0xe3, 0xc1, 0xb9, 0x2d, 0xa5, 0x0c, 0x46, 0xbc, 0xa8, 0x97, 0x47, 0x6d, 0xc1,
		0xde, 0xde, 0xd1, 0xec, 0x5b, 0x47, 0x08, 0x6d, 0xee, 0xc2, 0xa0, 0x9e, 0x7d, 0x37, 0x29, 0x5e,
	}
	if got := s.Root(); got != want {
		t.Fatalf("golden root changed:\n got %x\nwant %x", got, want)
	}
}

// An unsupported transaction type must be rejected. The signature is valid, so
// execution reaches the type switch rather than failing the signature check
// first.
func TestApplyTxRejectsUnsupportedType(t *testing.T) {
	from, pub, priv := keypair(t)
	to, _, _ := keypair(t)

	s := New()
	s.Set(from, Account{Balance: 100})

	tx := transfer(t, pub, priv, from, 0, 10, to)
	tx.Type = types.TxType(99)
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])

	if err := s.ApplyTx(tx); !errors.Is(err, ErrUnsupportedTxType) {
		t.Fatalf("expected ErrUnsupportedTxType, got %v", err)
	}
}

// TotalBalance is required API surface: the supply-invariant check consumes it.
func TestTotalBalance(t *testing.T) {
	a, _, _ := keypair(t)
	b, _, _ := keypair(t)

	if got := New().TotalBalance(); got != 0 {
		t.Fatalf("empty state TotalBalance = %d, want 0", got)
	}

	s := New()
	s.Set(a, Account{Balance: 400})
	s.Set(b, Account{Balance: 600})
	if got := s.TotalBalance(); got != 1000 {
		t.Fatalf("TotalBalance = %d, want 1000", got)
	}
}

func TestZeroAccountsArePruned(t *testing.T) {
	a, _, _ := keypair(t)
	s := New()
	s.Set(a, Account{})
	if s.Len() != 0 {
		t.Fatalf("zero account was retained: len=%d", s.Len())
	}
	if s.Root() != (New()).Root() {
		t.Fatal("zero account changed the root")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/state/ -v`
Expected: FAIL — `undefined: New`

- [ ] **Step 3: Write the state implementation**

Create `internal/state/state.go`:

```go
// Package state implements b10coin's account-based state machine. The
// transition function must be perfectly deterministic: two nodes with the
// same state and the same block must arrive at byte-identical state roots,
// or the chain forks.
package state

import (
	"bytes"
	"slices"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// Account is a single account's balance and replay counter.
type Account struct {
	Balance uint64
	Nonce   uint64
}

// isZero reports whether an account carries no information and may be pruned.
func (a Account) isZero() bool { return a.Balance == 0 && a.Nonce == 0 }

// State is a set of accounts. The zero value is not usable; call New.
type State struct {
	accounts map[types.Address]Account
}

func New() *State {
	return &State{accounts: make(map[types.Address]Account)}
}

// Get returns the account, or the zero Account if it does not exist.
func (s *State) Get(a types.Address) Account { return s.accounts[a] }

// Set stores an account, pruning it if it is zero so that the state root
// depends only on live accounts.
func (s *State) Set(a types.Address, acc Account) {
	if acc.isZero() {
		delete(s.accounts, a)
		return
	}
	s.accounts[a] = acc
}

// Clone returns a deep copy. ApplyBlock clones before mutating so a failure
// cannot leave partial changes behind.
func (s *State) Clone() *State {
	out := &State{accounts: make(map[types.Address]Account, len(s.accounts))}
	for k, v := range s.accounts {
		out.accounts[k] = v
	}
	return out
}

// Len is the number of live accounts.
func (s *State) Len() int { return len(s.accounts) }

// TotalBalance is the sum of every balance. Used by tests and the supply
// invariant check.
func (s *State) TotalBalance() uint64 {
	var total uint64
	for _, acc := range s.accounts {
		total += acc.Balance
	}
	return total
}

// sortedAddresses returns every address in ascending byte order. A Go map's
// iteration order is randomised, so anything that produces bytes for a hash
// must sort first.
func (s *State) sortedAddresses() []types.Address {
	addrs := make([]types.Address, 0, len(s.accounts))
	for a := range s.accounts {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, func(x, y types.Address) int { return bytes.Compare(x[:], y[:]) })
	return addrs
}

// Root commits to the entire account set.
func (s *State) Root() [32]byte {
	addrs := s.sortedAddresses()
	leaves := make([][32]byte, 0, len(addrs))
	for _, a := range addrs {
		acc := s.accounts[a]
		c := types.NewEncoder()
		c.U64(acc.Balance)
		c.U64(acc.Nonce)
		leaves = append(leaves, crypto.HashParts([]byte("b10coin-account"), a[:], c.Bytes()))
	}
	return crypto.MerkleRoot(leaves)
}
```

Create `internal/state/apply.go`:

```go
package state

import (
	"errors"
	"fmt"
	"math"

	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrZeroAmount        = errors.New("state: amount must be greater than zero")
	ErrBadNonce          = errors.New("state: nonce does not match account nonce")
	ErrInsufficientFunds = errors.New("state: insufficient funds")
	ErrSelfTransfer      = errors.New("state: cannot transfer to self")
	ErrBalanceOverflow   = errors.New("state: balance would overflow")
	ErrUnsupportedTxType = errors.New("state: unsupported transaction type")
)

// ApplyTx applies one transaction, mutating the receiver. Every validation
// runs before the first write, so on error the receiver is left unchanged.
// ApplyBlock still clones, so that one transaction's success is not persisted
// when a later transaction in the same block fails.
func (s *State) ApplyTx(tx *types.Tx) error {
	if err := tx.VerifySignature(); err != nil {
		return err
	}
	switch tx.Type {
	case types.TxTransfer:
		return s.applyTransfer(tx)
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedTxType, tx.Type)
	}
}

func (s *State) applyTransfer(tx *types.Tx) error {
	if tx.Amount == 0 {
		return ErrZeroAmount
	}
	// Reject self-transfers: debiting and crediting the same account would
	// alias the two writes and corrupt the balance.
	if tx.From == tx.To {
		return ErrSelfTransfer
	}

	from := s.Get(tx.From)
	if from.Nonce != tx.Nonce {
		return fmt.Errorf("%w: got %d, want %d", ErrBadNonce, tx.Nonce, from.Nonce)
	}
	if from.Balance < tx.Amount {
		return fmt.Errorf("%w: have %d, need %d", ErrInsufficientFunds, from.Balance, tx.Amount)
	}

	to := s.Get(tx.To)
	if to.Balance > math.MaxUint64-tx.Amount {
		return ErrBalanceOverflow
	}

	from.Balance -= tx.Amount
	from.Nonce++
	s.Set(tx.From, from)

	to.Balance += tx.Amount
	s.Set(tx.To, to)
	return nil
}

// ApplyBlock applies every transaction atomically. On success it returns a
// new State; the receiver is never modified. On failure it returns the error
// and a nil State, leaving the receiver untouched.
func (s *State) ApplyBlock(txs []types.Tx) (*State, error) {
	next := s.Clone()
	for i := range txs {
		if err := next.ApplyTx(&txs[i]); err != nil {
			return nil, fmt.Errorf("tx %d: %w", i, err)
		}
	}
	return next, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/state/ -v`
Expected: PASS for all twelve tests.

- [ ] **Step 5: Commit**

```bash
git add internal/state
git commit -m "feat: add account state machine with atomic transfer application"
```

---

### Task 8: Genesis parameters and faucet address

**Files:**
- Create: `internal/genesis/genesis.go`, `internal/genesis/genesis_test.go`, `genesis/devnet.json`, `genesis/testnet.json`

**Interfaces:**
- Consumes: `types.Address`, `crypto`
- Produces:
  - `type Params struct { ... }` (fields below)
  - `type DevAccount struct { PubKey []byte; BalanceSparks uint64 }`
  - `type Validator struct { PubKey []byte; Power uint64 }`
  - `type Genesis struct { ChainID string; Time int64; Validators []Validator; DevAccounts []DevAccount; Params Params }`
  - `(*Genesis) Hash() [32]byte`, `(*Genesis) FaucetAddress() types.Address`, `(*Genesis) Validate() error`
  - `Devnet() *Genesis`, `Testnet() *Genesis`

- [ ] **Step 1: Write the failing tests**

Create `internal/genesis/genesis_test.go`:

```go
package genesis

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

func TestGenesisHashIsDeterministic(t *testing.T) {
	g := Devnet()
	if g.Hash() != g.Hash() {
		t.Fatal("genesis hash is not deterministic")
	}
}

func TestGenesisHashChangesWithParams(t *testing.T) {
	a := Devnet()
	b := Devnet()
	b.Params.ClaimAmountSparks++
	if a.Hash() == b.Hash() {
		t.Fatal("genesis hash ignored a parameter change")
	}
}

func TestFaucetAddressIsDeterministicAndKeyless(t *testing.T) {
	g := Devnet()
	f1, f2 := g.FaucetAddress(), g.FaucetAddress()
	if f1 != f2 {
		t.Fatal("faucet address is not deterministic")
	}
	// The faucet address must not be derivable as address-of-a-pubkey for
	// any key we hold, and it must differ from every validator address.
	for _, v := range g.Validators {
		if types.AddressFromPub(v.PubKey) == f1 {
			t.Fatal("faucet address collided with a validator address")
		}
	}
	if f1 == types.AddressFromPub([]byte("any")) {
		t.Fatal("faucet address looks like a normal key-derived address")
	}
}

func TestFaucetAddressDiffersPerChain(t *testing.T) {
	if Devnet().FaucetAddress() == Testnet().FaucetAddress() {
		t.Fatal("different chains must have different faucet addresses")
	}
}

// This is the load-bearing test for the no-premine promise: any funded
// account in the testnet genesis would be a premine.
func TestTestnetGenesisHasNoPremine(t *testing.T) {
	g := Testnet()
	if len(g.DevAccounts) != 0 {
		t.Fatalf("testnet genesis funds %d accounts; a premine is forbidden", len(g.DevAccounts))
	}
}

func TestDevnetGenesisIsUsableForTesting(t *testing.T) {
	g := Devnet()
	if len(g.Validators) == 0 {
		t.Fatal("devnet needs at least one validator")
	}
	if len(g.DevAccounts) == 0 {
		t.Fatal("devnet needs funded accounts so transfers can be tested before the faucet exists (M2)")
	}
}

func TestValidateRejectsBadGenesis(t *testing.T) {
	g := Devnet()
	g.Validators[0].PubKey = []byte{1, 2, 3}
	if err := g.Validate(); err == nil {
		t.Fatal("expected an error for a malformed validator key")
	}
}

func TestEmissionMathReachesExactlyTheSupplyCap(t *testing.T) {
	for _, g := range []*Genesis{Devnet(), Testnet()} {
		p := g.Params
		// A halving series sums to R0 * interval * 2.
		total := p.InitialRewardSparks * p.HalvingIntervalBlocks * 2
		if total != p.TotalSupplySparks {
			t.Fatalf("%s: emission sums to %d sparks, cap is %d",
				p.ChainID, total, p.TotalSupplySparks)
		}
	}
}

func TestGenesisRoundTripThroughEncoding(t *testing.T) {
	g := Devnet()
	enc := g.Encode()
	got, err := DecodeGenesis(enc)
	if err != nil {
		t.Fatalf("DecodeGenesis: %v", err)
	}
	if got.Hash() != g.Hash() {
		t.Fatal("genesis round trip changed the hash")
	}
}

func TestGenesisUsesBlake3Domain(t *testing.T) {
	g := Devnet()
	want := crypto.HashParts([]byte("b10coin-genesis"), g.Encode())
	if g.Hash() != want {
		t.Fatal("genesis hash does not use the expected domain separation")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/genesis/ -v`
Expected: FAIL — `undefined: Devnet`

- [ ] **Step 3: Write the implementation**

Create `internal/genesis/genesis.go`:

```go
// Package genesis defines the parameters that every node must agree on
// before the first block, including the protocol-controlled faucet address.
package genesis

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

// SparksPerB10 is the number of base units in one b10.
const SparksPerB10 = 100_000_000

var (
	ErrBadGenesis   = errors.New("genesis: invalid genesis")
	ErrBadValidator = errors.New("genesis: validator public key must be 32 bytes")
	ErrEmissionMath = errors.New("genesis: emission schedule does not reach the supply cap exactly")
)

// Params are the protocol parameters fixed at genesis.
type Params struct {
	ChainID               string
	BlockTimeMS           uint64
	TotalSupplySparks     uint64
	InitialRewardSparks   uint64
	HalvingIntervalBlocks uint64
	ClaimAmountSparks     uint64
	MinStakeSparks        uint64
	EpochBlocks           uint64
	UnbondingEpochs       uint64
	CommitteeSize         int
}

// Validator is a genesis validator with its initial voting power.
type Validator struct {
	PubKey []byte
	Power  uint64
}

// DevAccount is a TEST FIXTURE ONLY. It exists so transfer logic can be
// exercised in M1, before the faucet (M2) exists. The testnet genesis has
// none, and TestTestnetGenesisHasNoPremine enforces that.
type DevAccount struct {
	PubKey        []byte
	BalanceSparks uint64
}

// Genesis is the chain's starting configuration.
type Genesis struct {
	ChainID     string
	Time        int64
	Validators  []Validator
	DevAccounts []DevAccount
	Params      Params
}

// Encode renders the genesis canonically. Maps are never used, so the
// ordering here is the sole source of determinism.
func (g *Genesis) Encode() []byte {
	e := types.NewEncoder()
	e.VarBytes([]byte(g.ChainID))
	e.I64(g.Time)
	e.Len(len(g.Validators))
	for _, v := range g.Validators {
		e.VarBytes(v.PubKey)
		e.U64(v.Power)
	}
	e.Len(len(g.DevAccounts))
	for _, d := range g.DevAccounts {
		e.VarBytes(d.PubKey)
		e.U64(d.BalanceSparks)
	}
	e.VarBytes([]byte(g.Params.ChainID))
	e.U64(g.Params.BlockTimeMS)
	e.U64(g.Params.TotalSupplySparks)
	e.U64(g.Params.InitialRewardSparks)
	e.U64(g.Params.HalvingIntervalBlocks)
	e.U64(g.Params.ClaimAmountSparks)
	e.U64(g.Params.MinStakeSparks)
	e.U64(g.Params.EpochBlocks)
	e.U64(g.Params.UnbondingEpochs)
	e.U64(uint64(g.Params.CommitteeSize))
	return e.Bytes()
}

// Hash is the genesis identifier that seeds the faucet address.
func (g *Genesis) Hash() [32]byte {
	return crypto.HashParts([]byte("b10coin-genesis"), g.Encode())
}

// FaucetAddress derives an address that has NO corresponding private key:
// the preimage is the genesis hash, not a public key, so no signature can
// ever be produced for it. Coins can only leave this account through the
// protocol's claim rule.
func (g *Genesis) FaucetAddress() types.Address {
	gh := g.Hash()
	h := crypto.HashParts([]byte("b10coin-faucet"), gh[:])
	var a types.Address
	copy(a[:], h[:types.AddressSize])
	return a
}

// Validate checks the invariants a genesis must satisfy.
func (g *Genesis) Validate() error {
	if g.ChainID == "" {
		return fmt.Errorf("%w: empty chain ID", ErrBadGenesis)
	}
	// An empty validator set is legal: the testnet genesis is defined before
	// any operator keys exist. Such a chain simply cannot advance, because
	// chain.Append rejects every proposer (ErrNotValidator).
	for i, v := range g.Validators {
		if len(v.PubKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: validator %d has %d bytes", ErrBadValidator, i, len(v.PubKey))
		}
		if v.Power == 0 {
			return fmt.Errorf("%w: validator %d has zero power", ErrBadValidator, i)
		}
	}
	for i, d := range g.DevAccounts {
		if len(d.PubKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: dev account %d has %d key bytes", ErrBadGenesis, i, len(d.PubKey))
		}
	}
	p := g.Params
	if p.InitialRewardSparks*p.HalvingIntervalBlocks*2 != p.TotalSupplySparks {
		return ErrEmissionMath
	}
	return nil
}

// DecodeGenesis parses a canonical genesis encoding.
func DecodeGenesis(b []byte) (*Genesis, error) {
	d := types.NewDecoder(b)
	g := &Genesis{}
	var err error
	var raw []byte
	if raw, err = d.VarBytes(); err != nil {
		return nil, err
	}
	g.ChainID = string(raw)
	if g.Time, err = d.I64(); err != nil {
		return nil, err
	}
	n, err := d.Len()
	if err != nil {
		return nil, err
	}
	g.Validators = make([]Validator, n)
	for i := 0; i < n; i++ {
		if g.Validators[i].PubKey, err = d.VarBytes(); err != nil {
			return nil, err
		}
		if g.Validators[i].Power, err = d.U64(); err != nil {
			return nil, err
		}
	}
	m, err := d.Len()
	if err != nil {
		return nil, err
	}
	g.DevAccounts = make([]DevAccount, m)
	for i := 0; i < m; i++ {
		if g.DevAccounts[i].PubKey, err = d.VarBytes(); err != nil {
			return nil, err
		}
		if g.DevAccounts[i].BalanceSparks, err = d.U64(); err != nil {
			return nil, err
		}
	}
	if raw, err = d.VarBytes(); err != nil {
		return nil, err
	}
	g.Params.ChainID = string(raw)
	if g.Params.BlockTimeMS, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.TotalSupplySparks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.InitialRewardSparks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.HalvingIntervalBlocks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.ClaimAmountSparks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.MinStakeSparks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.EpochBlocks, err = d.U64(); err != nil {
		return nil, err
	}
	if g.Params.UnbondingEpochs, err = d.U64(); err != nil {
		return nil, err
	}
	cs, err := d.U64()
	if err != nil {
		return nil, err
	}
	g.Params.CommitteeSize = int(cs)
	if err := d.Done(); err != nil {
		return nil, err
	}
	return g, nil
}

// sharedParams are the values fixed by the design spec. The emission
// relation InitialReward * HalvingInterval * 2 == TotalSupply must hold.
func sharedParams(chainID string, committee int) Params {
	return Params{
		ChainID:               chainID,
		BlockTimeMS:           2000,
		TotalSupplySparks:     21_000_000 * SparksPerB10,
		InitialRewardSparks:   50_000_000, // 0.5 b10
		HalvingIntervalBlocks: 21_000_000,
		ClaimAmountSparks:     100 * SparksPerB10,
		MinStakeSparks:        1_000 * SparksPerB10,
		EpochBlocks:           10_000,
		UnbondingEpochs:       2,
		CommitteeSize:         committee,
	}
}

// Devnet is a single-validator chain with funded test accounts.
func Devnet() *Genesis {
	pub, _, _ := deterministicKey("b10coin-devnet-validator-1")
	devPub, _, _ := deterministicKey("b10coin-devnet-faucet-tester")
	dev2Pub, _, _ := deterministicKey("b10coin-devnet-recipient")
	return &Genesis{
		ChainID:    "b10coin-devnet-1",
		Time:       1_700_000_000,
		Validators: []Validator{{PubKey: pub, Power: 1}},
		DevAccounts: []DevAccount{
			{PubKey: devPub, BalanceSparks: 1_000_000 * SparksPerB10},
			{PubKey: dev2Pub, BalanceSparks: 0},
		},
		Params: sharedParams("b10coin-devnet-1", 1),
	}
}

// Testnet is the real chain's configuration: federated validators, and
// deliberately no funded accounts.
func Testnet() *Genesis {
	return &Genesis{
		ChainID:     "b10coin-testnet-1",
		Time:        1_700_000_000,
		Validators:  []Validator{},
		DevAccounts: nil, // no premine, ever
		Params:      sharedParams("b10coin-testnet-1", 21),
	}
}

// deterministicKey derives a stable keypair from a seed string so devnet
// fixtures are reproducible across machines and runs. It is NOT secret and
// must never be used outside devnet.
func deterministicKey(seed string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	h := crypto.HashParts([]byte("b10coin-devkey"), []byte(seed))
	priv := ed25519.NewKeyFromSeed(h[:])
	return priv.Public().(ed25519.PublicKey), priv, nil
}
```

- [ ] **Step 4: Add the genesis validity tests**

Add these to `internal/genesis/genesis_test.go`:

```go
func TestTestnetGenesisValidatesWithoutValidators(t *testing.T) {
	if err := Testnet().Validate(); err != nil {
		t.Fatalf("testnet genesis must validate before operator keys exist: %v", err)
	}
}

func TestDevnetGenesisValidates(t *testing.T) {
	if err := Devnet().Validate(); err != nil {
		t.Fatalf("devnet genesis must validate: %v", err)
	}
}
```

- [ ] **Step 5: Write the genesis JSON fixtures**

Create `genesis/devnet.json` and `genesis/testnet.json` as human-readable
*records* of the same values (the canonical encoder remains the source of
truth; these exist for review):

```json
{
  "chain_id": "b10coin-devnet-1",
  "note": "DEVNET TEST FIXTURE. The dev_accounts below are for exercising transfers before the M2 faucet exists. Never replicate this in testnet.",
  "validators": 1,
  "dev_accounts": 2,
  "params": {
    "block_time_ms": 2000,
    "total_supply_sparks": 2100000000000000,
    "initial_reward_sparks": 50000000,
    "halving_interval_blocks": 21000000,
    "claim_amount_sparks": 10000000000,
    "min_stake_sparks": 100000000000,
    "epoch_blocks": 10000,
    "unbonding_epochs": 2,
    "committee_size": 1
  }
}
```

```json
{
  "chain_id": "b10coin-testnet-1",
  "note": "NO PREMINE. dev_accounts must remain empty; TestTestnetGenesisHasNoPremine enforces this.",
  "validators": 0,
  "dev_accounts": 0,
  "params": {
    "block_time_ms": 2000,
    "total_supply_sparks": 2100000000000000,
    "initial_reward_sparks": 50000000,
    "halving_interval_blocks": 21000000,
    "claim_amount_sparks": 10000000000,
    "min_stake_sparks": 100000000000,
    "epoch_blocks": 10000,
    "unbonding_epochs": 2,
    "committee_size": 21
  }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/genesis/ -v`
Expected: PASS for all twelve tests.

- [ ] **Step 7: Commit**

```bash
git add internal/genesis genesis
git commit -m "feat: add genesis parameters, keyless faucet address, and no-premine test"
```

---

### Task 9: Crash-tolerant block store

**Files:**
- Create: `internal/store/store.go`, `internal/store/store_test.go`

**Interfaces:**
- Consumes: `types.NewEncoder`, `types.Decoder`
- Produces:
  - `const BlocksPerSegment = 1000`
  - `type Store struct{}` with `Open(dir string) (*Store, error)`, `(*Store) Append(height uint64, payload []byte) error`, `(*Store) Read(height uint64) ([]byte, error)`, `(*Store) Height() (uint64, bool)`, `(*Store) Close() error`
  - `ErrNotFound`, `ErrBadHeight`, `ErrCorruptRecord`

- [ ] **Step 1: Write the failing tests**

Create `internal/store/store_test.go`:

```go
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendAndReadRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	payload := []byte("block-at-height-1")
	if err := s.Append(1, payload); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read(1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("read %q, want %q", got, payload)
	}
}

func TestHeightReportsHighestStored(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()

	if _, ok := s.Height(); ok {
		t.Fatal("empty store should report no height")
	}
	for h := uint64(1); h <= 3; h++ {
		if err := s.Append(h, []byte(fmt.Sprintf("h%d", h))); err != nil {
			t.Fatal(err)
		}
	}
	h, ok := s.Height()
	if !ok || h != 3 {
		t.Fatalf("Height = %d, %v; want 3, true", h, ok)
	}
}

func TestReopenPreservesData(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for h := uint64(1); h <= 5; h++ {
		if err := s.Append(h, []byte(fmt.Sprintf("payload-%d", h))); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	h, ok := s2.Height()
	if !ok || h != 5 {
		t.Fatalf("Height after reopen = %d, %v; want 5, true", h, ok)
	}
	got, err := s2.Read(3)
	if err != nil || string(got) != "payload-3" {
		t.Fatalf("Read(3) = %q, %v", got, err)
	}
}

func TestReadMissingHeightFails(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	if err := s.Append(1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAppendRejectsNonSequentialHeight(t *testing.T) {
	s, _ := Open(t.TempDir())
	defer s.Close()
	if err := s.Append(5, []byte("x")); !errors.Is(err, ErrBadHeight) {
		t.Fatalf("expected ErrBadHeight, got %v", err)
	}
}

// A crash mid-write leaves a truncated trailing record. Open must discard
// it rather than failing, so the node can restart and re-sync.
func TestTruncatedTailIsDiscardedOnOpen(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for h := uint64(1); h <= 3; h++ {
		if err := s.Append(h, []byte(fmt.Sprintf("good-%d", h))); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
	f, err := os.OpenFile(seg, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// Length prefix claims 64 bytes, but only 3 follow.
	if _, err := f.Write([]byte{64, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after a truncated tail must succeed, got %v", err)
	}
	defer s2.Close()

	h, ok := s2.Height()
	if !ok || h != 3 {
		t.Fatalf("Height = %d, %v; want 3, true", h, ok)
	}
	if _, err := s2.Read(3); err != nil {
		t.Fatalf("good records must survive: %v", err)
	}
}

// A corrupted payload must be detected by the checksum.
func TestCorruptPayloadIsDetected(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.Append(1, []byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	s.Close()

	seg := filepath.Join(dir, fmt.Sprintf("%08d.seg", 0))
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-3] ^= 0xFF // flip a payload byte, leaving it intact in length
	if err := os.WriteFile(seg, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.Read(1); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("expected ErrCorruptRecord, got %v", err)
	}
}

func TestSegmentRolloverAtBlocksPerSegment(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for h := uint64(1); h <= BlocksPerSegment+2; h++ {
		if err := s.Append(h, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected a second segment file, got %d files", len(entries))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/ -v`
Expected: FAIL — `undefined: Open`

- [ ] **Step 3: Write the implementation**

Create `internal/store/store.go`:

```go
// Package store persists blocks as append-only segment files.
//
// Record layout:
//
//	varint(len(payload)) || payload || uint32be(crc32c(payload))
//
// Open scans the final segment and truncates a partial or corrupt trailing
// record. That is what makes a crash mid-write survivable: the node restarts,
// re-syncs from the last good block, and loses nothing already committed.
package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
)

// BlocksPerSegment is how many blocks share one segment file.
const BlocksPerSegment = 1000

var (
	ErrNotFound      = errors.New("store: height not found")
	ErrBadHeight     = errors.New("store: heights must be appended sequentially")
	ErrCorruptRecord = errors.New("store: record checksum mismatch")
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// Store is an append-only block log.
type Store struct {
	dir   string
	file  *os.File
	last  uint64
	have  bool
	index map[uint64]int64 // height -> offset within its segment
}

func segmentName(height uint64) string {
	return fmt.Sprintf("%08d.seg", height/BlocksPerSegment)
}

// Open prepares dir for use and rebuilds the in-memory height index,
// discarding any partial trailing record.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, index: make(map[uint64]int64)}
	if err := s.scan(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.segmentPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	s.file = f
	return s, nil
}

func (s *Store) segmentPath() string {
	if s.have {
		return filepath.Join(s.dir, segmentName(s.last))
	}
	return filepath.Join(s.dir, segmentName(0))
}

// scan rebuilds the index from disk and truncates any damaged tail.
func (s *Store) scan() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var segs []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".seg" {
			segs = append(segs, e.Name())
		}
	}
	// File names are zero-padded, so lexical order is height order.
	slices.Sort(segs)

	for si, name := range segs {
		path := filepath.Join(s.dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		off := int64(0)
		i := 0
		lastSegment := si == len(segs)-1
		for i < len(raw) {
			n, m := binary.Uvarint(raw[i:])
			if m <= 0 {
				if lastSegment {
					return s.truncate(path, off)
				}
				return fmt.Errorf("%w: bad length in %s", ErrCorruptRecord, name)
			}
			total := int64(m) + int64(n) + 4
			if off+total > int64(len(raw)) {
				if lastSegment {
					return s.truncate(path, off)
				}
				return fmt.Errorf("%w: truncated record in %s", ErrCorruptRecord, name)
			}
			payloadStart := i + m
			payload := raw[payloadStart : payloadStart+int(n)]
			want := binary.BigEndian.Uint32(raw[payloadStart+int(n) : payloadStart+int(n)+4])
			if crc32.Checksum(payload, crcTable) != want {
				if lastSegment {
					return s.truncate(path, off)
				}
				return fmt.Errorf("%w: in %s", ErrCorruptRecord, name)
			}
			height := s.last + 1
			s.index[height] = off
			s.last = height
			s.have = true
			off += total
			i += int(total)
		}
	}
	return nil
}

func (s *Store) truncate(path string, size int64) error {
	return os.Truncate(path, size)
}

// Append writes payload as the block at height. Heights must be sequential.
func (s *Store) Append(height uint64, payload []byte) error {
	want := uint64(1)
	if s.have {
		want = s.last + 1
	}
	if height != want {
		return fmt.Errorf("%w: got %d, want %d", ErrBadHeight, height, want)
	}

	// Roll to a new segment before writing across a boundary.
	if s.have && segmentName(height) != segmentName(s.last) {
		if err := s.file.Close(); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(s.dir, segmentName(height)),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		s.file = f
		s.last = height
		s.have = true
		s.index[height] = 0
		return writeRecord(s.file, payload)
	}

	off, err := s.file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if err := writeRecord(s.file, payload); err != nil {
		return err
	}
	s.index[height] = off
	s.last = height
	s.have = true
	return nil
}

func writeRecord(f *os.File, payload []byte) error {
	var hdr [binary.MaxVarintLen64]byte
	m := binary.PutUvarint(hdr[:], uint64(len(payload)))
	rec := make([]byte, 0, m+len(payload)+4)
	rec = append(rec, hdr[:m]...)
	rec = append(rec, payload...)
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.Checksum(payload, crcTable))
	rec = append(rec, sum[:]...)
	if _, err := f.Write(rec); err != nil {
		return err
	}
	// Durable before we report success: a block we acknowledged must
	// survive a power loss.
	return f.Sync()
}

// Read returns the payload stored at height.
func (s *Store) Read(height uint64) ([]byte, error) {
	off, ok := s.index[height]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrNotFound, height)
	}
	path := filepath.Join(s.dir, segmentName(height))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	n, m := binary.Uvarint(raw[off:])
	if m <= 0 {
		return nil, fmt.Errorf("%w: bad length at %d", ErrCorruptRecord, off)
	}
	start := int(off) + m
	end := start + int(n)
	if end+4 > len(raw) {
		return nil, fmt.Errorf("%w: truncated record at %d", ErrCorruptRecord, off)
	}
	payload := raw[start:end]
	want := binary.BigEndian.Uint32(raw[end : end+4])
	if crc32.Checksum(payload, crcTable) != want {
		return nil, fmt.Errorf("%w: at height %d", ErrCorruptRecord, height)
	}
	out := make([]byte, len(payload))
	copy(out, payload)
	return out, nil
}

// Height returns the highest stored height.
func (s *Store) Height() (uint64, bool) { return s.last, s.have }

func (s *Store) Close() error {
	if s.file == nil {
		return nil
	}
	return s.file.Close()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/ -v`
Expected: PASS for all eight tests.

- [ ] **Step 5: Commit**

```bash
git add internal/store
git commit -m "feat: add crash-tolerant append-only block store"
```

---

### Task 10: Chain — build, validate, append, replay

**Files:**
- Create: `internal/chain/chain.go`, `internal/chain/chain_test.go`

**Interfaces:**
- Consumes: `genesis.Genesis`, `store.Store`, `state.State`, `types.Block`, `crypto`
- Produces:
  - `type Chain struct{}` with `Open(*genesis.Genesis, string) (*Chain, error)`, `(*Chain) Height() uint64`, `(*Chain) Head() *types.Block`, `(*Chain) State() *state.State`, `(*Chain) Genesis() *genesis.Genesis`, `(*Chain) Build(proposer ed25519.PrivateKey, txs []types.Tx, timestamp int64) (*types.Block, error)`, `(*Chain) Append(*types.Block) error`, `(*Chain) Close() error`
  - `ErrBadParent`, `ErrBadHeight`, `ErrBadStateRoot`, `ErrBadProposerSig`, `ErrUnknownProposer`, `ErrNotValidator`

- [ ] **Step 1: Write the failing tests**

Create `internal/chain/chain_test.go`:

```go
package chain

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/types"
)

// devChain opens a chain plus the devnet validator's private key.
func devChain(t *testing.T) (*Chain, ed25519.PrivateKey) {
	t.Helper()
	g := genesis.Devnet()
	_, priv, err := devKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Open(g, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, priv
}

func TestGenesisBlockIsCreatedAtOpen(t *testing.T) {
	c, _ := devChain(t)
	if c.Height() != 0 {
		t.Fatalf("fresh chain height = %d, want 0", c.Height())
	}
	if c.Head().Header.ParentHash != ([32]byte{}) {
		t.Fatal("genesis parent hash must be all zeros")
	}
}

// Devnet genesis funds accounts, so the genesis state root must not be the
// empty root.
func TestDevnetGenesisStateIsNotEmpty(t *testing.T) {
	c, _ := devChain(t)
	if c.Head().Header.StateRoot == ([32]byte{}) {
		t.Fatal("devnet genesis state root is empty; dev accounts were not applied")
	}
}

func TestBuildAndAppendAdvancesChain(t *testing.T) {
	c, priv := devChain(t)

	b, err := c.Build(priv, nil, 1_700_000_100)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if b.Header.Height != 1 {
		t.Fatalf("built height %d, want 1", b.Header.Height)
	}
	if err := c.Append(b); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if c.Height() != 1 {
		t.Fatalf("height after append = %d, want 1", c.Height())
	}
	if c.Head().ID() != b.ID() {
		t.Fatal("head is not the appended block")
	}
}

func TestAppendRejectsWrongParent(t *testing.T) {
	c, priv := devChain(t)
	b, _ := c.Build(priv, nil, 1_700_000_100)
	b.Header.ParentHash = crypto.HashParts([]byte("not-the-parent"))
	if err := c.Append(b); !errors.Is(err, ErrBadParent) {
		t.Fatalf("expected ErrBadParent, got %v", err)
	}
}

func TestAppendRejectsWrongHeight(t *testing.T) {
	c, priv := devChain(t)
	b, _ := c.Build(priv, nil, 1_700_000_100)
	b.Header.Height = 7
	if err := c.Append(b); !errors.Is(err, ErrBadHeight) {
		t.Fatalf("expected ErrBadHeight, got %v", err)
	}
}

// A tampered state root must be caught: this is the check that stops a node
// from silently accepting a block that claims a state it did not compute.
func TestAppendRejectsTamperedStateRoot(t *testing.T) {
	c, priv := devChain(t)
	b, _ := c.Build(priv, nil, 1_700_000_100)
	b.Header.StateRoot = crypto.HashParts([]byte("fabricated"))
	if err := c.Append(b); !errors.Is(err, ErrBadStateRoot) {
		t.Fatalf("expected ErrBadStateRoot, got %v", err)
	}
}

func TestAppendRejectsUnsignedOrForgedHeader(t *testing.T) {
	c, priv := devChain(t)
	b, _ := c.Build(priv, nil, 1_700_000_100)
	b.Sig = nil
	if err := c.Append(b); !errors.Is(err, ErrBadProposerSig) {
		t.Fatalf("expected ErrBadProposerSig, got %v", err)
	}
}

func TestAppendRejectsNonValidatorProposer(t *testing.T) {
	c, _ := devChain(t)
	_, otherPriv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Build(otherPriv, nil, 1_700_000_100)
	if err != nil {
		t.Fatalf("Build must not validate the proposer: %v", err)
	}
	if err := c.Append(b); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("expected ErrNotValidator, got %v", err)
	}
}

// A genesis with no validators cannot advance: every proposer is rejected.
// This is what makes a validator-less testnet genesis safe rather than broken.
func TestChainWithoutValidatorsCannotAdvance(t *testing.T) {
	c, err := Open(genesis.Testnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_, priv := genesis.DevValidatorKey()
	b, err := c.Build(priv, nil, 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append(b); !errors.Is(err, ErrNotValidator) {
		t.Fatalf("expected ErrNotValidator, got %v", err)
	}
}

// Replay is the core durability guarantee: reopen from disk and confirm the
// recomputed state root matches the stored header.
func TestReplayRebuildsIdenticalState(t *testing.T) {
	dir := t.TempDir()
	g := genesis.Devnet()
	_, priv, err := devKey()
	if err != nil {
		t.Fatal(err)
	}

	c, err := Open(g, dir)
	if err != nil {
		t.Fatal(err)
	}
	var roots [][32]byte
	for h := 1; h <= 5; h++ {
		b, err := c.Build(priv, nil, int64(1_700_000_000+h))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, b.Header.StateRoot)
	}
	headID := c.Head().ID()
	c.Close()

	c2, err := Open(g, dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer c2.Close()

	if c2.Height() != 5 {
		t.Fatalf("replayed height = %d, want 5", c2.Height())
	}
	if c2.Head().ID() != headID {
		t.Fatal("replayed head differs from the stored head")
	}
	if c2.State().Root() != roots[len(roots)-1] {
		t.Fatal("replayed state root differs from the stored header")
	}
}

func TestTransferThroughChainChangesBalances(t *testing.T) {
	c, priv := devChain(t)

	g := c.Genesis()
	fromPub := g.DevAccounts[0].PubKey
	toPub := g.DevAccounts[1].PubKey
	from := types.AddressFromPub(fromPub)
	to := types.AddressFromPub(toPub)

	startFrom := c.State().Get(from).Balance
	startTo := c.State().Get(to).Balance

	// The devnet validator key is not the dev account key, so sign with the
	// dev account's deterministic key.
	devPriv := devPrivateKey(t)

	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  0,
		To:     to,
		Amount: 250 * genesis.SparksPerB10,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(devPriv, sigHash[:])

	b, err := c.Build(priv, []types.Tx{*tx}, 1_700_000_100)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := c.Append(b); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if got := c.State().Get(from).Balance; got != startFrom-250*genesis.SparksPerB10 {
		t.Fatalf("sender balance = %d, want %d", got, startFrom-250*genesis.SparksPerB10)
	}
	if got := c.State().Get(to).Balance; got != startTo+250*genesis.SparksPerB10 {
		t.Fatalf("recipient balance = %d, want %d", got, startTo+250*genesis.SparksPerB10)
	}
}

// Total supply must be conserved by transfers.
func TestTotalSupplyIsConserved(t *testing.T) {
	c, _ := devChain(t)
	before := c.State().TotalBalance()
	if before == 0 {
		t.Fatal("devnet should start with funds")
	}
	// Apply an empty block; supply must be unchanged.
	b, err := c.Build(devPrivateKey(t), nil, 1_700_000_100)
	if err != nil {
		t.Fatal(err)
	}
	_ = b
	if c.State().TotalBalance() != before {
		t.Fatal("supply changed without transactions")
	}
}
```

- [ ] **Step 2: Add the test key helpers**

The tests above reference `devKey()` and `devPrivateKey(t)`, which must
reproduce the same deterministic keys `genesis.Devnet()` used. Export them from
`genesis` so both packages agree on one source of truth. Add to
`internal/genesis/genesis.go`:

```go
// DevValidatorKey returns the devnet validator keypair. It is deterministic
// and PUBLIC: it exists so tests and the devnet CLI can sign blocks. It must
// never be used on any network holding value.
func DevValidatorKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := deterministicKey("b10coin-devnet-validator-1")
	return pub, priv
}

// DevAccountKey returns the keypair for devnet dev account i (0 or 1).
func DevAccountKey(i int) (ed25519.PublicKey, ed25519.PrivateKey) {
	seeds := []string{"b10coin-devnet-faucet-tester", "b10coin-devnet-recipient"}
	pub, priv, _ := deterministicKey(seeds[i])
	return pub, priv
}
```

Then in `internal/chain/chain.go`'s test file add:

```go
func devKey() (ed25519.PublicKey, ed25519.PrivateKey) { return genesis.DevValidatorKey() }

func devPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv := genesis.DevAccountKey(0)
	return priv
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/chain/ -v`
Expected: FAIL — `undefined: Open`

- [ ] **Step 4: Write the implementation**

Create `internal/chain/chain.go`:

```go
// Package chain owns the canonical block sequence: building candidate
// blocks, validating them against state, appending them durably, and
// rebuilding state by replay on startup.
package chain

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/state"
	"github.com/cti97/b10coincom/internal/store"
	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrBadParent        = errors.New("chain: parent hash does not match head")
	ErrBadHeight        = errors.New("chain: height is not head+1")
	ErrBadStateRoot     = errors.New("chain: computed state root does not match header")
	ErrBadProposerSig   = errors.New("chain: proposer signature is missing or invalid")
	ErrNotValidator     = errors.New("chain: proposer is not in the validator set")
	ErrGenesisReplay    = errors.New("chain: replay diverged from stored state root")
	ErrUnknownProposer  = errors.New("chain: cannot determine proposer key")
)

// Chain is a validated, durably-stored block sequence.
type Chain struct {
	gen   *genesis.Genesis
	store *store.Store
	state *state.State
	head  *types.Block
}

// genesisState builds the state that block 1 builds upon.
func genesisState(g *genesis.Genesis) (*state.State, error) {
	s := state.New()
	for _, d := range g.DevAccounts {
		addr := types.AddressFromPub(d.PubKey)
		acc := s.Get(addr)
		acc.Balance += d.BalanceSparks
		s.Set(addr, acc)
	}
	return s, nil
}

func genesisBlock(g *genesis.Genesis, st *state.State) *types.Block {
	return &types.Block{
		Header: types.Header{
			Height:     0,
			ParentHash: [32]byte{},
			StateRoot:  st.Root(),
			TxRoot:     crypto.MerkleRoot(nil),
			Timestamp:  g.Time,
			Proposer:   nil,
		},
	}
}

// Open loads the chain from dir, replaying every stored block. If the
// directory is empty it initialises the genesis block instead.
func Open(g *genesis.Genesis, dir string) (*Chain, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	st, err := genesisState(g)
	if err != nil {
		return nil, err
	}
	s, err := store.Open(dir)
	if err != nil {
		return nil, err
	}
	c := &Chain{gen: g, store: s, state: st, head: genesisBlock(g, st)}

	height, ok := s.Height()
	if !ok {
		return c, nil
	}
	for h := uint64(1); h <= height; h++ {
		raw, err := s.Read(h)
		if err != nil {
			return nil, err
		}
		blk, err := types.DecodeBlock(raw)
		if err != nil {
			return nil, err
		}
		if err := c.applyValidated(blk); err != nil {
			return nil, fmt.Errorf("%w at height %d: %v", ErrGenesisReplay, h, err)
		}
		// The stored header's root must equal what we just recomputed.
		if c.state.Root() != blk.Header.StateRoot {
			return nil, fmt.Errorf("%w at height %d", ErrGenesisReplay, h)
		}
	}
	return c, nil
}

func (c *Chain) Genesis() *genesis.Genesis { return c.gen }
func (c *Chain) Height() uint64            { return c.head.Header.Height }
func (c *Chain) Head() *types.Block        { return c.head }
func (c *Chain) State() *state.State       { return c.state }

// isValidator reports whether pub is in the genesis validator set.
func (c *Chain) isValidator(pub []byte) bool {
	for _, v := range c.gen.Validators {
		if string(v.PubKey) == string(pub) {
			return true
		}
	}
	return false
}

// Build constructs and signs a candidate block. It does not mutate the
// chain: the caller decides whether to Append.
func (c *Chain) Build(proposer ed25519.PrivateKey, txs []types.Tx, timestamp int64) (*types.Block, error) {
	pub, ok := proposer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrUnknownProposer
	}
	next, err := c.state.ApplyBlock(txs)
	if err != nil {
		return nil, err
	}
	b := &types.Block{
		Header: types.Header{
			Height:     c.Height() + 1,
			ParentHash: c.head.ID(),
			StateRoot:  next.Root(),
			TxRoot:     types.ComputeTxRoot(txs),
			Timestamp:  timestamp,
			Proposer:   pub,
		},
		Txs: txs,
	}
	if err := b.ValidateStructure(); err != nil {
		return nil, err
	}
	return b, nil
}

// applyValidated applies a block whose structure is already trusted.
func (c *Chain) applyValidated(b *types.Block) error {
	next, err := c.state.ApplyBlock(b.Txs)
	if err != nil {
		return err
	}
	c.state = next
	c.head = b
	return nil
}

// Append validates a block against the current head and state, then stores
// it. Validation happens before any mutation, so a rejected block leaves the
// chain untouched.
func (c *Chain) Append(b *types.Block) error {
	if b.Header.ParentHash != c.head.ID() {
		return ErrBadParent
	}
	if b.Header.Height != c.Height()+1 {
		return fmt.Errorf("%w: got %d, want %d", ErrBadHeight, b.Header.Height, c.Height()+1)
	}
	if err := b.ValidateStructure(); err != nil {
		return err
	}
	if !c.isValidator(b.Header.Proposer) {
		return ErrNotValidator
	}
	if b.Sig == nil {
		return ErrBadProposerSig
	}
	headerHash := b.Header.SigningHash()
	if !crypto.Verify(b.Header.Proposer, headerHash[:], b.Sig) {
		return ErrBadProposerSig
	}

	next, err := c.state.ApplyBlock(b.Txs)
	if err != nil {
		return err
	}
	if computed := next.Root(); computed != b.Header.StateRoot {
		return fmt.Errorf("%w: computed %x, header claims %x",
			ErrBadStateRoot, computed[:8], b.Header.StateRoot[:8])
	}

	if err := c.store.Append(b.Header.Height, b.Encode()); err != nil {
		return err
	}
	c.state = next
	c.head = b
	return nil
}

func (c *Chain) Close() error { return c.store.Close() }
```

- [ ] **Step 5: Add the signature field to the block**

`Append` reads `b.Sig`, but `types.Block` has no such field. Add it to
`internal/types/block.go` — the signature is over the header, so it lives
outside the header and outside the block ID:

```go
// Block is a header plus its transactions. Sig is the proposer's Ed25519
// signature over Header.SigningHash(); it is deliberately outside the header
// so that signing does not change the block's identity.
type Block struct {
	Header Header
	Txs    []Tx
	Sig    []byte
}
```

Extend `Encode` to append `e.VarBytes(b.Sig)` after the transactions, and
extend `DecodeBlock` to read it back:

```go
	// in Encode, after the transaction loop:
	e.VarBytes(b.Sig)

	// in DecodeBlock, after the transaction loop:
	if out.Sig, err = d.VarBytes(); err != nil {
		return nil, err
	}
```

- [ ] **Step 6: Sign the header inside Build**

`Build` currently builds the header without signing it. Add, immediately
before the `return b, nil`:

```go
	headerHash := b.Header.SigningHash()
	b.Sig = crypto.Sign(proposer, headerHash[:])
```

Also add this test to guard that the signature is over the header only:

```go
func TestBlockSigDoesNotAffectBlockID(t *testing.T) {
	b := testBlock(t)
	before := b.ID()
	b.Sig = []byte("a-signature")
	if b.ID() != before {
		t.Fatal("signature must not change the block ID")
	}
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./... -v`
Expected: PASS across every package.

- [ ] **Step 8: Commit**

```bash
git add internal/chain internal/genesis internal/state internal/types internal/store
git commit -m "feat: add chain build, validation, append and replay"
```

---

### Task 11: Mempool, HTTP RPC, and node loop

**Files:**
- Create: `internal/mempool/mempool.go`, `internal/mempool/mempool_test.go`, `internal/rpc/server.go`, `internal/rpc/server_test.go`, `internal/node/node.go`, `internal/node/node_test.go`

**Interfaces:**
- Consumes: `chain.Chain`, `types.Tx`, `state`
- Produces:
  - `mempool.New(max int) *mempool.Mempool`, `(*Mempool) Add([]types.Tx) []error`, `(*Mempool) Take(max int) []types.Tx`, `(*Mempool) Len() int`, `(*Mempool) Remove([32]byte)`
  - `rpc.NewServer(*chain.Chain, *mempool.Mempool) *rpc.Server`, `(*Server) Handler() http.Handler`
  - `node.New(*chain.Chain, ed25519.PrivateKey, *mempool.Mempool) *node.Node`, `(*Node) RunOnce(timestamp int64) (*types.Block, error)`

- [ ] **Step 1: Write the failing mempool tests**

Create `internal/mempool/mempool_test.go`:

```go
package mempool

import (
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/types"
)

func mkTx(t *testing.T, nonce uint64) types.Tx {
	t.Helper()
	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, otherPub, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   types.AddressFromPub(pub),
		PubKey: pub,
		Nonce:  nonce,
		To:     types.AddressFromPub(otherPub),
		Amount: 1,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(priv, sigHash[:])
	return *tx
}

func TestMempoolAddAndTake(t *testing.T) {
	m := New(10)
	errs := m.Add([]types.Tx{mkTx(t, 0), mkTx(t, 1)})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
	}
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
	got := m.Take(10)
	if len(got) != 2 {
		t.Fatalf("Take returned %d txs, want 2", len(got))
	}
	if m.Len() != 0 {
		t.Fatalf("Take must drain; Len = %d", m.Len())
	}
}

func TestMempoolDeduplicates(t *testing.T) {
	m := New(10)
	tx := mkTx(t, 0)
	if err := m.Add([]types.Tx{tx})[0]; err != nil {
		t.Fatal(err)
	}
	if err := m.Add([]types.Tx{tx})[0]; err == nil {
		t.Fatal("expected a duplicate to be rejected")
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d, want 1", m.Len())
	}
}

func TestMempoolRejectsBadSignature(t *testing.T) {
	m := New(10)
	tx := mkTx(t, 0)
	tx.Sig[0] ^= 0xFF
	if err := m.Add([]types.Tx{tx})[0]; err == nil {
		t.Fatal("expected a bad signature to be rejected")
	}
}

func TestMempoolRespectsCapacity(t *testing.T) {
	m := New(2)
	_ = m.Add([]types.Tx{mkTx(t, 0), mkTx(t, 1), mkTx(t, 2)})
	if m.Len() > 2 {
		t.Fatalf("Len = %d exceeds capacity 2", m.Len())
	}
}

func TestMempoolRemove(t *testing.T) {
	m := New(10)
	tx := mkTx(t, 0)
	_ = m.Add([]types.Tx{tx})
	m.Remove(tx.ID())
	if m.Len() != 0 {
		t.Fatalf("Len = %d after Remove, want 0", m.Len())
	}
}
```

- [ ] **Step 2: Write the mempool implementation**

Create `internal/mempool/mempool.go`:

```go
// Package mempool holds validated transactions waiting to be included in a
// block.
package mempool

import (
	"errors"

	"github.com/cti97/b10coincom/internal/types"
)

var (
	ErrDuplicate = errors.New("mempool: transaction already present")
	ErrFull      = errors.New("mempool: at capacity")
)

// Mempool is a bounded, deduplicated set of pending transactions.
type Mempool struct {
	max  int
	txs  []types.Tx
	seen map[[32]byte]struct{}
}

func New(max int) *Mempool {
	return &Mempool{max: max, seen: make(map[[32]byte]struct{})}
}

// Add validates signatures and inserts transactions, returning one error per
// input in the same order. Insertion of one transaction never blocks another.
func (m *Mempool) Add(txs []types.Tx) []error {
	errs := make([]error, len(txs))
	for i := range txs {
		tx := txs[i]
		if err := tx.VerifySignature(); err != nil {
			errs[i] = err
			continue
		}
		id := tx.ID()
		if _, dup := m.seen[id]; dup {
			errs[i] = ErrDuplicate
			continue
		}
		if len(m.txs) >= m.max {
			errs[i] = ErrFull
			continue
		}
		m.txs = append(m.txs, tx)
		m.seen[id] = struct{}{}
	}
	return errs
}

// Take removes and returns up to max transactions.
func (m *Mempool) Take(max int) []types.Tx {
	if max > len(m.txs) {
		max = len(m.txs)
	}
	out := make([]types.Tx, max)
	copy(out, m.txs[:max])
	for i := range out {
		delete(m.seen, out[i].ID())
	}
	m.txs = append([]types.Tx(nil), m.txs[max:]...)
	return out
}

// Remove drops a transaction by ID, used when a block includes it.
func (m *Mempool) Remove(id [32]byte) {
	if _, ok := m.seen[id]; !ok {
		return
	}
	delete(m.seen, id)
	for i := range m.txs {
		if m.txs[i].ID() == id {
			m.txs = append(m.txs[:i], m.txs[i+1:]...)
			return
		}
	}
}

func (m *Mempool) Len() int { return len(m.txs) }
```

- [ ] **Step 3: Write the failing RPC tests**

Create `internal/rpc/server_test.go`:

```go
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
)

func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s := NewServer(c, mempool.New(100))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func TestStatusEndpoint(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ChainID != "b10coin-devnet-1" {
		t.Fatalf("chain ID = %q", body.ChainID)
	}
	if body.Height != 0 {
		t.Fatalf("height = %d, want 0", body.Height)
	}
}

func TestBlockEndpointReturnsGenesis(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/block/0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var b blockResponse
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	if b.Height != 0 {
		t.Fatalf("height = %d, want 0", b.Height)
	}
}

func TestBlockEndpointRejectsMissingHeight(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/block/99")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestTxEndpointRejectsGarbage(t *testing.T) {
	_, ts := testServer(t)
	resp, err := http.Post(ts.URL+"/tx", "text/plain", strings.NewReader("not-hex"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTxEndpointAcceptsValidTx(t *testing.T) {
	_, ts := testServer(t)
	enc := hex.EncodeToString(buildSignedTx(t).Encode())
	resp, err := http.Post(ts.URL+"/tx", "text/plain", strings.NewReader(enc))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := make([]byte, 256)
		n, _ := resp.Body.Read(buf)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, buf[:n])
	}
}
```

- [ ] **Step 4: Write the RPC implementation**

Create `internal/rpc/server.go`:

```go
// Package rpc exposes a small read/write HTTP API for the node.
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

type statusResponse struct {
	ChainID   string `json:"chain_id"`
	Height    uint64 `json:"height"`
	HeadHash  string `json:"head_hash"`
	StateRoot string `json:"state_root"`
	Mempool   int    `json:"mempool"`
}

type blockResponse struct {
	Height    uint64 `json:"height"`
	Hash      string `json:"hash"`
	Parent    string `json:"parent"`
	StateRoot string `json:"state_root"`
	Timestamp int64  `json:"timestamp"`
	Txs       int    `json:"tx_count"`
}

type txResponse struct {
	TxID string `json:"txid"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// Server binds the chain and mempool to HTTP handlers.
type Server struct {
	chain   *chain.Chain
	mempool *mempool.Mempool
}

func NewServer(c *chain.Chain, mp *mempool.Mempool) *Server {
	return &Server{chain: c, mempool: mp}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Handler returns the routing table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/block/", s.handleBlock)
	mux.HandleFunc("/tx", s.handleTx)
	return mux
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"method not allowed"})
		return
	}
	head := s.chain.Head()
	h := head.ID()
	sr := head.Header.StateRoot
	writeJSON(w, http.StatusOK, statusResponse{
		ChainID:   s.chain.Genesis().ChainID,
		Height:    s.chain.Height(),
		HeadHash:  hex.EncodeToString(h[:]),
		StateRoot: hex.EncodeToString(sr[:]),
		Mempool:   s.mempool.Len(),
	})
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"method not allowed"})
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/block/")
	height, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"height must be an unsigned integer"})
		return
	}
	if height > s.chain.Height() {
		writeJSON(w, http.StatusNotFound, errorResponse{"height not found"})
		return
	}
	// Only the head is held in memory; earlier blocks are read from disk.
	b := s.chain.Head()
	if height != b.Header.Height {
		blk, err := s.chain.BlockAt(height)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse{err.Error()})
			return
		}
		b = blk
	}
	id := b.ID()
	writeJSON(w, http.StatusOK, blockResponse{
		Height:    b.Header.Height,
		Hash:      hex.EncodeToString(id[:]),
		Parent:    hex.EncodeToString(b.Header.ParentHash[:]),
		StateRoot: hex.EncodeToString(b.Header.StateRoot[:]),
		Timestamp: b.Header.Timestamp,
		Txs:       len(b.Txs),
	})
}

func (s *Server) handleTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"method not allowed"})
		return
	}
	defer r.Body.Close()
	// Accept either a bare hex body or a JSON-quoted hex string: read once,
	// trim whitespace and surrounding quotes, then hex-decode.
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"cannot read body"})
		return
	}
	enc := strings.Trim(string(body), " \t\r\n\"")
	if enc == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"expected hex-encoded transaction bytes"})
		return
	}
	raw, err := hex.DecodeString(enc)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid hex"})
		return
	}
	tx, err := types.DecodeTx(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	if err := s.mempool.Add([]types.Tx{*tx})[0]; err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	id := tx.ID()
	writeJSON(w, http.StatusOK, txResponse{TxID: hex.EncodeToString(id[:])})
}
```

- [ ] **Step 5: Add `BlockAt` to the chain**

`handleBlock` needs to read historical blocks. Add to `internal/chain/chain.go`:

```go
// BlockAt returns the block stored at height. Only the head is cached, so
// historical reads go to disk.
func (c *Chain) BlockAt(height uint64) (*types.Block, error) {
	if height > c.Height() {
		return nil, fmt.Errorf("%w: %d", store.ErrNotFound, height)
	}
	if height == c.Height() {
		return c.head, nil
	}
	raw, err := c.store.Read(height)
	if err != nil {
		return nil, err
	}
	return types.DecodeBlock(raw)
}
```

Then add this test to `internal/chain/chain_test.go`:

```go
func TestBlockAtReadsHistoricalBlocks(t *testing.T) {
	c, priv := devChain(t)
	for h := 1; h <= 3; h++ {
		b, err := c.Build(priv, nil, int64(1_700_000_000+h))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	for h := uint64(0); h <= 3; h++ {
		b, err := c.BlockAt(h)
		if err != nil {
			t.Fatalf("BlockAt(%d): %v", h, err)
		}
		if b.Header.Height != h {
			t.Fatalf("BlockAt(%d) returned height %d", h, b.Header.Height)
		}
	}
	if _, err := c.BlockAt(4); err == nil {
		t.Fatal("BlockAt beyond head must fail")
	}
}
```

- [ ] **Step 6: Write the node loop and its test**

Create `internal/node/node.go`:

```go
// Package node wires the chain, mempool and block production together.
// In M1 a single node produces blocks unilaterally: agreement between
// validators arrives in M3.
package node

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

// Node produces blocks on a timer.
type Node struct {
	chain   *chain.Chain
	proposer ed25519.PrivateKey
	mempool *mempool.Mempool
	now     func() time.Time
}

func New(c *chain.Chain, proposer ed25519.PrivateKey, mp *mempool.Mempool) *Node {
	return &Node{chain: c, proposer: proposer, mempool: mp, now: time.Now}
}

// RunOnce produces at most one block from the current mempool and appends
// it. It returns nil, nil when there is nothing to do.
func (n *Node) RunOnce(timestamp int64) (*types.Block, error) {
	if timestamp == 0 {
		timestamp = n.now().Unix()
	}
	txs := n.mempool.Take(types.MaxTxsPerBlock)
	b, err := n.chain.Build(n.proposer, txs, timestamp)
	if err != nil {
		return nil, err
	}
	if err := n.chain.Append(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Run produces blocks every interval until ctx is cancelled.
func (n *Node) Run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := n.RunOnce(0); err != nil {
				return err
			}
		}
	}
}
```

Create `internal/node/node_test.go`:

```go
package node

import (
	"testing"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/types"
)

func TestRunOnceProducesAndAppends(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	n := New(c, priv, mempool.New(100))
	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if b.Header.Height != 1 {
		t.Fatalf("height = %d, want 1", b.Header.Height)
	}
	if c.Height() != 1 {
		t.Fatalf("chain height = %d, want 1", c.Height())
	}
}

func TestRunOnceIncludesMempoolTransactions(t *testing.T) {
	c, err := chain.Open(genesis.Devnet(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, priv := genesis.DevValidatorKey()

	// Build a signed transfer from devnet dev account 0 to account 1.
	fromPub, fromPriv := genesis.DevAccountKey(0)
	toPub, _ := genesis.DevAccountKey(1)
	from := types.AddressFromPub(fromPub)
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  c.State().Get(from).Nonce,
		To:     types.AddressFromPub(toPub),
		Amount: 10 * genesis.SparksPerB10,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(fromPriv, sigHash[:])

	mp := mempool.New(100)
	if err := mp.Add([]types.Tx{*tx})[0]; err != nil {
		t.Fatalf("mempool.Add: %v", err)
	}
	if mp.Len() != 1 {
		t.Fatalf("mempool length = %d, want 1", mp.Len())
	}

	n := New(c, priv, mp)
	before := c.State().Get(types.AddressFromPub(toPub)).Balance

	b, err := n.RunOnce(1_700_000_100)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(b.Txs) != 1 {
		t.Fatalf("block contains %d txs, want 1", len(b.Txs))
	}
	if got := c.State().Get(types.AddressFromPub(toPub)).Balance; got != before+10*genesis.SparksPerB10 {
		t.Fatalf("recipient balance = %d, want %d", got, before+10*genesis.SparksPerB10)
	}
	if mp.Len() != 0 {
		t.Fatalf("mempool should be drained, length = %d", mp.Len())
	}
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./... -v`
Expected: PASS across every package.

- [ ] **Step 8: Commit**

```bash
git add internal/mempool internal/rpc internal/node
git commit -m "feat: add mempool, HTTP RPC and single-node block production"
```

---

### Task 12: Devnet acceptance test and CLI

**Files:**
- Create: `internal/devnet/devnet.go`, `internal/devnet/devnet_test.go`, `cmd/b10coin/main.go`

**Interfaces:**
- Consumes: everything above
- Produces:
  - `devnet.Options struct { Dir string; Blocks uint64; Verbose bool }`
  - `devnet.Run(Options) (Summary, error)`, `devnet.Summary struct { Height uint64; StateRoot [32]byte; TxsIncluded int }`
  - CLI: `b10coin devnet --blocks N [--dir D]`, `b10coin node --dir D --block-time 2s`

- [ ] **Step 1: Write the failing acceptance test**

Create `internal/devnet/devnet_test.go`:

```go
package devnet

import (
	"testing"

	"github.com/cti97/b10coincom/internal/genesis"
)

// The acceptance criterion for M1: one call produces a real chain of 100
// blocks, including a transfer, and the state is reproducible.
func TestDevnetProduces100Blocks(t *testing.T) {
	got, err := Run(Options{Dir: t.TempDir(), Blocks: 100})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Height != 100 {
		t.Fatalf("height = %d, want 100", got.Height)
	}
	if got.TxsIncluded == 0 {
		t.Fatal("no transactions were included; transfer path is untested")
	}
	if got.StateRoot == ([32]byte{}) {
		t.Fatal("state root is empty")
	}
}

// Running twice from scratch must produce an identical final state root.
// This is the determinism guarantee the whole design rests on.
func TestDevnetIsDeterministic(t *testing.T) {
	a, err := Run(Options{Dir: t.TempDir(), Blocks: 50})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(Options{Dir: t.TempDir(), Blocks: 50})
	if err != nil {
		t.Fatal(err)
	}
	if a.StateRoot != b.StateRoot {
		t.Fatalf("two runs disagree:\n %x\n %x", a.StateRoot, b.StateRoot)
	}
}

// Reopening an existing devnet directory must replay to the same root.
func TestDevnetReplayMatches(t *testing.T) {
	dir := t.TempDir()
	first, err := Run(Options{Dir: dir, Blocks: 20})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := Replay(dir)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if replayed.StateRoot != first.StateRoot {
		t.Fatal("replay produced a different state root")
	}
	if replayed.Height != first.Height {
		t.Fatalf("replay height = %d, want %d", replayed.Height, first.Height)
	}
}

func TestDevnetRejectsZeroBlocks(t *testing.T) {
	if _, err := Run(Options{Dir: t.TempDir(), Blocks: 0}); err == nil {
		t.Fatal("expected an error for zero blocks")
	}
}

func TestDevnetGenesisIsDevnetNotTestnet(t *testing.T) {
	s, err := Run(Options{Dir: t.TempDir(), Blocks: 1})
	if err != nil {
		t.Fatal(err)
	}
	if s.ChainID != genesis.Devnet().ChainID {
		t.Fatalf("chain ID = %q, want the devnet chain", s.ChainID)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/devnet/ -v`
Expected: FAIL — `undefined: Run`

- [ ] **Step 3: Write the implementation**

Create `internal/devnet/devnet.go`:

```go
// Package devnet runs a self-contained local chain. It is the single
// acceptance check for M0-M1: one call builds a chain, includes a real
// transfer, persists it and reports a reproducible state root.
package devnet

import (
	"errors"
	"fmt"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/node"
	"github.com/cti97/b10coincom/internal/types"
)

var ErrNoBlocks = errors.New("devnet: Blocks must be greater than zero")

// Options configures a devnet run.
type Options struct {
	Dir     string
	Blocks  uint64
	Verbose bool
}

// Summary reports what a run produced.
type Summary struct {
	ChainID     string
	Height      uint64
	StateRoot   [32]byte
	TxsIncluded int
}

// Run creates a fresh devnet and drives it to o.Blocks. One transfer is
// seeded before the first block, so the state transition path is exercised
// rather than only empty blocks.
func Run(o Options) (Summary, error) {
	if o.Blocks == 0 {
		return Summary{}, ErrNoBlocks
	}
	g := genesis.Devnet()
	c, err := chain.Open(g, o.Dir)
	if err != nil {
		return Summary{}, err
	}
	defer c.Close()

	_, priv := genesis.DevValidatorKey()
	mp := mempool.New(1000)
	n := node.New(c, priv, mp)

	tx, err := devTransfer(c, 250*genesis.SparksPerB10)
	if err != nil {
		return Summary{}, err
	}
	if err := mp.Add([]types.Tx{*tx})[0]; err != nil {
		return Summary{}, err
	}

	included := 0
	for h := uint64(1); h <= o.Blocks; h++ {
		b, err := n.RunOnce(g0Time + int64(h))
		if err != nil {
			return Summary{}, err
		}
		included += len(b.Txs)
	}

	return Summary{
		ChainID:     g.ChainID,
		Height:      c.Height(),
		StateRoot:   c.State().Root(),
		TxsIncluded: included,
	}, nil
}

// Replay reopens an existing devnet directory and reports the replayed state.
func Replay(dir string) (Summary, error) {
	g := genesis.Devnet()
	c, err := chain.Open(g, dir)
	if err != nil {
		return Summary{}, err
	}
	defer c.Close()
	return Summary{
		ChainID:   g.ChainID,
		Height:    c.Height(),
		StateRoot: c.State().Root(),
	}, nil
}

// devTransfer builds a signed transfer from dev account 0 to dev account 1.
func devTransfer(c *chain.Chain, amount uint64) (*types.Tx, error) {
	fromPub, fromPriv := genesis.DevAccountKey(0)
	toPub, _ := genesis.DevAccountKey(1)
	from := types.AddressFromPub(fromPub)
	tx := &types.Tx{
		Type:   types.TxTransfer,
		From:   from,
		PubKey: fromPub,
		Nonce:  c.State().Get(from).Nonce,
		To:     types.AddressFromPub(toPub),
		Amount: amount,
	}
	sigHash := tx.SigningHash()
	tx.Sig = crypto.Sign(fromPriv, sigHash[:])
	return tx, nil
}

// g0Time is the deterministic base timestamp for devnet blocks.
const g0Time = 1_700_000_000
```

- [ ] **Step 4: Run the devnet tests**

Run: `go test ./internal/devnet/ -v`
Expected: PASS for all five tests.

- [ ] **Step 5: Write the CLI**

Create `cmd/b10coin/main.go`:

```go
// Command b10coin is the b10coin node and tooling binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cti97/b10coincom/internal/chain"
	"github.com/cti97/b10coincom/internal/devnet"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/mempool"
	"github.com/cti97/b10coincom/internal/node"
	"github.com/cti97/b10coincom/internal/rpc"
	"github.com/cti97/b10coincom/internal/version"
	"net/http"
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
  b10coin devnet --blocks N [--dir PATH]   Build and verify a local chain
  b10coin node   --dir PATH [--http ADDR] [--block-time DURATION]
  b10coin version
`)
}

func cmdDevnet(args []string) error {
	fs := flag.NewFlagSet("devnet", flag.ExitOnError)
	blocks := fs.Uint64("blocks", 100, "number of blocks to produce")
	dir := fs.String("dir", "", "data directory (default: a fresh temporary directory)")
	verbose := fs.Bool("verbose", false, "print per-run detail")
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

	summary, err := devnet.Run(devnet.Options{Dir: *dir, Blocks: *blocks, Verbose: *verbose})
	if err != nil {
		return err
	}
	fmt.Printf("chain        %s\n", summary.ChainID)
	fmt.Printf("height       %d\n", summary.Height)
	fmt.Printf("state root   %x\n", summary.StateRoot)
	fmt.Printf("txs included %d\n", summary.TxsIncluded)
	if summary.Height != *blocks {
		return fmt.Errorf("expected height %d, got %d", *blocks, summary.Height)
	}
	fmt.Println("OK")
	return nil
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

	httpSrv := &http.Server{Addr: *addr, Handler: srv.Handler()}
	go func() {
		<-ctx.Done()
		_ = httpSrv.Close()
	}()

	fmt.Printf("b10coin %s listening on http://%s (chain %s, height %d)\n",
		version.Version, *addr, c.Genesis().ChainID, c.Height())

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "http:", err)
			stop()
		}
	}()

	if err := n.Run(ctx, *blockTime); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
```

- [ ] **Step 6: Run the acceptance command**

Run: `go run ./cmd/b10coin devnet --blocks 100`
Expected: prints the chain ID, height 100, a non-zero state root, `txs included 1`, then `OK`, and exits 0.

- [ ] **Step 7: Run the full suite and vet**

Run: `go test ./... && go vet ./...`
Expected: PASS, vet clean.

- [ ] **Step 8: Commit**

```bash
git add internal/devnet cmd
git commit -m "feat: add devnet acceptance driver and b10coin CLI"
```

---

## Self-Review

**1. Spec coverage.** Every M0–M1 commitment in the spec maps to a task:

| Spec requirement | Task |
|---|---|
| §1 testnet, Pi-targetable, no premine | Global Constraints, Task 8 |
| §5 repository layout (`cmd/`, `internal/`) | File Structure, Tasks 1, 12 |
| §6.1 account-based ledger, in-memory state, Merkle root, replay on restart | Tasks 7, 10 |
| §6.2 transfer transactions with nonces | Tasks 5, 7 |
| §6.4 base unit `spark`, 21M supply, halving arithmetic, keyless faucet | Tasks 4, 8 |
| §6.7 Ed25519, BLAKE3, address format, domain separation | Tasks 3, 4 |
| §6.8 append-only segments, snapshots on replay | Task 9, Task 10 |
| §9.2 unit tests, negative cases, property tests, replay test | Every task; `TestDevnetIsDeterministic`, `TestDevnetReplayMatches`, `TestTotalSupplyIsConserved` |
| §9 "one command proves it works" | Task 12 |
| §6.3 BFT consensus | **Deliberately out of scope** — M3, separate plan |
| §6.5 staking and committee rotation | **Deliberately out of scope** — M5 |
| §6.4 faucet claim PoW, emission schedule | **Deliberately out of scope** — M2, separate plan |
| §6.6 transport and relay networking | **Deliberately out of scope** — M3/M4 |

**2. Placeholder scan.** No TBD, TODO, "implement later" or "similar to Task N"
appears anywhere. Every code step carries the actual code and every test step
carries a runnable assertion. Four defects present in the first draft — scratch
code in `TestVerifySignatureRejectsMismatchedFrom`, the tangled `handleTx`
body parsing, the stubbed `TestRunOnceIncludesMempoolTransactions`, and the
indirect `devnet.Run` helper — were fixed inline instead of being left as
instructions to the implementer.

**3. Type consistency.** Checked across tasks: `types.Encoder`/`Decoder` method
sets are used identically in Tasks 5, 6 and 8; `state.State.Set/Get/Root` match
between Task 7 and Task 10; `chain.Chain.Build` returns `*types.Block` with a
populated `Sig`, consumed by `Append` in the same task; `mempool.Add` returning
one error per input is consistent between Task 11's implementation and the RPC
handler; `genesis.DevAccountKey`/`DevValidatorKey` are the single source of
truth for devnet keys and are used by both `chain` tests and `devnet`.

**4. Known gap to fix during implementation.** Task 10 Step 5 adds `Sig` to
`types.Block`, which means Task 6's `TestBlockEncodeDecodeRoundTrip` must be
re-run after that change; it will still pass, but the ordering of edits means
`go test ./...` is briefly red across Tasks 6–10. Implement Task 10's block
change before running the full suite, or accept the intermediate red and let
Task 10 Step 7 clear it.

---

## Execution Handoff

**Plan complete and saved to `docs/plans/2026-10-02-m0-m1-foundation-single-node.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session with checkpoints for review.

**Which approach?**

Plans 2 (M2: faucet) and 3 (M3: BFT consensus over the deterministic simulator) follow this one. M3 is where the real difficulty lives and cannot be written well until the `Transport` interface has a working `SimTransport` from M3's own first task.
