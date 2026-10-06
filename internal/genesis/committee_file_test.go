package genesis

// The committee file is audit A-1's replacement for "derive the committee
// from N": these tests pin that the loader accepts exactly the shape the
// deploy recipe tells operators to write — public keys, powers, one chain
// ID of their own choosing — and refuses everything the committee must not
// tolerate (duplicate keys, zero power, empty chain ID, trailing junk).
// Each test names the mutant it kills; the sharpest is the duplicate-key
// refusal, which pins S-5's double-power bug class at the only place an
// operator writes by hand.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

func committeeFileBytes(t *testing.T, pubs ...[]byte) []byte {
	t.Helper()
	entries := make([]CommitteeEntry, 0, len(pubs))
	for i, p := range pubs {
		entries = append(entries, CommitteeEntry{Name: "node-" + string(rune('a'+i)), PubKey: hex.EncodeToString(p), Power: 1})
	}
	raw, err := json.Marshal(CommitteeFile{ChainID: "test-committee-1", Validators: entries})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// testPub derives a distinct deterministic 32-byte value for a test seat.
// The committee file treats it as an Ed25519 public key (32 bytes is all the
// format enforces); nothing in this file signs with one.
func testPub(i int) []byte {
	h := crypto.HashParts([]byte("b10coin-committee-file-test"), []byte{byte(i)})
	return h[:32]
}

// TestCommitteeFileBuildsTheGenesisEveryMemberShares parses a file listing
// one real public key and requires the returned genesis to open the chain
// the file described: the file's chain ID, the file's validator set, the
// fixture parameters, and — the no-premine rule — NO dev accounts.
func TestCommitteeFileBuildsTheGenesisEveryMemberShares(t *testing.T) {
	pub, _ := DevAccountKey(0) // a REAL Ed25519 public key from the fixture
	g, err := ParseCommitteeJSON(committeeFileBytes(t, pub))
	if err != nil {
		t.Fatalf("ParseCommitteeJSON: %v", err)
	}
	if g.ChainID != "test-committee-1" || g.Params.ChainID != g.ChainID {
		t.Fatalf("chain ID not taken from the file: %q / %+v", g.ChainID, g.Params.ChainID)
	}
	if len(g.Validators) != 1 {
		t.Fatalf("committee of %d, want the file's one entry", len(g.Validators))
	}
	if string(g.Validators[0].PubKey) != string(pub) {
		t.Fatal("the file's public key did not survive into the genesis")
	}
	if g.Params.CommitteeSize != 1 {
		t.Fatalf("Params.CommitteeSize %d, want the file's committee size 1 (kept in step so the encoded genesis matches the committee)", g.Params.CommitteeSize)
	}
	if len(g.DevAccounts) != 0 {
		t.Fatalf("a committee file minted %d dev accounts: a shared chain has no premine, ever", len(g.DevAccounts))
	}
	// Fixture parameters deliberately survive: the file is the COMMITTEE
	// section only, so a rogue file cannot mint a richer economy.
	if g.Params.BlockTimeMS != Devnet().Params.BlockTimeMS || g.Params.MaxClaimsPerBlock != Devnet().Params.MaxClaimsPerBlock {
		t.Fatal("the committee file changed fixture parameters; only chain ID and committee come from it")
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("the parsed genesis must validate: %v", err)
	}
	if len(g.Validators[0].PubKey) != ed25519.PublicKeySize {
		t.Fatalf("validator key is %d bytes, want %d", len(g.Validators[0].PubKey), ed25519.PublicKeySize)
	}
}

// TestCommitteeFileSizeIsNotTheIdentity pins the audit's exact wording: the
// committee size must come from the FILE's list, not from the chain ID — and
// the chain ID the file chose is the one the members run, so nothing derives
// simnet-style "size in the name" identities here.
func TestCommitteeFileSizeIsNotTheIdentity(t *testing.T) {
	for _, size := range []int{1, 2, 3} {
		pubs := make([][]byte, size)
		for i := range pubs {
			pubs[i] = testPub(i)
		}
		g, err := ParseCommitteeJSON(committeeFileBytes(t, pubs...))
		if err != nil {
			t.Fatalf("committee of %d: %v", size, err)
		}
		if len(g.Validators) != size || g.Params.CommitteeSize != size {
			t.Fatalf("committee of %d came back as %d entries / Params.CommitteeSize %d", size, len(g.Validators), g.Params.CommitteeSize)
		}
		// The fixture committee's chain ID leaks its size (`b10coin-simnet-N`).
		// A committee file's chain ID must be exactly what the file says — the
		// size must live only in the key list, invisible to /status readers.
		if strings.Contains(g.ChainID, "simnet") {
			t.Fatalf("chain ID %q was derived from the committee; the size must not be published through the chain ID", g.ChainID)
		}
	}
}

// TestCommitteeFileNoteNeverEntersTheHash: the optional note is for humans.
// Two files differing only in their note must describe the SAME chain.
func TestCommitteeFileNoteNeverEntersTheHash(t *testing.T) {
	pub, _ := DevAccountKey(0)
	a := committeeFileBytes(t, pub)
	var f CommitteeFile
	if err := json.Unmarshal(a, &f); err != nil {
		t.Fatal(err)
	}
	f.Note = "edited by hand — must not change the chain"
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	ga, err := ParseCommitteeJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	gb, err := ParseCommitteeJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if ga.Hash() != gb.Hash() {
		t.Fatal("the note field changed the genesis hash: annotations must never be consensus input")
	}
}

// TestCommitteeFileOrderIsConsensus pins that seat position is the entry's
// position: flipping two entries makes a different genesis (different
// proposer draws), so every member must share ONE byte-identical file.
func TestCommitteeFileOrderIsConsensus(t *testing.T) {
	pubA, _ := DevAccountKey(0)
	pubB, _ := DevAccountKey(1)
	ab, err := ParseCommitteeJSON(committeeFileBytes(t, pubA, pubB))
	if err != nil {
		t.Fatal(err)
	}
	ba, err := ParseCommitteeJSON(committeeFileBytes(t, pubB, pubA))
	if err != nil {
		t.Fatal(err)
	}
	if ab.Hash() == ba.Hash() {
		t.Fatal("two different seat orders hashed to one genesis; entry order must be part of the identity")
	}
}

func TestCommitteeFileRejectsBadInput(t *testing.T) {
	pubA, _ := DevAccountKey(0)
	pubB, _ := DevAccountKey(1)
	valid := committeeFileBytes(t, pubA, pubB)

	cases := map[string][]byte{
		"not json":            []byte("hello"),
		"empty chain id":      []byte(`{"chain_id":"","validators":[]}`),
		"no validators":       []byte(`{"chain_id":"x","validators":[]}`),
		"trailing junk":       append(append([]byte{}, valid...), []byte("garbage")...),
		"bad hex pubkey":      []byte(`{"chain_id":"x","validators":[{"pubkey":"zz","power":1}]}`),
		"short pubkey":        []byte(`{"chain_id":"x","validators":[{"pubkey":"abcd","power":1}]}`),
		"zero power":          []byte(`{"chain_id":"x","validators":[{"pubkey":"` + hex.EncodeToString(pubA) + `","power":0}]}`),
		"duplicate pubkey":    committeeFileBytes(t, pubA, pubA),
		"too many seats":      committeeFileBytes256(t),
		"missing validators":  []byte(`{"chain_id":"x"}`),
		"whitespace chain id": []byte(`{"chain_id":"   ","validators":[{"pubkey":"` + hex.EncodeToString(pubA) + `","power":1}]}`),
	}
	for name, body := range cases {
		g, err := ParseCommitteeJSON(body)
		if err == nil {
			t.Errorf("%s: accepted; chain %q with %d validators", name, g.ChainID, len(g.Validators))
			continue
		}
		if !errors.Is(err, ErrBadCommitteeFile) {
			t.Errorf("%s: error must carry ErrBadCommitteeFile, got %v", name, err)
		}
	}
}

// TestSeatOfPubKeyNamesTheListedSeat: the seat is the public key's POSITION,
// and an unlisted key is -1 — the value that makes a validator refuse to
// start rather than silently sign as a seat it does not hold (audit A-1).
func TestSeatOfPubKeyNamesTheListedSeat(t *testing.T) {
	pubA, _ := DevAccountKey(0)
	pubB, _ := DevAccountKey(1)
	g, err := ParseCommitteeJSON(committeeFileBytes(t, pubA, pubB))
	if err != nil {
		t.Fatal(err)
	}
	if got := SeatOfPubKey(g.Validators, pubB); got != 1 {
		t.Fatalf("seat of pubB = %d, want 1 (its position)", got)
	}
	stranger := make([]byte, 32)
	if got := SeatOfPubKey(g.Validators, stranger); got != -1 {
		t.Fatalf("seat of an unlisted key = %d, want -1", got)
	}
}

func committeeFileBytes256(t *testing.T) []byte {
	t.Helper()
	// 256 seats with 256 DISTINCT keys — the ceiling test must fail on the
	// count, never on a duplicate.
	f := CommitteeFile{ChainID: "huge", Validators: make([]CommitteeEntry, 256)}
	for i := range f.Validators {
		b := make([]byte, 32)
		b[0], b[1] = byte(i>>8)+1, byte(i)
		f.Validators[i] = CommitteeEntry{PubKey: hex.EncodeToString(b), Power: 1}
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
