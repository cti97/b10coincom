package genesis

// The committee file is audit A-1's replacement for "derive the committee
// from N": these tests pin that the loader accepts exactly the shape the
// deploy recipe tells operators to write — public keys, powers, one chain
// ID of their own choosing — and refuses everything the committee must not
// tolerate (duplicate keys, zero power, empty chain ID, trailing junk).
// Each test names the mutant it kills; the sharpest is the duplicate-key
// refusal, which pins S-5's double-power bug class at the only place an
// operator writes by hand.
//
// Audit RT-2 added two rules and the tests below pin both: a power under
// MIN_STAKE is refused (a one-spark genesis bond is a committee-capture
// vector, not a small stake), and an optional committee_size may exceed the
// key list so admission does not imply eviction. The helper therefore writes
// MIN_STAKE, not one spark — the pre-RT-2 shape is now the thing under test.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cti97/b10coincom/internal/crypto"
)

func committeeFileBytes(t *testing.T, pubs ...[]byte) []byte {
	t.Helper()
	entries := make([]CommitteeEntry, 0, len(pubs))
	minPower := Devnet().Params.MinStakeSparks
	for i, p := range pubs {
		entries = append(entries, CommitteeEntry{Name: "node-" + string(rune('a'+i)), PubKey: hex.EncodeToString(p), Power: minPower})
	}
	raw, err := json.Marshal(CommitteeFile{ChainID: "test-committee-1", Validators: entries})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// committeeFileBytesWithSize is committeeFileBytes plus an explicit seat count,
// so a test can ask for spare seats (or too few).
func committeeFileBytesWithSize(t *testing.T, size int, pubs ...[]byte) []byte {
	t.Helper()
	var f CommitteeFile
	if err := json.Unmarshal(committeeFileBytes(t, pubs...), &f); err != nil {
		t.Fatal(err)
	}
	f.CommitteeSize = size
	raw, err := json.Marshal(f)
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
	// A valid power, so each case below fails for its NAMED reason and not
	// for the RT-2 floor.
	minPower := Devnet().Params.MinStakeSparks

	cases := map[string][]byte{
		"not json":            []byte("hello"),
		"empty chain id":      []byte(`{"chain_id":"","validators":[]}`),
		"no validators":       []byte(`{"chain_id":"x","validators":[]}`),
		"trailing junk":       append(append([]byte{}, valid...), []byte("garbage")...),
		"bad hex pubkey":      []byte(fmt.Sprintf(`{"chain_id":"x","validators":[{"pubkey":"zz","power":%d}]}`, minPower)),
		"short pubkey":        []byte(fmt.Sprintf(`{"chain_id":"x","validators":[{"pubkey":"abcd","power":%d}]}`, minPower)),
		"zero power":          []byte(`{"chain_id":"x","validators":[{"pubkey":"` + hex.EncodeToString(pubA) + `","power":0}]}`),
		"duplicate pubkey":    committeeFileBytes(t, pubA, pubA),
		"too many seats":      committeeFileBytes256(t),
		"missing validators":  []byte(`{"chain_id":"x"}`),
		"whitespace chain id": []byte(fmt.Sprintf(`{"chain_id":"   ","validators":[{"pubkey":"%s","power":%d}]}`, hex.EncodeToString(pubA), minPower)),
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

// TestCommitteeFileRefusesAPowerBelowMinStake is RT-2's refusal. A seat's
// power IS its genesis bond (chain.genesisState writes Amount = Power,
// unscaled), so the file may not create a bond the state refuses a Bond
// transaction to create. Before this rule the shipped three-Pi recipe
// (`"power": 1`) let ONE MIN_STAKE bond hold 10^11 of 10^11+2 of the power —
// about 100% — because the cap does not bind below four seats.
//
// The boundary is exercised on both sides at the shipped value (10^11): one
// spark under is refused, the floor itself is accepted.
func TestCommitteeFileRefusesAPowerBelowMinStake(t *testing.T) {
	pubA, _ := DevAccountKey(0)
	pubB, _ := DevAccountKey(1)
	minPower := Devnet().Params.MinStakeSparks
	if minPower != 100_000_000_000 {
		t.Fatalf("MIN_STAKE is %d sparks, want 10^11 (1,000 b10); this test's boundary is the shipped one", minPower)
	}

	for _, tc := range []struct {
		name  string
		power uint64
		want  bool // accepted?
	}{
		{"one spark (the shipped example before RT-2)", 1, false},
		{"one spark under the floor", minPower - 1, false},
		{"the floor itself", minPower, true},
		{"above the floor", minPower + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"chain_id":"rt2","validators":[{"pubkey":"%s","power":%d},{"pubkey":"%s","power":%d}]}`,
				hex.EncodeToString(pubA), tc.power, hex.EncodeToString(pubB), minPower))
			g, err := ParseCommitteeJSON(raw)
			if tc.want {
				if err != nil {
					t.Fatalf("power %d must be accepted at MIN_STAKE %d, got %v", tc.power, minPower, err)
				}
				if g.Validators[0].Power != tc.power {
					t.Fatalf("power = %d, want the file's %d (no rescaling)", g.Validators[0].Power, tc.power)
				}
				return
			}
			if err == nil {
				t.Fatalf("power %d sparks was accepted against MIN_STAKE %d: a genesis bond under the candidacy floor is the RT-2 capture vector", tc.power, minPower)
			}
			if !errors.Is(err, ErrBadCommitteeFile) {
				t.Fatalf("the refusal must carry ErrBadCommitteeFile, got %v", err)
			}
			if !strings.Contains(err.Error(), "MIN_STAKE") {
				t.Fatalf("the refusal must name MIN_STAKE and the seat, got: %v", err)
			}
		})
	}
}

// TestCommitteeFileSpareSeatsAreAConsensusParameter: committee_size above the
// key list is accepted and lands in the genesis (so it is in the genesis hash),
// and a committee smaller than the list is refused — a key the file publishes
// must be able to hold a seat. Zero keeps the old default (one seat per key),
// which is the only way an existing file's hash can stay the same.
func TestCommitteeFileSpareSeatsAreAConsensusParameter(t *testing.T) {
	pubA, _ := DevAccountKey(0)
	pubB, _ := DevAccountKey(1)

	g, err := ParseCommitteeJSON(committeeFileBytesWithSize(t, 4, pubA, pubB))
	if err != nil {
		t.Fatalf("committee_size 4 over 2 validators must be accepted (spare seats): %v", err)
	}
	if g.Params.CommitteeSize != 4 || len(g.Validators) != 2 {
		t.Fatalf("committee_size = %d over %d validators, want 4 over 2", g.Params.CommitteeSize, len(g.Validators))
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("the parsed genesis must validate: %v", err)
	}

	// The seat count is consensus input, not a note: two files differing only in
	// committee_size must be two different chains.
	four, err := ParseCommitteeJSON(committeeFileBytesWithSize(t, 4, pubA, pubB))
	if err != nil {
		t.Fatal(err)
	}
	three, err := ParseCommitteeJSON(committeeFileBytesWithSize(t, 3, pubA, pubB))
	if err != nil {
		t.Fatal(err)
	}
	if four.Hash() == three.Hash() {
		t.Fatal("committee_size did not enter the genesis hash: the seat count is consensus input")
	}

	// Smaller than the list is refused.
	if _, err := ParseCommitteeJSON(committeeFileBytesWithSize(t, 1, pubA, pubB)); err == nil {
		t.Fatal("committee_size 1 over 2 validators was accepted: a published seat could never be seated")
	} else if !errors.Is(err, ErrBadCommitteeFile) {
		t.Fatalf("a too-small committee_size must carry ErrBadCommitteeFile, got %v", err)
	}
	// Past the ceiling is refused, with the committee-file sentinel.
	if _, err := ParseCommitteeJSON(committeeFileBytesWithSize(t, maxCommitteeSize+1, pubA)); err == nil {
		t.Fatal("committee_size past the 255-seat ceiling was accepted")
	} else if !errors.Is(err, ErrBadCommitteeFile) {
		t.Fatalf("an over-ceiling committee_size must carry ErrBadCommitteeFile, got %v", err)
	}
	// Absent means the list's length.
	def, err := ParseCommitteeJSON(committeeFileBytes(t, pubA, pubB))
	if err != nil {
		t.Fatal(err)
	}
	if def.Params.CommitteeSize != 2 {
		t.Fatalf("default committee_size = %d, want the list's 2", def.Params.CommitteeSize)
	}
}

// TestTheShippedExampleCommitteeFileIsLoadable pins the example file the deploy
// recipe tells operators to copy. The audit's section 6 recorded "example file
// untested", and RT-2's vector was exactly that file's "power": 1 — so the
// checked-in example must parse, carry no sub-floor seat, and ask for at least
// one spare seat (admission without eviction).
func TestTheShippedExampleCommitteeFileIsLoadable(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/deploy/committee.example.json")
	if err != nil {
		t.Fatalf("the deploy recipe's example file is missing or unreadable: %v", err)
	}
	g, err := ParseCommitteeJSON(raw)
	if err != nil {
		t.Fatalf("scripts/deploy/committee.example.json does not load: %v", err)
	}
	minPower := Devnet().Params.MinStakeSparks
	for i, v := range g.Validators {
		if v.Power < minPower {
			t.Fatalf("the shipped example's validator %d carries power %d, under MIN_STAKE %d: it would ship RT-2's one-spark genesis seat", i, v.Power, minPower)
		}
	}
	if g.Params.CommitteeSize <= len(g.Validators) {
		t.Fatalf("the shipped example asks for committee_size %d over %d validators: it must leave a spare seat so admission does not imply eviction",
			g.Params.CommitteeSize, len(g.Validators))
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
	// count, never on a duplicate or the power floor.
	f := CommitteeFile{ChainID: "huge", Validators: make([]CommitteeEntry, 256)}
	for i := range f.Validators {
		b := make([]byte, 32)
		b[0], b[1] = byte(i>>8)+1, byte(i)
		f.Validators[i] = CommitteeEntry{PubKey: hex.EncodeToString(b), Power: Devnet().Params.MinStakeSparks}
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
