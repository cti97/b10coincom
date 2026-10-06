package devnet

// The genesis-file mode is audit A-1's core fix: the committee comes from a
// shared file of PUBLIC keys and each validator signs with a key it holds.
// These tests kill the mutants that would reopen A-1:
//
//   - a membership mutant returning seat 0 (or an error suppressed into a
//     fallback) lets a stranger key sign as any seat —
//     TestStartValidatorRefusesAKeyOutsideTheCommittee.
//   - a "nil key means derive fixture" mutant in genesis-file mode would
//     relaunch the publicly-derivable committee from the real path —
//     TestStartValidatorRequiresAKeyInGenesisMode.
//   - the signature-swap mutant (committee listed but keys ignored) can only
//     survive if a --key committee still FINALISES over real TCP —
//     TestGenesisFileCommitteeFinalisesOverRealTCP, which also proves a
//     peer ACCEPTS a --key node's votes (the votes verify against the file's
//     public keys) while the derived-fixture key of the same seat would be
//     refused before any message is signed.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cti97/b10coincom/internal/crypto"
	"github.com/cti97/b10coincom/internal/genesis"
	"github.com/cti97/b10coincom/internal/simnet"
)

// committeeGenesisWithKeys builds a genesis-file-mode committee listing the
// given REAL random keys, going through the same loader the CLI runs.
func committeeGenesisWithKeys(t *testing.T, chainID string, pubs []ed25519.PublicKey) (*genesis.Genesis, error) {
	t.Helper()
	entries := make([]genesis.CommitteeEntry, 0, len(pubs))
	for i, p := range pubs {
		entries = append(entries, genesis.CommitteeEntry{Name: fmt.Sprintf("node-%d", i), PubKey: fmt.Sprintf("%x", []byte(p)), Power: 1})
	}
	raw, err := json.Marshal(genesis.CommitteeFile{ChainID: chainID, Validators: entries})
	if err != nil {
		t.Fatal(err)
	}
	return genesis.ParseCommitteeJSON(raw)
}

func randomKeys(t *testing.T, n int) []ed25519.PrivateKey {
	t.Helper()
	out := make([]ed25519.PrivateKey, n)
	for i := range out {
		pub, priv, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		_ = pub
		out[i] = priv
	}
	return out
}

// TestStartValidatorRefusesAKeyOutsideTheCommittee is the audit's refusal
// requirement verbatim: a validator whose key is not in the committee must
// refuse to start with a clear message, never silently sign as a seat it
// does not hold. The mutant this kills: StartValidator defaulting the seat
// to 0 (the fixture path's shape) when the key lookup misses — which would
// let a stranger impersonate seat 0 of any committee whose file it obtains.
func TestStartValidatorRefusesAKeyOutsideTheCommittee(t *testing.T) {
	keys := randomKeys(t, 2)
	g, err := committeeGenesisWithKeys(t, "outside-key-test", []ed25519.PublicKey{keys[0].Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	// keys[1] is a genuinely generated key that the file does NOT list —
	// the strongest form of the attack scenario.
	_, err = StartValidator(ValidatorConfig{Dir: t.TempDir(), Genesis: g, Key: keys[1]})
	if err == nil {
		t.Fatal("a validator whose key is not in the committee must refuse to start")
	}
	for _, want := range []string{"not listed", "committee"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name the problem (%q missing): %v", want, err)
		}
	}
}

func TestStartValidatorRefusesAFixtureDerivedKeyAgainstARealCommittee(t *testing.T) {
	// The audit attack in one line: the old fixture key schedule cannot be a
	// member of a real committee, so the fixture-derived seat 0 must be
	// refused exactly like any other stranger key.
	keys := randomKeys(t, 1)
	g, err := committeeGenesisWithKeys(t, "fixture-key-test", []ed25519.PublicKey{keys[0].Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = StartValidator(ValidatorConfig{Dir: t.TempDir(), Genesis: g, Key: simnet.ValidatorKey(0)})
	if err == nil {
		t.Fatal("the publicly derivable fixture key must be refused by a genesis-file committee")
	}
	if !strings.Contains(err.Error(), "not listed") {
		t.Errorf("refusal must be the membership refusal, got: %v", err)
	}
}

func TestStartValidatorRequiresAKeyInGenesisMode(t *testing.T) {
	keys := randomKeys(t, 1)
	g, err := committeeGenesisWithKeys(t, "keyless-test", []ed25519.PublicKey{keys[0].Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StartValidator(ValidatorConfig{Dir: t.TempDir(), Genesis: g}); err == nil {
		t.Fatal("genesis-file mode without a key must fail loudly, not fall back to a fixture key")
	}
	// A contradictory fixture flag alongside --genesis is refused, not
	// ignored: it names a committee the file did not choose.
	if _, err := StartValidator(ValidatorConfig{Dir: t.TempDir(), Genesis: g, Key: keys[0], Index: 1}); err == nil {
		t.Fatal("--index alongside a genesis file must be refused")
	}
}

// TestGenesisFileCommitteeFinalisesOverRealTCP proves the mode END TO END:
// two validators listed by public key in one file, each signing with its own
// held key, finalise over real sockets and hold one history. A peer accepts
// the --key node's votes because they verify against the FILE's public keys;
// the fixture-derived key in the test above could not have signed at all.
func TestGenesisFileCommitteeFinalisesOverRealTCP(t *testing.T) {
	keys := randomKeys(t, 2)
	g, err := committeeGenesisWithKeys(t, "keyfile-finalise-test", []ed25519.PublicKey{
		keys[0].Public().(ed25519.PublicKey),
		keys[1].Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	vs := make([]*Validator, 2)
	for i := 0; i < 2; i++ {
		vs[i], err = StartValidator(ValidatorConfig{Dir: t.TempDir(), Genesis: g, Key: keys[i], Listen: "127.0.0.1:0"})
		if err != nil {
			t.Fatalf("starting key-file validator %d: %v", i, err)
		}
		defer func(i int) { _ = vs[i].Close() }(i)
		if seat := vs[i].Seat(); seat != i {
			t.Fatalf("validator %d derived seat %d from its key, want %d", i, seat, i)
		}
	}
	if err := connectMesh(vs); err != nil {
		t.Fatal(err)
	}
	h := waitConvergedEqual(t, vs, 4, 90*time.Second)
	assertIdenticalHistory(t, vs, h)
	// Each member's own key produced votes: the vote-heights recorded on the
	// wire prove this validator SIGNED (its key verified against the file's
	// listed public keys), which is the "a --key node produces votes a peer
	// accepts" half of the audit's proof.
	for i := range vs {
		if len(vs[i].VotedHeights()) == 0 {
			t.Fatalf("validator %d never put a vote on the wire; no held-key signature was exercised", i)
		}
	}
}
