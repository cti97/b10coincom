package keystore

// The key file is the audit A-1 trust anchor: the ONLY container of real
// validator key material. Each test names the mutant that must die:
//
//   - a permissions mutant (0600 -> 0644, or a dropped chmod) makes the key
//     readable by group/others — TestGenerateWritesAnOwnerOnlyKeyFile.
//   - a no-overwrite mutant (O_EXCL dropped, or the existing file quietly
//     truncated) turns a careless rerun into a silently replaced identity —
//     TestGenerateRefusesToOverwrite.
//   - a load mutant that skips the recorded-versus-derived public key check
//     would use a mangled or doctored file as-is — TestLoadRefusesAMismatchingPublicKey.
//   - a load mutant that skips the permission check re-opens the read-anywhere
//     hole on every later run — TestLoadRefusesAGroupReadableKeyFile.

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenerateWritesAnOwnerOnlyKeyFileAndLoadRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b10coin.key")
	f, priv, err := Generate(path)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if f.Version != FileVersion {
		t.Fatalf("version %d, want %d", f.Version, FileVersion)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no owner-only mode; on the Unix targets the file must be
	// EXACTLY owner-rw, not merely "not world readable" (0606 was never the
	// contract).
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %04o, want 0600", info.Mode().Perm())
	}

	priv2, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	pub1, _ := priv.Public().(ed25519.PublicKey)
	pub2, _ := priv2.Public().(ed25519.PublicKey)
	if string(pub1) != string(pub2) {
		t.Fatal("Load returned a different key than Generate wrote")
	}
}

func TestGenerateRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b10coin.key")
	if _, _, err := Generate(path); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Generate(path)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second Generate must refuse with ErrExists, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the refused overwrite still touched the file: the original key must survive byte-for-byte")
	}
}

func TestGenerateCreatesTheParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "b10coin.key")
	if _, _, err := Generate(path); err != nil {
		t.Fatalf("Generate into a fresh parent: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file missing after Generate: %v", err)
	}
}

func TestLoadRefusesAGroupReadableKeyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports no Unix mode bits; the permission check is skipped by design there")
	}
	path := filepath.Join(t.TempDir(), "b10coin.key")
	if _, _, err := Generate(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if !errors.Is(err, ErrBadPermissions) {
		t.Fatalf("a 0644 key file must be refused with ErrBadPermissions, got %v", err)
	}
}

func TestLoadRefusesAMismatchingPublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b10coin.key")
	if _, priv, err := Generate(path); err != nil {
		t.Fatal(err)
	} else {
		// Overwrite the file with a doctored one: right private key, wrong
		// recorded public half. Load must notice rather than sign as a key
		// the file's own body contradicts.
		pub, _ := priv.Public().(ed25519.PublicKey)
		forged := `{"version":1,"private_key":"` + hexOf(priv) +
			`","public_key":"` + hexOf(pub[:len(pub)-1]) + `ab"`
		if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a key file whose public half contradicts its private key must be refused")
	}
}

func TestLoadRefusesGarbageUnknownVersionsAndWrongSizes(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"not json":     "this is not a key file",
		"bad version":  `{"version":99,"private_key":"","public_key":""}`,
		"bad hex":      `{"version":1,"private_key":"zz","public_key":""}`,
		"short key":    `{"version":1,"private_key":"abcd","public_key":""}`,
		"empty object": `{}`,
	}
	for name, content := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".key")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); !errors.Is(err, ErrBadKeyFile) {
			t.Errorf("%s: Load must refuse with ErrBadKeyFile, got %v", name, err)
		}
	}
}

func hexOf(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0xf])
	}
	return string(out)
}
