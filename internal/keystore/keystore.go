// Package keystore reads and writes the operator key file: the one file that
// holds a validator's Ed25519 private key.
//
// Until the audit's A-1 fix nothing on disk held key material: every seat of
// the networked fixture committee derived its private key from the public
// seed "b10coin-simnet-validator" plus the seat number, so anyone with the
// repository could sign as any validator. This package is the minimum that
// changes: operators generate REAL keys (`b10coin keygen`), the key lands in
// a file with owner-only permissions, the file refuses to be overwritten
// (regenerating over a live validator's key would silently fork its identity),
// and loading re-derives the public key to refuse a file whose two halves
// disagree.
//
// The file format is deliberately boring JSON (versioned, hex key material):
// an operator can inspect it with any tool, and the version field gives a
// future format change an explicit rejection path instead of silent misuse.
package keystore

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cti97/b10coincom/internal/crypto"
)

// FileVersion is the only key-file version this build reads or writes.
const FileVersion = 1

var (
	// ErrExists reports that Generate refused to overwrite an existing key
	// file. Overwriting is never an accident worth allowing: the second
	// generation produces a DIFFERENT key, so an incautious rerun would
	// orphan the key the genesis already lists.
	ErrExists = errors.New("keystore: refusing to overwrite an existing key file")
	// ErrBadKeyFile reports an unreadable, unparseable or self-inconsistent
	// key file.
	ErrBadKeyFile = errors.New("keystore: invalid key file")
	// ErrBadPermissions reports a key file readable by group or others. A
	// private key that leaks its permissions leaks its votes.
	ErrBadPermissions = errors.New("keystore: key file must be readable only by its owner (chmod 600)")
)

// File is the JSON document written by Generate and read by Load.
type File struct {
	// Version pins the format. Load refuses anything it does not know.
	Version int `json:"version"`
	// PrivateKey is the 64-byte Ed25519 private key as 128 hex characters.
	PrivateKey string `json:"private_key"`
	// PublicKey is the matching 32-byte public key as 64 hex characters.
	// It is the convenience that lets an operator verify what a file signs
	// as WITHOUT loading the private half into any other tool.
	PublicKey string `json:"public_key"`
	// CreatedAt is the generation time, purely documentary.
	CreatedAt time.Time `json:"created_at"`
	// Note is optional operator annotation, ignored on load.
	Note string `json:"note,omitempty"`
}

// Generate creates a fresh Ed25519 keypair and writes it to path as a JSON
// key file with owner-only permissions. It refuses to overwrite an existing
// file (ErrExists): a keygen rerun that silently replaced the key would turn
// a running validator into an impostor of its own seat.
func Generate(path string) (*File, ed25519.PrivateKey, error) {
	// The parent directory is made owner-only as well: a 0755 directory
	// between a 0600 key and the world is how keys leak to co-hosted users.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, nil, fmt.Errorf("keystore: creating %s: %w", dir, err)
		}
	}

	pub, priv, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("keystore: generating key: %w", err)
	}
	f := &File{
		Version:    FileVersion,
		PrivateKey: hex.EncodeToString(priv),
		PublicKey:  hex.EncodeToString(pub),
		CreatedAt:  time.Now().UTC(),
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	raw = append(raw, '\n')

	// O_EXCL is the no-overwrite guarantee at open time, not a checked
	// beforehand race window. 0o600 is the mode the directory contract
	// expects; the explicit Chmod below pins it even under a shared umask.
	fd, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, nil, fmt.Errorf("%w: %s (a second run always derives a DIFFERENT key; regenerate only on purpose, elsewhere)", ErrExists, path)
		}
		return nil, nil, fmt.Errorf("keystore: cannot create %s: %w", path, err)
	}
	if _, err := fd.Write(raw); err != nil {
		fd.Close()
		return nil, nil, fmt.Errorf("keystore: writing %s: %w", path, err)
	}
	if err := fd.Close(); err != nil {
		return nil, nil, fmt.Errorf("keystore: closing %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, nil, fmt.Errorf("keystore: pinning permissions on %s: %w", path, err)
	}
	return f, priv, nil
}

// Load reads and validates the key file at path and returns its private key.
//
// Two things are checked beyond parseability, because a node that silently
// used a broken key file would sign as nobody:
//   - the recorded public key must equal the public key the private key
//     derives (a mangled copy fails here, at the operator, not on the wire);
//   - on Unix, the file must be owner-only readable (see ErrBadPermissions).
//     Windows has no Unix permission model; the check is skipped there and
//     file security rests on the filesystem's own ACLs.
func Load(path string) (ed25519.PrivateKey, error) {
	if info, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%w: cannot stat %s: %v", ErrBadKeyFile, path, err)
	} else if info.IsDir() {
		return nil, fmt.Errorf("%w: %s is a directory", ErrBadKeyFile, path)
	} else if perm := info.Mode().Perm(); perm&(0o077) != 0 && !isWindows {
		return nil, fmt.Errorf("%w: %s has mode %04o", ErrBadPermissions, path, perm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %v", ErrBadKeyFile, path, err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%w: %s is not a key file: %v", ErrBadKeyFile, path, err)
	}
	if f.Version != FileVersion {
		return nil, fmt.Errorf("%w: %s declares format version %d, this build reads %d", ErrBadKeyFile, path, f.Version, FileVersion)
	}
	privBytes, err := hex.DecodeString(strings.TrimSpace(f.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: private key is not hex: %v", ErrBadKeyFile, path, err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: %s: private key is %d bytes, want %d", ErrBadKeyFile, path, len(privBytes), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(privBytes)
	if len(f.PublicKey) > 0 {
		pubBytes, err := hex.DecodeString(strings.TrimSpace(f.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("%w: %s: public key is not hex: %v", ErrBadKeyFile, path, err)
		}
		derived, _ := priv.Public().(ed25519.PublicKey)
		if len(pubBytes) != ed25519.PublicKeySize || string(pubBytes) != string(derived) {
			return nil, fmt.Errorf("%w: %s: recorded public key does not match the private key (a damaged or doctored file)", ErrBadKeyFile, path)
		}
	}
	return priv, nil
}

// isWindows keeps the Unix-only permission check from refusing every key file
// on Windows, where os.Stat reports no Unix mode bits.
var isWindows = os.PathSeparator == '\\'
