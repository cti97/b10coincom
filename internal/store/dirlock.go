// Data-directory ownership.
//
// The store is an append-only log with no coordination between writers: two
// processes (or two handles in one process) pointed at the same directory
// each Seek to their own end offset and interleave records into the same
// segment and the same lock log, and each numbers the heights from its own
// record count. The result is a corrupted block log and, worse, a validator's
// precommit promise interleaved by its twin - exactly the safety evidence the
// lock log exists to keep intact.
//
// So Open takes an exclusive lock on a LOCK file in the directory and holds
// it until Close. The lock is a stdlib-only pidfile created atomically with
// os.Link, not a kernel advisory lock: no build-tagged syscall is needed, and
// the package builds unchanged on macOS, Linux and Windows.
//
//   - Acquisition is os.Link(tmp, LOCK) from a fully-written unique temp
//     file. Link is atomic and fails with EEXIST if the name is taken, so two
//     processes starting together produce exactly one winner; and because the
//     published file is already complete, no reader can observe a half-built
//     owner. A plain O_CREATE|O_EXCL followed by a write would expose an
//     empty window in which a second process could mistake a live lock for a
//     crash.
//   - The owner is recorded as its PID plus a random per-process token.
//     Staleness is decided by PID liveness (kill(pid, 0) on Unix,
//     OpenProcess on Windows): a lock whose owner is dead is broken by the
//     next Open. The token is what keeps our own reused PID from being read
//     as our own lock.
//   - Concurrent breaking of the same stale lock is serialised through a
//     second link-created file, LOCK.break. The breaker re-reads LOCK while
//     holding that mutex and refuses to remove a lock that has meanwhile
//     become live: recovery must never delete the winner another process
//     just installed. A break mutex left by a SIGKILL is NOT auto-cleared:
//     only the process that created a marker may unlink it, because
//     remove-after-read of a marker is precisely how two recoverers could
//     each destroy the other's fresh lock. It is reported for operator
//     removal instead.
//   - The lock is NOT re-entrant, within a process or across processes: two
//     *Store handles on one directory would interleave exactly as two
//     processes would, so a second Open is refused and told why. Close
//     releases the lock, after which the directory can be reopened.
//
// What this does NOT protect against, stated plainly:
//
//   - A reused PID. If a crashed owner's PID is later taken by an unrelated
//     process, its stale lock looks live and Open refuses until an operator
//     removes <dir>/LOCK. This implementation catches the one reuse it can
//     see (the PID is ours but the token is not) and documents the rest.
//   - A breaker SIGKILLed inside its tiny recovery critical section. Its
//     <dir>/LOCK.break is left behind and the next recovery refuses with a
//     message naming both files for the operator to remove. This is the one
//     automatic-recovery gap, and it is deliberate: silently deleting a
//     marker is the only way two recoverers could both become writers.
//   - A filesystem without hard links (some FAT/exFAT volumes, some network
//     filesystems). os.Link fails there and Open fails loudly rather than
//     running unsynchronised.
//   - An operator who deletes the LOCK file while an owner is live: a second
//     process would then be admitted. The LOCK file is part of the data
//     directory's state, not disposable.
//
// It is deliberately a file comment, not the package comment: store.go's
// package doc owns the record/framing story.

package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// lockFileName is the data-directory ownership marker. It deliberately does
// not end in ".seg", so scan never indexes it as a block height, and it is a
// different file from the consensus lock log (locks.log).
const lockFileName = "LOCK"

// breakFileName serialises concurrent recovery of one stale LOCK.
const breakFileName = "LOCK.break"

// lockFileMagic heads every lock file. A file without it is not one this
// package wrote and is treated as stale.
const lockFileMagic = "b10coin-data-dir-lock 1"

const (
	// lockAcquireAttempts bounds the retry loop that breaks stale locks. A
	// live, foreign owner is refused on the first pass; only stale or
	// vanishing locks consume attempts.
	lockAcquireAttempts = 50
	// lockBreakAttempts bounds waiting on the break mutex.
	lockBreakAttempts = 50
	// lockBreakWait is how long to yield to another process's in-progress
	// recovery before retrying. It is only ever reached while another live
	// process holds the break mutex.
	lockBreakWait = 2 * time.Millisecond
)

// ErrDataDirInUse is returned by Open when the directory is already owned by
// another process (or by another open Store in this process). The error names
// the directory and, when known, the owning PID.
var ErrDataDirInUse = errors.New("store: data directory is already being written by another process")

// processToken is a random value minted once per process. Together with the
// PID it identifies this process's lock: a lock file naming our PID but a
// different token was written by a dead predecessor whose PID we now hold.
var (
	processTokenOnce sync.Once
	processTokenVal  string
	processTokenErr  error
)

func processToken() (string, error) {
	processTokenOnce.Do(func() {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			processTokenErr = err
			return
		}
		processTokenVal = hex.EncodeToString(b[:])
	})
	return processTokenVal, processTokenErr
}

// dirLockMu serialises acquisitions within this process. It is not the
// mutual exclusion - the LOCK file is - but the break mutex is identified by
// pid and process token, which cannot tell two goroutines of one process
// apart; serialising them here means a LOCK.break naming this process is
// always a leftover this process may safely clear, never a sibling mid-break.
// It is held across the whole acquire, including the bounded stale-recovery
// wait.
var dirLockMu sync.Mutex

// lockHolder is the parsed content of a lock file.
type lockHolder struct {
	pid   int
	token string
}

// dirLock is an acquired data-directory lock.
type dirLock struct {
	path  string // the LOCK file
	token string // this process's token, as written
}

func lockContent(token string) string {
	return fmt.Sprintf("%s\npid %d\nproc %s\n", lockFileMagic, os.Getpid(), token)
}

func parseLockHolder(raw []byte) (lockHolder, bool) {
	lines := strings.Split(string(raw), "\n")
	if len(lines) == 0 || lines[0] != lockFileMagic {
		return lockHolder{}, false
	}
	var h lockHolder
	var havePID, haveToken bool
	for _, ln := range lines[1:] {
		switch {
		case strings.HasPrefix(ln, "pid "):
			n, err := strconv.Atoi(strings.TrimPrefix(ln, "pid "))
			if err != nil || n <= 0 {
				return lockHolder{}, false
			}
			h.pid, havePID = n, true
		case strings.HasPrefix(ln, "proc "):
			t := strings.TrimPrefix(ln, "proc ")
			if t == "" {
				return lockHolder{}, false
			}
			h.token, haveToken = t, true
		}
	}
	return h, havePID && haveToken
}

// readLockHolder reads and parses a lock file. The boolean is false when the
// file is gone, empty, or not in this package's format - in every case there
// is no live owner this package recorded.
func readLockHolder(path string) (lockHolder, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return lockHolder{}, false
	}
	return parseLockHolder(raw)
}

// holderIsLiveProcess reports whether a recorded holder is a live process
// that is not this one. A holder with our PID and our token is this process
// (live); with a foreign token it is a dead predecessor whose PID we reused.
func holderIsLiveProcess(h lockHolder, token string) bool {
	if h.pid == os.Getpid() {
		return h.token == token
	}
	return processAlive(h.pid)
}

// stageLockFile writes a complete ownership record to a unique temp file in
// dir and returns its path. The caller links it into place; on any failure it
// removes the temp. CreateTemp uses O_CREATE|O_EXCL and 0600.
func stageLockFile(dir, token string) (string, error) {
	f, err := os.CreateTemp(dir, lockFileName+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("store: staging the data-directory lock in %s: %w", dir, err)
	}
	name := f.Name()
	if _, err := f.WriteString(lockContent(token)); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("store: writing the data-directory lock %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("store: closing the staged data-directory lock %s: %w", name, err)
	}
	return name, nil
}

// acquireDirLock takes the exclusive lock on dir or returns an error. dir
// must already exist.
func acquireDirLock(dir string) (*dirLock, error) {
	token, err := processToken()
	if err != nil {
		return nil, fmt.Errorf("store: data-directory lock: %w", err)
	}
	dirLockMu.Lock()
	defer dirLockMu.Unlock()

	path := filepath.Join(dir, lockFileName)
	for attempt := 0; attempt < lockAcquireAttempts; attempt++ {
		tmp, err := stageLockFile(dir, token)
		if err != nil {
			return nil, err
		}
		linkErr := os.Link(tmp, path)
		_ = os.Remove(tmp)
		if linkErr == nil {
			return &dirLock{path: path, token: token}, nil
		}
		if !errors.Is(linkErr, fs.ErrExist) {
			return nil, fmt.Errorf("store: taking the data-directory lock %s: %w", path, linkErr)
		}

		h, ok := readLockHolder(path)
		if !ok {
			// Gone (another recovery removed it) or not in our format.
			// Either way no live owner this package recorded: clear and
			// retry.
			if err := breakStaleLock(dir, path, token); err != nil {
				return nil, err
			}
			continue
		}
		if h.pid == os.Getpid() && h.token == token {
			return nil, fmt.Errorf("%w: %s (already open in this process, pid %d; close that handle first)",
				ErrDataDirInUse, dir, h.pid)
		}
		if holderIsLiveProcess(h, token) {
			return nil, fmt.Errorf("%w: %s (held by pid %d; if that process is gone and its PID was reused, remove %s)",
				ErrDataDirInUse, dir, h.pid, path)
		}
		if err := breakStaleLock(dir, path, token); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("store: data directory %s: could not take the data-directory lock %s after %d attempts",
		dir, path, lockAcquireAttempts)
}

// breakStaleLock removes the (supposedly stale) lock at path while holding
// the break mutex, so two processes recovering the same stale lock cannot
// remove each other's fresh one. Its caller holds dirLockMu.
func breakStaleLock(dir, path, token string) error {
	breakPath := filepath.Join(dir, breakFileName)
	for attempt := 0; attempt < lockBreakAttempts; attempt++ {
		tmp, err := stageLockFile(dir, token)
		if err != nil {
			return err
		}
		linkErr := os.Link(tmp, breakPath)
		_ = os.Remove(tmp)
		if linkErr == nil {
			return removeStaleUnderBreakMutex(path, breakPath, token)
		}
		if !errors.Is(linkErr, fs.ErrExist) {
			return fmt.Errorf("store: taking the stale-lock break mutex %s: %w", breakPath, linkErr)
		}
		h, ok := readLockHolder(breakPath)
		if !ok {
			// The holder released it between our link and our read: retry.
			if _, statErr := os.Stat(breakPath); errors.Is(statErr, fs.ErrNotExist) {
				continue
			}
			// Present but not one of ours: a foreign or corrupt marker. Do
			// not remove it - see below.
			return staleMarkerError(dir, path, breakPath, 0)
		}
		if h.pid == os.Getpid() && h.token == token {
			// A previous break of ours leaked the mutex (its remove failed
			// mid-way); dirLockMu means no sibling of ours can hold it, so
			// we may take it over and finish.
			return removeStaleUnderBreakMutex(path, breakPath, token)
		}
		if h.pid != os.Getpid() && processAlive(h.pid) {
			time.Sleep(lockBreakWait)
			continue
		}
		// A foreign holder that is not alive: a breaker was killed inside
		// its critical section. Auto-removing the marker here would be a
		// remove-after-read race in which two recoverers each delete the
		// other's fresh marker and then each delete the other's fresh LOCK -
		// two writers on one directory, the exact failure this lock exists
		// to prevent. Refuse loudly and name the marker for the operator.
		return staleMarkerError(dir, path, breakPath, h.pid)
	}
	return fmt.Errorf("store: data directory %s: could not clear the stale lock %s after %d attempts",
		dir, path, lockBreakAttempts)
}

// staleMarkerError reports a LOCK.break that no live process owns and that
// this package refuses to delete: only the process that created a marker may
// remove it, because remove-after-read of a marker is exactly how two
// recoverers could each destroy the other's fresh lock.
func staleMarkerError(dir, lockPath, breakPath string, pid int) error {
	owner := "an unreadable owner"
	if pid > 0 {
		owner = fmt.Sprintf("pid %d", pid)
	}
	return fmt.Errorf("store: data directory %s: a crashed process left the stale-recovery marker %s (%s); remove it and retry (the stale %s is then recovered automatically)",
		dir, breakPath, owner, lockPath)
}

// removeStaleUnderBreakMutex removes path and then always releases the break
// mutex. The re-read is what makes recovery safe: while we waited for the
// mutex another process may have already broken the same stale lock and
// installed its own live one, and removing THAT would hand one directory to
// two writers.
func removeStaleUnderBreakMutex(path, breakPath, token string) error {
	remove := true
	if h, ok := readLockHolder(path); ok && holderIsLiveProcess(h, token) {
		remove = false
	}
	var rmErr error
	if remove {
		rmErr = os.Remove(path)
	}
	_ = os.Remove(breakPath)
	if rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		return fmt.Errorf("store: breaking the stale data-directory lock %s: %w", path, rmErr)
	}
	return nil
}

// release drops the lock. It removes the LOCK file only if it still carries
// this process's token: if some other actor replaced it, that actor's lock is
// not ours to remove.
func (l *dirLock) release() {
	if l == nil {
		return
	}
	if h, ok := readLockHolder(l.path); ok && h.pid == os.Getpid() && h.token == l.token {
		_ = os.Remove(l.path)
	}
}
