package store

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The data-directory lock is cross-process, so the only honest test of it
// starts a second process. TestMain re-executes this test binary as that
// second process when the environment names a child mode; the ordinary run is
// untouched. Nothing here races: the parent waits for the child to announce
// it holds the lock on a pipe before probing, and waits for the child to be
// reaped before probing the stale path - the state under test is constructed,
// never provoked through a buffer or a sleep.
const (
	lockChildEnv = "B10COIN_STORE_LOCK_CHILD"
	lockChildDir = "B10COIN_STORE_LOCK_DIR"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(lockChildEnv); mode != "" {
		os.Exit(lockChildMain(mode))
	}
	os.Exit(m.Run())
}

func lockChildMain(mode string) int {
	switch mode {
	case "pid":
		fmt.Println(os.Getpid())
		return 0
	case "hold":
		s, err := Open(os.Getenv(lockChildDir))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		fmt.Println("locked")
		// Block until the parent kills us or closes the pipe. A kill is the
		// crash path: the lock file is left behind with no clean Close.
		_, _ = io.Copy(io.Discard, os.Stdin)
		_ = s.Close()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown %s mode %q\n", lockChildEnv, mode)
		return 2
	}
}

// deadChildPid starts and reaps a child and returns its now-dead PID.
func deadChildPid(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), lockChildEnv+"=pid")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("starting the pid-reporting child: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		t.Fatalf("the pid-reporting child printed %q: %v", out, err)
	}
	return pid
}

// A second process on one directory must be refused while the owner lives,
// and the refusal must name the directory and the owning PID. The owner is
// killed WITHOUT a clean Close, so the same test then proves the crash path:
// the lock the dead process left must not wedge the directory.
func TestSecondProcessIsRefusedWhileTheOwnerLivesAndRecoversAfterItDies(t *testing.T) {
	dir := t.TempDir()

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), lockChildEnv+"=hold", lockChildDir+"="+dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "locked" {
		t.Fatalf("the owner process did not report holding the lock: line %q, err %v", line, err)
	}
	ownerPid := cmd.Process.Pid

	// Live owner: refused, with an operator-readable diagnosis.
	if _, err := Open(dir); !errors.Is(err, ErrDataDirInUse) {
		t.Fatalf("Open on a directory owned by a live process = %v, want ErrDataDirInUse", err)
	} else {
		if !strings.Contains(err.Error(), dir) {
			t.Fatalf("the refusal does not name the directory %q: %v", dir, err)
		}
		if !strings.Contains(err.Error(), strconv.Itoa(ownerPid)) {
			t.Fatalf("the refusal does not name the owning pid %d: %v", ownerPid, err)
		}
	}

	// Crash: kill without a clean Close, leaving the pidfile behind.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("killing the owner: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		// The process was killed, so a non-nil wait status is expected; only
		// a failure to reap would matter, and Wait still reaped it.
		_ = err
	}
	waited = true
	if processAlive(ownerPid) {
		t.Fatalf("test setup: pid %d is still alive after being killed and reaped", ownerPid)
	}
	if _, err := os.Stat(filepath.Join(dir, lockFileName)); err != nil {
		t.Fatalf("test setup: the killed owner left no lock file to recover from: %v", err)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("a lock left by a dead process must be broken, not wedge the directory: %v", err)
	}
	defer s.Close()
	if err := s.Append(1, []byte("after-recovery")); err != nil {
		t.Fatalf("the recovered store cannot write: %v", err)
	}
}

// A directory opened, closed and reopened in one process must work: Close
// must release the lock, or every legitimate restart would be refused.
func TestReopenAfterCloseInOneProcessSucceeds(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Append(1, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatalf("reopening a closed directory: %v", err)
	}
	defer second.Close()
	if h, ok := second.Height(); !ok || h != 1 {
		t.Fatalf("Height after reopen = %d,%v; want 1,true", h, ok)
	}
}

// The lock is deliberately NOT re-entrant, within a process or across
// processes: two *Store handles on one directory would Seek and interleave
// exactly as two processes would. The in-process case is refused like any
// other, and the refusal must leave the owner fully usable.
func TestSecondOpenInOneProcessIsRefusedAndNamesTheDirectory(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Append(1, []byte("kept")); err != nil {
		t.Fatal(err)
	}

	_, err = Open(dir)
	if !errors.Is(err, ErrDataDirInUse) {
		t.Fatalf("a second Open in the same process = %v, want ErrDataDirInUse", err)
	}
	if !strings.Contains(err.Error(), dir) {
		t.Fatalf("the in-process refusal does not name the directory %q: %v", dir, err)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Fatalf("the in-process refusal does not name this pid %d: %v", os.Getpid(), err)
	}

	// The refused attempt must not have disturbed the owner: its bytes, its
	// lock and its ability to append are all intact.
	if got, err := first.Read(1); err != nil || string(got) != "kept" {
		t.Fatalf("Read(1) after a refused second Open = %q, %v; the owner was disturbed", got, err)
	}
	if err := first.Append(2, []byte("still-mine")); err != nil {
		t.Fatalf("the owner could not append after the refusal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, lockFileName)); err != nil {
		t.Fatalf("the refused Open removed the owner's lock: %v", err)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatalf("reopening after the owner closed: %v", err)
	}
	defer again.Close()
	if h, ok := again.Height(); !ok || h != 2 {
		t.Fatalf("Height after reopen = %d,%v; want 2,true - the LOCK file must not be scanned as a block", h, ok)
	}
}

// A lock file naming a PID that is genuinely dead is broken on the next Open.
// The state is constructed on disk (the file is written by the test, with a
// real reaped child's PID) rather than provoked by a crash.
func TestStaleLockLeftByADeadProcessIsBroken(t *testing.T) {
	dir := t.TempDir()
	dead := deadChildPid(t)
	if processAlive(dead) {
		t.Fatalf("test setup: pid %d is alive; the lock would not be stale", dead)
	}
	raw := fmt.Sprintf("%s\npid %d\nproc 00112233445566778899aabbccddeeff\n", lockFileMagic, dead)
	if err := os.WriteFile(filepath.Join(dir, lockFileName), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("a lock left by dead pid %d must be broken, not wedge the directory: %v", dead, err)
	}
	defer s.Close()
	if err := s.Append(1, []byte("recovered")); err != nil {
		t.Fatalf("the recovered store cannot write: %v", err)
	}
}

// The one PID reuse this implementation can see: a lock naming OUR pid but
// not our per-process token was left by a dead predecessor whose PID we now
// hold. It must be treated as stale, not mistaken for our own live lock -
// otherwise the directory would be permanently unusable by its rightful owner.
func TestLockWithOurReusedPidButAForeignTokenIsStale(t *testing.T) {
	dir := t.TempDir()
	token, err := processToken()
	if err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf("%s\npid %d\nproc %s\n", lockFileMagic, os.Getpid(), strings.Repeat("f", len(token)))
	if raw == fmt.Sprintf("%s\npid %d\nproc %s\n", lockFileMagic, os.Getpid(), token) {
		t.Fatal("test setup: the foreign token equals this process's token")
	}
	if err := os.WriteFile(filepath.Join(dir, lockFileName), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("a lock naming our reused pid with a foreign token must be broken: %v", err)
	}
	defer s.Close()
}

// Acquisition must be atomic, not a check-then-create. Eight goroutines race
// for one empty directory behind a start barrier; the assertion is on the
// INVARIANT (exactly one winner), never on which goroutine wins, so it is
// sound under every interleaving - a serialised run has one winner too. A
// Stat-then-Create implementation would let two goroutines both see an empty
// directory and both create.
func TestSimultaneousAcquisitionsProduceExactlyOneWinner(t *testing.T) {
	dir := t.TempDir()
	const racers = 8

	start := make(chan struct{})
	results := make(chan *dirLock, racers)
	errs := make(chan error, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			l, err := acquireDirLock(dir)
			if err != nil {
				errs <- err
				return
			}
			results <- l
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)

	winners := 0
	for l := range results {
		winners++
		l.release()
	}
	if winners != 1 {
		t.Fatalf("%d of %d simultaneous acquisitions won; exactly one writer may own the directory", winners, racers)
	}
	losers := 0
	for err := range errs {
		losers++
		if !errors.Is(err, ErrDataDirInUse) {
			t.Fatalf("a losing acquisition returned %v, want ErrDataDirInUse", err)
		}
	}
	if losers != racers-1 {
		t.Fatalf("%d losers reported an error, want %d", losers, racers-1)
	}
}

// Stale recovery must never delete a lock that has BECOME live while the
// breaker waited for the break mutex. Without the re-read under that mutex,
// two processes that both judged the same lock stale would each remove the
// other's fresh lock and both become writers. The interleaving is
// constructed here by hand: a live lock is already in place when the
// recovery primitive runs holding the break mutex, exactly the state the
// racing breaker would reach.
func TestStaleRecoveryRefusesToRemoveALockThatBecameLive(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, lockFileName)
	breakPath := filepath.Join(dir, breakFileName)

	live, err := acquireDirLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer live.release()
	token, err := processToken()
	if err != nil {
		t.Fatal(err)
	}
	// Hold the break mutex the way a breaker does: link a staged file in.
	tmp, err := stageLockFile(dir, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(tmp, breakPath); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(tmp)

	if err := removeStaleUnderBreakMutex(lockPath, breakPath, token); err != nil {
		t.Fatalf("recovery with a live lock in place: %v", err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("recovery removed a lock that had become live: %v - a second writer would now be admitted", err)
	}
	if h, ok := readLockHolder(lockPath); !ok || !holderIsLiveProcess(h, token) {
		t.Fatalf("the surviving lock is no longer the live one: %+v, %v", h, ok)
	}
	// The break mutex must have been released on the no-op path too.
	if _, err := os.Stat(breakPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the break mutex was not released after refusing to remove a live lock: %v", err)
	}
}
