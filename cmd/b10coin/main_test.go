package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cti97/b10coincom/internal/genesis"
)

// captureStdout runs fn with os.Stdout swapped for a pipe and returns what
// fmt.Printf wrote. The devnet command reports through stdout only, so the
// wire format IS the observable surface the multi-path assertions pin.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()
	fn()
	os.Stdout = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// The --validators flag must swap the RUN, not decorate it: a multi-validator
// invocation drives the committee (per-validator heights, the agreement line),
// not the single-node faucet loop with a different number on the front.
//
// Killing mutant B (compiled): cmdDevnet ignores --validators and always takes
// the single-node path. Both subchecks catch it: the first finds no
// "validators   4" multi report (and finds the claims block the multi path
// never prints), the second finds --claims silently absorbed instead of
// refused.
func TestCmdDevnetMultiValidatorDrivesTheMultiPath(t *testing.T) {
	out := captureStdout(t, func() {
		if err := cmdDevnet([]string{"--validators", "4", "--blocks", "3", "--dir", t.TempDir()}); err != nil {
			t.Errorf("cmdDevnet multi: %v", err)
		}
	})
	for _, want := range []string{"validators   4", "heights", "agreed       yes", "OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("the multi-validator run's output is missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "claims paid") {
		t.Errorf("the multi-validator run printed the single-node faucet block; got:\n%s", out)
	}

	// An explicit --claims alongside a committee is refused, not silently
	// dropped: the claim scenario has no transaction path into a committee,
	// so honouring the run while ignoring the flag would print an empty
	// faucet report and look like a broken faucet.
	if err := cmdDevnet([]string{"--validators", "4", "--blocks", "2", "--claims", "1", "--dir", t.TempDir()}); err == nil {
		t.Error("--claims with --validators > 1 must fail the command, not drop the flag")
	}
}

// An EXPLICIT --validators always names the committee that gets run — the
// flag's ABSENCE is the only way to ask for the single-node run, so that
// `--validators 0` cannot silently become the single-node path and
// `--validators 1` really runs the one-member committee.
//
// Killing mutant (compiled): the multi-path condition reverts to
// `*validators > 1`. Then `--validators 0` exits 0 as a single-node run
// instead of failing, and `--validators 1` claims it ran the committee while
// printing `b10coin-devnet-1` with the faucet block.
func TestCmdDevnetExplicitValidatorsAlwaysMeansTheCommittee(t *testing.T) {
	if err := cmdDevnet([]string{"--validators", "0", "--blocks", "2", "--dir", t.TempDir()}); err == nil {
		t.Error("--validators 0 names an empty committee; it must fail, not fall back to the single-node run")
	}
	out := captureStdout(t, func() {
		if err := cmdDevnet([]string{"--validators", "1", "--blocks", "2", "--dir", t.TempDir()}); err != nil {
			t.Errorf("cmdDevnet --validators 1: %v", err)
		}
	})
	if !strings.Contains(out, "b10coin-simnet-1") || !strings.Contains(out, "validators   1") {
		t.Errorf("an explicit --validators 1 must run the one-member committee, got:\n%s", out)
	}
	if strings.Contains(out, "claims paid") {
		t.Errorf("an explicit --validators 1 ran the single-node faucet path, got:\n%s", out)
	}
}

// --- The networked node command (M4 Task 6): --peers, --relay, real subprocesses. ---
//
// These run the actual binary because that is the surface the flag parses:
// `--peers/--relay` live in main's flag handling, and an in-process call of a
// helper cannot notice a CLI mutant that ignores them. The assertion that
// separates the committee from the M1 producer is the CHAIN ID: the single-node
// path runs b10coin-devnet-1, the committee path b10coin-simnet-4.

var (
	cliBinOnce   sync.Once
	cliBinPath   string
	cliRelayPath string
	cliBinErr    error
)

// buildCliBinaries compiles the node and relay binaries once per test binary
// run, into a temporary directory.
func buildCliBinaries(t *testing.T) (nodeBin, relayBin string) {
	t.Helper()
	cliBinOnce.Do(func() {
		root := moduleRoot(t)
		out, err := os.MkdirTemp("", "b10coins-bin-")
		if err != nil {
			cliBinErr = err
			return
		}
		nodeBin := filepath.Join(out, "b10coin")
		relayBin := filepath.Join(out, "b10coin-relay")
		build := func(dst, pkg string) {
			cmd := exec.Command("go", "build", "-o", dst, pkg)
			cmd.Dir = root
			b, err := cmd.CombinedOutput()
			if err != nil {
				cliBinErr = fmt.Errorf("building %s: %v: %s", pkg, err, b)
			}
		}
		build(nodeBin, "./cmd/b10coin")
		build(relayBin, "./cmd/b10coin-relay")
		cliBinPath, cliRelayPath = nodeBin, relayBin
	})
	if cliBinErr != nil {
		t.Fatalf("building the CLI binaries: %v", cliBinErr)
	}
	return cliBinPath, cliRelayPath
}

// moduleRoot walks up from this test's own file to the go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the module root: runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("no go.mod above the test file")
	return ""
}

// openLoopbackListener binds a fresh loopback listener. It is a seam ONLY so
// the forced-duplicate probe can hand the allocator a collision and observe the
// fast failure; the real path cannot collide (see reservePorts), and nothing
// but that probe swaps it.
var openLoopbackListener = func() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

// reservePorts binds n loopback ports AT THE SAME TIME and releases them all
// only after the set is proven unique. The previous fixture freePort(t) bound
// and released one port per call, and the mesh test called it eight times back
// to back: a released port returns to the OS's pool, so a later call could be
// handed the SAME port again (Task-6 review finding: "freePort bind-and-release
// leaves a small port-reuse race for the subprocess CLI tests"). Two nodes
// sharing a port means one subprocess can never bind it, a mesh link silently
// vanishes, and the committee never forms — exactly the one CI failure of this
// test. Holding every listener open closes that window by construction: the
// OS cannot hand out a port that is still bound, and the explicit set check
// turns "somehow duplicated" into an immediate, named failure instead of a 60s
// timeout on a node that can never come up.
func reservePorts(t *testing.T, n int) []int {
	t.Helper()
	ports := make([]int, 0, n)
	listeners := make([]net.Listener, 0, n)
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	for i := 0; i < n; i++ {
		l, err := openLoopbackListener()
		if err != nil {
			t.Fatalf("reserving port %d of %d: %v", i+1, n, err)
		}
		listeners = append(listeners, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	// The set is proven unique while EVERY listener is still open — the only
	// state in which uniqueness is even checkable.
	if a, first := findDuplicatePort(ports); a != -1 {
		t.Fatalf("the port allocator returned %d twice (listener %d and listener %d): two subprocesses would share one port, one could never bind, and the committee could not form", ports[a], a, first)
	}
	return ports
}

// findDuplicatePort reports the first port that appears twice (the later
// index first, then the index of its first appearance), or (-1, -1) when every
// port in the set is distinct.
func findDuplicatePort(ports []int) (int, int) {
	seen := make(map[int]int, len(ports))
	for i, p := range ports {
		if first, dup := seen[p]; dup {
			return i, first
		}
		seen[p] = i
	}
	return -1, -1
}

// The allocation the mesh test actually makes — 4 P2P + 4 HTTP, 50 rounds —
// must never come back with a duplicate. The test re-checks the returned set
// itself only so this contract survives even if someone later removes the
// guard inside reservePorts.
func TestReservePortsYieldsDistinctPorts(t *testing.T) {
	for round := 0; round < 50; round++ {
		ports := reservePorts(t, 8)
		if a, first := findDuplicatePort(ports); a != -1 {
			t.Fatalf("round %d: the allocator returned %d twice (listeners %d and %d): %v", round, ports[a], a, first, ports)
		}
	}
}

// The guard that makes a duplicate an immediate failure is itself pinned: it
// must name the first clash, and it must stay quiet on a clean set.
func TestFindDuplicatePortNamesTheClash(t *testing.T) {
	a, first := findDuplicatePort([]int{40001, 40002, 40001, 40003, 40003})
	if a != 2 || first != 0 {
		t.Fatalf("findDuplicatePort reported (%d, %d), want (2, 0)", a, first)
	}
	if a, first := findDuplicatePort([]int{40001, 40002}); a != -1 || first != -1 {
		t.Fatalf("distinct ports reported as duplicates: (%d, %d)", a, first)
	}
}

type cliNodeProc struct {
	cmd  *exec.Cmd
	http int // the --http port the test polls; -1 when the process has no RPC
	// Both streams are captured: a networked node reports its chain, seat and
	// dial list on stdout, and a failed bind on stderr. The pre-fix harness
	// captured stdout into a buffer that was never shown, so the one CI
	// failure printed nothing but "never reached height 2".
	stdout *syncBuffer
	stderr *syncBuffer

	mu      sync.Mutex
	exited  bool
	exitErr error
	done    chan struct{} // closed once the process is reaped (and streams drained)
}

// syncBuffer is a bytes.Buffer safe to read while its writer lives. The exec
// package streams a subprocess's output into it from its own goroutine, and
// the stall report reads the tail of a node's output while the node is still
// running — without the mutex that read is a data race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// startCliNode starts one node subprocess with both output streams captured
// and a reaper goroutine: a node that exits at boot (a failed bind is the
// classic case) used to sit invisible behind a full 60s poll timeout, its
// crash reason discarded with its stream buffers.
func startCliNode(t *testing.T, bin string, httpPort int, args ...string) *cliNodeProc {
	t.Helper()
	c := exec.Command(bin, args...)
	p := &cliNodeProc{
		cmd:    c,
		http:   httpPort,
		stdout: &syncBuffer{},
		stderr: &syncBuffer{},
		done:   make(chan struct{}),
	}
	c.Stdout = p.stdout
	c.Stderr = p.stderr
	if err := c.Start(); err != nil {
		t.Fatalf("starting %v: %v", args, err)
	}
	go func() {
		// Wait blocks until the process exits AND the exec-internal output
		// copiers drain; after that no one writes the buffers again.
		err := c.Wait()
		p.mu.Lock()
		p.exited, p.exitErr = true, err
		p.mu.Unlock()
		close(p.done)
	}()
	return p
}

// stop kills the subprocess and waits for the reaper goroutine.
func (p *cliNodeProc) stop(t *testing.T) {
	t.Helper()
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	<-p.done
}

// state reports whether the subprocess has already exited, and with what.
func (p *cliNodeProc) state() (exited bool, exitErr error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exited, p.exitErr
}

func (p *cliNodeProc) statusURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/status", p.http)
}

// tails renders the captured stderr then stdout as indented blocks; empty
// streams (the common passing case) render nothing.
func (p *cliNodeProc) tails() string {
	return streamTail(p.stderr, "stderr") + streamTail(p.stdout, "stdout")
}

var statusClient = &http.Client{Timeout: 2 * time.Second}

// cliStatus is the /status answer the tests poll on.
type cliStatus struct {
	ChainID string `json:"chain_id"`
	Height  uint64 `json:"height"`
}

// fetchStatus reads one node's /status once; anything that is not a decoded
// 200 OK is an error.
func fetchStatus(url string) (cliStatus, error) {
	var st cliStatus
	resp, err := statusClient.Get(url)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("%s", resp.Status)
	}
	return st, json.NewDecoder(resp.Body).Decode(&st)
}

// waitForHeight polls member i's /status until it reports height >= want. On
// timeout it names every node's last-known state — not just the caller's — so
// the next flake says which node was behind and why.
func waitForHeight(t *testing.T, members []*cliNodeProc, i int, want uint64, timeout time.Duration) {
	t.Helper()
	p := members[i]
	deadline := time.Now().Add(timeout)
	var lastPollErr string
	for {
		st, err := fetchStatus(p.statusURL())
		if err != nil {
			lastPollErr = err.Error()
		} else if st.Height >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(stallReport(members, i, want, lastPollErr))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// stallReport renders why the committee did not reach want: the failing
// node's own last poll, then every node's last /status, its process state,
// and the tail of its captured stderr and stdout. The pre-fix failure printed
// one line ("never reached height 2"), which cost a full CI round trip to
// diagnose.
func stallReport(members []*cliNodeProc, behind int, want uint64, lastPollErr string) string {
	var w strings.Builder
	fmt.Fprintf(&w, "node %d at %s never reached height %d", behind, members[behind].statusURL(), want)
	if lastPollErr != "" {
		fmt.Fprintf(&w, " (its own last poll: %s)", lastPollErr)
	}
	w.WriteString("\nevery node's last-known state:\n")
	for i, p := range members {
		st, err := fetchStatus(p.statusURL())
		fmt.Fprintf(&w, "  node %d %s: ", i, p.statusURL())
		if err != nil {
			fmt.Fprintf(&w, "NO ANSWER (%v)", err)
		} else {
			fmt.Fprintf(&w, "chain %q height %d (want >= %d)", st.ChainID, st.Height, want)
		}
		if exited, xerr := p.state(); exited {
			fmt.Fprintf(&w, ", process EXITED (%v)", xerr)
		} else {
			w.WriteString(", process running")
		}
		w.WriteByte('\n')
		w.WriteString(p.tails())
	}
	return w.String()
}

// streamTail renders up to the last 2 KiB of one captured stream under its
// label, indented; an empty stream renders nothing.
func streamTail(buf *syncBuffer, label string) string {
	if buf == nil || buf.Len() == 0 {
		return ""
	}
	s, cut := buf.String(), ""
	if len(s) > 2048 {
		s = s[len(s)-2048:]
		for s != "" && !utf8.RuneStart(s[0]) { // do not cut mid-rune
			s = s[1:]
		}
		cut = "    (earlier output cut)\n"
	}
	const pad = "      "
	return fmt.Sprintf("    %s:\n%s%s\n", label, cut, pad+strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+pad))
}

// The --peers path: four nodes, four --listen addresses, dial lists complete,
// and the committee finalises. THIS is the test that catches a CLI mutant that
// ignores --peers (it would run four M1 producers on b10coin-devnet-1 — the
// chain id assertion names that), or that names the wrong seat.
func TestCliNodeDialsPeersAndRunsTheCommittee(t *testing.T) {
	nodeBin, _ := buildCliBinaries(t)

	// All 8 ports — 4 P2P + 4 HTTP — are reserved as ONE held-open set, so the
	// OS cannot hand the same port back twice (see reservePorts).
	ports := reservePorts(t, 8)
	p2p, httpPorts := ports[:4], ports[4:]
	procs := make([]*cliNodeProc, 0, 4)
	for i := 0; i < 4; i++ {
		dir := t.TempDir()
		peers := make([]string, 0, 3)
		for j := 0; j < 4; j++ {
			if i != j {
				peers = append(peers, fmt.Sprintf("127.0.0.1:%d", p2p[j]))
			}
		}
		args := []string{
			"node",
			"--dir", dir,
			"--http", fmt.Sprintf("127.0.0.1:%d", httpPorts[i]),
			"--listen", fmt.Sprintf("127.0.0.1:%d", p2p[i]),
			"--peers", strings.Join(peers, ","),
			"--validators", "4", "--index", strconv.Itoa(i),
		}
		procs = append(procs, startCliNode(t, nodeBin, httpPorts[i], args...))
		defer procs[len(procs)-1].stop(t)
	}
	for i := range procs {
		waitForHeight(t, procs, i, 2, 60*time.Second)
	}
	// All four at >= 2 on the SAME committee chain; the mutant that reverts a
	// node to the M1 single-node producer shows up as b10coin-devnet-1.
	assertCliStatusesCommittee(t, procs)
}

// The --relay path: the relay subprocess plus four nodes that dial it and
// nothing else. Kills a CLI mutant that drops --relay (nodes that dial nobody
// never meet the committee) and one that never starts the relay dial.
func TestCliNodeDialsTheRelayAndRunsTheCommittee(t *testing.T) {
	nodeBin, relayBin := buildCliBinaries(t)

	// Same held-open allocation: the relay's own port plus the four HTTP
	// ports, reserved together and released together.
	ports := reservePorts(t, 5)
	relayPort, httpPorts := ports[0], ports[1:]
	relayProc := startCliNode(t, relayBin, -1, "--addr", fmt.Sprintf("127.0.0.1:%d", relayPort), "--max-conns", "64")
	defer relayProc.stop(t)

	procs := make([]*cliNodeProc, 0, 4)
	for i := 0; i < 4; i++ {
		dir := t.TempDir()
		args := []string{
			"node",
			"--dir", dir,
			"--http", fmt.Sprintf("127.0.0.1:%d", httpPorts[i]),
			"--relay", fmt.Sprintf("127.0.0.1:%d", relayPort),
			"--validators", "4", "--index", strconv.Itoa(i),
		}
		procs = append(procs, startCliNode(t, nodeBin, httpPorts[i], args...))
		defer procs[len(procs)-1].stop(t)
	}
	for i := range procs {
		waitForHeight(t, procs, i, 2, 90*time.Second)
	}
	assertCliStatusesCommittee(t, procs)
}

// assertCliStatusesCommittee requires every subprocess's /status to name the
// committee chain (b10coin-simnet-4), which distinguishes a running consensus
// committee from four stray single-node producers.
func assertCliStatusesCommittee(t *testing.T, procs []*cliNodeProc) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	for i, p := range procs {
		resp, err := client.Get(p.statusURL())
		if err != nil {
			t.Fatalf("node %d status: %v %s", i, err, p.tails())
		}
		var st struct {
			ChainID string `json:"chain_id"`
			Height  uint64 `json:"height"`
		}
		err = json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("node %d status decode: %v %s", i, err, p.tails())
		}
		if st.ChainID != "b10coin-simnet-4" {
			t.Fatalf("node %d runs chain %q, want b10coin-simnet-4: the CLI did not run the committee path %s", i, st.ChainID, p.tails())
		}
		if st.Height < 2 {
			t.Fatalf("node %d at height %d, want >= 2 %s", i, st.Height, p.tails())
		}
	}
}

// --- keygen and the genesis-file node path (audit A-1). ---
//
// These pin the A-1 fix at its two surfaces: the key file (written once,
// owner-only, never overwritten) and the node flags that make a real
// committee possible — the committee from a shared file of PUBLIC keys, the
// seat key from a held file, and refusal at startup when the two disagree.

// keygenKey runs cmdKeygen in-process and returns the key file path plus the
// hex public key the command printed (the value an operator pastes into the
// committee file — the tests assemble real committee files from it).
func keygenKey(t *testing.T, dir, name string) (keyPath, pubHex string) {
	t.Helper()
	keyPath = filepath.Join(dir, name)
	out := captureStdout(t, func() {
		if err := cmdKeygen([]string{"--out", keyPath}); err != nil {
			t.Fatalf("cmdKeygen: %v", err)
		}
	})
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) == 3 && fields[0] == "public" && fields[1] == "key" && len(fields[2]) == 64 {
			return keyPath, fields[2]
		}
	}
	t.Fatalf("keygen printed no 64-hex public key line; output:\n%s", out)
	return "", ""
}

// writeCommitteeFile writes the shared committee JSON listing the given hex
// public keys under chainID.
func writeCommitteeFile(t *testing.T, dir, chainID string, pubHexes ...string) string {
	t.Helper()
	entries := make([]genesis.CommitteeEntry, 0, len(pubHexes))
	for i, k := range pubHexes {
		entries = append(entries, genesis.CommitteeEntry{Name: fmt.Sprintf("pi-%d", i), PubKey: k, Power: 1})
	}
	raw, err := json.Marshal(genesis.CommitteeFile{ChainID: chainID, Validators: entries})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "committee.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The keygen contract: created (0600), the public key and seat address are
// printed, and a second call refuses to overwrite. Killing mutant: keygen
// that truncates an existing file (O_EXCL dropped) would silently REPLACE a
// live validator's key — the refusal test also proves the original bytes
// survive untouched.
func TestCmdKeygenWritesOwnerOnlyKeyFileAndRefusesOverwrite(t *testing.T) {
	keyPath, pubHex := keygenKey(t, t.TempDir(), "b10coin.key")

	if info, err := os.Stat(keyPath); err != nil {
		t.Fatalf("stat key file: %v", err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %04o, want 0600 (owner-only)", info.Mode().Perm())
	}
	if len(pubHex) != 64 {
		t.Fatalf("printed public key is %d hex chars, want 64: %q", len(pubHex), pubHex)
	}

	// A rerun must refuse: a second generation derives a DIFFERENT key, so
	// an incautious overwrite orphans the key the committee file lists.
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdKeygen([]string{"--out", keyPath}); err == nil {
		t.Fatal("a second keygen on the same path must fail, not overwrite")
	} else if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("the refusal must say why: %v", err)
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the refused overwrite still modified the key file")
	}
}

// The genesis-file mode's flag contract, each refusal in-process (these all
// fail before anything is started):
//   - --genesis without --key must say who signs;
//   - a key OUTSIDE the committee must be refused before any seat is claimed
//     (the audit's refusal requirement, at the flag surface);
//   - fixture flags alongside --genesis must be refused, not silently mixed;
//   - --key on the single-node producer must be refused (the producer signs
//     with the devnet fixture; a key flag there could only lie).
func TestNodeGenesisModeFlagContract(t *testing.T) {
	dir := t.TempDir()
	k1, pub1 := keygenKey(t, dir, "validator-0.key")
	k2, _ := keygenKey(t, dir, "validator-1.key")
	cf := writeCommitteeFile(t, dir, "flag-contract-test", pub1)

	if err := cmdNode([]string{"--dir", filepath.Join(dir, "d1"), "--genesis", cf}); err == nil || !strings.Contains(err.Error(), "--key") {
		t.Errorf("--genesis without --key must demand the key file, got: %v", err)
	}
	if err := cmdNode([]string{"--dir", filepath.Join(dir, "d2"), "--genesis", cf, "--key", k2}); err == nil {
		t.Fatal("a key that is not in the committee must refuse to start")
	} else if !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("the refusal must be the membership refusal, got: %v", err)
	}
	if err := cmdNode([]string{"--dir", filepath.Join(dir, "d3"), "--genesis", cf, "--key", k1, "--validators", "3", "--index", "0"}); err == nil || !strings.Contains(err.Error(), "fixture") {
		t.Errorf("--validators/--index alongside --genesis must be refused as fixture flags, got: %v", err)
	}
	if err := cmdNode([]string{"--dir", filepath.Join(dir, "d4"), "--key", k1}); err == nil || !strings.Contains(err.Error(), "single-node") {
		t.Errorf("--key on the single-node producer must be refused, got: %v", err)
	}
	if err := cmdNode([]string{"--dir", filepath.Join(dir, "d5"), "--genesis", filepath.Join(dir, "missing.json"), "--key", k1}); err == nil {
		t.Error("a committee file that cannot be read must fail the command")
	}
}

// The happy path through the REAL binary: a one-member committee from a
// committee file, the seat key from a keygen file. This is the deployment
// shape of the fixed deploy recipe in miniature — and it pins that:
//   - the chain ID is the FILE's (no committee size was named on any flag;
//     /status no longer derives identity from N);
//   - the node refuses nothing about a key that IS listed, reaches height 1;
//   - a real-key committee does NOT print the fixture warning.
func TestCliNodeRunsAGenesisFileCommitteeWithItsHeldKey(t *testing.T) {
	nodeBin, _ := buildCliBinaries(t)
	ports := reservePorts(t, 1)
	httpPort := ports[0]

	cfgDir := filepath.Join(t.TempDir(), "cfg")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	keyPath, pubHex := keygenKey(t, cfgDir, "b10coin.key")
	cf := writeCommitteeFile(t, cfgDir, "cli-genesis-1", pubHex)

	p := startCliNode(t, nodeBin, httpPort,
		"node",
		"--dir", t.TempDir(),
		"--http", fmt.Sprintf("127.0.0.1:%d", httpPort),
		"--genesis", cf,
		"--key", keyPath,
	)
	defer p.stop(t)
	waitForHeight(t, []*cliNodeProc{p}, 0, 1, 90*time.Second)

	st, err := fetchStatus(p.statusURL())
	if err != nil {
		t.Fatalf("status: %v %s", err, p.tails())
	}
	if st.ChainID != "cli-genesis-1" {
		t.Fatalf("chain %q, want the committee file's cli-genesis-1: the chain ID must come from the shared file %s", st.ChainID, p.tails())
	}
	if want := "committee of 1, seat 0, key file "; !strings.Contains(p.stdout.String(), want) {
		t.Fatalf("the banner must name the committee, seat and key file (%q missing):\n%s", want, p.stdout.String())
	}
	if strings.Contains(p.stderr.String(), "FIXTURE COMMITTEE") {
		t.Fatalf("a held-key committee printed the FIXTURE warning; the warning belongs to the derived-committee path only:\n%s", p.tails())
	}
}

// The fixture node (--validators/--index) still runs exactly as before — the
// acceptance runs depend on it — but it must now be LOUDLY marked: the
// audit's bound on the fallback path. This subprocess test requires the
// warning on stderr while the committee works, killing the mutant that
// reports fixture keys as if they were safe.
func TestCliFixtureNodeStillRunsButWarnsItsKeysArePublic(t *testing.T) {
	nodeBin, _ := buildCliBinaries(t)
	ports := reservePorts(t, 1)
	p := startCliNode(t, nodeBin, ports[0],
		"node",
		"--dir", t.TempDir(),
		"--http", fmt.Sprintf("127.0.0.1:%d", ports[0]),
		"--validators", "1",
		"--index", "0",
	)
	defer p.stop(t)
	waitForHeight(t, []*cliNodeProc{p}, 0, 1, 90*time.Second)
	if st, err := fetchStatus(p.statusURL()); err != nil || st.ChainID != "b10coin-simnet-1" {
		t.Fatalf("fixture committee chain %q (err %v): the devnet fixture path must keep running", st.ChainID, err)
	}
	if !strings.Contains(p.stderr.String(), "FIXTURE COMMITTEE") {
		t.Fatalf("a publicly derivable committee started without the fixture warning:\n%s", p.tails())
	}
}

// TestCmdNodeRefusesAShortRelayAccessToken pins the node half of the token
// length floor (review, audit fix round 4). A token is the credential a relay
// checks once per dial, so a short one is brute-forced at network speed; the
// node must refuse it before it starts listening, not redial a relay that will
// refuse every handshake. The refusal happens while parsing flags, so this
// touches no socket.
func TestCmdNodeRefusesAShortRelayAccessToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "relay.token")
	if err := os.WriteFile(tokenPath, []byte("fifteen-bytes.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := cmdNode([]string{
		"--dir", filepath.Join(dir, "data"),
		"--relay", "127.0.0.1:7001",
		"--relay-access-token-file", tokenPath,
	})
	if err == nil {
		t.Fatal("a 14-byte relay access token was accepted; it is brute-forced by dialling")
	}
	if !strings.Contains(err.Error(), "at least") {
		t.Fatalf("the short-token refusal reads %q; it must name the minimum", err)
	}
	// And no data directory was created: the refusal precedes the store.
	if _, statErr := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(statErr) {
		t.Fatalf("the refused invocation created its data directory (stat err = %v)", statErr)
	}
}
