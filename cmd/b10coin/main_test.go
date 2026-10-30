package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	"github.com/cti97/b10coincom/internal/keystore"
	"github.com/cti97/b10coincom/internal/types"
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
		// A seat's power IS its genesis bond and must clear MIN_STAKE
		// (audit RT-2); one spark is the shape that made committee capture
		// cost a single MIN_STAKE.
		entries = append(entries, genesis.CommitteeEntry{Name: fmt.Sprintf("pi-%d", i), PubKey: k, Power: genesis.Devnet().Params.MinStakeSparks})
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

// ---------------------------------------------------------------------------
// M5 Task 6: the staking verbs
// ---------------------------------------------------------------------------

// stakingStub is the smallest node a staking verb talks to: /status with the
// chain's identity and stake parameters, /account/{address}, and /tx capturing
// the posted canonical bytes. It is a STUB, not a chain, because the verb's
// whole job is "read the node, sign, submit" - what the node then does with the
// bytes is the state machine's test, not this one's.
type stakingStub struct {
	t           *testing.T
	genesisHash [32]byte
	account     stakingAccount
	mu          sync.Mutex
	posts       [][]byte
	url         string
	ts          *httptest.Server
}

func newStakingStub(t *testing.T, genesisHash [32]byte, acc stakingAccount) *stakingStub {
	t.Helper()
	s := &stakingStub{t: t, genesisHash: genesisHash, account: acc}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"chain_id":         "stub-chain-1",
			"height":           uint64(7),
			"genesis_hash":     hex.EncodeToString(s.genesisHash[:]),
			"min_fee_sparks":   uint64(1),
			"min_stake_sparks": uint64(100_000_000_000),
			"epoch_blocks":     uint64(1_000),
			"unbonding_epochs": uint64(2),
			"committee_size":   1,
		})
	})
	mux.HandleFunc("/account/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(s.account)
	})
	mux.HandleFunc("/tx", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading POST /tx: %v", err)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(body)))
		if err != nil {
			t.Errorf("POST /tx body is not hex: %v", err)
		}
		s.mu.Lock()
		s.posts = append(s.posts, raw)
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"txid": strings.Repeat("ab", 32)})
	})
	s.ts = httptest.NewServer(mux)
	t.Cleanup(s.ts.Close)
	s.url = s.ts.URL
	return s
}

// posted decodes the single transaction the verb submitted.
func (s *stakingStub) posted() *types.Tx {
	s.t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.posts) != 1 {
		s.t.Fatalf("the verb posted %d transactions, want exactly 1", len(s.posts))
	}
	tx, err := types.DecodeTx(s.posts[0])
	if err != nil {
		s.t.Fatalf("the posted bytes do not decode: %v", err)
	}
	return tx
}

func stakingTestKey(t *testing.T) (string, ed25519.PublicKey, types.Address) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stake.key")
	_, priv, err := keystore.Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return path, pub, types.AddressFromPub(pub)
}

// TestStakeVerbSubmitsABondWithTheRightFields: the stub reports a genesis hash
// that is NOT the compiled-in devnet one. The verb must sign against the
// REPORTED hash - the signature verifies there and fails against devnet's -
// which is what makes a verb pointed at another chain produce a transaction
// that chain can verify, and one pointed at a doctored node a useless
// transaction rather than a dangerous one.
func TestStakeVerbSubmitsABondWithTheRightFields(t *testing.T) {
	keyPath, pub, addr := stakingTestKey(t)
	var reported [32]byte
	for i := range reported {
		reported[i] = byte(0xa0 + i)
	}
	if reported == genesis.Devnet().Hash() {
		t.Fatal("the test's reported hash must differ from the devnet genesis hash")
	}
	stub := newStakingStub(t, reported, stakingAccount{
		Address: addr.String(),
		Balance: 5_000 * genesis.SparksPerB10,
		Nonce:   3,
	})

	if err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000"}); err != nil {
		t.Fatalf("cmdStake: %v", err)
	}
	tx := stub.posted()
	if tx.Type != types.TxBond {
		t.Errorf("type = %d, want TxBond (%d)", tx.Type, types.TxBond)
	}
	if tx.From != addr {
		t.Errorf("from = %s, want %s", tx.From, addr)
	}
	if !bytes.Equal(tx.PubKey, pub) {
		t.Errorf("pubkey = %x, want %x", tx.PubKey, pub)
	}
	if tx.Nonce != 3 {
		t.Errorf("nonce = %d, want the account nonce 3", tx.Nonce)
	}
	if tx.Fee != 1 {
		t.Errorf("fee = %d, want the node's min_fee_sparks (1)", tx.Fee)
	}
	if want := uint64(100_000_000_000); tx.Amount != want {
		t.Errorf("amount = %d sparks, want %d (1000 b10; a b10 value passed straight through would be 1000)", tx.Amount, want)
	}
	if err := tx.VerifySignature(reported); err != nil {
		t.Errorf("the transaction does not verify against the genesis hash the stub reported: %v", err)
	}
	if err := tx.VerifySignature(genesis.Devnet().Hash()); err == nil {
		t.Error("the transaction verifies against the compiled-in devnet genesis hash: the verb signed for the wrong chain")
	}
}

// TestUnstakeWithNoAmountUnbondsTheWholeBond: omitting --amount means the whole
// bond read from /account, and an exit carries fee 0.
func TestUnstakeWithNoAmountUnbondsTheWholeBond(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(),
		Balance: 1,
		Nonce:   4,
		Bonded:  750 * genesis.SparksPerB10,
	})
	if err := cmdUnstake([]string{"--node", stub.url, "--key", keyPath}); err != nil {
		t.Fatalf("cmdUnstake: %v", err)
	}
	tx := stub.posted()
	if tx.Type != types.TxUnbond {
		t.Errorf("type = %d, want TxUnbond (%d)", tx.Type, types.TxUnbond)
	}
	if got, want := tx.Amount, uint64(750*genesis.SparksPerB10); got != want {
		t.Errorf("amount = %d, want the whole bond %d", got, want)
	}
	if tx.Fee != 0 {
		t.Errorf("fee = %d, want 0 (an unbond must not carry a fee)", tx.Fee)
	}
	if tx.Nonce != 4 {
		t.Errorf("nonce = %d, want 4", tx.Nonce)
	}
}

// TestUnstakePartialUsesTheGivenAmount is the other half of the amount rule:
// with --amount the transaction carries exactly that, not the whole bond. The
// fixture bonds 1,500 b10 so the 250.5 b10 exit leaves 1,249.5 b10 — above the
// floor audit ST-1 makes a partial exit respect.
func TestUnstakePartialUsesTheGivenAmount(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Nonce: 0, Bonded: 1_500 * genesis.SparksPerB10,
	})
	if err := cmdUnstake([]string{"--node", stub.url, "--key", keyPath, "--amount", "250.5"}); err != nil {
		t.Fatalf("cmdUnstake: %v", err)
	}
	if got, want := stub.posted().Amount, uint64(250*genesis.SparksPerB10+50_000_000); got != want {
		t.Errorf("amount = %d, want %d (250.5 b10)", got, want)
	}
}

// TestUnstakeRefusesAPartialExitBelowMinStake mirrors the state rule (audit
// ST-1): an exit must leave nothing or at least MIN_STAKE, so the verb refuses
// the same remainders the chain would, before signing anything. The carve-out
// shows up as the last case: a bond ALREADY under the floor (a genesis seat)
// may be exited in full, but not partially.
func TestUnstakeRefusesAPartialExitBelowMinStake(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	const minStake = 1_000 * genesis.SparksPerB10

	for _, tc := range []struct {
		name   string
		bonded uint64
		amount string
	}{
		{"leaves one spark", minStake, "999.99999999"},
		{"leaves one spark under the floor", minStake, "0.00000001"},
		{"leaves MIN_STAKE-1", 1_500 * genesis.SparksPerB10, "1000.00000001"},
		{"partial exit from a sub-floor genesis seat", 600 * genesis.SparksPerB10, "100"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
				Address: addr.String(), Nonce: 0, Bonded: tc.bonded,
			})
			err := cmdUnstake([]string{"--node", stub.url, "--key", keyPath, "--amount", tc.amount})
			if err == nil {
				t.Fatalf("a partial exit leaving less than MIN_STAKE was accepted (bonded %d, amount %s)", tc.bonded, tc.amount)
			}
			if !strings.Contains(err.Error(), "MIN_STAKE") {
				t.Errorf("the refusal must name MIN_STAKE, got: %v", err)
			}
			if len(stub.posts) != 0 {
				t.Errorf("the verb posted %d transaction(s) despite refusing", len(stub.posts))
			}
		})
	}
}

// TestUnstakeAllowsTheFullExitAndTheFloorRemainder is the accepting half of the
// same rule, so the verb cannot pass the refusal test by refusing everything:
// the whole bond goes through, and so does a partial that leaves EXACTLY
// MIN_STAKE. A sub-floor genesis seat also goes through IN FULL.
func TestUnstakeAllowsTheFullExitAndTheFloorRemainder(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)

	for _, tc := range []struct {
		name   string
		bonded uint64
		amount string
		want   uint64
	}{
		{"full exit", 1_000 * genesis.SparksPerB10, "", 1_000 * genesis.SparksPerB10},
		{"leaves exactly the floor", 1_500 * genesis.SparksPerB10, "500", 500 * genesis.SparksPerB10},
		{"one-spark genesis seat in full", 1, "0.00000001", 1},
		{"sub-floor genesis seat in full", 600 * genesis.SparksPerB10, "600", 600 * genesis.SparksPerB10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
				Address: addr.String(), Nonce: 0, Bonded: tc.bonded,
			})
			args := []string{"--node", stub.url, "--key", keyPath}
			if tc.amount != "" {
				args = append(args, "--amount", tc.amount)
			}
			if err := cmdUnstake(args); err != nil {
				t.Fatalf("cmdUnstake: %v", err)
			}
			if got := stub.posted().Amount; got != tc.want {
				t.Errorf("amount = %d sparks, want %d", got, tc.want)
			}
		})
	}
}

// TestStakeRefusesBelowMinStakeBeforeSubmitting: the node's min_stake_sparks is
// checked by the verb, so the operator gets the reason and the funding reality
// instead of a node-side refusal. Nothing is posted.
func TestStakeRefusesBelowMinStakeBeforeSubmitting(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: 10_000 * genesis.SparksPerB10,
	})
	err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "999"})
	if err == nil {
		t.Fatal("stake below MIN_STAKE must be refused")
	}
	if !strings.Contains(err.Error(), "MIN_STAKE") {
		t.Errorf("the refusal must name MIN_STAKE, got: %v", err)
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb posted %d transactions despite refusing", len(stub.posts))
	}
}

// TestTheVerbRefusesAKeyThatDoesNotOwnTheAccount: the node names a different
// account at the address this key signs as. Signing would be pointless at best
// and misleading at worst, so the verb refuses before submitting.
func TestTheVerbRefusesAKeyThatDoesNotOwnTheAccount(t *testing.T) {
	keyPath, _, _ := stakingTestKey(t)
	otherPub, _ := genesis.DevAccountKey(0)
	other := types.AddressFromPub(otherPub)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: other.String(), Balance: 5_000 * genesis.SparksPerB10,
	})
	err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000"})
	if err == nil {
		t.Fatal("a key whose account the node names differently must be refused")
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb posted %d transactions despite refusing", len(stub.posts))
	}
}

// TestTheVerbsRefuseANodeWithoutAGenesisHash: a pre-M5 node has no
// genesis_hash, and a staking signature bound to nothing the chain reports
// would be the "compiled-in assumption" defect the reported hash exists to
// prevent. The verb refuses instead of guessing.
func TestTheVerbsRefuseANodeWithoutAGenesisHash(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"chain_id": "old-node-1", "height": uint64(1),
			"min_fee_sparks": uint64(1), "min_stake_sparks": uint64(100_000_000_000),
			"epoch_blocks": uint64(1_000), "unbonding_epochs": uint64(2),
		})
	})
	mux.HandleFunc("/account/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(stakingAccount{Address: addr.String(), Bonded: 1_000 * genesis.SparksPerB10})
	})
	// A /tx that ACCEPTS: if the verb fell through and signed against a
	// zero genesis hash, this handler would take it and the assertion below
	// would see a post. A stub that 404s would hide that by failing the POST
	// for an unrelated reason.
	var posted int
	mux.HandleFunc("/tx", func(w http.ResponseWriter, r *http.Request) {
		posted++
		_ = json.NewEncoder(w).Encode(map[string]string{"txid": strings.Repeat("ab", 32)})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	if err := cmdUnstake([]string{"--node", ts.URL, "--key", keyPath}); err == nil {
		t.Fatal("a node that reports no genesis_hash must be refused, not signed for")
	}
	if posted != 0 {
		t.Errorf("the verb submitted %d transaction(s) to a node that reported no genesis_hash", posted)
	}
}

// TestWithdrawVerbReleasesOnlyMaturedRecords: the withdraw verb submits one
// TxWithdraw carrying no amount (the state machine derives the total from the
// matured records), and it refuses before submitting when nothing has matured.
func TestWithdrawVerbReleasesOnlyMaturedRecords(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	// Head 7, next 8. One record at 8 (mature by execution), one at 50.
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Nonce: 9,
		Unbonding: []stakingUnbondingRec{
			{Amount: 400 * genesis.SparksPerB10, ReleaseHeight: 8},
			{Amount: 600 * genesis.SparksPerB10, ReleaseHeight: 50},
		},
	})
	if err := cmdWithdraw([]string{"--node", stub.url, "--key", keyPath}); err != nil {
		t.Fatalf("cmdWithdraw: %v", err)
	}
	tx := stub.posted()
	if tx.Type != types.TxWithdraw {
		t.Errorf("type = %d, want TxWithdraw (%d)", tx.Type, types.TxWithdraw)
	}
	if tx.Amount != 0 {
		t.Errorf("amount = %d, want 0 (withdraw carries no amount; applyWithdraw derives the total)", tx.Amount)
	}
	if tx.Fee != 0 {
		t.Errorf("fee = %d, want 0", tx.Fee)
	}
	if tx.Nonce != 9 {
		t.Errorf("nonce = %d, want 9", tx.Nonce)
	}

	// Nothing mature: refused, and the message names the next release height.
	late := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Nonce: 9,
		Unbonding: []stakingUnbondingRec{{Amount: 1, ReleaseHeight: 50}},
	})
	err := cmdWithdraw([]string{"--node", late.url, "--key", keyPath})
	if err == nil {
		t.Fatal("withdraw with no matured record must be refused")
	}
	if !strings.Contains(err.Error(), "height 50") {
		t.Errorf("the refusal should name the next release height, got: %v", err)
	}
	if len(late.posts) != 0 {
		t.Errorf("the verb posted %d transactions despite refusing", len(late.posts))
	}
}

// TestStakeRefusesABondTheAccountCannotCover: the balance check is the verb's
// own, run before signing. Without it the operator learns "insufficient funds"
// from the node instead of from the command that asked, and the funding note
// (the honest answer to "where do I get MIN_STAKE?") is never shown.
func TestStakeRefusesABondTheAccountCannotCover(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: 500 * genesis.SparksPerB10, Nonce: 0,
	})
	err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000"})
	if err == nil {
		t.Fatal("a bond the account cannot cover must be refused by the verb")
	}
	if !strings.Contains(err.Error(), "short") {
		t.Errorf("the refusal should name the shortfall, got: %v", err)
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb posted %d transactions despite refusing", len(stub.posts))
	}
}

// TestStakeMayAccumulateToMinStake: the chain's floor is on the RESULTING bond
// (state.applyBond), so an existing 600 b10 bond plus a 400 b10 bond is legal
// even though 400 alone is not. A verb that checked only --amount would refuse
// a transaction the chain accepts - and its own "the floor is on the result"
// text would be false.
func TestStakeMayAccumulateToMinStake(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(),
		Balance: 5_000 * genesis.SparksPerB10,
		Nonce:   2,
		Bonded:  600 * genesis.SparksPerB10,
	})
	if err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "400"}); err != nil {
		t.Fatalf("staking a 400 b10 top-up onto a 600 b10 bond must be accepted: %v", err)
	}
	tx := stub.posted()
	if want := uint64(400 * genesis.SparksPerB10); tx.Amount != want {
		t.Errorf("amount = %d, want %d (the top-up, not the resulting bond)", tx.Amount, want)
	}
	if tx.Nonce != 2 {
		t.Errorf("nonce = %d, want 2", tx.Nonce)
	}
}
