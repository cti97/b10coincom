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
	"net/url"
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

	"github.com/cti97/b10coincom/internal/crypto"
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
	// --allow-local-peer-hints (audit M-2) is a PEER_EXCHANGE admission
	// exception, and PEER_EXCHANGE only runs on a networked node: a producer
	// that accepted, and silently ignored, a security-relevant switch would be
	// a flag that lies.
	if err := cmdNode([]string{"--dir", filepath.Join(dir, "d6"), "--allow-local-peer-hints"}); err == nil || !strings.Contains(err.Error(), "--allow-local-peer-hints") {
		t.Errorf("--allow-local-peer-hints on the single-node producer must be refused, got: %v", err)
	}
	if err := cmdNode([]string{"--dir", filepath.Join(dir, "d7"), "--allow-local-peer-hints", "--genesis", cf}); err == nil || !strings.Contains(err.Error(), "--key") {
		t.Errorf("--allow-local-peer-hints must be ACCEPTED on the networked path (the refusal here must be --genesis's own demand for --key), got: %v", err)
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
	fee         uint64 // the min_fee_sparks this node reports; 1 unless a test lies
	chainID     string // the chain_id this node reports; a claim --key run needs the devnet's
	posts       [][]byte
	url         string
	ts          *httptest.Server

	// Reads, counted so a test can prove a refusal happened before the verb
	// asked the node anything (M6 Task 1's local checks).
	statusCalls  int
	accountCalls int

	// M6 Task 0: the history read. historyBody is served verbatim by
	// /history; historyQuery and historyCalls record what the verb asked for,
	// so a test can assert the window and the echo check without a chain.
	historyBody  *walletHistory
	historyQuery url.Values
	historyCalls int
}

func newStakingStub(t *testing.T, genesisHash [32]byte, acc stakingAccount) *stakingStub {
	t.Helper()
	s := &stakingStub{t: t, genesisHash: genesisHash, account: acc, fee: 1, chainID: "stub-chain-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		fee := s.fee
		chainID := s.chainID
		s.statusCalls++
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"chain_id":         chainID,
			"height":           uint64(7),
			"genesis_hash":     hex.EncodeToString(s.genesisHash[:]),
			"min_fee_sparks":   fee,
			"min_stake_sparks": uint64(100_000_000_000),
			"epoch_blocks":     uint64(1_000),
			"unbonding_epochs": uint64(2),
			"committee_size":   1,
		})
	})
	mux.HandleFunc("/account/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.accountCalls++
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(s.account)
	})
	mux.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body := s.historyBody
		s.historyQuery = r.URL.Query()
		s.historyCalls++
		s.mu.Unlock()
		if body == nil {
			_ = json.NewEncoder(w).Encode(walletHistory{Txs: []walletHistoryEntry{}})
			return
		}
		_ = json.NewEncoder(w).Encode(body)
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

// setAccount replaces the account the stub reports, so one node can answer two
// reads with two different balances.
func (s *stakingStub) setAccount(acc stakingAccount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.account = acc
}

// setHistory replaces the body /history serves.
func (s *stakingStub) setHistory(h walletHistory) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.historyBody = &h
}

// historyAsked returns the last query the verb sent to /history and how many
// requests it made.
func (s *stakingStub) historyAsked() (url.Values, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.historyQuery, s.historyCalls
}

// setFee makes the stub report a different min_fee_sparks - the hostile node's
// lever in CL-1.
func (s *stakingStub) setFee(fee uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fee = fee
}

// setChainID makes the stub report a different chain_id. claim --key refuses
// any chain but the compiled-in devnet's, because the puzzle parameters are
// genesis state; a claim test therefore points this at genesis.Devnet().
func (s *stakingStub) setChainID(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chainID = id
}

// reads returns how many /status and /account reads the stub has served.
func (s *stakingStub) reads() (status, account int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusCalls, s.accountCalls
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

	if err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000", "--yes"}); err != nil {
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
	if err := cmdUnstake([]string{"--node", stub.url, "--key", keyPath, "--yes"}); err != nil {
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
	if err := cmdUnstake([]string{"--node", stub.url, "--key", keyPath, "--amount", "250.5", "--yes"}); err != nil {
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
			err := cmdUnstake([]string{"--node", stub.url, "--key", keyPath, "--amount", tc.amount, "--yes"})
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
			args := []string{"--node", stub.url, "--key", keyPath, "--yes"}
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
	err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "999", "--yes"})
	if err == nil {
		t.Fatal("stake below MIN_STAKE must be refused")
	}
	if !strings.Contains(err.Error(), "MIN_STAKE") {
		t.Errorf("the refusal must name MIN_STAKE, got: %v", err)
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb posted %d transactions despite refusing", len(stub.posts))
	}
	if strings.Contains(err.Error(), "no shipped genesis") {
		t.Errorf("a refusal on an account holding 10,000 b10 appended the no-funding-path hint: %v", err)
	}
}

// TestTheResumeLineNamesARestoredRound pins the startup note for the
// rolling-restart trigger: silent at round 0 (a fresh height, the healthy
// restart), and naming the height, the restored round and the advice otherwise.
func TestTheResumeLineNamesARestoredRound(t *testing.T) {
	if got := resumeLine(1081, 0); got != "" {
		t.Fatalf("a node starting at round 0 printed a resume note: %q", got)
	}
	got := resumeLine(1081, 20)
	for _, want := range []string{"height 1081", "round 20", "after the chain has advanced", "rolling restart"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the resume note does not say %q: %q", want, got)
		}
	}
}

// TestTheFundingHintAppearsOnlyWhenTheBalanceCannotReachMinStake is the M5
// re-run's misleading-hint finding (2026-10-30): refusing a stake for a
// two-spark FEE shortfall appended "no shipped genesis gives an operator's key
// MIN_STAKE" even though the account held a thousand times MIN_STAKE. The hint
// is now conditional on the spendable balance being below MIN_STAKE, which is
// the case it was written for. Both endings are asserted on constructed
// balances, and the ST-1 refusal is checked through the real verb.
func TestTheFundingHintAppearsOnlyWhenTheBalanceCannotReachMinStake(t *testing.T) {
	const minStake = uint64(100_000_000_000)
	// A thousand times MIN_STAKE, two sparks short of bond plus fee.
	rich := 1000 * minStake
	err := checkSpendable(rich, rich, 2, minStake)
	if err == nil {
		t.Fatal("a two-spark fee shortfall must still be refused")
	}
	if strings.Contains(err.Error(), "no shipped genesis") {
		t.Fatalf("an account holding 1000x MIN_STAKE was told it has no shipped path to MIN_STAKE: %v", err)
	}
	if !strings.Contains(err.Error(), "short 2 sparks") {
		t.Fatalf("the refusal must still say how short it is: %v", err)
	}
	// An empty account: the hint is the honest answer and must stay.
	err = checkSpendable(0, minStake, 1, minStake)
	if err == nil {
		t.Fatal("a bond the balance cannot cover must be refused")
	}
	if !strings.Contains(err.Error(), "no shipped genesis") {
		t.Fatalf("an account with no spendable funds was not told where MIN_STAKE comes from: %v", err)
	}
	// The same rule on the ST-1 refusal (the bond would end below MIN_STAKE):
	// a funded account gets the arithmetic, not the funding lecture; a fresh
	// account gets both.
	keyPath, _, addr := stakingTestKey(t)
	funded := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{Address: addr.String(), Balance: 10_000 * genesis.SparksPerB10})
	if err := cmdStake([]string{"--node", funded.url, "--key", keyPath, "--amount", "999", "--yes"}); err == nil || strings.Contains(err.Error(), "no shipped genesis") {
		t.Fatalf("a funded account's ST-1 refusal carried the funding hint: %v", err)
	}
	empty := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{Address: addr.String(), Balance: 0})
	if err := cmdStake([]string{"--node", empty.url, "--key", keyPath, "--amount", "999", "--yes"}); err == nil || !strings.Contains(err.Error(), "no shipped genesis") {
		t.Fatalf("a fresh account's ST-1 refusal dropped the funding hint: %v", err)
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
	err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000", "--yes"})
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
	if err := cmdUnstake([]string{"--node", ts.URL, "--key", keyPath, "--yes"}); err == nil {
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
	if err := cmdWithdraw([]string{"--node", stub.url, "--key", keyPath, "--yes"}); err != nil {
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
	err := cmdWithdraw([]string{"--node", late.url, "--key", keyPath, "--yes"})
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

// TestReleaseForecastRoundsToTheEpochBoundary: the unstake verb prints the
// height the state will RECORD, not head+1+cooldown (audit ST-4). The cooldown
// is a floor and the release height is the epoch boundary at or after it, so a
// forecast that printed the raw sum would name a height that can never appear.
func TestReleaseForecastRoundsToTheEpochBoundary(t *testing.T) {
	st := stakingStatus{Height: 100, EpochBlocks: 1_000, UnbondingEpochs: 2}
	line, ok := releaseForecast(1_000_000, st, 2_000)
	if !ok {
		t.Fatal("no forecast for a funded exit")
	}
	// head+1+cooldown = 2,101; the next 1,000-block boundary is 3,000.
	if !strings.Contains(line, "height 3000") {
		t.Fatalf("the forecast does not name the epoch boundary: %q", line)
	}
	// A release that already lands on a boundary does not move.
	st.Height = 999 // 1,000 + 2,000 = 3,000
	line, ok = releaseForecast(1_000_000, st, 2_000)
	if !ok || !strings.Contains(line, "height 3000") {
		t.Fatalf("an exact boundary moved: %q", line)
	}
	// Nothing recorded, no forecast: a height would promise a payout that cannot
	// happen.
	if line, ok := releaseForecast(0, st, 2_000); ok {
		t.Fatalf("a zero funded exit forecast a release: %q", line)
	}
}

// TestAUnbondForecastFollowsTheFundedFirstSplit is audit C-1 in the verb, both
// halves. The state returns the operator's FUNDED coins first and destroys the
// unfunded grant only past them; and a partial exit leaves a seat, so the text
// must not say the seat is gone.
func TestAUnbondForecastFollowsTheFundedFirstSplit(t *testing.T) {
	const minStake = 1_000 * genesis.SparksPerB10
	st := stakingStatus{Height: 5, EpochBlocks: 10, UnbondingEpochs: 2, MinStakeSparks: minStake}

	// A topped-up genesis seat: a MIN_STAKE grant plus the operator's own
	// MIN_STAKE. A partial exit of the operator's MIN_STAKE is funded-first, so it
	// is RECORDED, gets a release height, and the remaining MIN_STAKE keeps the
	// seat. This is the case the old text answered with "the seat is gone ... and
	// there is nothing to withdraw".
	effect := unbondEffect(minStake, 2*minStake, minStake, st)
	for _, want := range []string{"RETAINED", "100000000000 sparks stay bonded", "height", "withdraw"} {
		if !strings.Contains(effect, want) {
			t.Fatalf("a funded partial exit from a topped-up genesis seat does not say %q: %q", want, effect)
		}
	}
	// Nothing of the grant is touched, so nothing is destroyed and the seat is
	// not gone - the two claims the old text made unconditionally.
	if strings.Contains(effect, "destroyed") {
		t.Fatalf("a partial exit of the operator's own coins destroyed part of the grant: %q", effect)
	}
	if strings.Contains(effect, "the seat is gone") {
		t.Fatalf("a partial exit that leaves a seat says the seat is gone: %q", effect)
	}
	if funded, destroyed := splitUnbondExit(minStake, 2*minStake, minStake); funded != minStake || destroyed != 0 {
		t.Fatalf("split = (funded %d, destroyed %d), want (%d, 0): the operator's coins leave first", funded, destroyed, minStake)
	}

	// The whole bond: the funded part is released and the grant is destroyed in
	// the same transaction, and only now is the seat gone.
	effect = unbondEffect(2*minStake, 2*minStake, minStake, st)
	if !strings.Contains(effect, "the seat is gone") || !strings.Contains(effect, "destroyed") || !strings.Contains(effect, "height") {
		t.Fatalf("a full exit from a topped-up genesis seat = %q, want a release, a destruction and a leaving seat", effect)
	}
	if funded, destroyed := splitUnbondExit(2*minStake, 2*minStake, minStake); funded != minStake || destroyed != minStake {
		t.Fatalf("full-exit split = (%d, %d), want (%d, %d)", funded, destroyed, minStake, minStake)
	}

	// A pure genesis grant: nothing funded, so nothing is released, and the exit
	// is destroyed whole - with the seat gone only because the bond was the grant.
	effect = unbondEffect(minStake, minStake, minStake, st)
	if strings.Contains(effect, "height") || strings.Contains(effect, "withdraw") {
		t.Fatalf("a pure genesis exit forecast a payout: %q", effect)
	}
	if !strings.Contains(effect, "destroyed") || !strings.Contains(effect, "the seat is gone") {
		t.Fatalf("a pure genesis exit = %q, want destroyed and the seat gone", effect)
	}
}

// TestWithdrawRefusesATruncatedUnbondingReply: /account is windowed (audit
// ST-4), and a verb that signed on a partial list could report "nothing
// matured" while the node holds a matured record. It refuses instead.
func TestWithdrawRefusesATruncatedUnbondingReply(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Nonce: 1,
		Unbonding:      []stakingUnbondingRec{{Amount: 1, ReleaseHeight: 8}},
		UnbondingTotal: 5,
	})
	err := cmdWithdraw([]string{"--node", stub.url, "--key", keyPath, "--yes"})
	if err == nil {
		t.Fatal("a windowed (truncated) unbonding reply must be refused")
	}
	if !strings.Contains(err.Error(), "record") {
		t.Errorf("the refusal should name the record count, got: %v", err)
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb posted %d transactions despite refusing", len(stub.posts))
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
	err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000", "--yes"})
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
	if err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "400", "--yes"}); err != nil {
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

// ---------------------------------------------------------------------------
// CL-1: the fee ceiling, the preview, the confirmation and --dry-run
// ---------------------------------------------------------------------------

// printedTx finds the canonical bytes the preview printed and decodes them. It
// is deliberately a parser over stdout rather than a look at a variable: the
// test must see exactly what a user would copy out.
func printedTx(t *testing.T, out string) (*types.Tx, []byte) {
	t.Helper()
	const marker = "  bytes       "
	i := strings.Index(out, marker)
	if i < 0 {
		t.Fatalf("the preview printed no canonical bytes:\n%s", out)
	}
	line := out[i+len(marker):]
	if j := strings.IndexByte(line, '\n'); j >= 0 {
		line = line[:j]
	}
	raw, err := hex.DecodeString(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("the preview's bytes are not hex: %v\n%s", err, out)
	}
	tx, err := types.DecodeTx(raw)
	if err != nil {
		t.Fatalf("the preview's bytes do not decode: %v\n%s", err, out)
	}
	return tx, raw
}

// TestHostileNodeFeeIsRefused is CL-1's attack. The stub reports the TRUE
// genesis hash (so a signature would be valid on the real chain) and a fee
// equal to the whole spendable balance minus the bond. Before the fix the verb
// signed that transaction and posted it; applyBond on the real chain would
// then burn the entire balance as the fee. Now the ceiling refuses it before
// Sign, and the preview shows the hostile number as evidence.
func TestHostileNodeFeeIsRefused(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	balance := uint64(5_000) * genesis.SparksPerB10
	amount := uint64(1_000) * genesis.SparksPerB10
	hostileFee := balance - amount

	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: balance, Nonce: 0,
	})
	stub.setFee(hostileFee)

	var err error
	out := captureStdout(t, func() {
		err = cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000", "--yes"})
	})
	if err == nil {
		t.Fatal("a bond whose fee is the whole spendable balance was signed, not refused")
	}
	for _, want := range []string{"refusing to sign", "--max-fee", "ceiling", fmt.Sprint(defaultMaxFeeSparks)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must contain %q for the operator to act on it, got: %v", want, err)
		}
	}
	// Audit E-2: the instruction must quote the CEILING, never the fee the
	// node reported. A hostile node chooses balance-amount, so echoing it into
	// "Re-run with --max-fee N" hands the operator a copy-pasteable flag that
	// signs away the whole balance.
	// The hostile fee may appear ONCE, as the reported claim. It must not
	// appear again in the instruction: "raise --max-fee above <the node's
	// number>" would still steer an operator into copying it.
	if got := strings.Count(err.Error(), fmt.Sprint(hostileFee)); got != 1 {
		t.Errorf("the node's fee appears %d times in the refusal, want exactly 1 (the report); the instruction must quote the ceiling, not the node's number: %v", got, err)
	}
	if strings.Contains(err.Error(), fmt.Sprintf("--max-fee %d", hostileFee)) {
		t.Errorf("the refusal echoed the node's fee into the --max-fee instruction: %v", err)
	}
	if !strings.Contains(err.Error(), "raise --max-fee") {
		t.Errorf("the refusal does not tell the operator to choose a ceiling itself: %v", err)
	}
	// The transaction the node asked for was built and printed BEFORE the
	// refusal, so the operator can see the number that was refused.
	printed, _ := printedTx(t, out)
	if printed.Fee != hostileFee {
		t.Errorf("the preview shows fee %d, want the node's hostile %d", printed.Fee, hostileFee)
	}
	if printed.Fee+printed.Amount != balance {
		t.Errorf("the fixture no longer models the attack: fee %d + bond %d != balance %d",
			printed.Fee, printed.Amount, balance)
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb POSTed %d transaction(s) after a fee-ceiling refusal", len(stub.posts))
	}
	if len(printed.Sig) != 0 {
		t.Error("the printed transaction carries a signature: it was signed before the ceiling was enforced")
	}
	t.Logf("the user sees: error: %v", err)
}

// TestFeeCeilingDefaultAndMaxFee pins both directions: the default is the
// protocol minimum (1 spark on every shipped genesis), one spark above it is
// refused until --max-fee raises the ceiling, and a --max-fee below the ask
// still refuses.
func TestFeeCeilingDefaultAndMaxFee(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fee     uint64
		extra   []string
		wantFee uint64 // 0 means "must be refused"
	}{
		{"default accepts the protocol minimum", 1, nil, 1},
		{"default refuses one spark above it", 2, nil, 0},
		{"--max-fee raises the ceiling", 500, []string{"--max-fee", "500"}, 500},
		{"--max-fee below the ask still refuses", 500, []string{"--max-fee", "499"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyPath, _, addr := stakingTestKey(t)
			stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
				Address: addr.String(), Balance: 5_000 * genesis.SparksPerB10, Nonce: 0,
			})
			stub.setFee(tc.fee)
			args := append([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000", "--yes"}, tc.extra...)
			var err error
			captureStdout(t, func() { err = cmdStake(args) })
			if tc.wantFee == 0 {
				if err == nil {
					t.Fatalf("a fee of %d spark was accepted with args %v", tc.fee, tc.extra)
				}
				if len(stub.posts) != 0 {
					t.Errorf("the verb posted %d transaction(s) despite refusing", len(stub.posts))
				}
				return
			}
			if err != nil {
				t.Fatalf("a fee of %d spark should be accepted here: %v", tc.fee, err)
			}
			if got := stub.posted().Fee; got != tc.wantFee {
				t.Errorf("signed fee = %d sparks, want %d", got, tc.wantFee)
			}
		})
	}
}

// TestPrintedTransactionIsTheSignedBytes is the CL-1 preview property, checked
// end to end: the hex on stdout is the unsigned canonical encoding, the posted
// bytes are exactly those bytes plus a signature, and the signature verifies
// over the SIGNING HASH OF THE PRINTED BYTES. Any code that printed a
// re-rendered summary, or signed a different transaction than it showed, fails
// here.
func TestPrintedTransactionIsTheSignedBytes(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	var reported [32]byte
	for i := range reported {
		reported[i] = byte(0x40 + i)
	}
	stub := newStakingStub(t, reported, stakingAccount{
		Address: addr.String(), Balance: 5_000 * genesis.SparksPerB10, Nonce: 3,
	})

	var err error
	out := captureStdout(t, func() {
		err = cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000", "--yes"})
	})
	if err != nil {
		t.Fatalf("cmdStake: %v", err)
	}
	printed, raw := printedTx(t, out)
	posted := stub.posted()

	if len(printed.Sig) != 0 {
		t.Fatal("the printed transaction carries a signature: it was printed after Sign, not before")
	}
	// Identical except for the signature.
	unsigned := *posted
	unsigned.Sig = nil
	if !bytes.Equal(unsigned.Encode(), raw) {
		t.Errorf("the posted transaction is not the printed bytes plus a signature:\n printed %x\n posted  %x",
			raw, unsigned.Encode())
	}
	// The signature covers the printed bytes' signing hash, not some other
	// transaction's.
	h := printed.SigningHash(reported)
	if !crypto.Verify(posted.PubKey, h[:], posted.Sig) {
		t.Error("the posted signature does not verify over the PRINTED transaction's signing hash")
	}
	// The human-readable fields agree with the bytes (they are decoded from
	// them), so a summary rendered from another data source would show here.
	for _, want := range []string{
		fmt.Sprintf("  nonce       %d", printed.Nonce),
		fmt.Sprintf("  fee         %d spark", printed.Fee),
		fmt.Sprintf("  amount      %d sparks", printed.Amount),
		printed.From.String(),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the preview does not show %q:\n%s", want, out)
		}
	}
}

// TestBuildTxRendersTheDecodedBytes: the renderer takes bytes, not a struct, so
// a summary can only ever describe the encoding it prints. Odd values make it
// impossible to pass by echoing a stub's /status or the flag defaults.
func TestBuildTxRendersTheDecodedBytes(t *testing.T) {
	pub, _ := genesis.DevAccountKey(0)
	tx := &types.Tx{
		Type:   types.TxBond,
		From:   types.AddressFromPub(pub),
		PubKey: pub,
		Nonce:  42,
		Fee:    7,
		Amount: 123,
	}
	b, err := buildTx(tx)
	if err != nil {
		t.Fatalf("buildTx: %v", err)
	}
	var buf bytes.Buffer
	b.print(&buf, genesis.Devnet().Hash(), "http://node.invalid", txProvenance{amount: "from --amount"}, 9)
	out := buf.String()
	for _, want := range []string{
		"  nonce       42",
		"  fee         7 spark  (the node's claim; ceiling 9)",
		"  amount      123 sparks (0.00000123 b10)  (from --amount)",
		fmt.Sprintf("  bytes       %x", tx.Encode()),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the preview does not render %q from the bytes:\n%s", want, out)
		}
	}
}

// TestNonInteractiveRunRefusesWithoutYes: a script (or cron, or CI) has no
// terminal, so nothing is signed unless the run says --yes. The preview is
// still printed, so the operator can see what was declined.
func TestNonInteractiveRunRefusesWithoutYes(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: 5_000 * genesis.SparksPerB10, Nonce: 0,
	})
	old := askConfirmation
	askConfirmation = func() (string, error) { return "", errNoAnswer }
	defer func() { askConfirmation = old }()

	var err error
	out := captureStdout(t, func() {
		err = cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000"})
	})
	if err == nil {
		t.Fatal("a non-interactive run without --yes signed a transaction")
	}
	for _, want := range []string{"refusing to sign", "--yes", "--dry-run"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must mention %q, got: %v", want, err)
		}
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb posted %d transaction(s) without confirmation", len(stub.posts))
	}
	printed, _ := printedTx(t, out)
	if len(printed.Sig) != 0 {
		t.Error("the unconfirmed transaction was signed anyway")
	}
	t.Logf("the user sees: error: %v", err)
}

// TestTerminalConfirmationControlsSigning: --yes is not the only path. A TTY
// answer of "yes" signs; anything else refuses. Both states are constructed,
// never raced.
func TestTerminalConfirmationControlsSigning(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)

	// "no" (and any non-"yes" answer) refuses.
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: 5_000 * genesis.SparksPerB10, Nonce: 0,
	})
	old := askConfirmation
	askConfirmation = func() (string, error) { return "no\n", nil }
	var err error
	captureStdout(t, func() {
		err = cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000"})
	})
	askConfirmation = old
	if err == nil {
		t.Fatal("the answer \"no\" still signed a transaction")
	}
	if !strings.Contains(err.Error(), `"no"`) {
		t.Errorf("the refusal should quote the answer, got: %v", err)
	}
	if len(stub.posts) != 0 {
		t.Errorf("a refused confirmation posted %d transaction(s)", len(stub.posts))
	}

	// "yes" signs.
	stub2 := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: 5_000 * genesis.SparksPerB10, Nonce: 0,
	})
	askConfirmation = func() (string, error) { return "YES\n", nil }
	defer func() { askConfirmation = old }()
	captureStdout(t, func() {
		err = cmdStake([]string{"--node", stub2.url, "--key", keyPath, "--amount", "1000"})
	})
	if err != nil {
		t.Fatalf("the answer \"yes\" must sign: %v", err)
	}
	if len(stub2.posts) != 1 {
		t.Errorf("the confirmed transaction was posted %d times, want 1", len(stub2.posts))
	}
}

// TestDryRunSignsAndPostsNothing: --dry-run builds and prints, then stops. The
// stub records every POST, and there is not one; the preview carries no
// signature; and the confirmation question is never asked.
func TestDryRunSignsAndPostsNothing(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: 5_000 * genesis.SparksPerB10, Nonce: 0,
	})
	old := askConfirmation
	asked := false
	askConfirmation = func() (string, error) {
		asked = true
		return "", errNoAnswer
	}
	defer func() { askConfirmation = old }()

	var err error
	out := captureStdout(t, func() {
		err = cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000", "--dry-run"})
	})
	if err != nil {
		t.Fatalf("--dry-run must succeed without --yes: %v", err)
	}
	if asked {
		t.Error("--dry-run asked for confirmation; it signs nothing and needs none")
	}
	if len(stub.posts) != 0 {
		t.Fatalf("--dry-run POSTed %d transaction(s)", len(stub.posts))
	}
	if !strings.Contains(out, "NOT signed and NOT posted") {
		t.Errorf("the dry run does not say plainly that nothing was signed or posted:\n%s", out)
	}
	if strings.Contains(out, "txid") {
		t.Errorf("the dry run printed a txid:\n%s", out)
	}
	printed, _ := printedTx(t, out)
	if len(printed.Sig) != 0 {
		t.Error("--dry-run signed the transaction")
	}
	// The same proof for an exit, whose submit path shares the code.
	bondStub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Nonce: 0, Bonded: 1_000 * genesis.SparksPerB10,
	})
	var err2 error
	out2 := captureStdout(t, func() {
		err2 = cmdUnstake([]string{"--node", bondStub.url, "--key", keyPath, "--dry-run"})
	})
	if err2 != nil {
		t.Fatalf("unstake --dry-run: %v", err2)
	}
	if len(bondStub.posts) != 0 {
		t.Fatalf("unstake --dry-run POSTed %d transaction(s)", len(bondStub.posts))
	}
	if !strings.Contains(out2, "NOT signed and NOT posted") {
		t.Errorf("unstake --dry-run does not say nothing was signed or posted:\n%s", out2)
	}
}

// TestFutureNonceIsPrintedAsTheNodesClaim documents the decision for CL-1's
// future-nonce variant: the CLI has no trusted nonce to compare against, so it
// does not invent one. The nonce is printed as the node's claim and the whole
// transaction must be confirmed with it visible.
func TestFutureNonceIsPrintedAsTheNodesClaim(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: 5_000 * genesis.SparksPerB10, Nonce: 999,
	})
	var err error
	out := captureStdout(t, func() {
		err = cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000", "--yes"})
	})
	if err != nil {
		t.Fatalf("cmdStake: %v", err)
	}
	if !strings.Contains(out, "  nonce       999  (the node's claim)") {
		t.Errorf("the preview must show the nonce as the node's claim:\n%s", out)
	}
	printed, _ := printedTx(t, out)
	if printed.Nonce != 999 {
		t.Errorf("printed nonce = %d, want the node's 999", printed.Nonce)
	}
	if got := stub.posted().Nonce; got != 999 {
		t.Errorf("signed nonce = %d, want 999", got)
	}
}

// TestUnstakeWithoutAmountSaysTheAmountIsTheNodesClaim is CL-1's
// under-reported-bond variant: with no --amount the unbond amount is the bond
// THIS NODE reported, which the CLI cannot verify. The fix is not to pretend
// otherwise but to make the choice visible - the preview names the source and
// says an under-report makes the exit partial; --amount makes the number the
// operator's own.
func TestUnstakeWithoutAmountSaysTheAmountIsTheNodesClaim(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	bonded := uint64(750) * genesis.SparksPerB10
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Nonce: 4, Bonded: bonded,
	})
	var err error
	out := captureStdout(t, func() {
		err = cmdUnstake([]string{"--node", stub.url, "--key", keyPath, "--yes"})
	})
	if err != nil {
		t.Fatalf("cmdUnstake: %v", err)
	}
	if !strings.Contains(out, "the WHOLE bond as this node reports it") {
		t.Errorf("the preview must say the whole-bond amount is the node's claim:\n%s", out)
	}
	if !strings.Contains(out, "PARTIAL exit") {
		t.Errorf("the preview must say an under-report makes the exit partial:\n%s", out)
	}
	printed, _ := printedTx(t, out)
	if printed.Amount != bonded {
		t.Errorf("the unbond carries %d sparks, want the node's reported bond %d", printed.Amount, bonded)
	}

	// --amount replaces the node's number with the operator's.
	stub2 := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Nonce: 4, Bonded: 2_500 * genesis.SparksPerB10,
	})
	chosen := uint64(1_000) * genesis.SparksPerB10
	out2 := captureStdout(t, func() {
		err = cmdUnstake([]string{"--node", stub2.url, "--key", keyPath, "--amount", "1000", "--yes"})
	})
	if err != nil {
		t.Fatalf("cmdUnstake --amount: %v", err)
	}
	if !strings.Contains(out2, "(from --amount)") {
		t.Errorf("the preview must say the amount came from --amount:\n%s", out2)
	}
	printed2, _ := printedTx(t, out2)
	if printed2.Amount != chosen {
		t.Errorf("the unbond carries %d sparks, want the operator's %d", printed2.Amount, chosen)
	}
}

// TestStakeRefusesAZeroReportedFee: a bond with fee 0 can never apply on a
// validated genesis (MinFeeSparks >= 1), so a node reporting 0 is refused
// before anything is built - the same class of lie as the hostile fee, in the
// direction that would silently produce an invalid transaction.
func TestStakeRefusesAZeroReportedFee(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: 5_000 * genesis.SparksPerB10, Nonce: 0,
	})
	stub.setFee(0)
	err := cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000", "--yes"})
	if err == nil {
		t.Fatal("a bond with a zero fee was accepted; it can never apply")
	}
	if !strings.Contains(err.Error(), "min_fee_sparks 0") {
		t.Errorf("the refusal should name the reported zero, got: %v", err)
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb posted %d transaction(s) despite refusing", len(stub.posts))
	}
}

// TestGetJSONRefusesARedirect is audit CL-4: net/http follows redirects by
// default, so a node (or an on-path party answering the configured address)
// could move the staking verbs' /status and /account reads to another server.
// The configured URL is the trust boundary, so a redirect must fail closed.
func TestGetJSONRefusesARedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"height":7}`))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirect.Close()

	var out struct {
		Height uint64 `json:"height"`
	}
	err := getJSON(redirect.URL+"/status", &out)
	if err == nil {
		t.Fatal("getJSON followed a redirect; the configured node must be the only server read")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("the refusal should name the redirect, got: %v", err)
	}
	if out.Height != 0 {
		t.Errorf("the redirect target's body was decoded (height %d), so the redirect was followed", out.Height)
	}
}

// TestBondPreviewNamesItsEffectBeforeTheSignature is audit CL-2. CL-1 added the
// preview, --yes and --dry-run, but the consequence ("the seat changes only at
// a boundary") and the fact that a posted transaction cannot be cancelled used
// to print after POST /tx. The preview must carry both before the bytes that
// get signed - the dry run proves they are visible even when nothing is sent.
func TestBondPreviewNamesItsEffectBeforeTheSignature(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	stub := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: 5_000 * genesis.SparksPerB10, Nonce: 0,
	})
	var err error
	out := captureStdout(t, func() {
		err = cmdStake([]string{"--node", stub.url, "--key", keyPath, "--amount", "1000", "--yes"})
	})
	if err != nil {
		t.Fatalf("cmdStake: %v", err)
	}
	effect := strings.Index(out, "effect      the bond is applied")
	bytesAt := strings.Index(out, "bytes       ")
	txidAt := strings.Index(out, "txid        ")
	if effect < 0 {
		t.Fatalf("the preview does not state the bond's effect:\n%s", out)
	}
	if bytesAt < 0 || txidAt < 0 || !(effect < bytesAt && bytesAt < txidAt) {
		t.Fatalf("the effect must be previewed before the signed bytes and the post (effect=%d bytes=%d txid=%d):\n%s",
			effect, bytesAt, txidAt, out)
	}
	if !strings.Contains(out, "cannot cancel or replace") {
		t.Errorf("the preview does not say the transaction is irreversible:\n%s", out)
	}

	// A dry run prints the same effect and signs nothing: the operator can see
	// what would happen before deciding to run it for real.
	dry := newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: 5_000 * genesis.SparksPerB10, Nonce: 0,
	})
	out2 := captureStdout(t, func() {
		err = cmdStake([]string{"--node", dry.url, "--key", keyPath, "--amount", "1000", "--dry-run"})
	})
	if err != nil {
		t.Fatalf("cmdStake --dry-run: %v", err)
	}
	if !strings.Contains(out2, "effect      the bond is applied") || !strings.Contains(out2, "cannot cancel or replace") {
		t.Errorf("the dry-run preview omits the effect or the irreversibility:\n%s", out2)
	}
}

// TestReleaseForecastRefusesAHostileOverflow is audit CL-4's unstake display
// line. The node reports epoch_blocks and unbonding_epochs; their product,
// head+1+cooldown and the round-up to a boundary must all be overflow-checked,
// and an unrepresentable height must print no forecast rather than a wrapped
// one. The guards predate this round; this test pins them.
func TestReleaseForecastRefusesAHostileOverflow(t *testing.T) {
	const maxUint64 = ^uint64(0)
	if _, ok := cooldownBlocks(stakingStatus{EpochBlocks: maxUint64, UnbondingEpochs: 2}); ok {
		t.Fatal("cooldownBlocks accepted an epoch_blocks x unbonding_epochs product that overflows uint64")
	}
	if _, ok := releaseForecast(1, stakingStatus{Height: maxUint64, EpochBlocks: 1, UnbondingEpochs: 1}, 1); ok {
		t.Fatal("releaseForecast accepted head+1 wrapping to zero")
	}
	if _, ok := releaseForecast(1, stakingStatus{Height: 1, EpochBlocks: 1, UnbondingEpochs: 1}, maxUint64); ok {
		t.Fatal("releaseForecast accepted head+1+cooldown that overflows uint64")
	}
	if _, ok := releaseForecast(1, stakingStatus{Height: maxUint64 - 1, EpochBlocks: maxUint64 - 1, UnbondingEpochs: 1}, 0); ok {
		t.Fatal("releaseForecast accepted a round-up to the next boundary that overflows uint64")
	}
}

// TestStdinIsTerminalUsesThePortableCharDeviceTest pins audit E-1's test. The
// classifier must NOT compare against os.DevNull: on Windows a console handle
// and NUL both stat with zero volume serial and index, so os.SameFile matched
// and a real console was reported non-interactive. os.ModeCharDevice is the
// portable answer. Both cases below are constructed from real files, not from
// the runner's stdin.
func TestStdinIsTerminalUsesThePortableCharDeviceTest(t *testing.T) {
	pipe, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	defer pipeW.Close()
	if stdinIsTerminal(pipe) {
		t.Error("a pipe was reported as an interactive terminal: piped consent would be accepted")
	}

	regular, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if stdinIsTerminal(regular) {
		t.Error("a regular file was reported as an interactive terminal")
	}

	// os.DevNull is a character device on Unix AND on Windows (Go's own
	// TestFileStatNUL pins ModeDevice|ModeCharDevice for NUL). Reporting it
	// true is the point of the portable test; the READ path is what refuses it,
	// which the next test pins.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if !stdinIsTerminal(null) {
		t.Error("the null device is a character device; the portable test must report it as one (a Windows console handle has the same stat shape, and that is the bug E-1 fixed)")
	}
}

// TestRealAskConfirmationRefusesEveryNonTerminal runs the REAL askConfirmation
// (not the stubbed seam) against constructed stdin states. The positive "yes"
// path needs a terminal and cannot be built portably (a pty is Unix-only, and a
// Windows conpty is a different API), so this covers every refusal the guard
// exists for: a pipe carrying "yes", a regular file carrying "yes", and the
// null device, which is a character device and therefore reaches the read.
func TestRealAskConfirmationRefusesEveryNonTerminal(t *testing.T) {
	old := os.Stdin
	defer func() { os.Stdin = old }()

	pipe, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pipeW.WriteString("yes\n"); err != nil {
		t.Fatal(err)
	}
	pipeW.Close()
	os.Stdin = pipe
	if answer, err := askConfirmation(); err != errNoAnswer || answer != "" {
		t.Fatalf("a pipe carrying %q produced (%q, %v); want the errNoAnswer refusal: piped consent must never sign", "yes", answer, err)
	}
	pipe.Close()

	regular, err := os.CreateTemp(t.TempDir(), "answers-yes")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := regular.WriteString("yes\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := regular.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	os.Stdin = regular
	if answer, err := askConfirmation(); err != errNoAnswer || answer != "" {
		t.Fatalf("a regular file carrying %q produced (%q, %v); want the errNoAnswer refusal", "yes", answer, err)
	}
	regular.Close()

	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = null
	if answer, err := askConfirmation(); err != errNoAnswer || answer != "" {
		t.Fatalf("the null device produced (%q, %v); EOF must never look like consent", answer, err)
	}
	null.Close()
}

// ---------------------------------------------------------------------------
// M6 Task 0: the read verbs
// ---------------------------------------------------------------------------

// balanceLine pulls the value of one labelled line out of the verb's output.
func balanceLine(t *testing.T, out, label string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, label) {
			return strings.TrimPrefix(line, label)
		}
	}
	t.Fatalf("the balance output has no %q line:\n%s", label, out)
	return ""
}

// TestBalanceVerbPrintsSparksAndB10Exactly pins the money render: sparks first,
// and the b10 value produced by an INTEGER division. The 29,000,000 row is the
// one that catches a float: 0.29 does not survive a float64 round trip, so
// uint64(float64(sparks)/1e8*1e8) is 28,999,999 - one spark short. (0.1 DOES
// survive it, which is why the plan's 10,000,000 example cannot catch the
// mutant on its own; both rows are here.)
func TestBalanceVerbPrintsSparksAndB10Exactly(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: addr.String(), Balance: 10_000_000, Nonce: 1})
	out := captureStdout(t, func() {
		if err := cmdBalance([]string{"--node", s.url, "--key", keyPath}); err != nil {
			t.Fatal(err)
		}
	})
	if got := balanceLine(t, out, "balance"); !strings.Contains(got, "10000000 sparks (0.1 b10)") {
		t.Fatalf("balance line = %q, want 10000000 sparks (0.1 b10)", got)
	}

	// The value a float loses a spark on. --address also exercises the read
	// without a key file.
	s.setAccount(stakingAccount{Address: addr.String(), Balance: 29_000_000, Nonce: 2})
	out = captureStdout(t, func() {
		if err := cmdBalance([]string{"--node", s.url, "--address", addr.String()}); err != nil {
			t.Fatal(err)
		}
	})
	if got := balanceLine(t, out, "balance"); !strings.Contains(got, "29000000 sparks (0.29 b10)") {
		t.Fatalf("balance line = %q, want 29000000 sparks (0.29 b10)", got)
	}
	if strings.Contains(out, "28999999") {
		t.Fatalf("the balance render lost a spark to a float:\n%s", out)
	}
	// Whole b10 renders without a fraction, not as "1.00000000".
	s.setAccount(stakingAccount{Address: addr.String(), Balance: 100_000_000, Nonce: 3})
	out = captureStdout(t, func() {
		if err := cmdBalance([]string{"--node", s.url, "--key", keyPath}); err != nil {
			t.Fatal(err)
		}
	})
	if got := balanceLine(t, out, "balance"); !strings.Contains(got, "100000000 sparks (1 b10)") {
		t.Fatalf("balance line = %q, want 100000000 sparks (1 b10)", got)
	}
}

// TestBalanceOutputFormatIsStable pins every label the M6 walkthrough greps, in
// order and with their padding: renaming one breaks a documented command.
func TestBalanceOutputFormatIsStable(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{
		Address: addr.String(), Balance: 100_000_000, Nonce: 1,
		Bonded: 1_400 * genesis.SparksPerB10, UnbondingTotal: 2,
	})
	out := captureStdout(t, func() {
		if err := cmdBalance([]string{"--node", s.url, "--key", keyPath}); err != nil {
			t.Fatal(err)
		}
	})
	want := []string{
		"address     " + addr.String(),
		"balance     100000000 sparks (1 b10)",
		"nonce       1",
		"bonded      140000000000 sparks (1400 b10)",
		"unbonding   2 records",
		"chain       stub-chain-1",
		"height      7",
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != len(want) {
		t.Fatalf("balance printed %d lines, want %d:\n%s", len(lines), len(want), out)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("balance line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

// TestBalanceRefusesANodeNamingAnotherAccount: the verb may only show the
// account it asked for. A node that answers with a different address is
// refused BEFORE anything is printed.
func TestBalanceRefusesANodeNamingAnotherAccount(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	_, _, other := stakingTestKey(t)
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: other.String(), Balance: 100_000_000, Nonce: 1})
	var err error
	out := captureStdout(t, func() {
		err = cmdBalance([]string{"--node", s.url, "--key", keyPath})
	})
	if err == nil {
		t.Fatal("a node answering for another account was accepted")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("the refusal reads %q; it must say it refused", err)
	}
	if strings.Contains(out, "balance") {
		t.Fatalf("the refused verb still printed a balance:\n%s", out)
	}
	if addr == other {
		t.Fatal("the two test keys derived the same address")
	}
}

// TestBalanceRefusesBothOrNeitherAddressFlag: --key and --address are
// alternatives, and a read with neither has nothing to read.
func TestBalanceRefusesBothOrNeitherAddressFlag(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: addr.String()})
	for _, args := range [][]string{
		{"--node", s.url},
		{"--node", s.url, "--key", keyPath, "--address", addr.String()},
	} {
		if err := cmdBalance(args); err == nil {
			t.Fatalf("balance %v was accepted", args)
		}
	}
}

// TestHistoryVerbPrintsTheWindowAndItsLimit pins the two things design
// decision 5 makes a deliverable: the window the node actually scanned, and
// the no-index sentence, on EVERY run.
func TestHistoryVerbPrintsTheWindowAndItsLimit(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	toPub, _, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	to := types.AddressFromPub(toPub).String()
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: addr.String()})
	s.setHistory(walletHistory{
		Address: addr.String(), Head: 7, From: 1, To: 7, Blocks: 7,
		Txs: []walletHistoryEntry{
			{TxID: strings.Repeat("ab", 32), Height: 7, Type: "transfer", From: addr.String(), To: to, Amount: 49_999_999, Fee: 1},
			{TxID: strings.Repeat("cd", 32), Height: 1, Type: "faucet claim", From: addr.String(), Amount: 100_000_000},
		},
	})
	out := captureStdout(t, func() {
		if err := cmdHistory([]string{"--node", s.url, "--key", keyPath}); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{
		"blocks 1..7, scanned 7, newest first",
		"49999999 sparks (0.49999999 b10)",
		"to   " + to,
		"100000000 sparks (1 b10)",
		"faucet claim",
		"no transaction index",
		"not a complete account history",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("history output is missing %q:\n%s", want, out)
		}
	}
	// The default window is the CLI's too, and it reaches the node as a
	// positive number (a zero would be a 400 at the handler).
	q, calls := s.historyAsked()
	if calls != 1 {
		t.Fatalf("history made %d requests, want 1", calls)
	}
	if q.Get("blocks") != "100" {
		t.Fatalf("history asked for blocks=%q, want the default 100", q.Get("blocks"))
	}
	if q.Get("address") != addr.String() {
		t.Fatalf("history asked for address=%q, want %s", q.Get("address"), addr)
	}

	// --blocks is passed through.
	out = captureStdout(t, func() {
		if err := cmdHistory([]string{"--node", s.url, "--address", addr.String(), "--blocks", "3"}); err != nil {
			t.Fatal(err)
		}
	})
	q, _ = s.historyAsked()
	if q.Get("blocks") != "3" {
		t.Fatalf("history --blocks 3 sent blocks=%q", q.Get("blocks"))
	}
	if !strings.Contains(out, "no transaction index") {
		t.Fatalf("the no-index sentence vanished on a non-default window:\n%s", out)
	}

	// From the RECIPIENT's side the same entry names the sender, not the
	// reader's own address: "to <self>" tells a reader nothing.
	s.setHistory(walletHistory{
		Address: addr.String(), Head: 7, From: 1, To: 7, Blocks: 7,
		Txs: []walletHistoryEntry{
			{Height: 7, Type: "transfer", From: to, To: addr.String(), Amount: 49_999_999, Fee: 1},
		},
	})
	out = captureStdout(t, func() {
		if err := cmdHistory([]string{"--node", s.url, "--key", keyPath}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "from "+to) {
		t.Fatalf("a received transfer does not name its sender:\n%s", out)
	}
	if strings.Contains(out, "to   "+addr.String()) {
		t.Fatalf("a received transfer is reported as going to the reader himself:\n%s", out)
	}
}

// TestHistoryRefusesAZeroWindowBeforeAskingTheNode: --blocks 0 is refused by
// the CLI itself, so an invalid window costs no request.
func TestHistoryRefusesAZeroWindowBeforeAskingTheNode(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: addr.String()})
	if err := cmdHistory([]string{"--node", s.url, "--key", keyPath, "--blocks", "0"}); err == nil {
		t.Fatal("history --blocks 0 was accepted")
	}
	if _, calls := s.historyAsked(); calls != 0 {
		t.Fatalf("history --blocks 0 made %d request(s); it must refuse before the read", calls)
	}
}

// TestHistoryRefusesAnotherAccountsReply: the node echoes the address it
// answered for, and a reply for somebody else must not be printed as this
// account's history.
func TestHistoryRefusesAnotherAccountsReply(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	_, _, other := stakingTestKey(t)
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: addr.String()})
	s.setHistory(walletHistory{Address: other.String(), Head: 7, From: 1, To: 7, Blocks: 7, Txs: []walletHistoryEntry{}})
	var err error
	out := captureStdout(t, func() {
		err = cmdHistory([]string{"--node", s.url, "--key", keyPath})
	})
	if err == nil {
		t.Fatal("a history reply for another address was accepted")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("the refusal reads %q; it must say it refused", err)
	}
	if strings.Contains(out, "history for") {
		t.Fatalf("the refused verb still printed a history:\n%s", out)
	}
}

// TestHistoryOnAnEmptyChainSaysSo: head 0 is not an error and not a lie about
// a window that does not exist.
func TestHistoryOnAnEmptyChainSaysSo(t *testing.T) {
	keyPath, _, addr := stakingTestKey(t)
	var gh [32]byte
	s := newStakingStub(t, gh, stakingAccount{Address: addr.String()})
	s.setHistory(walletHistory{Address: addr.String(), Head: 0, Txs: []walletHistoryEntry{}})
	out := captureStdout(t, func() {
		if err := cmdHistory([]string{"--node", s.url, "--key", keyPath}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "no blocks to scan") {
		t.Fatalf("an empty chain was not reported as an empty window:\n%s", out)
	}
	if !strings.Contains(out, "no transaction index") {
		t.Fatalf("the no-index sentence is missing on an empty chain:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// M6 Task 1: send, claim --key, and the moved envelope
// ---------------------------------------------------------------------------

// sendTestSetup builds a key, a stub that reports that key's account, and a
// recipient address that is not the sender's.
func sendTestSetup(t *testing.T, balance, nonce uint64) (keyPath string, from types.Address, to types.Address, stub *stakingStub) {
	t.Helper()
	keyPath, _, from = stakingTestKey(t)
	toPub, _ := genesis.DevAccountKey(1)
	to = types.AddressFromPub(toPub)
	stub = newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: from.String(), Balance: balance, Nonce: nonce,
	})
	return keyPath, from, to, stub
}

// TestSendVerbSubmitsATransferWithTheRightFields: the verb's whole job. The
// stub reports a genesis hash that is NOT the compiled-in devnet one, so the
// signature verifies against the REPORTED hash and not against devnet's.
func TestSendVerbSubmitsATransferWithTheRightFields(t *testing.T) {
	keyPath, _, from := stakingTestKey(t)
	toPub, _ := genesis.DevAccountKey(1)
	to := types.AddressFromPub(toPub)
	var reported [32]byte
	for i := range reported {
		reported[i] = byte(0x70 + i)
	}
	stub := newStakingStub(t, reported, stakingAccount{
		Address: from.String(), Balance: 5 * genesis.SparksPerB10, Nonce: 2,
	})
	out := captureStdout(t, func() {
		if err := cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--yes"}); err != nil {
			t.Fatalf("cmdSend: %v", err)
		}
	})
	if !strings.Contains(out, "txid        ") {
		t.Errorf("a posted send printed no txid:\n%s", out)
	}
	tx := stub.posted()
	if tx.Type != types.TxTransfer {
		t.Errorf("type = %d, want TxTransfer", tx.Type)
	}
	if tx.From != from {
		t.Errorf("From = %s, want the key file's address %s", tx.From, from)
	}
	if tx.To != to {
		t.Errorf("To = %s, want %s", tx.To, to)
	}
	if tx.Nonce != 2 {
		t.Errorf("nonce = %d, want the stub's 2", tx.Nonce)
	}
	if tx.Fee != 1 {
		t.Errorf("fee = %d, want the stub's min_fee_sparks 1", tx.Fee)
	}
	if want := uint64(50_000_000); tx.Amount != want {
		t.Errorf("amount = %d, want %d sparks", tx.Amount, want)
	}
	h := tx.SigningHash(reported)
	if !crypto.Verify(tx.PubKey, h[:], tx.Sig) {
		t.Error("the signature does not verify against the REPORTED genesis hash")
	}
	devnet := tx.SigningHash(genesis.Devnet().Hash())
	if crypto.Verify(tx.PubKey, devnet[:], tx.Sig) {
		t.Error("the signature verifies against the compiled-in devnet hash: the verb assumed a chain instead of reading the node's")
	}
}

// TestSendPostsExactlyThePrintedBytesPlusASignature: the preview is not a
// summary rendered from a second source. Minus the signature, the posted
// encoding is byte-identical to the printed hex, and the printed transaction
// carries no signature at all.
func TestSendPostsExactlyThePrintedBytesPlusASignature(t *testing.T) {
	keyPath, from, to, stub := sendTestSetup(t, 5*genesis.SparksPerB10, 4)
	out := captureStdout(t, func() {
		if err := cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--yes"}); err != nil {
			t.Fatalf("cmdSend: %v", err)
		}
	})
	printed, raw := printedTx(t, out)
	posted := stub.posted()
	if len(printed.Sig) != 0 {
		t.Fatal("the printed transaction carries a signature: it was printed after Sign, not before")
	}
	unsigned := *posted
	unsigned.Sig = nil
	if !bytes.Equal(unsigned.Encode(), raw) {
		t.Errorf("the posted transaction is not the printed bytes plus a signature:\n printed %x\n posted  %x", raw, unsigned.Encode())
	}
	h := printed.SigningHash(genesis.Devnet().Hash())
	if !crypto.Verify(posted.PubKey, h[:], posted.Sig) {
		t.Error("the signature does not cover the PRINTED transaction's signing hash")
	}
	if printed.From != from {
		t.Errorf("printed From = %s, want %s", printed.From, from)
	}
}

// TestSendPreviewNamesTheRecipientAndTheAmount pins the preview's three facts:
// the recipient (from the decoded bytes), the amount in sparks and b10, and the
// fee line a TRANSFER has - the node's claim with the ceiling. The exit's "an
// exit is free" and the claim's "a claim may not carry a fee" are different
// facts and must not appear here.
func TestSendPreviewNamesTheRecipientAndTheAmount(t *testing.T) {
	keyPath, _, to, stub := sendTestSetup(t, 5*genesis.SparksPerB10, 0)
	out := captureStdout(t, func() {
		if err := cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--yes"}); err != nil {
			t.Fatalf("cmdSend: %v", err)
		}
	})
	for _, want := range []string{
		"to          " + to.String(),
		"50000000 sparks (0.5 b10)",
		"the node's claim; ceiling 1",
		"the recipient is credited when a block includes the transaction",
		"the fee is burned",
		"cannot be withdrawn",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the transfer preview does not contain %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"an exit is free", "a claim may not carry a fee"} {
		if strings.Contains(out, bad) {
			t.Errorf("the transfer preview inherited %q, which is false for a transfer:\n%s", bad, out)
		}
	}
}

// TestSendRefusesAHostileFee: CL-1's attack on the transfer path. The stub
// reports the TRUE genesis hash (so a signature would be valid on the real
// chain) and a fee equal to the whole spendable balance minus the amount.
// applyTransfer would burn it; the ceiling refuses before Sign, and the preview
// shows the hostile number as evidence without instructing the operator to
// copy it.
func TestSendRefusesAHostileFee(t *testing.T) {
	balance := uint64(5_000) * genesis.SparksPerB10
	amount := uint64(1) * genesis.SparksPerB10
	keyPath, from, to, stub := sendTestSetup(t, balance, 0)
	hostileFee := balance - amount
	stub.setFee(hostileFee)

	var err error
	out := captureStdout(t, func() {
		err = cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "1", "--yes"})
	})
	if err == nil {
		t.Fatal("a transfer whose fee is the whole spendable balance was signed, not refused")
	}
	for _, want := range []string{"refusing to sign", "ceiling", "--max-fee"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must contain %q, got: %v", want, err)
		}
	}
	if got := strings.Count(err.Error(), fmt.Sprint(hostileFee)); got != 1 {
		t.Errorf("the node's fee appears %d times in the refusal, want exactly 1 (the report); the instruction must quote the ceiling: %v", got, err)
	}
	if strings.Contains(err.Error(), fmt.Sprintf("--max-fee %d", hostileFee)) {
		t.Errorf("the refusal echoed the node's fee into the --max-fee instruction: %v", err)
	}
	printed, _ := printedTx(t, out)
	if printed.Fee != hostileFee {
		t.Errorf("the preview shows fee %d, want the node's hostile %d", printed.Fee, hostileFee)
	}
	if len(printed.Sig) != 0 {
		t.Error("the printed transaction carries a signature: it was signed before the ceiling was enforced")
	}
	if status, account := stub.reads(); status == 0 || account == 0 {
		t.Errorf("the hostile fee test expected the verb to read the node, got status=%d account=%d", status, account)
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb POSTed %d transaction(s) after a fee-ceiling refusal", len(stub.posts))
	}
	_ = from
}

// TestSendRefusesMoreThanTheAccountCanCover: 0.5 b10 from 0.4 b10 is refused
// with the shortfall, before signing.
func TestSendRefusesMoreThanTheAccountCanCover(t *testing.T) {
	keyPath, _, to, stub := sendTestSetup(t, 40_000_000, 0)
	err := cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--yes"})
	if err == nil {
		t.Fatal("a transfer the account cannot cover was not refused")
	}
	if !strings.Contains(err.Error(), "short") {
		t.Errorf("the refusal does not name the shortfall: %v", err)
	}
	if !strings.Contains(err.Error(), "short 10000001 sparks") {
		t.Errorf("the shortfall is wrong: 50,000,000 + 1 - 40,000,000 = 10,000,001. Got: %v", err)
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb posted %d transactions despite refusing", len(stub.posts))
	}
}

// TestASendRefusalDoesNotLectureAboutStake: the bond's MIN_STAKE funding note
// is true about a bond and misleading about a transfer. The refusal says how
// short the send is and nothing about staking.
func TestASendRefusalDoesNotLectureAboutStake(t *testing.T) {
	keyPath, _, to, stub := sendTestSetup(t, 40_000_000, 0)
	err := cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--yes"})
	if err == nil {
		t.Fatal("a transfer the account cannot cover was not refused")
	}
	if !strings.Contains(err.Error(), "short") {
		t.Errorf("the refusal must name the shortfall: %v", err)
	}
	for _, bad := range []string{"no shipped genesis", "MIN_STAKE", "stake"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("the transfer refusal lectures about staking (%q): %v", bad, err)
		}
	}
	// The bond's check still carries the hint when it applies, which is what
	// makes this a split rather than a deletion.
	if err := checkSpendable(0, 10, 1, 100); err == nil || !strings.Contains(err.Error(), "no shipped genesis") {
		t.Fatalf("checkSpendable dropped the bond-only funding hint: %v", err)
	}
	if err := checkCover(0, 10, 1); err == nil || strings.Contains(err.Error(), "no shipped genesis") {
		t.Fatalf("checkCover must not carry the bond hint: %v", err)
	}
}

// TestSendRefusesZeroAmountSelfTransferAndABadAddress: three cheap local
// refusals. Each must happen BEFORE the verb asks a node anything - a bad
// command line is not a network error, and a self-transfer could never apply.
func TestSendRefusesZeroAmountSelfTransferAndABadAddress(t *testing.T) {
	keyPath, from, to, stub := sendTestSetup(t, 5*genesis.SparksPerB10, 0)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"zero amount", []string{"--key", keyPath, "--to", to.String(), "--amount", "0"}, "zero sparks"},
		{"self transfer", []string{"--key", keyPath, "--to", from.String(), "--amount", "0.5"}, "transfer to self"},
		{"bad address", []string{"--key", keyPath, "--to", "not-an-address", "--amount", "0.5"}, "--to"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--node", stub.url}, tc.args...)
			err := cmdSend(args)
			if err == nil {
				t.Fatalf("%s was not refused", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s refusal does not contain %q: %v", tc.name, tc.want, err)
			}
			if status, account := stub.reads(); status != 0 || account != 0 {
				t.Errorf("%s refused only after asking the node (status=%d account=%d)", tc.name, status, account)
			}
			if len(stub.posts) != 0 {
				t.Errorf("%s posted %d transactions", tc.name, len(stub.posts))
			}
		})
	}
}

// TestSendDryRunSignsAndPostsNothing: --dry-run builds and prints, then stops.
// The confirmation is never asked, no byte is posted and the printed
// transaction has no signature.
func TestSendDryRunSignsAndPostsNothing(t *testing.T) {
	keyPath, _, to, stub := sendTestSetup(t, 5*genesis.SparksPerB10, 0)
	old := askConfirmation
	asked := false
	askConfirmation = func() (string, error) { asked = true; return "", errNoAnswer }
	defer func() { askConfirmation = old }()

	var err error
	out := captureStdout(t, func() {
		err = cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--dry-run"})
	})
	if err != nil {
		t.Fatalf("--dry-run must succeed without --yes: %v", err)
	}
	if asked {
		t.Error("--dry-run asked for confirmation; it signs nothing and needs none")
	}
	if len(stub.posts) != 0 {
		t.Fatalf("--dry-run POSTed %d transaction(s)", len(stub.posts))
	}
	if !strings.Contains(out, "NOT signed and NOT posted") {
		t.Errorf("the dry run does not say plainly that nothing was signed or posted:\n%s", out)
	}
	if strings.Contains(out, "txid") {
		t.Errorf("the dry run printed a txid:\n%s", out)
	}
	printed, _ := printedTx(t, out)
	if len(printed.Sig) != 0 {
		t.Error("--dry-run signed the transaction")
	}
	if printed.Type != types.TxTransfer {
		t.Errorf("the dry run printed type %d, want a transfer", printed.Type)
	}
}

// TestSendRefusesAZeroReportedMinFee: a zero-fee transfer could never apply,
// because every shipped genesis sets at least one spark and genesis.Validate
// refuses a zero minimum. A node reporting 0 is refused before signing.
func TestSendRefusesAZeroReportedMinFee(t *testing.T) {
	keyPath, _, to, stub := sendTestSetup(t, 5*genesis.SparksPerB10, 0)
	stub.setFee(0)
	err := cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.5", "--yes"})
	if err == nil {
		t.Fatal("a node reporting min_fee_sparks 0 was not refused")
	}
	if !strings.Contains(err.Error(), "min_fee_sparks 0") {
		t.Errorf("the refusal does not name the reported zero fee: %v", err)
	}
	if len(stub.posts) != 0 {
		t.Errorf("the verb posted %d transaction(s) despite refusing", len(stub.posts))
	}
}

// TestSendAmountIsParsedWithoutAFloat: 0.29 b10 is 29,000,000 sparks. The
// float64 round trip uint64(ParseFloat("0.29")*1e8) is 28,999,999 - one spark
// short - so a verb that parsed --amount through a float would post 28,999,999
// here. (0.1 happens to round-trip and would NOT catch it, which is why this
// row is 0.29 and not 0.1.)
func TestSendAmountIsParsedWithoutAFloat(t *testing.T) {
	keyPath, _, to, stub := sendTestSetup(t, 5*genesis.SparksPerB10, 0)
	out := captureStdout(t, func() {
		if err := cmdSend([]string{"--node", stub.url, "--key", keyPath, "--to", to.String(), "--amount", "0.29", "--yes"}); err != nil {
			t.Fatalf("cmdSend: %v", err)
		}
	})
	tx := stub.posted()
	if want := uint64(29_000_000); tx.Amount != want {
		t.Fatalf("amount = %d, want %d sparks (0.29 b10); a float parse would post 28,999,999", tx.Amount, want)
	}
	if !strings.Contains(out, "29000000 sparks (0.29 b10)") {
		t.Errorf("the preview does not render 29,000,000 sparks (0.29 b10):\n%s", out)
	}
	if strings.Contains(out, "28999999") {
		t.Errorf("the preview rendered the one-spark-short float value:\n%s", out)
	}
}

// claimTestSetup builds a key and a stub that reports the devnet chain ID (a
// claim's puzzle parameters are genesis state, so claim --key refuses any other
// chain) with the key's account at the given nonce.
func claimTestSetup(t *testing.T, balance, nonce uint64) (keyPath string, addr types.Address, stub *stakingStub) {
	t.Helper()
	keyPath, _, addr = stakingTestKey(t)
	stub = newStakingStub(t, genesis.Devnet().Hash(), stakingAccount{
		Address: addr.String(), Balance: balance, Nonce: nonce,
	})
	stub.setChainID(genesis.Devnet().ChainID)
	return keyPath, addr, stub
}

// TestClaimWithKeySignsForTheKeyFileAndUsesTheAccountsNonce: the whole point of
// --key. The posted claim's From is the key file's address (not a fresh
// ephemeral one), the nonce is the node's account nonce (not 0), the fee is 0
// by consensus, the epoch is derived from the node's height, and the signature
// verifies.
func TestClaimWithKeySignsForTheKeyFileAndUsesTheAccountsNonce(t *testing.T) {
	keyPath, addr, stub := claimTestSetup(t, 0, 1)
	out := captureStdout(t, func() {
		if err := cmdClaim([]string{"--node", stub.url, "--key", keyPath, "--yes"}); err != nil {
			t.Fatalf("cmdClaim --key: %v", err)
		}
	})
	tx := stub.posted()
	if tx.Type != types.TxFaucetClaim {
		t.Errorf("type = %d, want TxFaucetClaim", tx.Type)
	}
	if tx.From != addr {
		t.Errorf("From = %s, want the key file's address %s", tx.From, addr)
	}
	if tx.Nonce != 1 {
		t.Errorf("nonce = %d, want the node's account nonce 1", tx.Nonce)
	}
	if tx.Fee != 0 {
		t.Errorf("fee = %d, want 0 (state.ErrClaimCarriesFee)", tx.Fee)
	}
	// The stub is at height 7 with 1000-block epochs:
	// epoch = (7+1)/1000 + 1 = 1.
	if tx.Epoch != 1 {
		t.Errorf("epoch = %d, want (height+1)/epoch_blocks+1 = 1", tx.Epoch)
	}
	want := fmt.Sprintf("claimant    %x", addr[:])
	if !strings.Contains(out, want) {
		t.Errorf("the claim output does not name the claimant address %q:\n%s", want, out)
	}
	if !strings.Contains(out, "txid        ") {
		t.Errorf("the posted claim printed no txid:\n%s", out)
	}
	h := tx.SigningHash(genesis.Devnet().Hash())
	if !crypto.Verify(tx.PubKey, h[:], tx.Sig) {
		t.Error("the claim's signature does not verify against the devnet genesis hash")
	}
}

// TestClaimWithKeyGoesThroughTheEnvelope: claim --key is not a second signing
// path. --dry-run posts nothing and signs nothing, a non-TTY run without --yes
// refuses, --yes posts, and no key is written anywhere (it already is a file).
func TestClaimWithKeyGoesThroughTheEnvelope(t *testing.T) {
	keyPath, _, stub := claimTestSetup(t, 0, 0)
	dir := filepath.Dir(keyPath)
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 1. --dry-run: prints, signs nothing, posts nothing.
	var dryErr error
	out := captureStdout(t, func() {
		dryErr = cmdClaim([]string{"--node", stub.url, "--key", keyPath, "--dry-run"})
	})
	if dryErr != nil {
		t.Fatalf("claim --key --dry-run: %v", dryErr)
	}
	if len(stub.posts) != 0 {
		t.Fatalf("--dry-run POSTed %d claim(s)", len(stub.posts))
	}
	if !strings.Contains(out, "NOT signed and NOT posted") {
		t.Errorf("the claim dry run does not say nothing was signed or posted:\n%s", out)
	}
	if strings.Contains(out, "queued on the node") {
		t.Errorf("the claim dry run printed a queueing receipt for a claim it never sent:\n%s", out)
	}
	printed, _ := printedTx(t, out)
	if len(printed.Sig) != 0 {
		t.Error("--dry-run signed the claim")
	}

	// 2. No --yes on a non-TTY stdin: refuse before Sign. The state is
	// CONSTRUCTED by replacing askConfirmation, never provoked by a race.
	old := askConfirmation
	askConfirmation = func() (string, error) { return "", errNoAnswer }
	err = cmdClaim([]string{"--node", stub.url, "--key", keyPath})
	askConfirmation = old
	if err == nil {
		t.Fatal("a non-interactive claim --key without --yes was signed")
	}
	for _, want := range []string{"refusing to sign", "--yes", "--dry-run"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must mention %q, got: %v", want, err)
		}
	}
	if len(stub.posts) != 0 {
		t.Errorf("the unconfirmed claim POSTed %d transaction(s)", len(stub.posts))
	}

	// 3. --yes posts exactly one claim.
	if err := cmdClaim([]string{"--node", stub.url, "--key", keyPath, "--yes"}); err != nil {
		t.Fatalf("claim --key --yes: %v", err)
	}
	if len(stub.posts) != 1 {
		t.Fatalf("the confirmed claim posted %d transactions, want 1", len(stub.posts))
	}

	// 4. No new file appeared next to the key: --key reads the key it was
	// given, it never writes one "for convenience".
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("claim --key created %d file(s) in the key's directory; it must write none", len(after)-len(before))
	}
}

// TestClaimPreviewPrintsTheEpochAndThePowNonce: the claim's preview is not the
// bond/exit preview with a different type line. It names the epoch as the
// NODE's claim (the transaction's only time binding, signed) and the
// locally-solved proof-of-work nonce, and the fee line says a claim may not
// carry a fee rather than that an exit is free.
func TestClaimPreviewPrintsTheEpochAndThePowNonce(t *testing.T) {
	keyPath, _, stub := claimTestSetup(t, 0, 0)
	out := captureStdout(t, func() {
		if err := cmdClaim([]string{"--node", stub.url, "--key", keyPath, "--dry-run"}); err != nil {
			t.Fatalf("claim --key --dry-run: %v", err)
		}
	})
	for _, want := range []string{
		"epoch       1  (the node's claim",
		"pow nonce   ",
		"solved the puzzle locally",
		"a claim may not carry a fee",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the claim preview does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "an exit is free") {
		t.Errorf("the claim preview inherited the exit's fee line:\n%s", out)
	}
	printed, _ := printedTx(t, out)
	if got := fmt.Sprintf("epoch       %d", printed.Epoch); !strings.Contains(out, got) {
		t.Errorf("the preview's epoch does not match the printed bytes (%d):\n%s", printed.Epoch, out)
	}
	if got := fmt.Sprintf("pow nonce   %d", printed.PowNonce); !strings.Contains(out, got) {
		t.Errorf("the preview's pow nonce does not match the printed bytes (%d):\n%s", printed.PowNonce, out)
	}
}

// TestClaimWithoutKeyIsUnchanged: without --key the ephemeral path still
// solves the puzzle for a fresh key, still prints that key (or withholds it),
// still has NO preview and NO confirmation, and posts a claim whose From is not
// the key file's address.
func TestClaimWithoutKeyIsUnchanged(t *testing.T) {
	_, fileAddr, stub := claimTestSetup(t, 0, 0)
	out := captureStdout(t, func() {
		// --print-key is opt-in since audit W-6; this test is about the
		// shape of the full output, so it asks for the key.
		if err := cmdClaim([]string{"--node", stub.url, "--print-key"}); err != nil {
			t.Fatalf("cmdClaim (ephemeral): %v", err)
		}
	})
	for _, want := range []string{
		"claimant    ",
		"public key  ",
		"claim epoch ",
		"pow nonce   ",
		"txid        ",
		"no key file, no keystore: the ephemeral signing key cannot be recovered later.",
		"ephemeral key ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the ephemeral claim output lost %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"transaction to sign", "  bytes       ", "NOT signed and NOT posted"} {
		if strings.Contains(out, bad) {
			t.Errorf("the ephemeral claim gained %q, which belongs to the --key envelope:\n%s", bad, out)
		}
	}
	tx := stub.posted()
	if tx.Type != types.TxFaucetClaim {
		t.Errorf("type = %d, want TxFaucetClaim", tx.Type)
	}
	if tx.Nonce != 0 {
		t.Errorf("nonce = %d, want 0 (a fresh ephemeral key has never transacted)", tx.Nonce)
	}
	if tx.Fee != 0 {
		t.Errorf("fee = %d, want 0", tx.Fee)
	}
	if tx.From == fileAddr {
		t.Error("the ephemeral claim signed for the --key file's address")
	}
	if len(tx.Sig) == 0 {
		t.Error("the ephemeral claim was posted without a signature")
	}

	// --print-key=false withholds the secret and says so; the claimant is
	// still printed.
	out = captureStdout(t, func() {
		if err := cmdClaim([]string{"--node", stub.url, "--print-key=false"}); err != nil {
			t.Fatalf("cmdClaim --print-key=false: %v", err)
		}
	})
	if strings.Contains(out, "<- copy now only if you plan a follow-up transfer") {
		t.Errorf("--print-key=false still printed the ephemeral key:\n%s", out)
	}
	if !strings.Contains(out, "pass --print-key to see it") {
		t.Errorf("--print-key=false does not say the key was withheld:\n%s", out)
	}
}

// TestNodeRefusesABlockTimeBelowOneSecond: the producer stamps blocks with
// time.Now().Unix() and the chain requires strictly increasing timestamps, so
// two blocks in one second stop the node. The refusal is cheap and names the
// cause; the walkthrough copies commands, and 500ms would be a dead node.
func TestNodeRefusesABlockTimeBelowOneSecond(t *testing.T) {
	for _, bt := range []string{"500ms", "999ms", "0s"} {
		d, perr := time.ParseDuration(bt)
		if perr != nil {
			t.Fatal(perr)
		}
		err := checkProducerBlockTime(d)
		if err == nil {
			t.Fatalf("--block-time %s was accepted; it can only kill the node at the second block", bt)
		}
		for _, want := range []string{"below the 1s floor", "whole seconds", "strictly greater"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the --block-time %s refusal does not name %q: %v", bt, want, err)
			}
		}
	}
	// The command uses the same check before it binds a listener. It must
	// refuse, not start a node that dies at height 1.
	if err := cmdNode([]string{"--dir", t.TempDir(), "--http", "127.0.0.1:0", "--block-time", "500ms"}); err == nil {
		t.Fatal("cmdNode accepted --block-time 500ms")
	}
	// 1s is the floor and is accepted by the check (the node itself is not
	// started here: the suite binds real ports and this test does not need one).
	if err := checkProducerBlockTime(time.Second); err != nil {
		t.Errorf("1s must be accepted: %v", err)
	}
}
