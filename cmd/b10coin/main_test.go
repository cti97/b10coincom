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

// freePort hands out an unbound loopback port (bind-and-release; a small race
// window is acceptable in a test fixture, and a failed subprocess bind is loud).
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type cliNodeProc struct {
	cmd    *exec.Cmd
	http   int
	stderr *bytes.Buffer
}

// startCliNode starts one node subprocess; httpPort is the --http port the
// test will poll.
func startCliNode(t *testing.T, bin string, httpPort int, args ...string) *cliNodeProc {
	t.Helper()
	c := exec.Command(bin, args...)
	stderr := &bytes.Buffer{}
	c.Stdout = &bytes.Buffer{}
	c.Stderr = stderr
	if err := c.Start(); err != nil {
		t.Fatalf("starting %v: %v", args, err)
	}
	return &cliNodeProc{cmd: c, http: httpPort, stderr: stderr}
}

func (p *cliNodeProc) stop(t *testing.T) {
	t.Helper()
	if p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
}

// status polls one node's /status until it reports height >= want, or fails.
func statusHeight(t *testing.T, port int, want uint64, timeout time.Duration) uint64 {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/status", port)
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	for {
		var st struct {
			ChainID string `json:"chain_id"`
			Height  uint64 `json:"height"`
		}
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			err = json.NewDecoder(resp.Body).Decode(&st)
			resp.Body.Close()
			if err == nil && st.Height >= want {
				return st.Height
			}
		} else if resp != nil {
			resp.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("node at %s never reached height %d", url, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// The --peers path: four nodes, four --listen addresses, dial lists complete,
// and the committee finalises. THIS is the test that catches a CLI mutant that
// ignores --peers (it would run four M1 producers on b10coin-devnet-1 — the
// chain id assertion names that), or that names the wrong seat.
func TestCliNodeDialsPeersAndRunsTheCommittee(t *testing.T) {
	nodeBin, _ := buildCliBinaries(t)

	p2p := make([]int, 4)
	httpPorts := make([]int, 4)
	dirs := make([]string, 4)
	for i := range p2p {
		p2p[i] = freePort(t)
		httpPorts[i] = freePort(t)
		dirs[i] = t.TempDir()
	}
	procs := make([]*cliNodeProc, 0, 4)
	for i := 0; i < 4; i++ {
		peers := make([]string, 0, 3)
		for j := 0; j < 4; j++ {
			if i != j {
				peers = append(peers, fmt.Sprintf("127.0.0.1:%d", p2p[j]))
			}
		}
		args := []string{
			"node",
			"--dir", dirs[i],
			"--http", fmt.Sprintf("127.0.0.1:%d", httpPorts[i]),
			"--listen", fmt.Sprintf("127.0.0.1:%d", p2p[i]),
			"--peers", strings.Join(peers, ","),
			"--validators", "4", "--index", strconv.Itoa(i),
		}
		procs = append(procs, startCliNode(t, nodeBin, httpPorts[i], args...))
		defer procs[len(procs)-1].stop(t)
	}
	for _, p := range procs {
		statusHeight(t, p.http, 2, 60*time.Second)
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

	relayPort := freePort(t)
	relayProc := startCliNode(t, relayBin, -1, "--addr", fmt.Sprintf("127.0.0.1:%d", relayPort), "--max-conns", "64")
	defer relayProc.stop(t)

	httpPorts := make([]int, 4)
	dirs := make([]string, 4)
	procs := make([]*cliNodeProc, 0, 4)
	for i := 0; i < 4; i++ {
		httpPorts[i] = freePort(t)
		dirs[i] = t.TempDir()
		args := []string{
			"node",
			"--dir", dirs[i],
			"--http", fmt.Sprintf("127.0.0.1:%d", httpPorts[i]),
			"--relay", fmt.Sprintf("127.0.0.1:%d", relayPort),
			"--validators", "4", "--index", strconv.Itoa(i),
		}
		procs = append(procs, startCliNode(t, nodeBin, httpPorts[i], args...))
		defer procs[len(procs)-1].stop(t)
	}
	for _, p := range procs {
		statusHeight(t, p.http, 2, 90*time.Second)
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
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/status", p.http))
		if err != nil {
			t.Fatalf("node %d status: %v (stderr: %s)", i, err, p.stderr.String())
		}
		var st struct {
			ChainID string `json:"chain_id"`
			Height  uint64 `json:"height"`
		}
		err = json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("node %d status decode: %v", i, err)
		}
		if st.ChainID != "b10coin-simnet-4" {
			t.Fatalf("node %d runs chain %q, want b10coin-simnet-4: the CLI did not run the committee path (stderr: %s)", i, st.ChainID, p.stderr.String())
		}
		if st.Height < 2 {
			t.Fatalf("node %d at height %d, want >= 2", i, st.Height)
		}
	}
}
