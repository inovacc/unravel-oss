//go:build integration

/*
Copyright (c) 2026 Security Research
*/

package mcptools

import (
	"bufio"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/mcp/lifecycle"
)

// TestParentWatcherEndToEnd builds the real unravel binary and the
// mcpparent test helper, spawns the helper which in turn spawns
// unravel.exe mcp with a never-closing stdin, kills the helper, and
// asserts the unravel process exits within 15 seconds (the production
// 5-second poll + a generous grace window for cmd.Wait + OS cleanup).
//
// Tagged 'integration' because it shells out to 'go build' and spawns
// real subprocesses; expected runtime ~30-60 seconds. Run with:
//
//	go test -tags=integration -run TestParentWatcherEndToEnd ./pkg/mcptools/...
func TestParentWatcherEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	tmp := t.TempDir()

	unravelBin := filepath.Join(tmp, exeName("unravel"))
	parentBin := filepath.Join(tmp, exeName("mcpparent"))

	build(t, unravelBin, ".")
	build(t, parentBin, "./internal/devtools/mcpparent")

	cmd := exec.Command(parentBin, unravelBin)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = nil // discard MCP JSON-RPC chatter
	if err := cmd.Start(); err != nil {
		t.Fatalf("start parent: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Read the unravel PID from the helper's first stdout line.
	rdr := bufio.NewReader(stdout)
	pidLine, err := rdr.ReadString('\n')
	if err != nil {
		t.Fatalf("read child pid: %v", err)
	}
	unravelPID, err := strconv.Atoi(strings.TrimSpace(pidLine))
	if err != nil {
		t.Fatalf("parse child pid %q: %v", pidLine, err)
	}

	// Give the unravel process a moment to finish its startup so the
	// parent watcher is actually running before we kill the parent.
	time.Sleep(2 * time.Second)
	if !lifecycle.ProcessAlive(unravelPID) {
		t.Fatalf("unravel pid %d did not stay alive long enough to start watcher", unravelPID)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill parent: %v", err)
	}
	_, _ = cmd.Process.Wait()

	// Poll: ProcessAlive should return false within ~10s on the
	// production 5s poll cadence + ServerSession shutdown latency.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if !lifecycle.ProcessAlive(unravelPID) {
			return // success
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("unravel pid %d still alive 15s after parent kill", unravelPID)
}

func build(t *testing.T, out, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	// Run from the repo root regardless of where the test was invoked.
	cmd.Dir = e2eRepoRoot(t)
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s -> %s: %v\n%s", pkg, out, err, data)
	}
}

func e2eRepoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func exeName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}
