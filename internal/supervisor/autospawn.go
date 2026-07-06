/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// ErrAutospawnTestBinary is returned by Autospawn when os.Executable()
// resolves to a `go test` binary. Spawning it would re-run the whole
// suite detached (a self-replicating process leak), so the spawn is
// refused. Callers can errors.Is on this to fail fast instead of waiting
// out the socket-poll budget for a daemon that will never appear.
var ErrAutospawnTestBinary = errors.New("autospawn: refusing to spawn from a test binary")

// confirmLiveAttempts/confirmLiveBackoff bound how long Autospawn waits for a
// freshly spawned daemon to become reachable before deciding it died on
// startup. Vars (not consts) so tests can shrink them.
var (
	confirmLiveAttempts = 30
	confirmLiveBackoff  = 100 * time.Millisecond
)

// detachedExecFn is the detached-exec seam. Production wires it to the
// platform-specific detachedExec in autospawn_{unix,windows}.go; tests
// override it to avoid forking a real child.
var detachedExecFn = detachedExec

// Autospawn launches a detached supervisor process from execPath with
// args=[]string{"daemon", "serve", "--detached"}. Runs the spawn-guard
// check first; returns ErrSpawnLoopDetected if blocked.
//
// socketDir is the directory holding spawn-history.json (always a real
// filesystem path, not a named-pipe path).
//
// confirmLive is an optional liveness probe. cmd.Start() succeeding only
// proves the OS forked the process — it says nothing about whether the
// daemon survived init (DB connect, migrations, bind). When confirmLive is
// non-nil, Autospawn polls it for a bounded window and records exit_code=0
// only once the child is confirmed reachable; if it never comes up the spawn
// is recorded as a failure so the crash-loop guard counts startup deaths.
// A nil confirmLive preserves the legacy "record success on fork" behaviour.
//
// Platform-specific detached-exec lives in autospawn_{unix,windows}.go.
func Autospawn(execPath, socketDir string, confirmLive func() bool) error {
	// Refuse to spawn from a `go test` binary: os.Executable() under `go test`
	// is the test binary, so exec'ing it as `daemon serve --detached` re-runs
	// the whole suite detached, which dials the supervisor and autospawns again
	// — a self-replicating process leak. Real deployments exec the `unravel`
	// binary, never `*.test`/`*.test.exe`.
	if isTestBinary(execPath) {
		return fmt.Errorf("%w: %q", ErrAutospawnTestBinary, execPath)
	}
	sh, err := NewSpawnHistory(filepath.Join(socketDir, "spawn-history.json"))
	if err != nil {
		return fmt.Errorf("autospawn: load history: %w", err)
	}
	if err := sh.CheckGuard(); err != nil {
		return err
	}
	if err := detachedExecFn(execPath, "daemon", "serve", "--detached"); err != nil {
		// Record failure; persist; surface error.
		_ = sh.Record(1)
		return fmt.Errorf("autospawn: detached exec: %w", err)
	}
	if confirmLive != nil && !waitLive(confirmLive) {
		// Forked but never became reachable: treat as a startup death so the
		// crash-loop guard can see it (CheckGuard counts only exit_code != 0).
		_ = sh.Record(1)
		return fmt.Errorf("autospawn: daemon spawned but never became reachable")
	}
	// confirmed live (or no probe supplied): record a success marker.
	_ = sh.Record(0)
	return nil
}

// isTestBinary reports whether path is a `go test` binary (…/pkg.test or
// pkg.test.exe). See Autospawn for why these must never be spawned.
func isTestBinary(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(base, ".test") || strings.HasSuffix(base, ".test.exe")
}

// waitLive polls confirmLive up to confirmLiveAttempts times, returning true
// as soon as the daemon is reachable.
func waitLive(confirmLive func() bool) bool {
	for i := 0; i < confirmLiveAttempts; i++ {
		if confirmLive() {
			return true
		}
		time.Sleep(confirmLiveBackoff)
	}
	return false
}
