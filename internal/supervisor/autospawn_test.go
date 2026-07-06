/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// stubDetachedExec replaces the real detached-exec seam for tests so no
// child process is actually forked, and shrinks the liveness-poll window so
// never-live cases resolve quickly.
func stubDetachedExec(t *testing.T, fn func(execPath string, args ...string) error) {
	t.Helper()
	prevExec := detachedExecFn
	prevAttempts := confirmLiveAttempts
	prevBackoff := confirmLiveBackoff
	detachedExecFn = fn
	confirmLiveAttempts = 3
	confirmLiveBackoff = time.Millisecond
	t.Cleanup(func() {
		detachedExecFn = prevExec
		confirmLiveAttempts = prevAttempts
		confirmLiveBackoff = prevBackoff
	})
}

// loadHistory reads the persisted spawn-history.json and counts failure
// events (exit_code != 0) within the guard window.
func failureCount(t *testing.T, path string) int {
	t.Helper()
	sh, err := NewSpawnHistory(path)
	if err != nil {
		t.Fatalf("reload history: %v", err)
	}
	n := 0
	for _, e := range sh.events {
		if e.ExitCode != 0 {
			n++
		}
	}
	return n
}

func TestAutospawn_NeverLive_RecordsFailure(t *testing.T) {
	tmp := t.TempDir()
	histPath := filepath.Join(tmp, "spawn-history.json")
	stubDetachedExec(t, func(string, ...string) error { return nil }) // fork "succeeds"

	// confirmLive always reports the child never became reachable.
	err := Autospawn("unravel", tmp, func() bool { return false })
	if err == nil {
		t.Fatalf("Autospawn with never-live child: want error, got nil")
	}
	if got := failureCount(t, histPath); got != 1 {
		t.Fatalf("failure events recorded = %d, want 1 (spawned-but-never-reachable must count toward the guard)", got)
	}
}

func TestAutospawn_LiveChild_RecordsSuccess(t *testing.T) {
	tmp := t.TempDir()
	histPath := filepath.Join(tmp, "spawn-history.json")
	stubDetachedExec(t, func(string, ...string) error { return nil })

	if err := Autospawn("unravel", tmp, func() bool { return true }); err != nil {
		t.Fatalf("Autospawn with live child: %v", err)
	}
	if got := failureCount(t, histPath); got != 0 {
		t.Fatalf("failure events recorded = %d, want 0 (a confirmed-live spawn is a success)", got)
	}
}

func TestAutospawn_NeverLive_TripsGuardAfter3(t *testing.T) {
	tmp := t.TempDir()
	stubDetachedExec(t, func(string, ...string) error { return nil })

	for i := 0; i < 3; i++ {
		_ = Autospawn("unravel", tmp, func() bool { return false })
	}
	// The 4th attempt must be blocked by the crash-loop guard, proving the
	// never-live spawns were counted as failures.
	err := Autospawn("unravel", tmp, func() bool { return false })
	if !errors.Is(err, ErrSpawnLoopDetected) {
		t.Fatalf("after 3 never-live spawns: got %v, want ErrSpawnLoopDetected", err)
	}
}

func TestAutospawn_ExecFailure_RecordsFailure(t *testing.T) {
	tmp := t.TempDir()
	histPath := filepath.Join(tmp, "spawn-history.json")
	stubDetachedExec(t, func(string, ...string) error { return errors.New("fork failed") })

	// confirmLive should never be consulted when exec itself fails.
	called := false
	err := Autospawn("unravel", tmp, func() bool { called = true; return true })
	if err == nil {
		t.Fatalf("Autospawn with exec failure: want error, got nil")
	}
	if called {
		t.Fatalf("confirmLive must not run when detached-exec fails")
	}
	if got := failureCount(t, histPath); got != 1 {
		t.Fatalf("failure events recorded = %d, want 1", got)
	}
}

func TestAutospawn_NilConfirmLive_DefaultsToSuccess(t *testing.T) {
	// A nil confirmLive preserves the legacy "record success on fork" behaviour
	// for callers that have no liveness probe to inject.
	tmp := t.TempDir()
	histPath := filepath.Join(tmp, "spawn-history.json")
	stubDetachedExec(t, func(string, ...string) error { return nil })

	if err := Autospawn("unravel", tmp, nil); err != nil {
		t.Fatalf("Autospawn nil confirmLive: %v", err)
	}
	if got := failureCount(t, histPath); got != 0 {
		t.Fatalf("failure events recorded = %d, want 0", got)
	}
}
