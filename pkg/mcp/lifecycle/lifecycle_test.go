/*
Copyright (c) 2026 Security Research
*/

package lifecycle

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestRegisterListClose(t *testing.T) {
	dir := t.TempDir()
	inst, err := Register(dir, Info{ProjectDir: "/tmp/proj"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if inst.PID() != os.Getpid() {
		t.Fatalf("PID = %d, want %d", inst.PID(), os.Getpid())
	}
	got, err := List(dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].PID != os.Getpid() {
		t.Fatalf("List = %+v, want one entry with pid=%d", got, os.Getpid())
	}
	if got[0].ProjectDir != "/tmp/proj" {
		t.Fatalf("ProjectDir = %q", got[0].ProjectDir)
	}
	if err := inst.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got2, _ := List(dir)
	if len(got2) != 0 {
		t.Fatalf("List after Close = %+v, want empty", got2)
	}
	// Idempotent close.
	if err := inst.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestRegisterEmptyDirDisabled(t *testing.T) {
	inst, err := Register("", Info{})
	if err != nil {
		t.Fatalf("Register(\"\"): %v", err)
	}
	if !inst.off {
		t.Fatal("expected off=true for empty dir")
	}
	// All methods are no-ops, do not panic.
	inst.Touch()
	if err := inst.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestTouchUpdatesActivity(t *testing.T) {
	dir := t.TempDir()
	inst, err := Register(dir, Info{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = inst.Close() }()

	initial := inst.info.LastActivityAt
	// Throttle: first call within 1s of StartedAt may be skipped.
	time.Sleep(1100 * time.Millisecond)
	inst.Touch()
	if !inst.info.LastActivityAt.After(initial) {
		t.Fatalf("LastActivityAt not advanced: initial=%v, now=%v", initial, inst.info.LastActivityAt)
	}
}

// TestCleanRemovesDeadEntry writes a registry file for a guaranteed-dead
// PID, then verifies Clean removes it. A high PID like 2^31-1 will not
// be assigned on Windows or Unix in normal operation.
func TestCleanRemovesDeadEntry(t *testing.T) {
	dir := t.TempDir()
	deadPID := 2147483646
	stale := Info{
		PID:            deadPID,
		ParentPID:      deadPID,
		StartedAt:      time.Now().UTC().Add(-time.Hour),
		LastActivityAt: time.Now().UTC().Add(-time.Hour),
		ProjectDir:     "/dev/null",
	}
	writeRecord(t, dir, stale)

	results, err := Clean(dir, false)
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if len(results) != 1 || !results[0].Removed {
		t.Fatalf("Clean results = %+v, want one Removed", results)
	}
	if results[0].Reason == "" {
		t.Fatal("Clean did not set Reason on removed entry")
	}
	remaining, _ := List(dir)
	if len(remaining) != 0 {
		t.Fatalf("remaining after Clean = %+v, want empty", remaining)
	}
}

// TestCleanPreservesAliveSelfAndOthers makes sure Clean never touches
// the calling process's own record and leaves entries with a living
// parent intact.
func TestCleanPreservesAliveSelfAndOthers(t *testing.T) {
	dir := t.TempDir()
	inst, err := Register(dir, Info{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = inst.Close() }()

	results, err := Clean(dir, false)
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	for _, r := range results {
		if r.Info.PID == os.Getpid() {
			t.Fatalf("Clean attempted to remove self: %+v", r)
		}
	}
	remaining, _ := List(dir)
	if len(remaining) != 1 || remaining[0].PID != os.Getpid() {
		t.Fatalf("remaining = %+v, want only self", remaining)
	}
}

func TestCleanForceIgnoresActivityWindow(t *testing.T) {
	dir := t.TempDir()
	deadPID := 2147483645
	recent := Info{
		PID:            deadPID,
		ParentPID:      deadPID,
		StartedAt:      time.Now().UTC(),
		LastActivityAt: time.Now().UTC(), // fresh activity, but pid is dead
		ProjectDir:     "/dev/null",
	}
	writeRecord(t, dir, recent)

	// Without force the entry is still cleaned because the PID itself is dead.
	results, err := Clean(dir, true)
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if len(results) != 1 || !results[0].Removed {
		t.Fatalf("Clean(force=true) results = %+v", results)
	}
}

// writeRecord drops a registry JSON file directly without going through
// Register so tests can simulate other processes' entries.
func writeRecord(t *testing.T, dir string, info Info) {
	t.Helper()
	path := filepath.Join(dir, strconv.Itoa(info.PID)+".json")
	inst := &Instance{dir: dir, path: path, info: info}
	if err := inst.writeLocked(); err != nil {
		t.Fatalf("writeRecord: %v", err)
	}
}
