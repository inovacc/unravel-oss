/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewSpawnHistory_CorruptFileErrors(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "spawn-history.json")
	// A truncated / garbled history file (e.g. a crash mid-write) must NOT
	// be silently swallowed — that disables the crash-loop guard.
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	_, err := NewSpawnHistory(path)
	if err == nil {
		t.Fatalf("NewSpawnHistory on corrupt file: want error, got nil")
	}
}

func TestSpawnGuard_AllowsWhenEmpty(t *testing.T) {
	tmp := t.TempDir()
	sh, err := NewSpawnHistory(filepath.Join(tmp, "spawn-history.json"))
	if err != nil {
		t.Fatalf("NewSpawnHistory: %v", err)
	}
	if err := sh.CheckGuard(); err != nil {
		t.Errorf("CheckGuard empty: %v", err)
	}
}

func TestSpawnGuard_BlocksAfter3FailuresIn10s(t *testing.T) {
	tmp := t.TempDir()
	sh, _ := NewSpawnHistory(filepath.Join(tmp, "spawn-history.json"))

	base := time.Now()
	sh.now = func() time.Time { return base }
	if err := sh.Record(1); err != nil {
		t.Fatal(err)
	}
	sh.now = func() time.Time { return base.Add(2 * time.Second) }
	if err := sh.Record(1); err != nil {
		t.Fatal(err)
	}
	sh.now = func() time.Time { return base.Add(5 * time.Second) }
	if err := sh.Record(1); err != nil {
		t.Fatal(err)
	}

	sh.now = func() time.Time { return base.Add(6 * time.Second) }
	err := sh.CheckGuard()
	if !errors.Is(err, ErrSpawnLoopDetected) {
		t.Errorf("CheckGuard after 3 failures in 6s: got %v, want ErrSpawnLoopDetected", err)
	}
}

func TestSpawnGuard_AllowsAfterWindowExpires(t *testing.T) {
	tmp := t.TempDir()
	sh, _ := NewSpawnHistory(filepath.Join(tmp, "spawn-history.json"))

	base := time.Now()
	sh.now = func() time.Time { return base }
	_ = sh.Record(1)
	_ = sh.Record(1)
	_ = sh.Record(1)

	sh.now = func() time.Time { return base.Add(15 * time.Second) }
	if err := sh.CheckGuard(); err != nil {
		t.Errorf("CheckGuard 15s after failures: %v (expected window expired)", err)
	}
}

func TestSpawnGuard_SuccessExitsNotCounted(t *testing.T) {
	tmp := t.TempDir()
	sh, _ := NewSpawnHistory(filepath.Join(tmp, "spawn-history.json"))

	base := time.Now()
	sh.now = func() time.Time { return base }
	_ = sh.Record(0)
	_ = sh.Record(0)
	_ = sh.Record(0)
	if err := sh.CheckGuard(); err != nil {
		t.Errorf("CheckGuard after 3 successes: %v (success exits should not block)", err)
	}
}

func TestSpawnGuard_PersistsAcrossInstances(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "spawn-history.json")

	sh1, _ := NewSpawnHistory(path)
	base := time.Now()
	sh1.now = func() time.Time { return base }
	_ = sh1.Record(1)
	_ = sh1.Record(1)
	_ = sh1.Record(1)

	sh2, err := NewSpawnHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	sh2.now = func() time.Time { return base.Add(1 * time.Second) }
	if err := sh2.CheckGuard(); !errors.Is(err, ErrSpawnLoopDetected) {
		t.Errorf("CheckGuard on reloaded history: got %v, want ErrSpawnLoopDetected", err)
	}
}
