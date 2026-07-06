/*
Copyright (c) 2026 Security Research

Round-trip + atomic-rename tests for pkg/ai/cache. Each test uses a unique
namespace under store.CacheDir() and cleans up via t.Cleanup, avoiding any
need to override the store helper.
*/
package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/store"
)

// nsForTest returns a namespace unique to t.Name() and registers cleanup.
func nsForTest(t *testing.T) string {
	t.Helper()
	ns := "test-ai-cache-" + strings.ReplaceAll(t.Name(), "/", "_")
	t.Cleanup(func() {
		_ = os.RemoveAll(filepath.Join(store.CacheDir(), ns))
	})
	return ns
}

func TestPutGet_RoundTrip(t *testing.T) {
	ns := nsForTest(t)
	body := []byte(`{"x":1}`)
	if err := Put(ns, "k.json", body); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := Get(ns, "k.json")
	if !ok {
		t.Fatalf("Get: ok=false, want true")
	}
	if string(got) != string(body) {
		t.Fatalf("body mismatch: got=%q want=%q", got, body)
	}
}

func TestGet_Miss(t *testing.T) {
	ns := nsForTest(t)
	got, ok := Get(ns, "nonexistent")
	if ok {
		t.Fatalf("Get: ok=true on miss")
	}
	if got != nil {
		t.Fatalf("Get: body=%q on miss, want nil", got)
	}
}

func TestPut_AtomicNoTmpLeftover(t *testing.T) {
	ns := nsForTest(t)
	if err := Put(ns, "k.json", []byte("hello")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	dir := filepath.Join(store.CacheDir(), ns)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover tmp file: %s", e.Name())
		}
	}
}

func TestPut_Overwrite(t *testing.T) {
	ns := nsForTest(t)
	if err := Put(ns, "k.json", []byte("first")); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	if err := Put(ns, "k.json", []byte("second")); err != nil {
		t.Fatalf("Put second: %v", err)
	}
	got, ok := Get(ns, "k.json")
	if !ok {
		t.Fatalf("Get: ok=false after overwrite")
	}
	if string(got) != "second" {
		t.Fatalf("overwrite failed: got=%q want=%q", got, "second")
	}
}

// TestPut_RenameFailureCleansTmp forces os.Rename to fail by making the
// destination path a directory, then asserts Put surfaces the error AND
// leaves no orphan temp file behind (the regression for finding #12). A
// unique temp name is used per Put, so a failed rename must self-clean.
func TestPut_RenameFailureCleansTmp(t *testing.T) {
	ns := nsForTest(t)
	dir := filepath.Join(store.CacheDir(), ns)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir ns: %v", err)
	}
	// Make the destination filename an existing non-empty directory so
	// os.Rename(tmp, dest) fails on every platform.
	dest := filepath.Join(dir, "k.json")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "occupied"), []byte("x"), 0o644); err != nil {
		t.Fatalf("occupy dest: %v", err)
	}

	if err := Put(ns, "k.json", []byte("body")); err == nil {
		t.Fatalf("Put: expected error renaming onto a directory, got nil")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("orphan tmp file left after rename failure: %s", e.Name())
		}
	}
}

// TestPut_UniqueTmpNoFixedNameCollision verifies that concurrent writers to
// the same cache key do not share a single fixed temp path (the torn-rename
// hazard from finding #12). With a fixed "<key>.tmp" name, two goroutines
// writing the same temp file produced a Windows sharing violation; with
// unique per-call temp files that class of failure disappears. The OS-level
// REPLACE_EXISTING rename can still transiently race on Windows, so we
// tolerate that specific failure but require that (a) at least one Put wins,
// (b) the final content is correct, and (c) no orphan *.tmp leaks.
func TestPut_UniqueTmpNoFixedNameCollision(t *testing.T) {
	ns := nsForTest(t)
	const n = 16
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { errs <- Put(ns, "same-key.json", []byte("payload")) }()
	}
	wins := 0
	for i := 0; i < n; i++ {
		if err := <-errs; err == nil {
			wins++
		} else if strings.Contains(err.Error(), "being used by another process") {
			t.Fatalf("fixed-temp-name sharing violation should not occur with unique temps: %v", err)
		}
	}
	if wins == 0 {
		t.Fatalf("no concurrent Put succeeded")
	}
	if got, ok := Get(ns, "same-key.json"); !ok || string(got) != "payload" {
		t.Fatalf("Get after concurrent Put: ok=%v body=%q", ok, got)
	}
	// No leaked temp files from any of the racers.
	entries, err := os.ReadDir(filepath.Join(store.CacheDir(), ns))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("orphan tmp file after concurrent Put: %s", e.Name())
		}
	}
}

func TestPut_CrossNamespaceIsolation(t *testing.T) {
	nsA := nsForTest(t) + "-a"
	nsB := nsForTest(t) + "-b"
	t.Cleanup(func() {
		_ = os.RemoveAll(filepath.Join(store.CacheDir(), nsA))
		_ = os.RemoveAll(filepath.Join(store.CacheDir(), nsB))
	})
	if err := Put(nsA, "k", []byte("A")); err != nil {
		t.Fatalf("Put A: %v", err)
	}
	if got, ok := Get(nsB, "k"); ok {
		t.Fatalf("cross-ns leak: Get(nsB) returned ok=true, body=%q", got)
	}
}
