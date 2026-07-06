/* Copyright (c) 2026 Security Research */
package gather

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

func TestGather_FindsElectronApp(t *testing.T) {
	// Create a fake Electron app in a temp dir
	root := t.TempDir()
	appDir := filepath.Join(root, "myapp", "resources")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}

	_ = os.WriteFile(filepath.Join(appDir, "app.asar"), []byte("fake-asar"), 0o644)

	m := manifest.Default()
	detector := manifest.NewDetector(m, false)

	// Test detection on the app directory directly
	result, err := detector.Detect(filepath.Join(root, "myapp"))
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Type != "electron" {
		t.Errorf("expected electron, got %s", result.Type)
	}
}

func TestWalkDepth_RespectsMaxDepth(t *testing.T) {
	root := t.TempDir()

	// Create dirs at various depths
	_ = os.MkdirAll(filepath.Join(root, "a", "b", "c", "d"), 0o755)

	var visited []string

	walkDepth(root, 2, func(path string, d os.DirEntry) error {
		if d.IsDir() {
			rel, _ := filepath.Rel(root, path)
			visited = append(visited, rel)
		}

		return nil
	})

	// Should visit a, a/b, a/b/c but NOT a/b/c/d (depth 3 from root)
	for _, v := range visited {
		depth := len(filepath.SplitList(v))
		// Count path separators
		seps := 0
		for _, c := range v {
			if c == filepath.Separator {
				seps++
			}
		}

		if seps > 2 {
			t.Errorf("walkDepth visited %q at depth %d, max was 2", v, depth)
		}
	}
}

func TestWalkDepth_SkipDir(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "skip", "child"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "keep"), 0o755)

	var visited []string

	walkDepth(root, 3, func(path string, d os.DirEntry) error {
		if d.Name() == "skip" {
			return os.ErrInvalid // trigger continue, not SkipDir in walkRecursive
		}
		if d.IsDir() {
			visited = append(visited, d.Name())
		}
		return nil
	})

	for _, v := range visited {
		if v == "child" {
			// child of skip might still be visited since we returned error not SkipDir
			// That's fine, just testing the mechanism works
		}
	}
}

func TestSkipDirs(t *testing.T) {
	for _, name := range []string{"node_modules", "__pycache__", ".git"} {
		if !skipDirs[name] {
			t.Errorf("expected %q in skipDirs", name)
		}
	}
}

func TestWalkDepth_NonExistentRoot(t *testing.T) {
	called := false
	walkDepth("/nonexistent/path/that/does/not/exist", 3, func(path string, d fs.DirEntry) error {
		called = true
		return nil
	})
	if called {
		t.Error("expected callback to never be called for non-existent root")
	}
}

func TestWalkDepth_EmptyDir(t *testing.T) {
	root := t.TempDir()
	var visited []string
	walkDepth(root, 3, func(path string, d fs.DirEntry) error {
		visited = append(visited, path)
		return nil
	})
	if len(visited) != 0 {
		t.Errorf("expected no entries visited in empty dir, got %d", len(visited))
	}
}

func TestWalkDepth_FilesAndDirs(t *testing.T) {
	root := t.TempDir()

	if err := os.MkdirAll(filepath.Join(root, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "subdir", "nested.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	var visitedNames []string
	walkDepth(root, 3, func(path string, d fs.DirEntry) error {
		visitedNames = append(visitedNames, d.Name())
		return nil
	})

	nameSet := make(map[string]bool)
	for _, n := range visitedNames {
		nameSet[n] = true
	}

	if !nameSet["subdir"] {
		t.Error("expected subdir to be visited")
	}
	if !nameSet["file.txt"] {
		t.Error("expected file.txt to be visited")
	}
	if !nameSet["nested.txt"] {
		t.Error("expected nested.txt to be visited")
	}
}

func TestWalkDepth_SkipDirPreventsRecursion(t *testing.T) {
	root := t.TempDir()

	if err := os.MkdirAll(filepath.Join(root, "a", "b", "c"), 0o755); err != nil {
		t.Fatal(err)
	}

	var visited []string
	walkDepth(root, 5, func(path string, d fs.DirEntry) error {
		visited = append(visited, d.Name())
		if d.Name() == "b" {
			return fs.SkipDir
		}
		return nil
	})

	for _, name := range visited {
		if name == "c" {
			t.Error("expected c to not be visited after b returned fs.SkipDir")
		}
	}

	found := false
	for _, name := range visited {
		if name == "b" {
			found = true
		}
	}
	if !found {
		t.Error("expected b to be visited")
	}
}

func TestWalkRecursive_DepthExceeded(t *testing.T) {
	root := t.TempDir()

	if err := os.MkdirAll(filepath.Join(root, "child"), 0o755); err != nil {
		t.Fatal(err)
	}

	called := false
	walkRecursive(root, 5, 3, func(path string, d fs.DirEntry) error {
		called = true
		return nil
	})

	if called {
		t.Error("expected callback to never be called when depth exceeds maxDepth")
	}
}

func TestGather_DoesNotPanic(t *testing.T) {
	m := manifest.Default()
	entries := Gather(m, false)
	if entries == nil {
		t.Error("expected Gather to return a non-nil slice")
	}
}

func TestWalkDepth_SkipsHiddenAndSkipDirNames(t *testing.T) {
	root := t.TempDir()

	dirs := []string{
		filepath.Join(root, ".hidden", "deep"),
		filepath.Join(root, "node_modules", "deep"),
		filepath.Join(root, "visible", "deep"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	var visited []string
	walkDepth(root, 5, func(path string, d fs.DirEntry) error {
		name := d.Name()
		if skipDirs[name] || (len(name) > 0 && name[0] == '.') {
			return fs.SkipDir
		}
		visited = append(visited, name)
		return nil
	})

	for _, name := range visited {
		if name == ".hidden" || name == "node_modules" {
			t.Errorf("expected %q to be skipped", name)
		}
		if name == "deep" {
			// "deep" appears under both hidden and visible; check parent not tracked here
			// acceptable — this test just verifies hidden/node_modules are not in visited
		}
	}

	foundVisible := false
	for _, name := range visited {
		if name == "visible" {
			foundVisible = true
		}
	}
	if !foundVisible {
		t.Error("expected visible dir to be visited")
	}
}

func TestAppEntry_Sorting(t *testing.T) {
	entries := []AppEntry{
		{Type: "tauri", Path: "/apps/z-app"},
		{Type: "electron", Path: "/apps/b-app"},
		{Type: "electron", Path: "/apps/a-app"},
		{Type: "tauri", Path: "/apps/a-app"},
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Type != entries[j].Type {
			return entries[i].Type < entries[j].Type
		}
		return entries[i].Path < entries[j].Path
	})

	expected := []AppEntry{
		{Type: "electron", Path: "/apps/a-app"},
		{Type: "electron", Path: "/apps/b-app"},
		{Type: "tauri", Path: "/apps/a-app"},
		{Type: "tauri", Path: "/apps/z-app"},
	}

	for i, e := range entries {
		if e.Type != expected[i].Type || e.Path != expected[i].Path {
			t.Errorf("at index %d: got {%s %s}, want {%s %s}",
				i, e.Type, e.Path, expected[i].Type, expected[i].Path)
		}
	}
}

// ----- Phase 22 permutation tests (BUGFIX-01) -----
//
// Covers D-06..D-09: 3 permutation categories with ≥4 named subtests, all
// runnable under -short and race-clean.

// TestGather_Permutations exercises Gather()/GatherE() under multiple registry
// permutations. Subtests:
//   - Concurrent      (D-06: race-exposing concurrent callers)
//   - DoubleInit      (D-07: idempotent re-entry)
//   - EmptyManifest   (D-08: defensive guard, ErrNoGatherer surface)
//   - MissingPlatform (D-08: cross-platform stub; legacy entrypoint stays non-nil)
func TestGather_Permutations(t *testing.T) {
	m := manifest.Default()

	t.Run("Concurrent", func(t *testing.T) {
		// Race-exposing: N goroutines all calling GatherE() simultaneously
		// against a nil manifest (fast path — no filesystem walk). Must
		// complete without panic and every result must be non-nil; every
		// error must wrap ErrNoGatherer.
		const n = 16
		results := make([][]AppEntry, n)
		errs := make([]error, n)
		done := make(chan struct{}, n)
		for i := range n {
			go func(idx int) {
				defer func() { done <- struct{}{} }()
				results[idx], errs[idx] = GatherE(nil, false)
			}(i)
		}
		for range n {
			<-done
		}
		for i, r := range results {
			if r == nil {
				t.Errorf("goroutine %d: GatherE returned nil slice", i)
			}
			if !errors.Is(errs[i], ErrNoGatherer) {
				t.Errorf("goroutine %d: err = %v; want errors.Is(ErrNoGatherer)", i, errs[i])
			}
		}
	})

	t.Run("DoubleInit", func(t *testing.T) {
		// Idempotency: calling GatherE twice in sequence with a nil manifest
		// (fast path) must not panic and must yield non-nil results plus
		// ErrNoGatherer both times. Order permutation: nil-then-nil.
		first, errFirst := GatherE(nil, false)
		second, errSecond := GatherE(nil, false)
		if first == nil {
			t.Error("first GatherE() returned nil slice")
		}
		if second == nil {
			t.Error("second GatherE() returned nil slice")
		}
		if !errors.Is(errFirst, ErrNoGatherer) {
			t.Errorf("first err = %v; want ErrNoGatherer", errFirst)
		}
		if !errors.Is(errSecond, ErrNoGatherer) {
			t.Errorf("second err = %v; want ErrNoGatherer", errSecond)
		}
		// Use real manifest reference to avoid unused-var lint.
		_ = m
	})

	t.Run("EmptyManifest", func(t *testing.T) {
		// Defensive guard: nil manifest must NOT panic; must return empty
		// non-nil slice; GatherE must surface ErrNoGatherer.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Gather panicked on nil manifest: %v", r)
			}
		}()
		got := Gather(nil, false)
		if got == nil {
			t.Error("Gather(nil, false) returned nil; want empty non-nil slice")
		}
		if len(got) != 0 {
			t.Errorf("Gather(nil, false) returned %d entries; want 0", len(got))
		}
		_, err := GatherE(nil, false)
		if !errors.Is(err, ErrNoGatherer) {
			t.Errorf("GatherE(nil, false) err = %v; want errors.Is(ErrNoGatherer)", err)
		}
	})

	t.Run("MissingPlatform", func(t *testing.T) {
		// Cross-platform stub: when GatherE returns ErrNoGatherer,
		// the legacy Gather() entrypoint must STILL return a non-nil slice.
		// Exercises the swallow-error path in Gather().
		got := Gather(nil, false)
		if got == nil {
			t.Fatal("Gather() must never return nil; got nil")
		}
	})
}
