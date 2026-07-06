/*
Copyright (c) 2026 Security Research
*/

package ingest

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestWalkKSFolder_Counts(t *testing.T) {
	tmp := t.TempDir()
	ks := filepath.Join(tmp, "ks")
	// 5 .so libs
	for i := range 5 {
		writeFile(t, filepath.Join(ks, "native", "libfoo"+string(rune('0'+i))+".so"),
			[]byte("ELF-fake-"+string(rune('0'+i))))
	}
	// 3 .js files
	for i := range 3 {
		writeFile(t, filepath.Join(ks, "js", "mod"+string(rune('a'+i))+".js"),
			[]byte("module.exports = "+string(rune('a'+i))))
	}
	// 1 native .dll
	writeFile(t, filepath.Join(ks, "win", "core.dll"), []byte("MZ-fake-dll"))
	// 1 data file (txt — should NOT be a module)
	writeFile(t, filepath.Join(ks, "data", "readme.txt"), []byte("readme"))

	res, err := WalkKSFolder(context.Background(), ks, "kb1", "myapp", WalkOptions{
		AllowedRoots: []string{tmp},
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// 5 .so + 3 .js + 1 .dll = 9 modules
	if res.ModuleCount != 9 {
		t.Errorf("ModuleCount: got=%d want=9", res.ModuleCount)
	}
	// All 10 files (9 modules + 1 txt) are unique → file count 10
	if res.FileCount != 10 {
		t.Errorf("FileCount: got=%d want=10", res.FileCount)
	}
	// Bodies count = unique module sha256 (all distinct content) = 9
	if res.BodyCount != 9 {
		t.Errorf("BodyCount: got=%d want=9", res.BodyCount)
	}
	// BinarySHA256 should be populated (first .so or .dll seen)
	if res.BinarySHA256 == "" {
		t.Error("BinarySHA256: expected non-empty")
	}
}

func TestWalkKSFolder_PathTraversalRejected(t *testing.T) {
	// Use OS temp as the allowed root and try walking somewhere else.
	root := t.TempDir()
	other := t.TempDir()

	_, err := WalkKSFolder(context.Background(), other, "kb1", "myapp", WalkOptions{
		AllowedRoots: []string{root},
	})
	if err == nil {
		t.Fatal("expected error for ksDir outside allowed root")
	}
	if !strings.Contains(err.Error(), "ks dir outside kb-store root") {
		t.Errorf("error message: got=%q want substring %q",
			err.Error(), "ks dir outside kb-store root")
	}
}

func TestWalkKSFolder_SymlinkSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows; skipping")
	}
	tmp := t.TempDir()
	ks := filepath.Join(tmp, "ks")
	writeFile(t, filepath.Join(ks, "real.js"), []byte("module.exports = 1"))

	target := filepath.Join(ks, "real.js")
	link := filepath.Join(ks, "alias.js")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	res, err := WalkKSFolder(context.Background(), ks, "kb1", "myapp", WalkOptions{
		AllowedRoots: []string{tmp},
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// Symlink skipped: only the real.js module is seen.
	if res.ModuleCount != 1 {
		t.Errorf("ModuleCount: got=%d want=1 (symlink should be skipped)", res.ModuleCount)
	}
}

func TestWalkKSFolder_DedupesBodies(t *testing.T) {
	tmp := t.TempDir()
	ks := filepath.Join(tmp, "ks")
	// Two files with identical content → one body, two modules
	writeFile(t, filepath.Join(ks, "a.js"), []byte("same"))
	writeFile(t, filepath.Join(ks, "b.js"), []byte("same"))

	res, err := WalkKSFolder(context.Background(), ks, "kb1", "myapp", WalkOptions{
		AllowedRoots: []string{tmp},
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if res.ModuleCount != 2 {
		t.Errorf("ModuleCount: got=%d want=2", res.ModuleCount)
	}
	if res.BodyCount != 1 {
		t.Errorf("BodyCount: got=%d want=1 (dedup)", res.BodyCount)
	}
}
