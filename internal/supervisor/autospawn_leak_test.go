/*
Copyright (c) 2026 Security Research

Regression test for the autospawn test-binary fork-bomb. Autospawn execs
execPath as `daemon serve --detached`. Under `go test`, os.Executable() is the
test binary, so spawning it re-runs the whole suite detached — which dials the
supervisor and autospawns again, a self-replicating process leak (observed:
hundreds of orphaned `*.test.exe daemon serve --detached`). Autospawn must
refuse to spawn from a test binary.
*/
package supervisor

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestAutospawn_RefusesTestBinary(t *testing.T) {
	orig := detachedExecFn
	called := false
	detachedExecFn = func(string, ...string) error { called = true; return nil }
	defer func() { detachedExecFn = orig }()

	dir := t.TempDir()
	for _, p := range []string{
		filepath.Join("x", "tools.test.exe"),  // Windows test binary
		filepath.Join("x", "supervisor.test"), // POSIX test binary
	} {
		called = false
		err := Autospawn(p, dir, nil)
		if err == nil {
			t.Fatalf("Autospawn(%q): expected refusal error, got nil", p)
		}
		if !errors.Is(err, ErrAutospawnTestBinary) {
			t.Fatalf("Autospawn(%q): expected ErrAutospawnTestBinary, got %v", p, err)
		}
		if called {
			t.Fatalf("Autospawn(%q): detachedExecFn must NOT run for a test binary", p)
		}
	}
}

func TestAutospawn_AllowsRealBinary(t *testing.T) {
	orig := detachedExecFn
	called := false
	detachedExecFn = func(string, ...string) error { called = true; return nil }
	defer func() { detachedExecFn = orig }()

	dir := t.TempDir()
	if err := Autospawn(filepath.Join("x", "unravel.exe"), dir, nil); err != nil {
		t.Fatalf("Autospawn(real binary): unexpected error %v", err)
	}
	if !called {
		t.Fatal("Autospawn(real binary): detachedExecFn should run for a non-test binary")
	}
}
