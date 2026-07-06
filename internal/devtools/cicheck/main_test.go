// Table-driven exit-logic + pwsh-skip tests for the cicheck devtool.
//
// The D-05 synthetic-smoke case shells `go run . dissect` and is therefore
// slow; it is gated behind !testing.Short() so the default
// `go test ./internal/devtools/cicheck/...` run stays fast. Run the smoke
// case explicitly with `go test ./internal/devtools/cicheck/... -run Smoke`
// (no -short). No t.Skipf is used for any GOOS — mirrors the
// scorer_crypto_test.go cross-platform invariant.
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// repoRoot resolves the actual repository root (four levels up from this
// package: internal/devtools/cicheck/ -> repo) so the clean-repo case runs
// against the real tracked .github/ scaffolding.
func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return abs
}

// writeScripts materialises the five D-01 script names under
// <root>/.github/scripts/. The script whose name == brokenName gets
// deliberately invalid bash so `bash -n` must fail on it.
func writeScripts(t *testing.T, root, brokenName string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "scripts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir scripts: %v", err)
	}
	for _, f := range d01Scripts {
		body := "#!/usr/bin/env bash\nset -euo pipefail\necho ok\n"
		if f == brokenName {
			// `if` with no matching `then/fi` — guaranteed bash -n failure.
			body = "#!/usr/bin/env bash\nif then fi (\n"
		}
		if err := os.WriteFile(filepath.Join(dir, f+".sh"), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
}

func TestRunCleanRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("clean-repo case exercises the D-05 smoke (go run . dissect); skipped in -short")
	}
	violations, ioErr := run(repoRoot(t))
	if ioErr != nil {
		t.Fatalf("unexpected ioErr: %v", ioErr)
	}
	if len(violations) != 0 {
		t.Fatalf("clean repo expected 0 violations, got %d: %v", len(violations), violations)
	}
}

func TestClauseBashN(t *testing.T) {
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(`C:\Windows\System32\bash.exe`); err != nil {
			// bash still resolvable via PATH (git-bash) in CI/dev; only guard
			// the explicit-absent case. No t.Skipf per-GOOS otherwise.
			_ = err
		}
	}
	cases := []struct {
		name        string
		broken      string
		wantMinViol int
	}{
		{name: "all-valid", broken: "", wantMinViol: 0},
		{name: "one-broken-script", broken: "flip-v2-6-reqs", wantMinViol: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeScripts(t, root, tc.broken)
			v := clauseBashN(root)
			if len(v) < tc.wantMinViol {
				t.Fatalf("%s: want >=%d violations, got %d: %v", tc.name, tc.wantMinViol, len(v), v)
			}
			if tc.broken == "" && len(v) != 0 {
				t.Fatalf("all-valid: expected 0 violations, got %v", v)
			}
		})
	}
}

// TestClauseBashNWindowsPathRobustness is the GAP-71-01 regression guard.
// The original clauseBashN handed bash an absolute path
// (filepath.Join(filepath.Abs(root), ...)). On native Windows that is a
// backslash drive path like `C:\...\My Drive\...\x.sh` which Git-Bash/WSL
// cannot resolve ("No such file or directory") — silently defeating the
// "Windows-doable" goal. The fix runs bash with cwd=root and a repo-relative
// forward-slash path. This test forces a root whose path contains a space
// (mimicking the real "My Drive" install path); pre-fix it fails on native
// Windows, post-fix it passes on Git-Bash and the Linux CI runner alike.
func TestClauseBashNWindowsPathRobustness(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dir with space")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir spaced root: %v", err)
	}
	writeScripts(t, root, "") // all five scripts valid
	v := clauseBashN(root)
	if len(v) != 0 {
		t.Fatalf("GAP-71-01 regression: clauseBashN must resolve scripts under a "+
			"spaced/absolute root via cwd+relative path, got %d violation(s): %v", len(v), v)
	}
}

func TestClausePwshSkip(t *testing.T) {
	// .github/scripts/ exists with zero .ps1 -> clause must pass with no
	// violations and pwsh is never invoked (no panic, no error).
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "scripts"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	v := clausePwshAST(root)
	if len(v) != 0 {
		t.Fatalf("pwsh-skip: expected 0 violations (N/A by construction), got %v", v)
	}
}

func TestClauseYAMLMissing(t *testing.T) {
	// Absent kb-capture-ci.yml -> exactly one read-failure violation.
	root := t.TempDir()
	v := clauseYAML(root)
	if len(v) == 0 {
		t.Fatalf("missing YAML: expected a read-failure violation, got none")
	}
}

func TestClauseSmokeFixtureMissing(t *testing.T) {
	// Empty root has no synthetic_pe.bin -> smoke reports a fixture-missing
	// violation without invoking `go run . dissect`.
	root := t.TempDir()
	v := clauseSmoke(root)
	if len(v) == 0 {
		t.Fatalf("missing fixture: expected a violation, got none")
	}
}

func TestRunSmokeReal(t *testing.T) {
	if testing.Short() {
		t.Skip("D-05 smoke shells `go run . dissect`; slow — skipped in -short")
	}
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "pkg", "knowledge", "scorecard", "testdata", "synthetic_pe.bin")); err != nil {
		t.Fatalf("committed fixture missing: %v", err)
	}
	v := clauseSmoke(root)
	if len(v) != 0 {
		t.Fatalf("smoke against committed fixture expected 0 violations, got %v", v)
	}
}
