/* Copyright (c) 2026 Security Research */
package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestRun_EntryPointEscapesPackageDir verifies that a weaponized package.json
// whose "main" field traverses outside packageDir is rejected before any
// exec.Command is issued.
func TestRun_EntryPointEscapesPackageDir(t *testing.T) {
	// Build a temp directory tree:
	//   root/
	//     pkg/           ← packageDir
	//       package.json ← "main": "../../outside.js"
	//     outside.js     ← target the attacker wants executed
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	pkgJSON := `{"name":"evil","version":"1.0.0","main":"../../outside.js"}`
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create the target file so os.Stat does not reject it before our guard.
	if err := os.WriteFile(filepath.Join(root, "outside.js"), []byte("console.log('pwned')"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Run(context.Background(), pkgDir, Options{})
	if err == nil {
		t.Fatal("expected error: entry point escapes packageDir, but Run returned nil")
	}
}

// TestRun_EntryPointInsidePackageDirAllowed verifies that a legitimate
// entry point that stays within packageDir is accepted (no false positive).
func TestRun_EntryPointInsidePackageDirAllowed(t *testing.T) {
	pkgDir := t.TempDir()

	// package.json pointing to a sub-path inside pkgDir.
	pkgJSON := `{"name":"legit","version":"1.0.0","main":"lib/index.js"}`
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	libDir := filepath.Join(pkgDir, "lib")
	if err := os.Mkdir(libDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create the entry point — Run will fail later (no real node) but must
	// NOT fail with the containment error.
	if err := os.WriteFile(filepath.Join(libDir, "index.js"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Run(context.Background(), pkgDir, Options{})
	// node binary may not be present; that is fine.  The critical thing is that
	// the error is NOT the containment error.
	if err != nil {
		msg := err.Error()
		if msg == "entry point \""+filepath.Join(pkgDir, "lib", "index.js")+"\" escapes package directory" {
			t.Fatalf("false positive: legitimate entry point was rejected: %v", err)
		}
		// Any other error (node not found, etc.) is acceptable.
	}
}

// TestRun_ExplicitAbsoluteEntryPointEscapes verifies that an Options.EntryPoint
// set to an absolute path outside packageDir is also rejected.
func TestRun_ExplicitAbsoluteEntryPointEscapes(t *testing.T) {
	pkgDir := t.TempDir()

	// Point to an existing file outside pkgDir.
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "evil.js")
	if err := os.WriteFile(outside, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Run(context.Background(), pkgDir, Options{EntryPoint: outside})
	if err == nil {
		t.Fatal("expected containment error for absolute entry point outside packageDir")
	}
}
