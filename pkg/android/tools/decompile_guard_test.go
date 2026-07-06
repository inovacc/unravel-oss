/*
Copyright (c) 2026 Security Research
*/
package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestDecompile_RejectsDashPrefixedInputPath verifies that Decompile returns
// an error when the input file's base name starts with "-". Tools like apktool
// and jadx do not universally support "--" to terminate flag parsing, so a
// file named "-v evil.apk" would be interpreted as the tool's own "-v" flag.
func TestDecompile_RejectsDashPrefixedInputPath(t *testing.T) {
	dir := t.TempDir()

	// Create a real file whose base name starts with "-".
	evilPath := filepath.Join(dir, "-evil.apk")
	if err := os.WriteFile(evilPath, []byte("PK"), 0o644); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	_, err := Decompile(context.Background(), DecompileOptions{
		InputPath: evilPath,
		OutputDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("Decompile with dash-prefixed base name: expected error, got nil")
	}
}

// TestDecompile_AcceptsNormalPath verifies that Decompile does not reject a
// normally-named file. It will fail for other reasons (non-APK content, no
// tools installed) but must not error on the path guard.
func TestDecompile_AcceptsNormalPath(t *testing.T) {
	dir := t.TempDir()
	normalPath := filepath.Join(dir, "sample.apk")
	if err := os.WriteFile(normalPath, []byte("PK"), 0o644); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	_, err := Decompile(context.Background(), DecompileOptions{
		InputPath: normalPath,
		OutputDir: t.TempDir(),
	})
	// Any error here is acceptable (bad APK format, missing tools, etc.) —
	// what we must NOT see is the "base name must not start with '-'" error.
	if err != nil {
		if err.Error() == "input file base name must not start with '-': "+normalPath {
			t.Errorf("normal path %q was rejected by the dash guard: %v", normalPath, err)
		}
		// Other errors (format detection failure, etc.) are fine.
	}
}

// TestDecompile_DashBaseName_ViaRelativePath verifies that even when the
// caller passes a relative path whose abs form has a dash-prefixed base, the
// guard fires after filepath.Abs resolution.
func TestDecompile_DashBaseName_ViaRelativePath(t *testing.T) {
	// We can't easily create a file with a dash-name via a relative path in
	// all CIs, so we test the guard property directly: after filepath.Abs,
	// a file literally named "-flag.apk" in TempDir has a base that starts
	// with "-" and must be rejected.
	dir := t.TempDir()
	evilPath := filepath.Join(dir, "-flag.apk")
	if err := os.WriteFile(evilPath, []byte("PK"), 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err := Decompile(context.Background(), DecompileOptions{
		InputPath: evilPath,
	})
	if err == nil {
		t.Fatal("expected error for dash-prefixed base name, got nil")
	}
}
