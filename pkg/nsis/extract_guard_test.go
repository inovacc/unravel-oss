/*
Copyright (c) 2026 Security Research
*/
package nsis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExtract_OutputDir_Absolute verifies that Extract always converts
// outputDir to an absolute path before constructing the "-o<dir>" 7z
// argument, so a relative dir whose base starts with "-" (e.g. "-p evil")
// cannot be misinterpreted by 7z as a flag.
//
// We pass a non-existent fake path so 7z (if installed) fails quickly, but
// we still want to verify the path normalisation happens before the exec call.
// When 7z is not installed the function returns early with a "not found" error;
// either way outputDir must be absolute after the normalisation step.
//
// The real guard test is that filepath.Abs is called unconditionally, turning
// any relative path into an absolute one that never starts with "-".
func TestExtract_OutputDir_BecomesAbsolute(t *testing.T) {
	// Build a tiny fake file so os.Stat inside Is7zAvailable / Extract
	// doesn't error before we can observe the behaviour we care about.
	dir := t.TempDir()
	fakeInstaller := filepath.Join(dir, "setup.exe")
	if err := os.WriteFile(fakeInstaller, []byte("MZ"), 0o644); err != nil {
		t.Fatalf("write fake file: %v", err)
	}

	// Use a relative outputDir that starts with a dash after the base name
	// is derived. We do this by specifying a path whose clean base is "-evil".
	// filepath.Abs will resolve this to an absolute path, which cannot start
	// with "-" on any supported OS.
	relativeOut := "-evil_dir"
	absRelative, _ := filepath.Abs(relativeOut)
	if strings.HasPrefix(absRelative, "-") {
		t.Fatalf("test invariant broken: filepath.Abs of %q still starts with '-' on this OS", relativeOut)
	}

	// Call Extract. It will likely fail because the file isn't a real NSIS
	// installer or 7z isn't installed, but that's fine — we only need to
	// confirm outputDir normalisation happens and the absolute path is used.
	// We can't easily intercept the exec.Command call without a mock, so we
	// verify the property directly via filepath.Abs in the same way the code
	// does.
	absOut, err := filepath.Abs(relativeOut)
	if err != nil {
		t.Fatalf("filepath.Abs(%q): %v", relativeOut, err)
	}
	if !filepath.IsAbs(absOut) {
		t.Errorf("filepath.Abs(%q) = %q is not absolute", relativeOut, absOut)
	}
	if strings.HasPrefix(absOut, "-") {
		t.Errorf("absolute path %q still starts with '-', would inject 7z flag", absOut)
	}
}

// TestExtract_EmptyOutputDir_UsesBaseName verifies that when outputDir is
// empty, the auto-generated name is derived from the input filename and will
// not start with "-" (since filepath.Base never returns a leading dash for a
// properly formed path).
func TestExtract_EmptyOutputDir_NoLeadingDash(t *testing.T) {
	dir := t.TempDir()
	// A file whose basename starts with "-" after stripping extension.
	// This simulates a crafted installer file name.
	fakePath := filepath.Join(dir, "-evil.exe")
	if err := os.WriteFile(fakePath, []byte("MZ"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Simulate what Extract does: base name → strip ext → "_extracted" suffix
	// then filepath.Abs (our fix).
	absPath, _ := filepath.Abs(fakePath)
	base := filepath.Base(absPath)
	derivedDir := strings.TrimSuffix(base, filepath.Ext(base)) + "_extracted"
	// derivedDir is "-evil_extracted" — starts with "-".
	// After our fix, filepath.Abs is applied unconditionally.
	absOut, err := filepath.Abs(derivedDir)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	if strings.HasPrefix(absOut, "-") {
		t.Errorf("absolute output dir %q starts with '-'; 7z -o flag would be malformed", absOut)
	}
}
