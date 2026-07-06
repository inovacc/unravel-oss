/* Copyright (c) 2026 Security Research */
package rpm

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestExtractCPIO_SymlinkTOCTOU verifies the TOCTOU symlink chaining attack is
// blocked: a directory-level symlink extracted first must not redirect a
// subsequent regular-file write outside outputDir.
//
// Attack pattern:
//  1. Entry 1: symlink  usr/lib  ->  <outsideDir>   (mode 0120777)
//  2. Entry 2: regular file  usr/lib/payload.txt
//
// Without the EvalSymlinks guard, the string-level prefix check for entry 2
// passes (usr/lib/payload.txt looks contained), but the OS would follow the
// symlink and write to outsideDir.
func TestExtractCPIO_SymlinkTOCTOU(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink TOCTOU test requires POSIX symlinks")
	}

	outputDir := t.TempDir()
	outsideDir := t.TempDir()

	var archive bytes.Buffer
	// Entry 1: directory-level symlink pointing outside outputDir.
	// mode 0120777 = symlink
	archive.Write(buildCPIOEntry("usr/lib", 0o120777, []byte(outsideDir)))
	// Entry 2: regular file through the symlinked directory.
	archive.Write(buildCPIOEntry("usr/lib/payload.txt", 0o100644, []byte("pwned")))
	archive.Write(buildCPIOTrailer())

	_, _, _, _ = extractCPIO(&archive, outputDir)

	// The payload must NOT have been written to outsideDir.
	if _, err := os.Stat(filepath.Join(outsideDir, "payload.txt")); err == nil {
		t.Fatal("TOCTOU symlink attack succeeded: payload.txt written outside outputDir")
	}
}

// TestExtractCPIO_SymlinkAbsoluteTarget verifies that a symlink with an
// absolute target is rejected by the string-level guard (filepath.IsAbs check).
func TestExtractCPIO_SymlinkAbsoluteTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires POSIX symlinks")
	}

	outputDir := t.TempDir()

	var archive bytes.Buffer
	// Symlink with absolute target — must be rejected.
	archive.Write(buildCPIOEntry("evil-link", 0o120777, []byte("/etc/passwd")))
	archive.Write(buildCPIOTrailer())

	_, _, _, errs := extractCPIO(&archive, outputDir)

	// Symlink must not exist on disk.
	if _, err := os.Lstat(filepath.Join(outputDir, "evil-link")); err == nil {
		t.Fatal("absolute symlink was not rejected — symlink exists on disk")
	}

	if len(errs) == 0 {
		t.Error("expected at least one error entry for the rejected absolute symlink")
	}
}

// TestExtractCPIO_SymlinkRelativeEscape verifies that a symlink whose relative
// target escapes outputDir via ".." traversal is rejected.
func TestExtractCPIO_SymlinkRelativeEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires POSIX symlinks")
	}

	outputDir := t.TempDir()

	var archive bytes.Buffer
	// Relative target that traverses outside: "../../tmp/evil"
	archive.Write(buildCPIOEntry("escape-link", 0o120777, []byte("../../tmp/evil")))
	archive.Write(buildCPIOTrailer())

	_, _, _, errs := extractCPIO(&archive, outputDir)

	if _, err := os.Lstat(filepath.Join(outputDir, "escape-link")); err == nil {
		t.Fatal("relative-escape symlink was not rejected — symlink exists on disk")
	}

	if len(errs) == 0 {
		t.Error("expected at least one error entry for the rejected escape symlink")
	}
}

// TestExtractCPIO_SafeSymlink verifies that a benign relative symlink that stays
// within outputDir is still created correctly (no false positive).
func TestExtractCPIO_SafeSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		tmp := t.TempDir()
		if err := os.Symlink("target", filepath.Join(tmp, "link")); err != nil {
			t.Skip("symlinks require elevated privileges on Windows")
		}
	}

	outputDir := t.TempDir()

	var archive bytes.Buffer
	// Create target file first, then a symlink to it.
	archive.Write(buildCPIOEntry("target.txt", 0o100644, []byte("hello")))
	archive.Write(buildCPIOEntry("link.txt", 0o120777, []byte("target.txt")))
	archive.Write(buildCPIOTrailer())

	files, _, _, errs := extractCPIO(&archive, outputDir)

	if len(errs) != 0 {
		t.Errorf("unexpected errors for safe symlink: %v", errs)
	}

	// Both the regular file and the symlink count as files.
	if files != 2 {
		t.Errorf("files = %d, want 2", files)
	}

	dest, err := os.Readlink(filepath.Join(outputDir, "link.txt"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if dest != "target.txt" {
		t.Errorf("symlink target = %q, want %q", dest, "target.txt")
	}
}
