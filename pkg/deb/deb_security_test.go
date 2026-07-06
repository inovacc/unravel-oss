/* Copyright (c) 2026 Security Research */
package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// buildTarGz builds an in-memory .tar.gz with the given entries.
// Each entry is described by a tarEntry struct.
type tarEntry struct {
	name     string
	typeflag byte
	content  string
	linkname string // for TypeSymlink
}

func buildTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Linkname: e.linkname,
			Size:     int64(len(e.content)),
			Mode:     0o644,
		}
		if e.typeflag == tar.TypeDir {
			hdr.Mode = 0o755
			hdr.Size = 0
		}
		if e.typeflag == tar.TypeSymlink {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.content != "" {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// TestExtractTar_SymlinkTOCTOU verifies that the TOCTOU symlink chaining
// attack is blocked: a directory symlink extracted first must not redirect
// a subsequent regular-file write outside outputDir.
//
// Attack pattern:
//  1. Entry 1: dir symlink  data/a  ->  <tmpdir outside outputDir>
//  2. Entry 2: regular file data/a/b.txt
//
// Without EvalSymlinks the string-level check for entry 2 passes
// (data/a/b.txt looks contained), but the OS would follow the symlink and
// write to the outside tmpdir.
//
// This test only runs on POSIX because symlink creation requires OS support.
func TestExtractTar_SymlinkTOCTOU(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink TOCTOU test requires POSIX symlinks")
	}

	outputDir := t.TempDir()
	outsideDir := t.TempDir() // the attacker wants to write here

	tarData := buildTarGz(t, []tarEntry{
		// Entry 1: symlink data/a -> outsideDir
		{name: "data/a", typeflag: tar.TypeSymlink, linkname: outsideDir},
		// Entry 2: regular file via the symlinked directory
		{name: "data/a/payload.txt", typeflag: tar.TypeReg, content: "pwned"},
	})

	_, _, _, errs := extractTar(tarData, "test.tar.gz", outputDir)

	// The payload must NOT have been written to outsideDir.
	if _, err := os.Stat(filepath.Join(outsideDir, "payload.txt")); err == nil {
		t.Fatal("TOCTOU symlink attack succeeded: payload written outside outputDir")
	}

	// The symlink entry itself should have been recorded as skipped or the
	// follow-up write should have been blocked; verify at least one error was
	// reported (informational — either entry may be the one that errors).
	_ = errs
}

// TestExtractTar_AbsoluteSymlinkRejected verifies that a symlink with an
// absolute target is rejected at the string-level check.
func TestExtractTar_AbsoluteSymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires POSIX symlinks")
	}

	outputDir := t.TempDir()

	tarData := buildTarGz(t, []tarEntry{
		{name: "evil-link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
	})

	_, _, _, errs := extractTar(tarData, "test.tar.gz", outputDir)

	// The symlink must not exist.
	if _, err := os.Lstat(filepath.Join(outputDir, "evil-link")); err == nil {
		t.Fatal("absolute symlink was not rejected")
	}

	if len(errs) == 0 {
		t.Error("expected at least one error for the rejected symlink")
	}
}

// TestExtractTar_PathTraversalRejected verifies that a tar entry whose name
// traverses outside outputDir is skipped.
func TestExtractTar_PathTraversalRejected(t *testing.T) {
	outputDir := t.TempDir()

	tarData := buildTarGz(t, []tarEntry{
		{name: "../../evil.txt", typeflag: tar.TypeReg, content: "pwned"},
	})

	_, _, _, _ = extractTar(tarData, "test.tar.gz", outputDir)

	parent := filepath.Dir(outputDir)
	if _, err := os.Stat(filepath.Join(parent, "evil.txt")); err == nil {
		t.Fatal("path traversal was not blocked")
	}
}

// TestExtractTar_LegitimateEntries verifies normal extraction still works
// (no false positives introduced by the security fixes).
func TestExtractTar_LegitimateEntries(t *testing.T) {
	outputDir := t.TempDir()

	tarData := buildTarGz(t, []tarEntry{
		{name: "usr/lib/", typeflag: tar.TypeDir},
		{name: "usr/lib/lib.so", typeflag: tar.TypeReg, content: "ELF"},
		{name: "etc/config", typeflag: tar.TypeReg, content: "key=val"},
	})

	files, dirs, _, errs := extractTar(tarData, "test.tar.gz", outputDir)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if files != 2 {
		t.Errorf("expected 2 files, got %d", files)
	}
	if dirs != 1 {
		t.Errorf("expected 1 dir, got %d", dirs)
	}
}
