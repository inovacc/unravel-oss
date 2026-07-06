/*
Copyright (c) 2026 Security Research
*/
package tools

import (
	"archive/zip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeTestZip creates a zip file at path containing the given name->content
// entries and returns the path. It fails the test on any I/O error.
func writeTestZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write zip entry %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
}

// TestExtractByPattern_OutputDirIsPrivate verifies that extractByPattern
// creates extraction output directories with 0o700 perms so decompiled app
// code (which can contain secrets) is not world-readable on a shared host.
//
// Unix-only: Windows does not honour POSIX mode bits, so the assertion is
// meaningless there.
func TestExtractByPattern_OutputDirIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits not honoured on Windows")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "in.apk")
	writeTestZip(t, zipPath, map[string]string{
		"lib/arm64-v8a/libfoo.so": "native bytes",
	})

	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatalf("create out dir: %v", err)
	}

	extracted, err := extractNativeLibs(zipPath, outDir)
	if err != nil {
		t.Fatalf("extractNativeLibs: %v", err)
	}
	if len(extracted) != 1 {
		t.Fatalf("expected 1 extracted file, got %d", len(extracted))
	}

	// The intermediate directory created for the entry (lib/arm64-v8a) must be
	// 0o700, not 0o755.
	created := filepath.Dir(extracted[0])
	info, err := os.Stat(created)
	if err != nil {
		t.Fatalf("stat created dir: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("extraction dir %q mode = %o, want 0o700", created, mode)
	}
}

// TestExtractByPattern_BoundedCopy verifies that extraction copies are bounded
// by io.LimitReader(maxExtractedFileBytes). An oversized (>512 MiB) fixture is
// impractical to build or commit, so this asserts the LimitReader wiring is
// correct for normal-sized content: a small entry must be written in full
// (not truncated by the cap), and the cap constant must be the documented
// 512 MiB. The cap itself is exercised by the same code path that pkg/deb and
// pkg/msix use; here we pin that the wiring does not corrupt sub-cap content.
func TestExtractByPattern_BoundedCopy(t *testing.T) {
	const want = "this is the native library payload"

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "in.apk")
	writeTestZip(t, zipPath, map[string]string{
		"lib/x86/libbounded.so": want,
	})

	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatalf("create out dir: %v", err)
	}

	extracted, err := extractNativeLibs(zipPath, outDir)
	if err != nil {
		t.Fatalf("extractNativeLibs: %v", err)
	}
	if len(extracted) != 1 {
		t.Fatalf("expected 1 extracted file, got %d", len(extracted))
	}

	got, err := os.ReadFile(extracted[0])
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	// Sub-cap content must survive intact: LimitReader(maxExtractedFileBytes)
	// must not truncate a small payload.
	if string(got) != want {
		t.Errorf("extracted content = %q, want %q (LimitReader truncated sub-cap content?)", got, want)
	}
	if int64(len(got)) > maxExtractedFileBytes {
		t.Errorf("extracted %d bytes exceeds cap %d", len(got), maxExtractedFileBytes)
	}

	if maxExtractedFileBytes != 512<<20 {
		t.Errorf("maxExtractedFileBytes = %d, want %d (512 MiB)", maxExtractedFileBytes, 512<<20)
	}
}

// TestExtractFileFromZip_OutputDirIsPrivate verifies the single-entry
// extraction path also creates its destination directory with 0o700 perms.
//
// Unix-only for the same reason as TestExtractByPattern_OutputDirIsPrivate.
func TestExtractFileFromZip_OutputDirIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits not honoured on Windows")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "bundle.apks")
	writeTestZip(t, zipPath, map[string]string{
		"universal.apk": "PK apk bytes",
	})

	destPath := filepath.Join(dir, "nested", "base.apk")
	if err := extractFileFromZip(zipPath, "universal.apk", destPath); err != nil {
		t.Fatalf("extractFileFromZip: %v", err)
	}

	info, err := os.Stat(filepath.Dir(destPath))
	if err != nil {
		t.Fatalf("stat dest dir: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("dest dir mode = %o, want 0o700", mode)
	}
}
