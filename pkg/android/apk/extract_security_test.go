/* Copyright (c) 2026 Security Research */
package apk

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// buildAPKSec creates a minimal zip file (APK) with a single named entry.
func buildAPKSec(t *testing.T, entryName, content string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.Create(entryName)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(content))
	_ = w.Close()

	f, err := os.CreateTemp(t.TempDir(), "test-*.apk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return f.Name()
}

// buildAPKSecWithSymlink creates a zip whose entry has Unix symlink bits set.
func buildAPKSecWithSymlink(t *testing.T, linkName, linkTarget string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fh := &zip.FileHeader{
		Name:   linkName,
		Method: zip.Store,
	}
	fh.SetMode(os.ModeSymlink | 0o777)
	fw, err := w.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(linkTarget))
	_ = w.Close()

	f, err := os.CreateTemp(t.TempDir(), "test-*.apk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return f.Name()
}

// TestExtract_ZipSlipSecurity verifies that a zip entry with a path traversal
// component does not escape the output directory.
func TestExtract_ZipSlipSecurity(t *testing.T) {
	apkPath := buildAPKSec(t, "../../evil.txt", "pwned")
	dest := t.TempDir()

	report, err := Extract(apkPath, dest, false)
	if err != nil {
		t.Fatalf("Extract returned unexpected error: %v", err)
	}
	_ = report

	parent := filepath.Dir(dest)
	if _, err := os.Stat(filepath.Join(parent, "evil.txt")); err == nil {
		t.Fatal("zip-slip: file escaped the destination directory")
	}
}

// TestExtract_SymlinkEntrySkippedSecurity verifies that symlink entries are
// skipped and do not create symlinks on disk (TOCTOU prevention).
func TestExtract_SymlinkEntrySkippedSecurity(t *testing.T) {
	apkPath := buildAPKSecWithSymlink(t, "classes/evil-link", "/etc/passwd")
	dest := t.TempDir()

	_, err := Extract(apkPath, dest, false)
	if err != nil {
		t.Fatalf("Extract returned unexpected error: %v", err)
	}

	linkPath := filepath.Join(dest, "classes", "evil-link")
	fi, statErr := os.Lstat(linkPath)
	if statErr == nil && fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("symlink entry was not skipped — symlink created on disk")
	}
}

// TestExtract_LegitimateFileSecurity verifies normal extraction still works
// after the guard additions (no false positive).
func TestExtract_LegitimateFileSecurity(t *testing.T) {
	apkPath := buildAPKSec(t, "AndroidManifest.xml", "<manifest/>")
	dest := t.TempDir()

	report, err := Extract(apkPath, dest, false)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if report.Files != 1 {
		t.Errorf("expected 1 extracted file, got %d", report.Files)
	}
	if _, err := os.Stat(filepath.Join(dest, "AndroidManifest.xml")); err != nil {
		t.Errorf("expected AndroidManifest.xml in dest: %v", err)
	}
}
