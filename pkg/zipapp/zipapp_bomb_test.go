/* Copyright (c) 2026 Security Research */
package zipapp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// buildZipAppBytes builds a valid Python zipapp in memory:
// a shebang line + a ZIP archive containing __main__.py.
func buildZipAppBytes(t *testing.T, mainPy string) []byte {
	t.Helper()
	files := map[string]string{
		"__main__.py": mainPy,
	}
	zipData := buildZIP(t, files)
	// Prepend a shebang so Analyze recognises it.
	shebang := []byte("#!/usr/bin/env python3\n")
	return append(shebang, zipData...)
}

// TestAnalyze_FileSizeCapRejected verifies that Analyze rejects a file whose
// size exceeds maxZipAppFileSize (decompression-bomb guard).
// The guard is strictly-greater-than, so we use cap+1 bytes.
func TestAnalyze_FileSizeCapRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.pyz")

	// Create a file of exactly maxZipAppFileSize+1 bytes — one byte over the cap.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	target := maxZipAppFileSize + 1
	chunk := bytes.Repeat([]byte{0x00}, 4096)
	remaining := target
	for remaining > 0 {
		toWrite := min(len(chunk), remaining)
		if _, err := f.Write(chunk[:toWrite]); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		remaining -= toWrite
	}
	_ = f.Close()

	_, err = Analyze(path)
	if err == nil {
		t.Fatalf("expected error for file of size %d (> cap), got nil", target)
	}
}

// TestAnalyze_BelowCapAccepted verifies that a small valid zipapp is analysed
// without error.
func TestAnalyze_BelowCapAccepted(t *testing.T) {
	data := buildZipAppBytes(t, `print("hello")`)
	dir := t.TempDir()
	path := filepath.Join(dir, "app.pyz")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Analyze(path)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
	if !result.IsZipApp {
		t.Error("expected IsZipApp=true")
	}
}

// TestAnalyze_CapConstantSane verifies that maxZipAppFileSize is a reasonable
// value: >= 1 MiB (allows real zipapps) and <= 1 GiB.
func TestAnalyze_CapConstantSane(t *testing.T) {
	if maxZipAppFileSize < 1<<20 {
		t.Errorf("maxZipAppFileSize %d is too small", maxZipAppFileSize)
	}
	if maxZipAppFileSize > 1<<30 {
		t.Errorf("maxZipAppFileSize %d is too large — bomb protection ineffective", maxZipAppFileSize)
	}
}
