/*
Copyright (c) 2026 Security Research
*/
package msix

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildMSIXWithEntries creates a .msix-style zip with the given number of tiny
// regular-file entries, each holding `body`. Used to exercise the aggregate
// entry-count / total-size caps without writing terabytes.
func buildMSIXWithEntries(t *testing.T, dir string, count int, body []byte) string {
	t.Helper()

	path := filepath.Join(dir, "bomb.msix")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for i := 0; i < count; i++ {
		fw, err := w.Create("file" + strings.Repeat("0", 0) + itoa(i) + ".bin")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(body)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// TestExtract_EntryCountCap verifies that an MSIX declaring more entries than
// the aggregate entry-count cap is rejected (decompression/many-files bomb),
// rather than writing an unbounded number of files to disk.
func TestExtract_EntryCountCap(t *testing.T) {
	// Shrink the cap so we don't need 100k real entries.
	origEntries := maxMSIXEntries
	maxMSIXEntries = 5
	defer func() { maxMSIXEntries = origEntries }()

	dir := t.TempDir()
	msixPath := buildMSIXWithEntries(t, dir, 20, []byte("x"))

	out := t.TempDir()
	_, err := Extract(msixPath, out)
	if err == nil {
		t.Fatal("expected error for entry count exceeding cap, got nil")
	}
}

// TestExtract_TotalSizeCap verifies that an MSIX whose cumulative extracted
// bytes exceed the aggregate total cap is rejected, even when no single entry
// exceeds the per-file cap.
func TestExtract_TotalSizeCap(t *testing.T) {
	origTotal := maxMSIXTotalBytes
	maxMSIXTotalBytes = 1024 // 1 KiB aggregate
	defer func() { maxMSIXTotalBytes = origTotal }()

	dir := t.TempDir()
	// 10 entries x 512 bytes = 5 KiB > 1 KiB cap.
	body := make([]byte, 512)
	msixPath := buildMSIXWithEntries(t, dir, 10, body)

	out := t.TempDir()
	_, err := Extract(msixPath, out)
	if err == nil {
		t.Fatal("expected error for aggregate size exceeding cap, got nil")
	}
}

// TestExtract_CapsAreGenerous guards against future shrinkage that would reject
// legitimately large MSIX packages.
func TestExtract_CapsAreGenerous(t *testing.T) {
	if maxMSIXTotalBytes < 1<<30 {
		t.Errorf("maxMSIXTotalBytes %d too small — would reject real packages", maxMSIXTotalBytes)
	}
	if maxMSIXEntries < 50_000 {
		t.Errorf("maxMSIXEntries %d too small — would reject real packages", maxMSIXEntries)
	}
}
