/*
Copyright (c) 2026 Security Research
*/
package msix

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExtract_OverPerFileCapSkippedNotTruncated verifies that an MSIX entry
// larger than the per-file cap is SKIPPED (dropped, not written as a truncated
// partial), while a normal sibling entry is extracted unaffected. Before the fix
// the over-cap entry was silently truncated to the cap and written to disk.
func TestExtract_OverPerFileCapSkippedNotTruncated(t *testing.T) {
	orig := maxExtractedFileBytes
	maxExtractedFileBytes = 16 << 10 // 16 KiB per-file cap
	defer func() { maxExtractedFileBytes = orig }()

	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.msix")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	write := func(name string, n int) {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(bytes.Repeat([]byte{0x42}, n)); err != nil {
			t.Fatal(err)
		}
	}
	write("big.bin", 64<<10)  // over cap
	write("small.bin", 4<<10) // under cap
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	report, err := Extract(path, out)
	if err != nil {
		t.Fatalf("Extract should not abort on a single over-cap entry: %v", err)
	}

	// The over-cap entry must NOT remain on disk as a truncated partial.
	if fi, statErr := os.Stat(filepath.Join(out, "big.bin")); statErr == nil {
		t.Fatalf("over-cap entry written (size %d) — expected skipped, not truncated", fi.Size())
	}

	// A skip note must be recorded for the over-cap entry.
	foundSkip := false
	for _, e := range report.Errors {
		if strings.Contains(e, "big.bin") {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Fatalf("expected a skip note for the over-cap entry, got %v", report.Errors)
	}

	// The normal sibling entry must be extracted in full.
	got, err := os.ReadFile(filepath.Join(out, "small.bin"))
	if err != nil {
		t.Fatalf("normal entry should be extracted: %v", err)
	}
	if len(got) != 4<<10 {
		t.Fatalf("normal entry size = %d, want %d (must be unaffected)", len(got), 4<<10)
	}
}
