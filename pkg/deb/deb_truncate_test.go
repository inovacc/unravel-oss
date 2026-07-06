/* Copyright (c) 2026 Security Research */
package deb

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExtractTar_OverPerFileCapSkippedNotTruncated verifies that a tar entry
// larger than the per-file cap is SKIPPED (dropped, not written as a truncated
// partial), while a normal sibling entry is extracted unaffected. Before the fix
// the over-cap entry was silently truncated to the cap and left on disk.
func TestExtractTar_OverPerFileCapSkippedNotTruncated(t *testing.T) {
	orig := maxExtractedFileBytes
	maxExtractedFileBytes = 16 << 10 // 16 KiB per-file cap
	defer func() { maxExtractedFileBytes = orig }()

	big := strings.Repeat("B", 64<<10)  // 64 KiB, over cap
	small := strings.Repeat("s", 4<<10) // 4 KiB, under cap
	data := buildTarGz(t, []tarEntry{
		{name: "big.bin", typeflag: tar.TypeReg, content: big},
		{name: "small.bin", typeflag: tar.TypeReg, content: small},
	})

	dest := t.TempDir()
	_, _, _, errs := extractTar(data, "data.tar.gz", dest)

	// The over-cap entry must NOT remain on disk as a truncated partial.
	if fi, err := os.Stat(filepath.Join(dest, "big.bin")); err == nil {
		t.Fatalf("over-cap entry written (size %d) — expected skipped, not truncated", fi.Size())
	}

	// A warning must be recorded for the skipped entry.
	foundSkip := false
	for _, e := range errs {
		if strings.Contains(e, "skipped") && strings.Contains(e, "big.bin") {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Fatalf("expected a skip warning for the over-cap entry, got %v", errs)
	}

	// The normal sibling entry must be extracted in full.
	got, err := os.ReadFile(filepath.Join(dest, "small.bin"))
	if err != nil {
		t.Fatalf("normal entry should be extracted: %v", err)
	}
	if len(got) != len(small) {
		t.Fatalf("normal entry size = %d, want %d (must be unaffected)", len(got), len(small))
	}
}
