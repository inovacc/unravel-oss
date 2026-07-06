package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// buildMixedJAR writes a .jar containing one over-cap entry and one small entry,
// each stored (uncompressed) so the on-disk size is deterministic.
func buildMixedJAR(t *testing.T, dir, name string, bigSize, smallSize int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	write := func(entry string, n int) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: entry, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(bytes.Repeat([]byte{0x42}, n)); err != nil {
			t.Fatal(err)
		}
	}
	write("big.bin", bigSize)
	write("small.bin", smallSize)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestExtractZip_OverPerFileCapSkippedNotTruncated verifies that an entry larger
// than the per-file cap is SKIPPED (dropped, not written as a truncated partial),
// while a normal sibling entry is extracted unaffected. Before the fix the
// over-cap entry was silently truncated to the cap and written to disk, producing
// corrupt analysis output with no signal.
func TestExtractZip_OverPerFileCapSkippedNotTruncated(t *testing.T) {
	orig := maxExtractSize
	maxExtractSize = 16 << 10 // 16 KiB per-file cap
	defer func() { maxExtractSize = orig }()

	dir := t.TempDir()
	// big = 64 KiB (over cap), small = 4 KiB (under cap).
	jar := buildMixedJAR(t, dir, "mixed.jar", 64<<10, 4<<10)

	e := New(slog.Default())
	dest := t.TempDir()

	if err := e.extractZip(context.Background(), jar, dest, budgetWithCap()); err != nil {
		t.Fatalf("extractZip should not abort on a single over-cap entry: %v", err)
	}

	// The over-cap entry must NOT be present as a truncated partial.
	if fi, err := os.Stat(filepath.Join(dest, "big.bin")); err == nil {
		t.Fatalf("over-cap entry was written (size %d) — expected it skipped, not truncated", fi.Size())
	}

	// The normal sibling entry must be extracted in full.
	got, err := os.ReadFile(filepath.Join(dest, "small.bin"))
	if err != nil {
		t.Fatalf("normal entry should be extracted: %v", err)
	}
	if len(got) != 4<<10 {
		t.Fatalf("normal entry size = %d, want %d (must be unaffected)", len(got), 4<<10)
	}
}
