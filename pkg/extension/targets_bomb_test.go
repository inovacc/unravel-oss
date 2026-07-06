/* Copyright (c) 2026 Security Research */
package extension

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"
)

// buildZIPWithStoredEntry builds an in-memory ZIP archive whose single entry
// contains exactly n bytes of stored (uncompressed) data.
func buildZIPWithStoredEntry(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fh := &zip.FileHeader{
		Name:   "payload.bin",
		Method: zip.Store,
	}
	fw, err := w.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{0xAB}, 4096)
	remaining := n
	for remaining > 0 {
		toWrite := min(len(chunk), remaining)
		if _, err := fw.Write(chunk[:toWrite]); err != nil {
			t.Fatal(err)
		}
		remaining -= toWrite
	}
	_ = w.Close()
	return buf.Bytes()
}

// TestExtractZIPEntries_ExactlyAtCapAccepted verifies that a zip entry whose
// uncompressed size equals the per-file cap (maxPerFileExt) is extracted, NOT
// falsely rejected. A legitimate file exactly at the cap must pass; only a
// strictly-over-cap entry is a decompression bomb.
func TestExtractZIPEntries_ExactlyAtCapAccepted(t *testing.T) {
	orig := maxPerFileExt
	maxPerFileExt = 64 << 10 // 64 KiB, shrunk so we don't allocate 256 MiB
	defer func() { maxPerFileExt = orig }()

	data := buildZIPWithStoredEntry(t, int(maxPerFileExt))
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()

	if err := extractZIPEntries(zr.File, dest); err != nil {
		t.Fatalf("entry exactly at the cap was falsely rejected: %v", err)
	}
	if _, err := os.Stat(dest + "/payload.bin"); err != nil {
		t.Errorf("expected payload.bin to be extracted at exactly-cap size: %v", err)
	}
}

// TestExtractZIPEntries_OverCapRejected verifies that a zip entry strictly
// larger than the per-file cap causes extractZIPEntries to return an error.
func TestExtractZIPEntries_OverCapRejected(t *testing.T) {
	orig := maxPerFileExt
	maxPerFileExt = 64 << 10
	defer func() { maxPerFileExt = orig }()

	data := buildZIPWithStoredEntry(t, int(maxPerFileExt)+4096) // strictly over cap
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()

	if err := extractZIPEntries(zr.File, dest); err == nil {
		t.Fatal("expected error when entry strictly exceeds maxPerFileExt cap, got nil")
	}
}

// TestExtractZIPEntries_BelowCapAccepted verifies that a zip entry whose size
// is strictly below the per-file cap is extracted without error.
func TestExtractZIPEntries_BelowCapAccepted(t *testing.T) {
	// 512 KiB — well below 256 MiB cap.
	data := buildZIPWithStoredEntry(t, 512<<10)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()

	if err := extractZIPEntries(zr.File, dest); err != nil {
		t.Fatalf("unexpected error for entry below cap: %v", err)
	}
	// Verify the file was actually written.
	if _, err := os.Stat(dest + "/payload.bin"); err != nil {
		t.Errorf("expected payload.bin to be extracted: %v", err)
	}
}

// TestExtractZIPEntries_EntryCountCapRejected verifies that an archive with
// more entries than maxExtractEntries is rejected (entry-flood bomb guard).
func TestExtractZIPEntries_EntryCountCapRejected(t *testing.T) {
	orig := maxExtractEntries
	maxExtractEntries = 5
	defer func() { maxExtractEntries = orig }()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := 0; i < 20; i++ {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: "f" + string(rune('a'+i)) + ".txt", Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte("x"))
	}
	_ = w.Close()

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if err := extractZIPEntries(zr.File, t.TempDir()); err == nil {
		t.Fatal("expected error when entry count exceeds maxExtractEntries, got nil")
	}
}

// TestExtractZIPEntries_AggregateCapRejected verifies that many sub-per-file-cap
// entries whose total exceeds maxAggregateExtractBytes are rejected.
func TestExtractZIPEntries_AggregateCapRejected(t *testing.T) {
	origAgg := maxAggregateExtractBytes
	maxAggregateExtractBytes = 8 << 10 // 8 KiB total budget
	defer func() { maxAggregateExtractBytes = origAgg }()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte{0xCD}, 4096)
	for i := 0; i < 10; i++ { // 10 * 4 KiB = 40 KiB > 8 KiB budget
		fw, err := w.CreateHeader(&zip.FileHeader{Name: "blob" + string(rune('a'+i)) + ".bin", Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(chunk)
	}
	_ = w.Close()

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if err := extractZIPEntries(zr.File, t.TempDir()); err == nil {
		t.Fatal("expected error when aggregate bytes exceed budget, got nil")
	}
}

// TestExtractZIPEntries_SymlinkSkipped verifies that a zip entry with symlink
// mode bits is skipped and does not create a file on disk.
func TestExtractZIPEntries_SymlinkSkipped(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fh := &zip.FileHeader{
		Name:   "evil-link",
		Method: zip.Store,
	}
	fh.SetMode(os.ModeSymlink | 0o777)
	fw, err := w.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("/etc/passwd"))
	_ = w.Close()

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()

	if err := extractZIPEntries(zr.File, dest); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dirEntries, _ := os.ReadDir(dest)
	for _, e := range dirEntries {
		if e.Name() == "evil-link" {
			t.Fatal("symlink entry was not skipped — file created on disk")
		}
	}
}
