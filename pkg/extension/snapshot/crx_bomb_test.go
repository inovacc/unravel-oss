/* Copyright (c) 2026 Security Research */
package snapshot

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// buildCRXStoredEntry creates a CRX3 whose single zip entry contains exactly
// n bytes of stored (uncompressed) data.
func buildCRXStoredEntry(t *testing.T, n int) []byte {
	t.Helper()

	var zipBuf bytes.Buffer
	w := zip.NewWriter(&zipBuf)
	fh := &zip.FileHeader{
		Name:   "payload.bin",
		Method: zip.Store,
	}
	fw, err := w.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{0xFF}, 4096)
	remaining := n
	for remaining > 0 {
		toWrite := min(len(chunk), remaining)
		if _, err := fw.Write(chunk[:toWrite]); err != nil {
			t.Fatal(err)
		}
		remaining -= toWrite
	}
	_ = w.Close()

	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	buf.Write(zipBuf.Bytes())
	return buf.Bytes()
}

// TestExtractCRX_ExactlyAtCapAccepted verifies that a CRX entry whose
// uncompressed size equals the per-file cap is extracted, NOT falsely rejected.
// A legitimate file exactly at the cap must pass; only strictly-over-cap is a bomb.
func TestExtractCRX_ExactlyAtCapAccepted(t *testing.T) {
	orig := maxPerFileCRX
	maxPerFileCRX = 64 << 10 // 64 KiB, shrunk so we don't allocate 256 MiB
	defer func() { maxPerFileCRX = orig }()

	crxData := buildCRXStoredEntry(t, int(maxPerFileCRX))
	dest := t.TempDir()

	if err := ExtractCRX(crxData, dest); err != nil {
		t.Fatalf("entry exactly at the cap was falsely rejected: %v", err)
	}
	if _, err := os.Stat(dest + "/payload.bin"); err != nil {
		t.Errorf("expected payload.bin to be extracted at exactly-cap size: %v", err)
	}
}

// TestExtractCRX_OverCapRejected verifies that a CRX entry strictly larger than
// the per-file cap is rejected (decompression-bomb guard).
func TestExtractCRX_OverCapRejected(t *testing.T) {
	orig := maxPerFileCRX
	maxPerFileCRX = 64 << 10
	defer func() { maxPerFileCRX = orig }()

	crxData := buildCRXStoredEntry(t, int(maxPerFileCRX)+4096) // strictly over cap
	dest := t.TempDir()

	if err := ExtractCRX(crxData, dest); err == nil {
		t.Fatal("expected error when entry strictly exceeds maxPerFileCRX cap, got nil")
	}
}

// TestExtractCRX_BelowCapAccepted verifies that a CRX entry whose size is
// strictly below the cap is extracted without error.
func TestExtractCRX_BelowCapAccepted(t *testing.T) {
	// 1 MiB — well below 256 MiB cap.
	crxData := buildCRXStoredEntry(t, 1<<20)
	dest := t.TempDir()

	if err := ExtractCRX(crxData, dest); err != nil {
		t.Fatalf("unexpected error for entry below cap: %v", err)
	}
}

// buildCRXManyEntries builds a CRX3 with `count` tiny stored entries.
func buildCRXManyEntries(t *testing.T, count int) []byte {
	t.Helper()
	var zipBuf bytes.Buffer
	w := zip.NewWriter(&zipBuf)
	for i := 0; i < count; i++ {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: "f" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".txt", Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte("x"))
	}
	_ = w.Close()

	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	buf.Write(zipBuf.Bytes())
	return buf.Bytes()
}

// TestExtractCRX_EntryCountCapRejected verifies that a CRX with more entries
// than maxCRXEntries is rejected (entry-flood bomb guard).
func TestExtractCRX_EntryCountCapRejected(t *testing.T) {
	orig := maxCRXEntries
	maxCRXEntries = 5
	defer func() { maxCRXEntries = orig }()

	crxData := buildCRXManyEntries(t, 30)
	if err := ExtractCRX(crxData, t.TempDir()); err == nil {
		t.Fatal("expected error when CRX entry count exceeds maxCRXEntries, got nil")
	}
}

// TestExtractCRX_AggregateCapRejected verifies that many sub-cap entries whose
// total exceeds maxAggregateCRXBytes are rejected.
func TestExtractCRX_AggregateCapRejected(t *testing.T) {
	orig := maxAggregateCRXBytes
	maxAggregateCRXBytes = 8 << 10 // 8 KiB budget
	defer func() { maxAggregateCRXBytes = orig }()

	var zipBuf bytes.Buffer
	w := zip.NewWriter(&zipBuf)
	chunk := bytes.Repeat([]byte{0xEE}, 4096)
	for i := 0; i < 10; i++ { // 40 KiB > 8 KiB budget
		fw, err := w.CreateHeader(&zip.FileHeader{Name: "blob" + string(rune('a'+i)) + ".bin", Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(chunk)
	}
	_ = w.Close()

	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	buf.Write(zipBuf.Bytes())

	if err := ExtractCRX(buf.Bytes(), t.TempDir()); err == nil {
		t.Fatal("expected error when aggregate CRX bytes exceed budget, got nil")
	}
}

// TestReadManifestBounded_SnapshotOversizedRejected verifies the snapshot
// manifest reader rejects an oversized manifest.json.
func TestReadManifestBounded_SnapshotOversizedRejected(t *testing.T) {
	orig := maxSnapshotManifestBytes
	maxSnapshotManifestBytes = 1 << 10
	defer func() { maxSnapshotManifestBytes = orig }()

	dir := t.TempDir()
	path := dir + "/manifest.json"
	big := bytes.Repeat([]byte{'x'}, 8<<10)
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifestBounded(path); err == nil {
		t.Fatal("expected error for oversized snapshot manifest, got nil")
	}
}

// TestExtractCRX_SymlinkSkipped verifies that a zip entry marked with Unix
// symlink mode bits (0120777) is silently skipped and does not create a file.
func TestExtractCRX_SymlinkSkipped(t *testing.T) {
	var zipBuf bytes.Buffer
	w := zip.NewWriter(&zipBuf)
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

	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	buf.Write(zipBuf.Bytes())

	dest := t.TempDir()
	if err := ExtractCRX(buf.Bytes(), dest); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No file named "evil-link" should appear in dest.
	dirEntries, _ := os.ReadDir(dest)
	for _, e := range dirEntries {
		if e.Name() == "evil-link" {
			t.Fatal("symlink entry was not skipped — file created on disk")
		}
	}
}
