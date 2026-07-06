/* Copyright (c) 2026 Security Research */
package asar

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenAndParse_HeaderBombRejected verifies that an ASAR file whose declared
// headerStrSize is enormous (0xFFFFFFFF) on a tiny file is rejected with an
// error before any ~4 GiB allocation, rather than OOMing the host.
func TestOpenAndParse_HeaderBombRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bomb.asar")

	// 16-byte prefix: [0:4] pickleSize (small valid), [4:8] totalHeaderSize,
	// [12:16] headerStrSize = 0xFFFFFFFF (attacker claims ~4 GiB header).
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], 8)            // small, passes detection-style checks
	binary.LittleEndian.PutUint32(buf[4:8], 8)            // totalHeaderSize
	binary.LittleEndian.PutUint32(buf[12:16], 0xFFFFFFFF) // headerStrSize bomb
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, _, _, err := OpenAndParse(path)
	if err == nil {
		t.Fatal("expected error for oversized header size, got nil")
	}
}

// TestExtract_OOBEntryRejected verifies that an ASAR entry whose declared
// region (dataOffset + fileOffset + size) extends beyond the archive file size
// is rejected with an error recorded in the report, not silently read past EOF.
func TestExtract_OOBEntryRejected(t *testing.T) {
	// Build a tiny ASAR archive with 4 bytes of data payload.
	// Then declare a file entry whose size claims 1 GiB — well beyond the archive.
	// The offset "0" + size "1 GiB" > archiveSize => should be rejected.
	smallPayload := []byte("data") // 4 bytes of real data
	files := map[string]*FileEntry{
		"bomb.bin": {
			Offset: "0",
			Size:   1 << 30, // 1 GiB — far beyond the 4-byte payload
		},
	}
	asarPath := buildTestASAR(t, files, smallPayload)

	f, header, _, dataOffset, err := OpenAndParse(asarPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	dest := t.TempDir()
	report := Extract(f, header, dataOffset, dest, asarPath, false)

	// The OOB entry must appear in Errors, not in Files.
	if report.Files > 0 {
		t.Errorf("expected 0 extracted files for OOB entry, got %d", report.Files)
	}
	if len(report.Errors) == 0 {
		t.Error("expected at least one error for OOB entry, got none")
	}
}

// TestExtract_CapConstantsSane verifies that the per-file and cumulative caps
// are set to values that protect against bombs without rejecting real inputs.
func TestExtract_CapConstantsSane(t *testing.T) {
	// Per-file cap: >= 1 MiB (allows real files), <= 1 GiB.
	if maxExtractedFileBytes < 1<<20 {
		t.Errorf("maxExtractedFileBytes %d is too small", maxExtractedFileBytes)
	}
	if maxExtractedFileBytes > 1<<30 {
		t.Errorf("maxExtractedFileBytes %d is too large — per-file bomb protection ineffective", maxExtractedFileBytes)
	}
	// Cumulative cap: >= 1 GiB, <= 64 GiB.
	if maxASARTotalBytes < 1<<30 {
		t.Errorf("maxASARTotalBytes %d is too small", maxASARTotalBytes)
	}
	if maxASARTotalBytes > 64*1024<<20 {
		t.Errorf("maxASARTotalBytes %d is too large — total bomb protection ineffective", maxASARTotalBytes)
	}
	_ = fmt.Sprintf("caps ok: per-file=%d total=%d", maxExtractedFileBytes, maxASARTotalBytes)
}

// TestExtract_LargeEntryRejectedByPerFileCap verifies that an entry claiming
// more than maxExtractedFileBytes is rejected by extractFile before any I/O.
func TestExtract_LargeEntryRejectedByPerFileCap(t *testing.T) {
	// Build a real data region of 4 bytes, but declare a file that claims
	// maxExtractedFileBytes + 1 bytes — the per-file guard fires first.
	smallPayload := []byte("XXXX")
	files := map[string]*FileEntry{
		"toobig.bin": {
			Offset: "0",
			Size:   maxExtractedFileBytes + 1,
		},
	}
	asarPath := buildTestASAR(t, files, smallPayload)

	f, header, _, dataOffset, err := OpenAndParse(asarPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	dest := t.TempDir()
	report := Extract(f, header, dataOffset, dest, asarPath, false)

	if report.Files > 0 {
		t.Errorf("expected 0 extracted files for oversized entry, got %d", report.Files)
	}
	if len(report.Errors) == 0 {
		t.Error("expected error for oversized entry, got none")
	}
	// The output file must not exist.
	if _, err := os.Stat(dest + "/toobig.bin"); err == nil {
		t.Error("toobig.bin was written despite being over the per-file cap")
	}
}
