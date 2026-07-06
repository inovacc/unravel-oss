package pyinst

import (
	"bytes"
	"compress/zlib"
	"testing"
)

// TestExtractEntry_ZlibBombBounded verifies that a compressed TOC entry whose
// zlib stream inflates far beyond the per-entry cap is skipped (returns nil)
// rather than materializing the full multi-MB/GB inflation in memory.
//
// SEC finding #20: extractEntry did io.ReadAll(zlib.NewReader(...)) with no cap.
// entry.UncompressedSize is attacker-controlled, so the guard must clamp to a
// hard ceiling regardless of the declared size.
func TestExtractEntry_ZlibBombBounded(t *testing.T) {
	// Shrink the cap so we can assert the bound without allocating GiB.
	orig := maxPyinstEntryBytes
	maxPyinstEntryBytes = 4096 // 4 KiB cap for the test
	defer func() { maxPyinstEntryBytes = orig }()

	// Build a zlib stream of zeros that inflates to 1 MiB — well past the cap,
	// but a tiny compressed payload (classic bomb shape).
	original := make([]byte, 1<<20) // 1 MiB of zeros
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(original); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := buf.Bytes()

	if int64(len(compressed)) >= maxPyinstEntryBytes {
		t.Fatalf("test setup: compressed payload %d not smaller than cap %d", len(compressed), maxPyinstEntryBytes)
	}

	entry := TOCEntry{
		Position:       0,
		CompressedSize: uint32(len(compressed)),
		// Attacker lies: claims a small uncompressed size to try to disable a
		// naive UncompressedSize-based guard.
		UncompressedSize: 100,
		IsCompressed:     true,
	}

	got := extractEntry(compressed, 0, entry)
	if got != nil {
		t.Fatalf("expected nil (bomb entry skipped), got %d bytes — decompression was unbounded", len(got))
	}
}

// TestExtractEntry_CompressedUnderCapStillWorks ensures the bound does not
// break a legitimate compressed entry that inflates within the cap.
func TestExtractEntry_CompressedUnderCapStillWorks(t *testing.T) {
	orig := maxPyinstEntryBytes
	maxPyinstEntryBytes = 1 << 20 // 1 MiB cap
	defer func() { maxPyinstEntryBytes = orig }()

	original := bytes.Repeat([]byte("legit module bytes\n"), 100) // ~1.9 KiB
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(original); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := buf.Bytes()

	entry := TOCEntry{
		Position:         0,
		CompressedSize:   uint32(len(compressed)),
		UncompressedSize: uint32(len(original)),
		IsCompressed:     true,
	}

	got := extractEntry(compressed, 0, entry)
	if !bytes.Equal(got, original) {
		t.Fatalf("legit compressed entry corrupted: got %d bytes, want %d", len(got), len(original))
	}
}
