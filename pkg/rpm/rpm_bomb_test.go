/* Copyright (c) 2026 Security Research */
package rpm

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// buildCPIOEntryDeclared builds a newc CPIO entry whose header declares
// declaredSize bytes of body, writing exactly declaredSize real bytes (data,
// zero-padded) plus 4-byte alignment. This lets tests craft an entry whose
// declared filesize exceeds a cap while keeping the stream byte-aligned.
func buildCPIOEntryDeclared(name string, mode uint32, declaredSize int, data []byte) []byte {
	var buf bytes.Buffer

	nameBytes := append([]byte(name), 0)
	nameSize := len(nameBytes)

	header := fmt.Sprintf("070701"+
		"%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
		1, mode, 0, 0, 1, 0, declaredSize, 0, 0, 0, 0, nameSize, 0)

	buf.WriteString(header)
	buf.Write(nameBytes)

	headerAndName := 110 + nameSize
	namePad := (4 - (headerAndName % 4)) % 4
	for range namePad {
		buf.WriteByte(0)
	}

	body := make([]byte, declaredSize)
	copy(body, data)
	buf.Write(body)

	dataPad := (4 - (declaredSize % 4)) % 4
	for range dataPad {
		buf.WriteByte(0)
	}

	return buf.Bytes()
}

// TestExtractCPIO_AggregateBudget (#16) verifies that a CPIO whose cumulative
// entry bytes exceed the aggregate budget stops with a recorded error.
func TestExtractCPIO_AggregateBudget(t *testing.T) {
	origTotal := maxRPMTotalBytes
	t.Cleanup(func() { maxRPMTotalBytes = origTotal })
	maxRPMTotalBytes = 4096 // tiny aggregate cap

	var archive bytes.Buffer
	// Three 2 KiB files: first two fit (4096), third overflows aggregate.
	archive.Write(buildCPIOEntry("a.bin", 0o100644, bytes.Repeat([]byte("A"), 2048)))
	archive.Write(buildCPIOEntry("b.bin", 0o100644, bytes.Repeat([]byte("B"), 2048)))
	archive.Write(buildCPIOEntry("c.bin", 0o100644, bytes.Repeat([]byte("C"), 2048)))
	archive.Write(buildCPIOTrailer())

	_, _, _, errs := extractCPIO(&archive, t.TempDir())
	if len(errs) == 0 {
		t.Fatal("expected aggregate-limit error, got none")
	}
}

// TestExtractCPIO_EntryCountBudget (#16) verifies the entry-count cap fires.
func TestExtractCPIO_EntryCountBudget(t *testing.T) {
	orig := maxRPMEntries
	t.Cleanup(func() { maxRPMEntries = orig })
	maxRPMEntries = 2

	var archive bytes.Buffer
	for i := 0; i < 5; i++ {
		archive.Write(buildCPIOEntry(fmt.Sprintf("f%d.bin", i), 0o100644, []byte("x")))
	}
	archive.Write(buildCPIOTrailer())

	_, _, _, errs := extractCPIO(&archive, t.TempDir())
	if len(errs) == 0 {
		t.Fatal("expected entry-count-limit error, got none")
	}
}

// TestExtractCPIO_OversizedEntrySkipAndContinue (#29) verifies that a leading
// over-cap entry is SKIPPED (not aborting the archive) and a benign trailing
// entry is still extracted.
func TestExtractCPIO_OversizedEntrySkipAndContinue(t *testing.T) {
	origCap := maxRPMEntryBytes
	t.Cleanup(func() { maxRPMEntryBytes = origCap })
	maxRPMEntryBytes = 16 // 16-byte per-entry cap for this test

	var archive bytes.Buffer
	// Leading entry declares 64 bytes (> 16-byte cap) -> must be skipped.
	archive.Write(buildCPIOEntryDeclared("evil.bin", 0o100644, 64, bytes.Repeat([]byte("E"), 64)))
	// Trailing benign entry (8 bytes) -> must still extract.
	archive.Write(buildCPIOEntry("good.txt", 0o100644, []byte("survived")))
	archive.Write(buildCPIOTrailer())

	outDir := t.TempDir()
	files, _, _, errs := extractCPIO(&archive, outDir)

	if len(errs) == 0 {
		t.Fatal("expected a skip error for the oversized entry")
	}
	if files != 1 {
		t.Fatalf("files = %d, want 1 (trailing benign entry must survive skip-and-continue)", files)
	}
	if _, err := os.Stat(filepath.Join(outDir, "good.txt")); err != nil {
		t.Fatalf("trailing benign entry was not extracted: %v", err)
	}
}
