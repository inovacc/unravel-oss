package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// buildTarGz returns a gzip-compressed tar built from the supplied headers.
// If body is non-nil for an entry, it is written after the header.
func buildTarGz(t *testing.T, entries []*tar.Header, bodies [][]byte) []byte {
	t.Helper()
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gw)
	for i, h := range entries {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if bodies != nil && bodies[i] != nil {
			if _, err := tw.Write(bodies[i]); err != nil {
				t.Fatalf("write body: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return gzBuf.Bytes()
}

// TestExtractTarGz_EntryCountFlood (finding #30) verifies that a tarball with
// more entries than maxTarEntries is rejected, bounding inode/syscall use.
func TestExtractTarGz_EntryCountFlood(t *testing.T) {
	// Shrink the cap so we don't need millions of real entries.
	orig := maxTarEntries
	maxTarEntries = 5
	defer func() { maxTarEntries = orig }()

	var entries []*tar.Header
	for i := 0; i < 50; i++ {
		entries = append(entries, &tar.Header{
			Name:     "package/dir" + strings.Repeat("a", i) + "/",
			Typeflag: tar.TypeDir,
			Mode:     0o755,
		})
	}
	data := buildTarGz(t, entries, nil)

	_, _, err := extractTarGz(bytes.NewReader(data), t.TempDir())
	if err == nil {
		t.Fatal("expected entry-count error, got nil")
	}
	if !strings.Contains(err.Error(), "entry count exceeds") {
		t.Fatalf("expected entry-count error, got: %v", err)
	}
}

// TestExtractTarGz_UnknownTypeInflationBomb (finding #31) verifies that an
// entry with an unknown typeflag and a large highly-compressible body cannot
// silently inflate unbounded — it is rejected (unsupported type) and the
// unified decompressed budget would otherwise trip.
func TestExtractTarGz_UnknownTypeInflationBomb(t *testing.T) {
	// Shrink the decompressed budget so the bomb is small to craft.
	origBudget := maxDownloadBytes
	maxDownloadBytes = 64 << 10 // 64 KiB
	defer func() { maxDownloadBytes = origBudget }()

	// Unknown typeflag 'A' with a 1 MiB declared body of zeros (compresses tiny).
	const bodyLen = 1 << 20
	entries := []*tar.Header{
		{
			Name:     "package/evil",
			Typeflag: 'A', // reserved/unknown — not TypeReg, not header-only
			Size:     bodyLen,
			Mode:     0o644,
		},
	}
	bodies := [][]byte{make([]byte, bodyLen)}
	data := buildTarGz(t, entries, bodies)

	_, _, err := extractTarGz(bytes.NewReader(data), t.TempDir())
	if err == nil {
		t.Fatal("expected error for unknown-type inflation bomb, got nil")
	}
	// Either the unsupported-type rejection or the budget guard is acceptable.
	if !strings.Contains(err.Error(), "unsupported tar entry type") &&
		!strings.Contains(err.Error(), "byte budget") {
		t.Fatalf("expected unsupported-type or budget error, got: %v", err)
	}
}

// TestExtractTarGz_LegitPackageExtracts confirms a normal small package still
// extracts cleanly under the caps (no false positive).
func TestExtractTarGz_LegitPackageExtracts(t *testing.T) {
	entries := []*tar.Header{
		{Name: "package/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "package/package.json", Typeflag: tar.TypeReg, Size: 13, Mode: 0o644},
		{Name: "package/index.js", Typeflag: tar.TypeReg, Size: 18, Mode: 0o644},
	}
	bodies := [][]byte{nil, []byte(`{"name":"ok"}`), []byte("module.exports={}")}
	bodies[2] = []byte("module.exports={};") // 18 bytes
	data := buildTarGz(t, entries, bodies)

	n, size, err := extractTarGz(bytes.NewReader(data), t.TempDir())
	if err != nil {
		t.Fatalf("legit package should extract, got: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 files, got %d", n)
	}
	if size != 13+18 {
		t.Fatalf("expected size 31, got %d", size)
	}
}
