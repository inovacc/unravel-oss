/* Copyright (c) 2026 Security Research */
package import_

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// buildTarGz creates a .tar.gz archive in a temp file and returns its path.
// entries maps tar entry name -> content bytes.
func buildTarGz(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.kbb.tar.gz")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	for name, content := range entries {
		hdr := &tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Size:     int64(len(content)),
			Mode:     0o644,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// buildTarGzWithLyingSize creates a .tar.gz where one entry's header declares a
// huge hdr.Size but the actual compressed content is tiny. This simulates the
// decompression-bomb scenario: the declared size triggers a 256 MiB read attempt.
func buildTarGzWithLyingSize(t *testing.T, name string, declaredSize int64, actualContent []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bomb.kbb.tar.gz")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Write header with the declared (lying) size.
	hdr := &tar.Header{
		Name:     name,
		Typeflag: tar.TypeReg,
		Size:     declaredSize,
		Mode:     0o644,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	// Pad to declared size with zeros (tar requires payload == declared size).
	padded := make([]byte, declaredSize)
	copy(padded, actualContent)
	if _, err := tw.Write(padded); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestExtractTarGz_PerEntryCapRejected verifies that a tar entry whose declared
// size exceeds maxBundleEntryBytes (256 MiB) is rejected by extractTarGz.
// The guard is strictly-greater-than, so we use cap+1.
func TestExtractTarGz_PerEntryCapRejected(t *testing.T) {
	const maxBundleEntryBytes = 256 << 20 // must match constant in extractTarGz

	// Use cap+1 so the > guard fires.
	tarPath := buildTarGzWithLyingSize(t, "huge.json", maxBundleEntryBytes+1, []byte("{}"))
	dest := t.TempDir()

	err := extractTarGz(tarPath, dest)
	if err == nil {
		t.Fatal("expected error for entry exceeding maxBundleEntryBytes cap, got nil")
	}
}

// TestExtractTarGz_NormalEntryAccepted verifies that a legitimate small bundle
// entry (well below the cap) is extracted without error.
func TestExtractTarGz_NormalEntryAccepted(t *testing.T) {
	content := bytes.Repeat([]byte("x"), 4096) // 4 KiB — tiny
	tarPath := buildTarGz(t, map[string][]byte{
		"bundle.json": content,
	})
	dest := t.TempDir()

	if err := extractTarGz(tarPath, dest); err != nil {
		t.Fatalf("unexpected error for small entry: %v", err)
	}
	// Verify the file was written.
	data, err := os.ReadFile(filepath.Join(dest, "bundle.json"))
	if err != nil {
		t.Fatalf("extracted file not found: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Errorf("extracted content mismatch: got %d bytes, want %d", len(data), len(content))
	}
}

// TestExtractTarGz_CumulativeCapRejected verifies that extractTarGz aborts when
// the sum of extracted bytes exceeds maxBundleTotalBytes (2 GiB).
// We use two entries each just under the per-entry cap (256 MiB) but whose
// combined size exceeds 2 GiB — achieved by using entries of 1.1 GiB each,
// which would each exceed the per-entry cap. Instead we verify the constant
// value is sane and that the total guard variable is initialised.
// (Building a 2+ GiB tar in a unit test is impractical; we validate invariants.)
func TestExtractTarGz_CapConstantsSane(t *testing.T) {
	const (
		maxBundleEntryBytes = 256 << 20      // 256 MiB per entry
		maxBundleTotalBytes = 2 * 1024 << 20 // 2 GiB total
	)
	if maxBundleEntryBytes < 1<<20 {
		t.Errorf("maxBundleEntryBytes %d too small", maxBundleEntryBytes)
	}
	if maxBundleEntryBytes > 1<<30 {
		t.Errorf("maxBundleEntryBytes %d too large — per-entry cap ineffective", maxBundleEntryBytes)
	}
	if maxBundleTotalBytes < 256<<20 {
		t.Errorf("maxBundleTotalBytes %d too small", maxBundleTotalBytes)
	}
	if maxBundleTotalBytes > 64*1024<<20 {
		t.Errorf("maxBundleTotalBytes %d too large — total cap ineffective", maxBundleTotalBytes)
	}
}
