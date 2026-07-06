/*
Copyright (c) 2026 Security Research
*/

package resources

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// buildBombAPK writes a tiny zip containing one entry whose decompressed
// content is `size` bytes of highly-compressible zeros.
func buildBombAPK(t *testing.T, entryName string, size int) string {
	t.Helper()
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "bomb.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	w, err := zw.Create(entryName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return apkPath
}

// TestScanAPK_ArscBombRejected verifies the resources.arsc decompressed read is
// bounded: an entry inflating past the cap must error rather than be fully
// materialized.
func TestScanAPK_ArscBombRejected(t *testing.T) {
	orig := maxARSCBytes
	maxARSCBytes = 4096 // shrink cap so we assert the bound without GBs
	defer func() { maxARSCBytes = orig }()

	apkPath := buildBombAPK(t, "resources.arsc", 64*1024) // 64 KiB > 4 KiB cap

	_, err := ScanAPK(apkPath)
	if err == nil {
		t.Fatal("expected error for oversized resources.arsc, got nil")
	}
	if !errors.Is(err, safeio.ErrLimitExceeded) {
		t.Fatalf("expected ErrLimitExceeded, got %v", err)
	}
}
