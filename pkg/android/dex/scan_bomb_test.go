/*
Copyright (c) 2026 Security Research
*/
package dex

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

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

// TestParseDexEntry_BombRejected verifies the classes*.dex decompressed read is
// bounded: a DEX entry inflating past the cap must error rather than be fully
// materialized into memory.
func TestParseDexEntry_BombRejected(t *testing.T) {
	orig := maxDexBytes
	maxDexBytes = 4096
	defer func() { maxDexBytes = orig }()

	apkPath := buildBombAPK(t, "classes.dex", 64*1024)

	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()

	var entry *zip.File
	for _, e := range zr.File {
		if isDexEntry(e.Name) {
			entry = e
			break
		}
	}
	if entry == nil {
		t.Fatal("dex entry not found")
	}

	_, err = parseDexEntry(entry)
	if err == nil {
		t.Fatal("expected error for oversized dex, got nil")
	}
	if !errors.Is(err, safeio.ErrLimitExceeded) {
		t.Fatalf("expected ErrLimitExceeded, got %v", err)
	}
}
