/* Copyright (c) 2026 Security Research */
package extension

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadManifestBounded_OversizedRejected verifies that a manifest.json larger
// than maxExtensionReadSize is rejected before it is fully read into memory,
// rather than OOMing the host via os.ReadFile + json.Unmarshal.
func TestReadManifestBounded_OversizedRejected(t *testing.T) {
	orig := maxExtensionReadSize
	maxExtensionReadSize = 1 << 10 // 1 KiB cap
	defer func() { maxExtensionReadSize = orig }()

	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	// 8 KiB manifest — over the 1 KiB injected cap.
	big := make([]byte, 8<<10)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := readManifestBounded(path); err == nil {
		t.Fatal("expected error for oversized manifest, got nil")
	}
}

// TestReadManifestBounded_SmallAccepted verifies a normal small manifest reads OK.
func TestReadManifestBounded_SmallAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(`{"name":"ok","version":"1.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := readManifestBounded(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected manifest data, got empty")
	}
}
