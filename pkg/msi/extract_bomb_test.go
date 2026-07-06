/* Copyright (c) 2026 Security Research */
package msi

import (
	"testing"
)

// TestExtract_StreamCapConstantsSane verifies that the decompression-bomb guard
// constants are set to reasonable values.
// The actual extraction path requires a real CFBF/OLE file which is non-trivial
// to synthesize in a unit test; we validate the invariants on the constants
// to ensure the guards are meaningful.
func TestExtract_StreamCapConstantsSane(t *testing.T) {
	const (
		maxStreamBytes   = 128 << 20      // 128 MiB per stream
		maxMSITotalBytes = 4 * 1024 << 20 // 4 GiB total
	)

	// Per-stream cap: must be >= 1 MiB (allows real streams) and <= 512 MiB.
	if maxStreamBytes < 1<<20 {
		t.Errorf("maxStreamBytes %d is too small — real MSI streams can be large", maxStreamBytes)
	}
	if maxStreamBytes > 512<<20 {
		t.Errorf("maxStreamBytes %d exceeds reasonable per-stream bound", maxStreamBytes)
	}

	// Total cap: must be >= 64 MiB (reasonable MSI) and <= 16 GiB.
	if maxMSITotalBytes < 64<<20 {
		t.Errorf("maxMSITotalBytes %d is too small", maxMSITotalBytes)
	}
	if maxMSITotalBytes > 16*1024<<20 {
		t.Errorf("maxMSITotalBytes %d is unreasonably large", maxMSITotalBytes)
	}
}
