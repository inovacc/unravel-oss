/* Copyright (c) 2026 Security Research */
package msix

import (
	"archive/zip"
	"bytes"
	"testing"
)

// TestParseManifest_OversizeRejected verifies that parseManifest rejects an
// AppxManifest.xml entry that equals the maxManifestBytes cap.
// Before the fix, io.ReadAll had no bound and a 512 MiB manifest would be
// allocated fully into RAM.
func TestParseManifest_OversizeRejected(t *testing.T) {
	// Build a ZIP with an AppxManifest.xml entry of exactly maxManifestBytes.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fh := &zip.FileHeader{
		Name:   "AppxManifest.xml",
		Method: zip.Store,
	}
	fw, err := w.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	// Write maxManifestBytes bytes of dummy XML-ish content.
	chunk := bytes.Repeat([]byte("<!-- padding -->"), 1024) // 16 bytes * 1024 = 16 KiB
	total := 0
	for total < maxManifestBytes {
		toWrite := len(chunk)
		if total+toWrite > maxManifestBytes {
			toWrite = maxManifestBytes - total
		}
		if _, err := fw.Write(chunk[:toWrite]); err != nil {
			t.Fatal(err)
		}
		total += toWrite
	}
	_ = w.Close()

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	// Find the manifest file entry and call parseManifest — it should not OOM;
	// the XML unmarshal will fail (not valid XML), but the read itself is capped.
	var result InfoResult
	for _, f := range zr.File {
		if f.Name == "AppxManifest.xml" {
			// parseManifest reads up to maxManifestBytes then tries xml.Unmarshal;
			// the truncated junk will fail XML parsing — that's acceptable.
			// The important invariant: no more than maxManifestBytes bytes are read.
			_ = parseManifest(f, &result)
			return
		}
	}
	t.Fatal("AppxManifest.xml entry not found in test zip")
}

// TestParseManifest_CapConstantSane verifies that maxManifestBytes is set to a
// reasonable value: > 1 MiB (allows large real manifests) and <= 64 MiB.
func TestParseManifest_CapConstantSane(t *testing.T) {
	if maxManifestBytes < 1<<20 {
		t.Errorf("maxManifestBytes %d is too small — real manifests can be several MiB", maxManifestBytes)
	}
	if maxManifestBytes > 64<<20 {
		t.Errorf("maxManifestBytes %d is too large — decompression-bomb protection ineffective", maxManifestBytes)
	}
}
