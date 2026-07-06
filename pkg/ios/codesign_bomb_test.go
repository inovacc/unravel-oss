package ios

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"
)

// TestReadZipFileByName_Bounded verifies that readZipFileByName does not read an
// unbounded amount from a zip entry. A malicious IPA can ship a high-ratio
// DEFLATE entry that inflates to gigabytes; the read must be capped at
// maxMetadataBytes so it cannot OOM the host. Reachable from VerifyCodeSign via
// archived-expanded-entitlements.xcent and embedded.mobileprovision.
func TestReadZipFileByName_Bounded(t *testing.T) {
	// Shrink the cap so we can assert the bound without allocating gigabytes.
	orig := maxMetadataBytes
	maxMetadataBytes = 1 << 10 // 1 KiB
	defer func() { maxMetadataBytes = orig }()

	const name = "Payload/Test.app/embedded.mobileprovision"
	// 64 KiB of highly compressible zeros — well over the shrunk 1 KiB cap.
	payload := make([]byte, 64<<10)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen as a zip ReadCloser by writing to a temp file (zip.OpenReader needs a path).
	dir := t.TempDir()
	ipaPath := dir + "/bomb.ipa"
	if err := os.WriteFile(ipaPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()

	data, err := readZipFileByName(zr, name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if int64(len(data)) > int64(maxMetadataBytes) {
		t.Fatalf("readZipFileByName returned %d bytes, want <= cap %d — read is unbounded", len(data), maxMetadataBytes)
	}
}
