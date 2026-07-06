package ios

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// writeStoredIPA writes a single stored (uncompressed) zip entry to a temp .ipa
// and returns an opened ReadCloser. The caller must Close it.
func writeStoredIPA(t *testing.T, name string, payload []byte) *zip.ReadCloser {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ipaPath := dir + "/app.ipa"
	if err := os.WriteFile(ipaPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

// TestReadZipFile_ExecutableNotTruncated verifies that the main Mach-O
// executable is read with the generous executable cap, NOT the 16 MiB metadata
// cap. Real iOS app binaries are 50-200+ MiB; reading them through the metadata
// cap silently truncates the Mach-O and breaks analysis. With a payload that
// exceeds the (shrunk) metadata cap but is within the executable cap, the FULL
// length must be preserved.
func TestReadZipFile_ExecutableNotTruncated(t *testing.T) {
	origMeta := maxMetadataBytes
	origExec := maxExecutableBytes
	maxMetadataBytes = 4 << 10   // 4 KiB metadata cap
	maxExecutableBytes = 1 << 20 // 1 MiB executable cap
	defer func() {
		maxMetadataBytes = origMeta
		maxExecutableBytes = origExec
	}()

	const name = "Payload/Test.app/Test"
	// 64 KiB: over the 4 KiB metadata cap, well under the 1 MiB exec cap.
	payload := bytes.Repeat([]byte{0x90}, 64<<10)

	zr := writeStoredIPA(t, name, payload)
	defer func() { _ = zr.Close() }()

	data, err := readZipFile(zr, name, maxExecutableBytes)
	if err != nil {
		t.Fatalf("unexpected error reading executable within exec cap: %v", err)
	}
	if int64(len(data)) != int64(len(payload)) {
		t.Fatalf("executable truncated: got %d bytes, want full %d — read used the wrong (metadata) cap", len(data), len(payload))
	}
}

// TestReadZipFile_ExecutableOverCapErrors verifies that an executable strictly
// larger than the executable cap ERRORS (safeio.ErrLimitExceeded) rather than
// being silently truncated — a true bomb is rejected, not mis-analyzed.
func TestReadZipFile_ExecutableOverCapErrors(t *testing.T) {
	origExec := maxExecutableBytes
	maxExecutableBytes = 16 << 10 // 16 KiB exec cap
	defer func() { maxExecutableBytes = origExec }()

	const name = "Payload/Test.app/Test"
	// 64 KiB: over the 16 KiB exec cap.
	payload := bytes.Repeat([]byte{0x90}, 64<<10)

	zr := writeStoredIPA(t, name, payload)
	defer func() { _ = zr.Close() }()

	_, err := readZipFile(zr, name, maxExecutableBytes)
	if !errors.Is(err, safeio.ErrLimitExceeded) {
		t.Fatalf("expected safeio.ErrLimitExceeded for over-cap executable, got %v", err)
	}
}
