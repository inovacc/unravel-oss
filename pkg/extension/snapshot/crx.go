/*
Copyright © 2026 Security Research
*/
package snapshot

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

const crxURLTemplate = "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=131.0&acceptformat=crx2,crx3&x=id%%3D%s%%26uc"

// DownloadCRX fetches a CRX file from the Chrome Web Store by extension ID.
func DownloadCRX(id string) ([]byte, error) {
	url := fmt.Sprintf(crxURLTemplate, id)
	client := &http.Client{Timeout: 60 * time.Second}

	resp, err := client.Get(url) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for extension %s", resp.StatusCode, id)
	}

	return io.ReadAll(resp.Body)
}

// maxPerFileCRX is the per-entry decompression cap for CRX extraction. A var
// (not a const) so tests can inject a small cap; an entry exactly at the cap is
// accepted and only strictly-over-cap is treated as a bomb.
var maxPerFileCRX int64 = 256 << 20 // 256 MiB

// Aggregate caps guard against multi-entry CRX bombs (a flood of tiny entries,
// or many near-cap entries) that fill disk/inodes under the per-file cap. Vars
// so tests can inject small caps; defaults are generous for real extensions.
var (
	maxAggregateCRXBytes int64 = 2 << 30 // 2 GiB total across all entries
	maxCRXEntries        int   = 50_000  // entry-count ceiling (dirs + files)
)

// maxSnapshotManifestBytes caps manifest.json reads in the snapshot pipeline.
// Real manifests are KB-scale; 5 MiB is a generous ceiling. Var so tests can
// inject a small cap.
var maxSnapshotManifestBytes int64 = 5 * 1024 * 1024

// readManifestBounded reads a manifest.json with a size cap so a hostile
// multi-hundred-MiB manifest cannot OOM the host via os.ReadFile + Unmarshal.
func readManifestBounded(path string) ([]byte, error) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxSnapshotManifestBytes {
		return nil, fmt.Errorf("manifest %s size %d exceeds %d-byte cap", path, fi.Size(), maxSnapshotManifestBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return safeio.ReadAllLimit(f, maxSnapshotManifestBytes)
}

// ExtractCRX unpacks a CRX3/CRX2 file into the destination directory.
func ExtractCRX(crxData []byte, destDir string) error {
	if len(crxData) < 12 {
		return fmt.Errorf("CRX data too short (%d bytes)", len(crxData))
	}

	magic := string(crxData[:4])
	if magic != "Cr24" {
		return fmt.Errorf("not a CRX file (magic: %q)", magic)
	}

	version := binary.LittleEndian.Uint32(crxData[4:8])

	// SEC: compute the ZIP offset in uint64 so a CRX2 pubKeyLen+sigLen sum over
	// attacker-controlled uint32s cannot wrap past the bound (defensive
	// consistency with pkg/extension/targets.go readCRXPayload).
	var zipOffset uint64
	switch version {
	case 3:
		headerLen := binary.LittleEndian.Uint32(crxData[8:12])
		zipOffset = 12 + uint64(headerLen)
	case 2:
		if len(crxData) < 16 {
			return fmt.Errorf("CRX2 data too short")
		}
		pubKeyLen := binary.LittleEndian.Uint32(crxData[8:12])
		sigLen := binary.LittleEndian.Uint32(crxData[12:16])
		zipOffset = 16 + uint64(pubKeyLen) + uint64(sigLen)
	default:
		return fmt.Errorf("unsupported CRX version: %d", version)
	}

	if zipOffset >= uint64(len(crxData)) {
		return fmt.Errorf("ZIP offset %d beyond data length %d", zipOffset, len(crxData))
	}

	zipData := crxData[zipOffset:]
	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("open ZIP: %w", err)
	}

	var totalWritten int64
	var entryCount int

	for _, zf := range zipReader.File {
		fpath := filepath.Join(destDir, filepath.FromSlash(zf.Name))

		if !strings.HasPrefix(filepath.Clean(fpath), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		// SEC: count every materialized entry (dir or file) so an entry flood
		// cannot exhaust inodes/syscalls before any per-file cap fires.
		entryCount++
		if entryCount > maxCRXEntries {
			return fmt.Errorf("CRX entry count exceeds %d (decompression bomb)", maxCRXEntries)
		}

		if zf.FileInfo().IsDir() {
			_ = os.MkdirAll(fpath, 0o755)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
			return fmt.Errorf("mkdir for %s: %w", fpath, err)
		}

		// Skip symlink entries to prevent symlink-escape attacks.
		if zf.Mode()&os.ModeSymlink != 0 {
			continue
		}

		rc, err := zf.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %s: %w", zf.Name, err)
		}

		outFile, err := os.Create(fpath)
		if err != nil {
			_ = rc.Close()
			return fmt.Errorf("create %s: %w", fpath, err)
		}

		// CopyLimit bounds per-file extraction: an entry exactly at the cap is
		// accepted; only a strictly-over-cap entry ERRORS (decompression bomb).
		n, err := safeio.CopyLimit(outFile, rc, maxPerFileCRX)
		_ = rc.Close()
		_ = outFile.Close()
		if err != nil {
			if errors.Is(err, safeio.ErrLimitExceeded) {
				return fmt.Errorf("extract %s: entry exceeds %d-byte cap (decompression bomb): %w", zf.Name, maxPerFileCRX, err)
			}
			return fmt.Errorf("extract %s: %w", zf.Name, err)
		}

		// SEC: accumulate actual bytes written and stop once the aggregate
		// across all entries exceeds the budget.
		totalWritten += n
		if totalWritten > maxAggregateCRXBytes {
			return fmt.Errorf("aggregate CRX extraction exceeds %d bytes (decompression bomb)", maxAggregateCRXBytes)
		}
	}

	return nil
}
