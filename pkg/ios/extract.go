package ios

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractResult summarizes an IPA extraction operation.
type ExtractResult struct {
	OutputDir  string `json:"output_dir"`
	Files      int    `json:"files"`
	TotalSize  int64  `json:"total_size"`
	AppBundle  string `json:"app_bundle"`
	Executable string `json:"executable,omitempty"`
}

const (
	// maxIPAPerFile caps each extracted entry at 256 MiB.
	maxIPAPerFile = 256 << 20 // 256 MiB
	// maxIPATotalSize caps total decompressed bytes at 8 GiB.
	maxIPATotalSize = 8 * 1024 << 20 // 8 GiB
	// maxIPAEntries caps the total number of entries to prevent count bombs.
	maxIPAEntries = 1 << 20 // 1 048 576
)

// Extract extracts an IPA file to outputDir.
// It sanitizes all paths to prevent zip-slip attacks and enforces
// decompression-bomb guards (per-file cap, cumulative cap, entry count cap).
func Extract(ipaPath, outputDir string) (*ExtractResult, error) {
	zr, err := zip.OpenReader(ipaPath)
	if err != nil {
		return nil, fmt.Errorf("open IPA: %w", err)
	}
	defer func() { _ = zr.Close() }()

	absOutput, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, fmt.Errorf("resolve output dir: %w", err)
	}

	result := &ExtractResult{
		OutputDir: absOutput,
	}

	var (
		totalExtracted int64
		entryCount     int
	)

	var appPrefix string

	for _, f := range zr.File {
		entryCount++
		if entryCount > maxIPAEntries {
			return nil, fmt.Errorf("IPA entry count exceeds %d-entry cap (decompression bomb)", maxIPAEntries)
		}

		// Sanitize: reject absolute paths and path traversal
		if filepath.IsAbs(f.Name) || strings.Contains(f.Name, "..") {
			continue
		}

		destPath := filepath.Join(absOutput, filepath.FromSlash(f.Name))

		// Ensure the file stays within output directory (zip-slip prevention).
		// The trailing separator is required so that a sibling directory whose
		// name shares a prefix (e.g. "/tmp/out-evil") cannot pass the check.
		if !strings.HasPrefix(filepath.Clean(destPath), absOutput+string(os.PathSeparator)) {
			continue
		}

		// Skip symlink entries — a zip symlink can be used in a two-step
		// TOCTOU attack to redirect subsequent writes outside the dest dir.
		if f.Mode()&os.ModeSymlink != 0 {
			continue
		}

		// Track .app bundle
		if appPrefix == "" {
			parts := strings.SplitN(f.Name, "/", 3)
			if len(parts) >= 2 && strings.EqualFold(parts[0], "Payload") && strings.HasSuffix(parts[1], ".app") {
				appPrefix = parts[0] + "/" + parts[1]
				result.AppBundle = filepath.Join(absOutput, filepath.FromSlash(appPrefix))
			}
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return nil, fmt.Errorf("mkdir %s: %w", destPath, err)
			}
			continue
		}

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir parent for %s: %w", destPath, err)
		}

		written, err := extractZipFile(f, destPath)
		if err != nil {
			return nil, fmt.Errorf("extract %s: %w", f.Name, err)
		}

		totalExtracted += written
		if totalExtracted > maxIPATotalSize {
			return nil, fmt.Errorf("IPA total decompressed size exceeds %d-byte cap (decompression bomb)", maxIPATotalSize)
		}

		result.Files++
		result.TotalSize += written
	}

	// Try to find the main executable
	if appPrefix != "" {
		plistData, err := os.ReadFile(filepath.Join(absOutput, filepath.FromSlash(appPrefix), "Info.plist"))
		if err == nil {
			if plist, err := ParseXMLPlist(plistData); err == nil {
				if exec := plistString(plist, "CFBundleExecutable"); exec != "" {
					execPath := filepath.Join(absOutput, filepath.FromSlash(appPrefix), exec)
					if _, err := os.Stat(execPath); err == nil {
						result.Executable = execPath
					}
				}
			}
		}
	}

	return result, nil
}

// extractZipFile extracts a single zip entry to destPath.
// Returns the number of bytes written.
func extractZipFile(f *zip.File, destPath string) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer func() { _ = rc.Close() }()

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode()|0o200)
	if err != nil {
		return 0, err
	}
	defer func() { _ = out.Close() }()

	// Cap each entry at 256 MiB; fail if the cap is hit (bomb indicator).
	n, err := io.Copy(out, io.LimitReader(rc, maxIPAPerFile))
	if err != nil {
		return n, err
	}
	if n == maxIPAPerFile {
		return n, fmt.Errorf("entry exceeds %d-byte per-file cap (decompression bomb)", maxIPAPerFile)
	}
	return n, nil
}
