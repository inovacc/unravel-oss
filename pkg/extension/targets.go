/*
Copyright © 2026 Security Research
*/
package extension

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/manifest"
	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// maxPerFileExt caps each extracted zip entry at 256 MiB to prevent
// decompression bombs. No real extension file is legitimately larger. A var
// (not a const) so tests can inject a small cap; a file exactly at the cap is
// accepted (only strictly-over-cap is a bomb).
var maxPerFileExt int64 = 256 << 20 // 256 MiB

// Aggregate extraction caps guard against multi-entry bombs (millions of tiny
// entries, or many near-per-file-cap entries) that fill disk/inodes while each
// individual entry stays under maxPerFileExt. Vars (not consts) so tests can
// inject small caps. Defaults are generous — real extensions are far smaller.
var (
	maxAggregateExtractBytes int64 = 2 << 30 // 2 GiB total across all entries
	maxExtractEntries        int   = 50_000  // entry-count ceiling (dirs + files)
)

type resolvedTarget struct {
	Path       string
	ID         string
	Browser    string
	Profile    string
	SourceType string
	Cleanup    func()
}

// ExtensionExtractResult holds extraction + analysis outputs for a single extension target.
type ExtensionExtractResult struct {
	Target       string         `json:"target"`
	SourceType   string         `json:"source_type"`
	OutputDir    string         `json:"output_dir"`
	FilesDir     string         `json:"files_dir"`
	FileCount    int            `json:"file_count"`
	AnalysisPath string         `json:"analysis_path"`
	ReportPath   string         `json:"report_path"`
	Analysis     *ExtensionInfo `json:"analysis"`
}

func resolveAnalysisTarget(target, filterBrowser string) (*resolvedTarget, error) {
	if fi, err := os.Stat(target); err == nil {
		if fi.IsDir() {
			return &resolvedTarget{
				Path:       target,
				ID:         filepath.Base(target),
				Browser:    "unknown",
				Profile:    "unknown",
				SourceType: "directory",
			}, nil
		}

		if isExtensionPackage(target) {
			return resolvePackageTarget(target)
		}

		return nil, fmt.Errorf("unsupported extension file target %q (expected .crx/.zip/.xpi)", target)
	}

	// Search by extension ID across browser profiles.
	profiles := DiscoverBrowsers(filterBrowser)
	for _, bp := range profiles {
		extPath := filepath.Join(bp.ExtDir, target)
		if _, err := os.Stat(extPath); err != nil {
			continue
		}

		return &resolvedTarget{
			Path:       extPath,
			ID:         target,
			Browser:    bp.Browser,
			Profile:    bp.Profile,
			SourceType: "installed_profile",
		}, nil
	}

	return nil, fmt.Errorf("extension %q not found in any browser profile", target)
}

func resolvePackageTarget(packagePath string) (*resolvedTarget, error) {
	tmpRoot, err := os.MkdirTemp("", "unravel_extpkg_")
	if err != nil {
		return nil, fmt.Errorf("create temp directory: %w", err)
	}

	baseName := strings.TrimSuffix(filepath.Base(packagePath), filepath.Ext(packagePath))
	if baseName == "" {
		baseName = "extension"
	}

	extRoot := filepath.Join(tmpRoot, baseName)

	versionDir := filepath.Join(extRoot, "1.0.0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		_ = os.RemoveAll(tmpRoot)
		return nil, fmt.Errorf("create extraction dir: %w", err)
	}

	if err := extractExtensionPackage(packagePath, versionDir); err != nil {
		_ = os.RemoveAll(tmpRoot)
		return nil, err
	}

	return &resolvedTarget{
		Path:       extRoot,
		ID:         baseName,
		Browser:    "unknown",
		Profile:    "unknown",
		SourceType: strings.TrimPrefix(strings.ToLower(filepath.Ext(packagePath)), "."),
		Cleanup: func() {
			_ = os.RemoveAll(tmpRoot)
		},
	}, nil
}

func isExtensionPackage(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".crx", ".zip", ".xpi":
		return true
	default:
		return false
	}
}

func extractExtensionPackage(packagePath, destDir string) error {
	ext := strings.ToLower(filepath.Ext(packagePath))
	switch ext {
	case ".crx":
		payload, err := readCRXPayload(packagePath)
		if err != nil {
			return err
		}

		return extractZIPBytes(payload, destDir)
	case ".zip", ".xpi":
		return extractZIPFile(packagePath, destDir)
	default:
		return fmt.Errorf("unsupported extension package %q", packagePath)
	}
}

func readCRXPayload(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CRX: %w", err)
	}

	if len(data) < 12 {
		return nil, fmt.Errorf("invalid CRX: header too small")
	}

	if string(data[:4]) != "Cr24" {
		return nil, fmt.Errorf("invalid CRX: missing Cr24 magic")
	}

	version := binary.LittleEndian.Uint32(data[4:8])

	// SEC: compute the payload offset in uint64. CRX2's 16+pubLen+sigLen sum is
	// done over attacker-controlled uint32s and wraps modulo 2^32 (e.g.
	// pubLen=0xFFFFFFF0, sigLen=0x20 -> 16), so a post-wrap `int(offset) >= len`
	// check passes and slices from mid-header. uint64 cannot overflow with these
	// addends.
	var offset uint64

	switch version {
	case 2:
		if len(data) < 16 {
			return nil, fmt.Errorf("invalid CRX2: header too small")
		}

		pubLen := binary.LittleEndian.Uint32(data[8:12])
		sigLen := binary.LittleEndian.Uint32(data[12:16])
		offset = 16 + uint64(pubLen) + uint64(sigLen)
	case 3:
		headerLen := binary.LittleEndian.Uint32(data[8:12])
		offset = 12 + uint64(headerLen)
	default:
		return nil, fmt.Errorf("unsupported CRX version %d", version)
	}

	if offset >= uint64(len(data)) {
		return nil, fmt.Errorf("invalid CRX payload offset")
	}

	payload := make([]byte, len(data)-int(offset))
	copy(payload, data[offset:])

	return payload, nil
}

func extractZIPFile(path, destDir string) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = zr.Close() }()

	return extractZIPEntries(zr.File, destDir)
}

func extractZIPBytes(data []byte, destDir string) error {
	reader := bytes.NewReader(data)

	zr, err := zip.NewReader(reader, int64(len(data)))
	if err != nil {
		return fmt.Errorf("parse zip payload: %w", err)
	}

	return extractZIPEntries(zr.File, destDir)
}

func extractZIPEntries(entries []*zip.File, destDir string) error {
	var totalWritten int64
	var entryCount int

	for _, entry := range entries {
		cleanName := filepath.Clean(entry.Name)
		if cleanName == "." || cleanName == "" {
			continue
		}

		if filepath.IsAbs(cleanName) || strings.HasPrefix(cleanName, "..") {
			continue
		}

		targetPath := filepath.Join(destDir, cleanName)

		rel, err := filepath.Rel(destDir, targetPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			continue
		}

		// SEC: count every materialized entry (dir or file) so a flood of tiny
		// entries cannot exhaust inodes/syscalls before any per-file cap fires.
		entryCount++
		if entryCount > maxExtractEntries {
			return fmt.Errorf("archive entry count exceeds %d (decompression bomb)", maxExtractEntries)
		}

		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("create dir %s: %w", targetPath, err)
			}

			continue
		}

		// Skip symlinks in archives.
		if entry.Mode()&os.ModeSymlink != 0 {
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return fmt.Errorf("create parent dir %s: %w", targetPath, err)
		}

		src, err := entry.Open()
		if err != nil {
			return fmt.Errorf("open archive file %s: %w", entry.Name, err)
		}

		dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			_ = src.Close()
			return fmt.Errorf("create target file %s: %w", targetPath, err)
		}

		// CopyLimit accepts an entry exactly at the cap and only ERRORS when an
		// entry strictly exceeds it, so a legitimate at-cap file is not falsely
		// rejected while a true bomb still aborts the extraction.
		n, copyErr := safeio.CopyLimit(dst, src, maxPerFileExt)
		closeErr := dst.Close()
		_ = src.Close()

		if copyErr != nil {
			if errors.Is(copyErr, safeio.ErrLimitExceeded) {
				return fmt.Errorf("write %s: entry exceeds %d-byte cap (decompression bomb): %w", targetPath, maxPerFileExt, copyErr)
			}
			return fmt.Errorf("write %s: %w", targetPath, copyErr)
		}

		if closeErr != nil {
			return fmt.Errorf("close %s: %w", targetPath, closeErr)
		}

		// SEC: accumulate the actual bytes written and stop once the aggregate
		// across all entries exceeds the budget, so many sub-cap entries cannot
		// sum to a disk-filling total.
		totalWritten += n
		if totalWritten > maxAggregateExtractBytes {
			return fmt.Errorf("aggregate extraction exceeds %d bytes (decompression bomb)", maxAggregateExtractBytes)
		}
	}

	return nil
}

// ExtractExtensionData extracts extension files and writes an analysis snapshot.
func ExtractExtensionData(m *manifest.Manifest, target, filterBrowser, outputDir string, verbose bool) (*ExtensionExtractResult, error) {
	if outputDir == "" {
		return nil, fmt.Errorf("output directory is required")
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	resolved, err := resolveAnalysisTarget(target, filterBrowser)
	if err != nil {
		return nil, err
	}

	if resolved.Cleanup != nil {
		defer resolved.Cleanup()
	}

	info, err := ParseExtension(resolved.Path, resolved.ID, resolved.Browser, resolved.Profile)
	if err != nil {
		return nil, err
	}

	info.SourceType = resolved.SourceType
	analyzeExtensionFull(info, m, verbose)

	filesDir := filepath.Join(outputDir, "files")
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		return nil, fmt.Errorf("create files output directory: %w", err)
	}

	if err := copyExtensionDir(info.Path, filesDir); err != nil {
		return nil, fmt.Errorf("copy extension files: %w", err)
	}

	analysisPath := filepath.Join(outputDir, "analysis.json")

	analysisJSON, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal analysis JSON: %w", err)
	}

	if err := os.WriteFile(analysisPath, analysisJSON, 0o644); err != nil {
		return nil, fmt.Errorf("write analysis JSON: %w", err)
	}

	generateReport(info, outputDir, 0)
	reportPath := filepath.Join(outputDir, "REPORT.md")

	return &ExtensionExtractResult{
		Target:       target,
		SourceType:   resolved.SourceType,
		OutputDir:    outputDir,
		FilesDir:     filesDir,
		FileCount:    info.FileStats.TotalFiles,
		AnalysisPath: analysisPath,
		ReportPath:   reportPath,
		Analysis:     info,
	}, nil
}
