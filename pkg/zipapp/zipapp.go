/*
Copyright (c) 2026 Security Research

Package zipapp implements detection and extraction of Python zipapp executables.

A Python zipapp is a ZIP archive (optionally prepended with a PE stub or
shebang line) containing a __main__.py entry point. The format is commonly
used by pip/pipx to create standalone CLI wrappers.

Detection: PE stub + embedded ZIP with __main__.py, or a file starting with
#! shebang and containing a ZIP.
*/
package zipapp

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ZipApp holds analysis results for a Python zipapp.
type ZipApp struct {
	Path       string     `json:"path"`
	Name       string     `json:"name"`
	Size       int64      `json:"size"`
	IsZipApp   bool       `json:"is_zipapp"`
	HasPEStub  bool       `json:"has_pe_stub,omitempty"`
	HasShebang bool       `json:"has_shebang,omitempty"`
	Shebang    string     `json:"shebang,omitempty"`
	MainPy     string     `json:"main_py,omitempty"`
	FileCount  int        `json:"file_count"`
	Files      []ZipEntry `json:"files,omitempty"`
	TotalSize  int64      `json:"total_uncompressed_size"`
	ZipOffset  int64      `json:"zip_offset"`
}

// ZipEntry represents a file inside the zipapp.
type ZipEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// IsZipAppBinary checks if a file is a Python zipapp.
func IsZipAppBinary(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	zipOff := findZipStart(data)
	if zipOff < 0 {
		return false, nil
	}

	r, err := zip.NewReader(bytes.NewReader(data[zipOff:]), int64(len(data)-zipOff))
	if err != nil {
		return false, nil
	}

	for _, f := range r.File {
		if f.Name == "__main__.py" {
			return true, nil
		}
	}

	return false, nil
}

// maxZipAppFileSize caps the binary loaded into memory at 256 MiB.
// A Python zipapp stub + embedded ZIP is never legitimately larger.
const maxZipAppFileSize = 256 << 20 // 256 MiB

// Analyze reads a zipapp and extracts metadata.
func Analyze(path string) (*ZipApp, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if stat.Size() > maxZipAppFileSize {
		return nil, fmt.Errorf("zipapp %s too large (%d bytes > %d-byte cap)", path, stat.Size(), maxZipAppFileSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	result := &ZipApp{
		Path: path,
		Name: filepath.Base(path),
		Size: stat.Size(),
	}

	// Check for PE stub
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		result.HasPEStub = true
	}

	// Check for shebang
	if len(data) >= 2 && data[0] == '#' && data[1] == '!' {
		result.HasShebang = true
		end := bytes.IndexByte(data, '\n')
		if end > 0 && end < 256 {
			result.Shebang = strings.TrimSpace(string(data[2:end]))
		}
	}

	zipOff := findZipStart(data)
	if zipOff < 0 {
		return result, nil
	}

	result.ZipOffset = int64(zipOff)

	r, err := zip.NewReader(bytes.NewReader(data[zipOff:]), int64(len(data)-zipOff))
	if err != nil {
		return result, nil
	}

	for _, f := range r.File {
		result.Files = append(result.Files, ZipEntry{
			Path: f.Name,
			Size: int64(f.UncompressedSize64),
		})
		result.TotalSize += int64(f.UncompressedSize64)

		if f.Name == "__main__.py" {
			result.IsZipApp = true
			// Read __main__.py content
			rc, err := f.Open()
			if err == nil {
				content, _ := io.ReadAll(rc)
				_ = rc.Close()
				result.MainPy = string(content)
			}
		}
	}

	result.FileCount = len(result.Files)

	return result, nil
}

// Extract extracts all files from a zipapp.
func Extract(path string, outputDir string, verbose bool) (*ZipApp, error) {
	result, err := Analyze(path)
	if err != nil {
		return nil, err
	}

	if !result.IsZipApp {
		return nil, fmt.Errorf("%s is not a Python zipapp", path)
	}

	// TODO: switch to zip.OpenReader streaming to avoid loading the whole archive into RAM.
	// This is left as-is because the zip offset detection (findZipStart) requires a []byte
	// slice view; refactoring to an io.ReaderAt + offset seek is non-trivial and out of scope here.
	// Analyze already enforces the file-size cap via stat; re-stat defensively in case the
	// file was replaced between the two calls.
	if fi, err2 := os.Stat(path); err2 == nil && fi.Size() > maxZipAppFileSize {
		return nil, fmt.Errorf("zipapp %s too large (%d bytes > %d-byte cap)", path, fi.Size(), maxZipAppFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}

	zipOff := findZipStart(data)
	r, err := zip.NewReader(bytes.NewReader(data[zipOff:]), int64(len(data)-zipOff))
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}

	const maxExtractedFileBytes = 512 << 20 // 512 MiB per-file cap

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		// Zip-slip guard: reject absolute paths and path traversal.
		if filepath.IsAbs(f.Name) {
			continue
		}
		outPath := filepath.Join(outputDir, filepath.FromSlash(f.Name))
		rel, relErr := filepath.Rel(outputDir, outPath)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			continue
		}

		dir := filepath.Dir(outPath)

		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		content, err := io.ReadAll(io.LimitReader(rc, maxExtractedFileBytes))
		_ = rc.Close()
		if err != nil {
			continue
		}

		if err := os.WriteFile(outPath, content, 0o644); err != nil {
			continue
		}

		if verbose {
			fmt.Printf("  %-50s %8d bytes\n", f.Name, len(content))
		}
	}

	// Write metadata
	meta, _ := json.MarshalIndent(result, "", "  ")
	metaPath := filepath.Join(outputDir, "UNRAVEL_META.json")
	_ = os.WriteFile(metaPath, meta, 0o644)

	return result, nil
}

func findZipStart(data []byte) int {
	// ZIP local file header signature
	sig := []byte{'P', 'K', 0x03, 0x04}
	return bytes.Index(data, sig)
}
