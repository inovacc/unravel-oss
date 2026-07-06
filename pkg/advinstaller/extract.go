/*
Copyright (c) 2026 Security Research
*/
package advinstaller

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// cfbfMagic is the OLE/CFBF compound document magic (MSI files).
var cfbfMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// cabMagic is the Microsoft Cabinet magic ("MSCF").
var cabMagic = []byte{0x4D, 0x53, 0x43, 0x46}

// ExtractResult holds the outcome of an MSI extraction attempt.
type ExtractResult struct {
	BootstrapperPath string `json:"bootstrapper_path"`
	MSIPath          string `json:"msi_path,omitempty"`
	MSISize          int64  `json:"msi_size,omitempty"`
	Method           string `json:"method"` // "overlay", "resource", "cab"
	Error            string `json:"error,omitempty"`
}

// ExtractMSI extracts the embedded MSI from an Advanced Installer bootstrapper.
// It tries multiple strategies: PE overlay (CFBF magic after last section),
// full-file CFBF scan, and CAB scan.
func ExtractMSI(bootstrapperPath, outputDir string) (*ExtractResult, error) {
	result := &ExtractResult{
		BootstrapperPath: bootstrapperPath,
	}

	info, err := os.Stat(bootstrapperPath)
	if err != nil {
		return nil, fmt.Errorf("stat bootstrapper: %w", err)
	}
	fileSize := info.Size()

	// Try overlay method first: parse PE to find end of last section.
	overlayStart, peErr := peOverlayOffset(bootstrapperPath)
	if peErr == nil && overlayStart > 0 && overlayStart < fileSize {
		off, findErr := findMagicOffset(bootstrapperPath, cfbfMagic, overlayStart)
		if findErr == nil && off >= overlayStart {
			outPath, sz, writeErr := writePayload(bootstrapperPath, off, outputDir)
			if writeErr == nil {
				result.MSIPath = outPath
				result.MSISize = sz
				result.Method = "overlay"
				return result, nil
			}
		}
	}

	// Fallback: scan entire file for CFBF magic starting from 100KB offset.
	const minScanOffset int64 = 100 * 1024
	off, err := findMagicOffset(bootstrapperPath, cfbfMagic, minScanOffset)
	if err == nil && off >= minScanOffset {
		outPath, sz, writeErr := writePayload(bootstrapperPath, off, outputDir)
		if writeErr == nil {
			result.MSIPath = outPath
			result.MSISize = sz
			result.Method = "resource"
			return result, nil
		}
	}

	// CAB method: scan for MSCF magic.
	cabOff, err := findMagicOffset(bootstrapperPath, cabMagic, minScanOffset)
	if err == nil && cabOff >= minScanOffset {
		outPath, sz, writeErr := writePayload(bootstrapperPath, cabOff, outputDir)
		if writeErr == nil {
			// Rename extension to .cab since it's a cabinet.
			cabPath := strings.TrimSuffix(outPath, filepath.Ext(outPath)) + ".cab"
			if renameErr := os.Rename(outPath, cabPath); renameErr == nil {
				outPath = cabPath
			}
			result.MSIPath = outPath
			result.MSISize = sz
			result.Method = "cab"
			return result, nil
		}
	}

	result.Error = "no embedded MSI or CAB found"
	return result, fmt.Errorf("no embedded MSI or CAB found in %s", bootstrapperPath)
}

// peOverlayOffset returns the file offset where the PE overlay begins
// (immediately after the last section's raw data).
func peOverlayOffset(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	peFile, err := pe.NewFile(f)
	if err != nil {
		return 0, fmt.Errorf("parse PE: %w", err)
	}
	defer func() { _ = peFile.Close() }()

	var maxEnd int64
	for _, sec := range peFile.Sections {
		end := int64(sec.Offset) + int64(sec.Size)
		if end > maxEnd {
			maxEnd = end
		}
	}
	if maxEnd == 0 {
		return 0, fmt.Errorf("no PE sections found")
	}
	return maxEnd, nil
}

// findMagicOffset searches for a byte pattern in a file starting from minOffset.
// It reads the file in chunks and returns the absolute file offset of the first match.
func findMagicOffset(path string, magic []byte, minOffset int64) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	fileSize := info.Size()

	if minOffset >= fileSize {
		return 0, fmt.Errorf("minOffset %d exceeds file size %d", minOffset, fileSize)
	}

	const chunkSize = 1024 * 1024 // 1 MB chunks
	overlap := int64(len(magic) - 1)
	buf := make([]byte, chunkSize)
	pos := minOffset

	for pos < fileSize {
		readSize := int64(chunkSize)
		if pos+readSize > fileSize {
			readSize = fileSize - pos
		}

		n, err := f.ReadAt(buf[:readSize], pos)
		if err != nil && err != io.EOF {
			return 0, fmt.Errorf("read at offset %d: %w", pos, err)
		}
		if n == 0 {
			break
		}

		idx := bytes.Index(buf[:n], magic)
		if idx >= 0 {
			return pos + int64(idx), nil
		}

		// Advance past chunk but keep overlap to catch magic spanning chunk boundary.
		advance := int64(n) - overlap
		if advance <= 0 {
			break
		}
		pos += advance
	}

	return 0, fmt.Errorf("magic bytes not found starting from offset %d", minOffset)
}

// writePayload copies bytes from offset to EOF into outputDir/<basename>.msi.
func writePayload(srcPath string, offset int64, outputDir string) (string, int64, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", 0, fmt.Errorf("create output dir: %w", err)
	}

	base := filepath.Base(srcPath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	outPath := filepath.Join(outputDir, name+".msi")

	src, err := os.Open(srcPath)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = src.Close() }()

	if _, err := src.Seek(offset, io.SeekStart); err != nil {
		return "", 0, fmt.Errorf("seek to offset %d: %w", offset, err)
	}

	dst, err := os.Create(outPath)
	if err != nil {
		return "", 0, fmt.Errorf("create output file: %w", err)
	}
	defer func() { _ = dst.Close() }()

	written, err := io.Copy(dst, src)
	if err != nil {
		return "", 0, fmt.Errorf("copy payload: %w", err)
	}

	return outPath, written, nil
}
