/*
Copyright (c) 2026 Security Research
*/
package nsis

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// nsisMagic is the NSIS archive magic value (0xDEADBEEF in little-endian).
const nsisMagic uint32 = 0xDEADBEEF

// nullsoftMarker is a string marker found in NSIS installers.
const nullsoftMarker = "NullsoftInst"

// overlaySearchLimit is the maximum number of bytes to scan in the overlay for magic.
const overlaySearchLimit = 512 * 1024

// InfoResult contains metadata about an NSIS installer.
type InfoResult struct {
	Path         string   `json:"path"`
	FileName     string   `json:"file_name"`
	Size         int64    `json:"size"`
	NSISVersion  string   `json:"nsis_version,omitempty"`
	Compression  string   `json:"compression,omitempty"`
	IsSolid      bool     `json:"is_solid"`
	HasUninstall bool     `json:"has_uninstall"`
	ScriptSize   int64    `json:"script_size,omitempty"`
	HeaderSize   int64    `json:"header_size,omitempty"`
	DataSize     int64    `json:"data_size,omitempty"`
	FileCount    int      `json:"file_count,omitempty"`
	Strings      []string `json:"strings,omitempty"`
}

// ExtractReport summarizes an NSIS extraction.
type ExtractReport struct {
	Source      string   `json:"source"`
	Output      string   `json:"output"`
	Files       int      `json:"files"`
	Directories int      `json:"directories"`
	TotalSize   int64    `json:"total_size"`
	Errors      []string `json:"errors,omitempty"`
}

// IsNSIS performs a quick check to determine if the file at path is an NSIS installer.
// It reads the PE file, finds the overlay after PE sections, and looks for
// NSIS magic bytes (0xDEADBEEF) or the "NullsoftInst" string.
func IsNSIS(path string) bool {
	offset, err := findOverlayOffset(path)
	if err != nil || offset <= 0 {
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil || offset >= stat.Size() {
		return false
	}

	// Read up to overlaySearchLimit bytes from the overlay
	remaining := stat.Size() - offset
	readSize := min(remaining, overlaySearchLimit)

	buf := make([]byte, readSize)
	if _, err := f.ReadAt(buf, offset); err != nil {
		return false
	}

	// Look for 0xDEADBEEF magic in the overlay
	// NSIS header: flags(4) + magic(4), so magic at offset+4 relative to overlay chunks
	for i := 0; i+8 <= len(buf); i += 4 {
		val := binary.LittleEndian.Uint32(buf[i : i+4])
		if val == nsisMagic {
			return true
		}
	}

	// Fallback: look for "NullsoftInst" string in first 8KB
	searchLen := min(len(buf), 8192)

	return bytes.Contains(buf[:searchLen], []byte(nullsoftMarker))
}

// Info parses the NSIS header from the PE overlay and returns installer metadata.
func Info(path string) (*InfoResult, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	stat, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	overlayOff, err := findOverlayOffset(absPath)
	if err != nil {
		return nil, fmt.Errorf("find overlay: %w", err)
	}

	if overlayOff <= 0 || overlayOff >= stat.Size() {
		return nil, fmt.Errorf("no overlay data found (PE ends at %d, file size %d)", overlayOff, stat.Size())
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	// Read overlay data
	remaining := stat.Size() - overlayOff
	readSize := min(remaining, overlaySearchLimit)

	buf := make([]byte, readSize)
	if _, err := f.ReadAt(buf, overlayOff); err != nil {
		return nil, fmt.Errorf("read overlay: %w", err)
	}

	result := &InfoResult{
		Path:     absPath,
		FileName: filepath.Base(absPath),
		Size:     stat.Size(),
		DataSize: remaining,
	}

	// Find the NSIS magic in overlay
	magicOffset := -1
	for i := 0; i+8 <= len(buf); i += 4 {
		val := binary.LittleEndian.Uint32(buf[i : i+4])
		if val == nsisMagic {
			magicOffset = i
			break
		}
	}

	if magicOffset >= 4 {
		// The 4 bytes before magic are flags
		flags := binary.LittleEndian.Uint32(buf[magicOffset-4 : magicOffset])

		// Parse compression type from flags bits 0-3
		compType := flags & 0x0F
		switch compType {
		case 0:
			result.Compression = "zlib"
		case 1:
			result.Compression = "bzip2"
		case 2:
			result.Compression = "lzma"
		default:
			result.Compression = fmt.Sprintf("unknown(%d)", compType)
		}

		// Bit 4 = solid mode
		result.IsSolid = (flags & 0x10) != 0

		// Read header size and data size after magic (offsets +4 and +8 from magic)
		if magicOffset+12 <= len(buf) {
			result.HeaderSize = int64(binary.LittleEndian.Uint32(buf[magicOffset+4 : magicOffset+8]))
			result.ScriptSize = int64(binary.LittleEndian.Uint32(buf[magicOffset+8 : magicOffset+12]))
		}

		// Determine NSIS version heuristic
		if magicOffset >= 12 {
			result.NSISVersion = "NSIS 2.x"
		}
		if result.Compression == "lzma" || result.IsSolid {
			result.NSISVersion = "NSIS 3.x"
		}
	} else if bytes.Contains(buf, []byte(nullsoftMarker)) {
		result.NSISVersion = "NSIS (version unknown)"
	} else {
		return nil, fmt.Errorf("NSIS magic not found in overlay")
	}

	// Check for uninstaller string
	result.HasUninstall = bytes.Contains(buf, []byte("uninstall")) ||
		bytes.Contains(buf, []byte("Uninstall"))

	// Extract notable strings from header area
	result.Strings = extractNotableStrings(buf)

	return result, nil
}

// Extract extracts the NSIS installer contents using 7z.
func Extract(path, outputDir string) (*ExtractReport, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	if !Is7zAvailable() {
		return nil, fmt.Errorf("7z not found in PATH; install p7zip-full to extract NSIS installers")
	}

	if outputDir == "" {
		base := filepath.Base(absPath)
		outputDir = strings.TrimSuffix(base, filepath.Ext(base)) + "_extracted"
	}

	// W5: ensure outputDir is absolute so the "-o<dir>" flag passed to 7z
	// cannot start with "-" and be misinterpreted as a 7z option (e.g. "-p"
	// for password). A relative dir whose first char is "-" (after base-name
	// stripping) would produce "-o-p evil" which 7z parses as a password flag.
	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, fmt.Errorf("resolve output dir: %w", err)
	}
	outputDir = absOutputDir

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	report := &ExtractReport{
		Source: absPath,
		Output: outputDir,
	}

	// Run 7z extraction. The output path is always absolute (validated above),
	// so the "-o<dir>" concatenation cannot inject a 7z flag.
	cmd := exec.Command("7z", "x", "-y", "-o"+outputDir, absPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("7z: %v: %s", err, string(output)))
		return report, fmt.Errorf("7z extraction failed: %w", err)
	}

	// Walk output directory to count results
	_ = filepath.Walk(outputDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("walk: %v", err))
			return nil
		}

		if info.IsDir() {
			report.Directories++
		} else {
			report.Files++
			report.TotalSize += info.Size()
		}

		return nil
	})

	// Subtract the output dir itself from directory count
	if report.Directories > 0 {
		report.Directories--
	}

	return report, nil
}

// Is7zAvailable checks if 7z is available in PATH.
func Is7zAvailable() bool {
	_, err := exec.LookPath("7z")
	return err == nil
}

// findOverlayOffset opens the file as PE and finds the end of all PE sections,
// which is where the overlay (NSIS archive) starts.
func findOverlayOffset(path string) (int64, error) {
	peFile, err := pe.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open PE: %w", err)
	}

	defer func() { _ = peFile.Close() }()

	var maxEnd int64

	for _, sec := range peFile.Sections {
		end := int64(sec.Offset) + int64(sec.Size)
		if end > maxEnd {
			maxEnd = end
		}
	}

	return maxEnd, nil
}

// extractNotableStrings scans a byte buffer for printable ASCII strings that look
// interesting for NSIS analysis (paths, registry keys, URLs, DLL names).
func extractNotableStrings(buf []byte) []string {
	var (
		result  []string
		current []byte
		seen    = make(map[string]bool)
	)

	flush := func() {
		if len(current) >= 8 {
			s := string(current)
			if isNotableString(s) && !seen[s] {
				seen[s] = true
				result = append(result, s)
			}
		}

		current = current[:0]
	}

	for _, b := range buf {
		if b >= 0x20 && b < 0x7f {
			current = append(current, b)
		} else {
			flush()
		}
	}

	flush()

	// Limit output
	if len(result) > 50 {
		result = result[:50]
	}

	return result
}

// isNotableString checks if a string is worth reporting.
func isNotableString(s string) bool {
	lower := strings.ToLower(s)

	// Paths
	if strings.Contains(s, "\\") || strings.Contains(s, "/") {
		return true
	}

	// Registry keys
	if strings.HasPrefix(lower, "hkey_") || strings.Contains(lower, "software\\") {
		return true
	}

	// URLs
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return true
	}

	// DLLs and executables
	if strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".exe") {
		return true
	}

	// NSIS-specific
	markers := []string{"$instdir", "$outdir", "$pluginsdir", "uninstall", "nsisdl", "nsexec"}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}

	return false
}
