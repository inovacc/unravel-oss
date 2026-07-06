/*
Copyright (c) 2026 Security Research
*/
package upx

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// InfoResult holds UPX packing information for a binary.
type InfoResult struct {
	Version      string  `json:"version,omitempty"`
	Format       string  `json:"format"`
	Ratio        float64 `json:"ratio"`
	PackedSize   int64   `json:"packed_size"`
	OriginalSize int64   `json:"original_size"`
	Method       string  `json:"method,omitempty"`
}

// IsAvailable returns true if the upx binary is in PATH.
func IsAvailable() bool {
	_, err := exec.LookPath("upx")
	return err == nil
}

// Info runs `upx -l` on the given binary and parses the tabular output.
func Info(path string) (*InfoResult, error) {
	out, err := exec.Command("upx", "-l", path).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("upx -l: %w\n%s", err, string(out))
	}

	return parseInfo(string(out))
}

// Unpack runs `upx -d` to decompress a UPX-packed binary to outputPath.
func Unpack(path, outputPath string) error {
	// W5: ensure outputPath is absolute so it cannot start with "-" and be
	// misinterpreted by upx as a flag (e.g. "-o-p" triggering a password
	// option). filepath.Abs resolves relative paths against the cwd, which
	// always starts with a volume/separator, never with "-".
	absOut, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("upx: resolve output path: %w", err)
	}
	outputPath = absOut

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	out, err := exec.Command("upx", "-d", "-o", outputPath, path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("upx -d: %w\n%s", err, string(out))
	}

	return nil
}

// HasUPXMarker reads the last 4KB of a file looking for the "UPX!" marker.
func HasUPXMarker(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || info.Size() < 512 {
		return false
	}

	// Read last 4KB where UPX stores its metadata
	readSize := min(info.Size(), int64(4096))

	buf := make([]byte, readSize)
	_, err = f.ReadAt(buf, info.Size()-readSize)
	if err != nil {
		return false
	}

	// Search for "UPX!" marker
	marker := []byte("UPX!")
	for i := 0; i <= len(buf)-4; i++ {
		if buf[i] == marker[0] && buf[i+1] == marker[1] && buf[i+2] == marker[2] && buf[i+3] == marker[3] {
			return true
		}
	}

	return false
}

// parseInfo parses the tabular output of `upx -l`.
// Example output:
//
//	                    Ultimate Packer for eXecutables
//	                       Copyright (C) ...
//	     File size         Ratio      Format      Name
//	--------------------   ------   -----------   -----------
//	 123456 ->     65432   53.01%   linux/amd64   mybinary
//	--------------------   ------   -----------   -----------
func parseInfo(output string) (*InfoResult, error) {
	result := &InfoResult{}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for the data line: original -> packed ratio format name
		if strings.Contains(line, "->") && strings.Contains(line, "%") {
			parts := strings.Fields(line)
			if len(parts) < 5 {
				continue
			}

			// Parse: original -> packed ratio% format name
			orig, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				continue
			}
			result.OriginalSize = orig

			packed, err := strconv.ParseInt(parts[2], 10, 64)
			if err != nil {
				continue
			}
			result.PackedSize = packed

			ratioStr := strings.TrimSuffix(parts[3], "%")
			ratio, err := strconv.ParseFloat(ratioStr, 64)
			if err == nil {
				result.Ratio = ratio
			}

			result.Format = parts[4]

			return result, nil
		}

		// Extract UPX version from header
		if strings.Contains(line, "Ultimate Packer for eXecutables") {
			// Version might be on next line or embedded
			continue
		}
	}

	if result.Format == "" {
		return nil, fmt.Errorf("could not parse upx output")
	}

	return result, nil
}
