/*
Copyright (c) 2026 Security Research
*/
package advinstaller

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

// advInstallerMarkers are strings commonly found in Advanced Installer bootstrappers.
var advInstallerMarkers = []string{
	"Advanced Installer",
	"advancedinstaller.com",
	"Caphyon",
	"ai_bootstrapper",
	"AIDLG_",
	"AiSetupExe",
	"SetupMain",
	"LaunchAiPackage",
	"AI_SETUP",
	"AI_INSTALL",
}

// BootstrapperInfo holds analysis results for a potential Advanced Installer bootstrapper.
type BootstrapperInfo struct {
	Path           string   `json:"path"`
	Size           int64    `json:"size"`
	IsAdvInstaller bool     `json:"is_advanced_installer"`
	Markers        []string `json:"markers,omitempty"`
	HasEmbeddedMSI bool     `json:"has_embedded_msi"`
	MSIOffset      int64    `json:"msi_offset,omitempty"`
	MSISize        int64    `json:"msi_size,omitempty"`
}

// Info analyzes a file to determine if it is an Advanced Installer bootstrapper
// and whether it contains an embedded MSI package.
func Info(path string) (*BootstrapperInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	result := &BootstrapperInfo{
		Path: path,
		Size: info.Size(),
	}

	// Read up to 2 MB for marker detection.
	const maxRead = 2 * 1024 * 1024
	data, err := readHead(path, maxRead)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	// Check for PE magic (MZ header).
	if len(data) < 2 || data[0] != 'M' || data[1] != 'Z' {
		return result, nil // Not a PE file.
	}

	// Scan for Advanced Installer markers.
	lower := strings.ToLower(string(data))
	for _, marker := range advInstallerMarkers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			result.Markers = append(result.Markers, marker)
		}
	}
	result.IsAdvInstaller = len(result.Markers) > 0

	// Scan for embedded MSI (CFBF magic).
	const minScanOffset int64 = 100 * 1024
	off, err := findMagicOffset(path, cfbfMagic, minScanOffset)
	if err == nil && off >= minScanOffset {
		result.HasEmbeddedMSI = true
		result.MSIOffset = off
		result.MSISize = info.Size() - off
	}

	// If no CFBF found, try CAB.
	if !result.HasEmbeddedMSI {
		cabOff, cabErr := findMagicOffset(path, cabMagic, minScanOffset)
		if cabErr == nil && cabOff >= minScanOffset {
			result.HasEmbeddedMSI = true
			result.MSIOffset = cabOff
			result.MSISize = info.Size() - cabOff
		}
	}

	return result, nil
}

// readHead reads up to maxBytes from the beginning of a file.
func readHead(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := min(info.Size(), maxBytes)

	buf := bytes.NewBuffer(make([]byte, 0, size))
	_, err = io.CopyN(buf, f, size)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf.Bytes(), nil
}
