/*
Copyright (c) 2026 Security Research
*/
package winsvc

import (
	"bufio"
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DriverInfo describes a Windows kernel driver.
type DriverInfo struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	INFFile     string `json:"inf_file,omitempty"`
	Class       string `json:"class,omitempty"`
	Provider    string `json:"provider,omitempty"`
	CatalogFile string `json:"catalog_file,omitempty"`
	IsWFP       bool   `json:"is_wfp"`
	IsSigned    bool   `json:"is_signed"`
}

// AnalyzeDriver examines a .sys file and its companion .inf if present.
func AnalyzeDriver(sysPath string) (*DriverInfo, error) {
	absPath, err := filepath.Abs(sysPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat driver: %w", err)
	}

	di := &DriverInfo{
		Path: absPath,
		Name: strings.TrimSuffix(filepath.Base(absPath), filepath.Ext(absPath)),
		Size: info.Size(),
	}

	// Check for Authenticode signature by inspecting PE security directory.
	di.IsSigned = hasPESignature(absPath)

	// Look for companion .inf file.
	dir := filepath.Dir(absPath)
	baseName := di.Name

	// Try exact match first, then glob all .inf files in the directory.
	candidates := []string{
		filepath.Join(dir, baseName+".inf"),
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "*.inf"))
	candidates = append(candidates, matches...)

	for _, infPath := range candidates {
		if _, statErr := os.Stat(infPath); statErr == nil {
			if parseINF(infPath, di) {
				break
			}
		}
	}

	// Determine WFP status from class.
	classLower := strings.ToLower(di.Class)
	if strings.Contains(classLower, "wfpcallout") ||
		strings.Contains(classLower, "netservice") ||
		strings.Contains(classLower, "wfp_callout") {
		di.IsWFP = true
	}

	return di, nil
}

// hasPESignature checks whether a PE file has an Authenticode signature
// by examining the security data directory entry.
func hasPESignature(path string) bool {
	peFile, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = peFile.Close() }()

	// Security directory is index 4 in the data directory.
	const imageDirectoryEntrySecurity = 4

	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if int(opt.NumberOfRvaAndSizes) <= imageDirectoryEntrySecurity {
			return false
		}
		return opt.DataDirectory[imageDirectoryEntrySecurity].Size > 0
	case *pe.OptionalHeader64:
		if int(opt.NumberOfRvaAndSizes) <= imageDirectoryEntrySecurity {
			return false
		}
		return opt.DataDirectory[imageDirectoryEntrySecurity].Size > 0
	default:
		return false
	}
}

// parseINF reads an INF file and populates driver info fields.
// Returns true if the INF was successfully parsed and contained relevant data.
func parseINF(infPath string, di *DriverInfo) bool {
	f, err := os.Open(infPath)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	found := false
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse key=value pairs (INF format).
		before, after, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key := strings.TrimSpace(before)
		value := strings.TrimSpace(after)

		// Remove surrounding quotes.
		value = strings.Trim(value, `"`)

		// Remove inline comments.
		if semiIdx := strings.Index(value, ";"); semiIdx >= 0 {
			value = strings.TrimSpace(value[:semiIdx])
		}

		switch strings.ToLower(key) {
		case "class":
			di.Class = value
			found = true
		case "provider":
			// INF providers often have %strtoken% — strip the percent signs.
			di.Provider = strings.Trim(value, "%")
			found = true
		case "catalogfile":
			di.CatalogFile = value
			found = true
		}
	}

	if found {
		di.INFFile = infPath
	}

	return found
}

// FindDrivers scans a directory for .sys files and analyzes each one.
func FindDrivers(dirPath string) ([]DriverInfo, error) {
	absDir, err := filepath.Abs(dirPath)
	if err != nil {
		return nil, fmt.Errorf("resolve dir: %w", err)
	}

	var drivers []DriverInfo

	err = filepath.Walk(absDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		if strings.EqualFold(filepath.Ext(path), ".sys") {
			di, analyzeErr := AnalyzeDriver(path)
			if analyzeErr == nil {
				drivers = append(drivers, *di)
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	return drivers, nil
}
