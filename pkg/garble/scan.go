/*
Copyright © 2026 Security Research
*/
package garble

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ScanResult holds the results of scanning a directory for garbled Go binaries.
type ScanResult struct {
	Directory     string             `json:"directory"`
	TotalFiles    int                `json:"total_files"`
	GoBinaryCount int                `json:"go_binary_count"`
	GarbledCount  int                `json:"garbled_count"`
	Results       []*DetectionResult `json:"results"`
}

// ScanDirectory walks a directory, identifies Go binaries, and runs garble detection on each.
func ScanDirectory(dirPath string, verbose bool) (*ScanResult, error) {
	absDir, err := filepath.Abs(dirPath)
	if err != nil {
		absDir = dirPath
	}

	result := &ScanResult{
		Directory: absDir,
	}

	err = filepath.Walk(dirPath, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		if fi.IsDir() {
			return nil
		}

		result.TotalFiles++

		if !isScanCandidate(fi.Name(), path) {
			return nil
		}

		if !isGoBinary(path) {
			if verbose {
				fmt.Printf("  [SKIP] %s (not a Go binary)\n", path)
			}

			return nil
		}

		result.GoBinaryCount++

		if verbose {
			fmt.Printf("  [SCAN] %s\n", path)
		}

		detection, detectErr := Detect(path)
		if detectErr != nil {
			if verbose {
				fmt.Printf("  [ERROR] %s: %v\n", path, detectErr)
			}

			return nil
		}

		result.Results = append(result.Results, detection)
		if detection.IsGarbled {
			result.GarbledCount++
		}

		return nil
	})

	return result, err
}

// isGoBinary checks if a file is a Go binary by looking for Go-specific sections.
func isGoBinary(binPath string) bool {
	format, err := detectFileFormat(binPath)
	if err != nil {
		return false
	}

	switch format {
	case FormatELF:
		return isGoELF(binPath)
	case FormatPE:
		return isGoPE(binPath)
	case FormatMachO:
		return isGoMachO(binPath)
	}

	return false
}

func isGoELF(binPath string) bool {
	f, err := elf.Open(binPath)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	// Check for Go-specific sections
	goSections := []string{".gopclntab", ".go.buildinfo", ".note.go.buildid", ".gosymtab", ".noptrdata"}
	for _, name := range goSections {
		if sect := f.Section(name); sect != nil {
			return true
		}
	}

	// Check symbols for Go runtime
	syms, _ := f.Symbols()
	for _, s := range syms {
		if strings.HasPrefix(s.Name, "runtime.") || strings.HasPrefix(s.Name, "go.") {
			return true
		}
	}

	return false
}

func isGoPE(binPath string) bool {
	f, err := pe.Open(binPath)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	// Check for Go-specific PE sections
	for _, sect := range f.Sections {
		switch sect.Name {
		case ".symtab", ".go.buildinfo":
			return true
		}
	}

	// Check COFF symbols for Go runtime
	if f.Symbols != nil {
		for _, s := range f.Symbols {
			if strings.HasPrefix(s.Name, "runtime.") || strings.HasPrefix(s.Name, "go.") {
				return true
			}
		}
	}

	return false
}

func isGoMachO(binPath string) bool {
	f, err := macho.Open(binPath)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	// Check for Go-specific sections
	if sect := f.Section("__go_buildinfo"); sect != nil {
		return true
	}

	if sect := f.Section("__gopclntab"); sect != nil {
		return true
	}

	// Check symbols for Go runtime
	if f.Symtab != nil {
		for _, s := range f.Symtab.Syms {
			if strings.HasPrefix(s.Name, "_runtime.") || strings.HasPrefix(s.Name, "_go.") {
				return true
			}
		}
	}

	return false
}

// isScanCandidate checks if a file should be considered for scanning based on extension or magic bytes.
func isScanCandidate(name, path string) bool {
	ext := strings.ToLower(filepath.Ext(name))

	// Common binary extensions
	switch ext {
	case ".exe", ".dll", ".so", ".dylib", "":
		// Extensionless: verify it's a recognized binary
		if ext == "" {
			_, err := detectFileFormat(path)
			return err == nil
		}

		return true
	}

	return false
}
