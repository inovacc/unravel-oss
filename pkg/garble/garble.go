/*
Copyright © 2026 Security Research
*/
package garble

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// BinaryFormat represents the detected binary format.
type BinaryFormat string

const (
	FormatPE    BinaryFormat = "PE"
	FormatELF   BinaryFormat = "ELF"
	FormatMachO BinaryFormat = "Mach-O"
)

// DetectionResult holds the result of garble obfuscation detection.
type DetectionResult struct {
	FilePath        string      `json:"file_path"`
	FileName        string      `json:"file_name"`
	FileSize        int64       `json:"file_size"`
	Format          string      `json:"format"`
	IsGarbled       bool        `json:"is_garbled"`
	Confidence      float64     `json:"confidence"`
	ConfidenceLabel string      `json:"confidence_label"`
	Heuristics      []Heuristic `json:"heuristics"`
}

// Heuristic represents a single detection heuristic and its result.
type Heuristic struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Detected    bool    `json:"detected"`
	Weight      float64 `json:"weight"`
	Details     string  `json:"details,omitempty"`
}

// Detect runs garble obfuscation detection heuristics on a Go binary.
func Detect(binPath string) (*DetectionResult, error) {
	absPath, err := filepath.Abs(binPath)
	if err != nil {
		absPath = binPath
	}

	fi, err := os.Stat(binPath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	format, err := detectFileFormat(binPath)
	if err != nil {
		return nil, err
	}

	result := &DetectionResult{
		FilePath: absPath,
		FileName: filepath.Base(binPath),
		FileSize: fi.Size(),
		Format:   string(format),
	}

	// Run all heuristics
	result.Heuristics = []Heuristic{
		checkBuildInfo(binPath),
		checkDWARF(binPath, format),
		checkHashedSymbols(binPath, format),
		checkGoPackagePaths(binPath, format),
		checkGoBuildID(binPath, format),
		checkGarbleStrings(binPath),
	}

	// Compute weighted confidence
	var (
		totalWeight    float64
		detectedWeight float64
	)

	for _, h := range result.Heuristics {
		totalWeight += h.Weight
		if h.Detected {
			detectedWeight += h.Weight
		}
	}

	if totalWeight > 0 {
		result.Confidence = detectedWeight / totalWeight
	}

	result.IsGarbled = result.Confidence >= 0.35
	result.ConfidenceLabel = confidenceLabel(result.Confidence)

	return result, nil
}

func confidenceLabel(conf float64) string {
	switch {
	case conf >= 0.85:
		return "CERTAIN"
	case conf >= 0.65:
		return "HIGH"
	case conf >= 0.45:
		return "MEDIUM"
	case conf >= 0.35:
		return "LOW"
	default:
		return "NONE"
	}
}

// detectFileFormat reads magic bytes to determine the binary format.
func detectFileFormat(binPath string) (BinaryFormat, error) {
	f, err := os.Open(binPath)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return "", fmt.Errorf("read magic bytes: %w", err)
	}

	// ELF: \x7fELF
	if magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
		return FormatELF, nil
	}

	// PE: MZ header
	if magic[0] == 'M' && magic[1] == 'Z' {
		return FormatPE, nil
	}

	// Mach-O: various magic numbers
	if (magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa && (magic[3] == 0xce || magic[3] == 0xcf)) ||
		(magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe) ||
		(magic[0] == 0xce && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe) {
		return FormatMachO, nil
	}

	return "", fmt.Errorf("unrecognized binary format (magic: %x)", magic)
}

// Heuristic 1: Missing build info (garble strips debug/buildinfo)
func checkBuildInfo(binPath string) Heuristic {
	h := Heuristic{
		Name:        "missing_build_info",
		Description: "Go build info is missing (garble strips it)",
		Weight:      0.15,
	}

	_, err := buildinfo.ReadFile(binPath)
	if err != nil {
		h.Detected = true
		h.Details = fmt.Sprintf("buildinfo.ReadFile failed: %v", err)
	} else {
		h.Details = "Build info present"
	}

	return h
}

// Heuristic 2: No DWARF debug info
func checkDWARF(binPath string, format BinaryFormat) Heuristic {
	h := Heuristic{
		Name:        "no_dwarf",
		Description: "DWARF debug information is absent",
		Weight:      0.15,
	}

	switch format {
	case FormatELF:
		f, err := elf.Open(binPath)
		if err != nil {
			h.Details = fmt.Sprintf("Cannot open ELF: %v", err)
			return h
		}

		defer func() { _ = f.Close() }()

		dw, err := f.DWARF()
		if err != nil || dw == nil {
			h.Detected = true
			h.Details = "No DWARF data in ELF"
		} else {
			h.Details = "DWARF data present"
		}

	case FormatPE:
		f, err := pe.Open(binPath)
		if err != nil {
			h.Details = fmt.Sprintf("Cannot open PE: %v", err)
			return h
		}

		defer func() { _ = f.Close() }()

		dw, err := f.DWARF()
		if err != nil || dw == nil {
			h.Detected = true
			h.Details = "No DWARF data in PE"
		} else {
			h.Details = "DWARF data present"
		}

	case FormatMachO:
		f, err := macho.Open(binPath)
		if err != nil {
			h.Details = fmt.Sprintf("Cannot open Mach-O: %v", err)
			return h
		}

		defer func() { _ = f.Close() }()

		dw, err := f.DWARF()
		if err != nil || dw == nil {
			h.Detected = true
			h.Details = "No DWARF data in Mach-O"
		} else {
			h.Details = "DWARF data present"
		}
	}

	return h
}

// Heuristic 3: Hashed symbol names (garble replaces names with base64 hashes)
func checkHashedSymbols(binPath string, format BinaryFormat) Heuristic {
	h := Heuristic{
		Name:        "hashed_symbols",
		Description: "Symbol names appear to be garble-hashed (base64-like)",
		Weight:      0.30,
	}

	// Pattern: garble produces names like short-base64 hashes
	// e.g., "aBcDeFgH", "X1y2Z3w4" — 8+ chars of [a-zA-Z0-9_] with mixed case and digits
	hashPattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{6,}$`)
	// Additional check: no dots, no slashes, no recognizable words
	readablePattern := regexp.MustCompile(`(?i)(main|init|runtime|fmt|os|net|http|sync|context|error|string|test|buf|read|write|close|open|get|set|new|make)`)

	symbols := collectSymbolNames(binPath, format)
	if len(symbols) == 0 {
		h.Details = "No symbols found"
		return h
	}

	hashedCount := 0
	totalFuncs := 0

	for _, name := range symbols {
		// Skip runtime and stdlib symbols
		if strings.HasPrefix(name, "runtime.") || strings.HasPrefix(name, "go.") ||
			strings.HasPrefix(name, "type.") || strings.HasPrefix(name, "go:") {
			continue
		}

		totalFuncs++

		// Check if the name looks like a hash (matches pattern but not readable)
		baseName := name
		if idx := strings.LastIndex(name, "."); idx >= 0 {
			baseName = name[idx+1:]
		}

		if hashPattern.MatchString(baseName) && !readablePattern.MatchString(baseName) {
			hashedCount++
		}
	}

	if totalFuncs > 0 {
		ratio := float64(hashedCount) / float64(totalFuncs)

		h.Details = fmt.Sprintf("%d/%d non-runtime symbols appear hashed (%.1f%%)", hashedCount, totalFuncs, ratio*100)
		if ratio > 0.4 {
			h.Detected = true
		}
	} else {
		h.Details = "No non-runtime symbols to analyze"
	}

	return h
}

// collectSymbolNames extracts symbol names from the binary.
func collectSymbolNames(binPath string, format BinaryFormat) []string {
	var names []string

	switch format {
	case FormatELF:
		f, err := elf.Open(binPath)
		if err != nil {
			return nil
		}

		defer func() { _ = f.Close() }()

		syms, _ := f.Symbols()
		for _, s := range syms {
			if s.Name != "" {
				names = append(names, s.Name)
			}
		}

		dynSyms, _ := f.DynamicSymbols()
		for _, s := range dynSyms {
			if s.Name != "" {
				names = append(names, s.Name)
			}
		}

	case FormatPE:
		f, err := pe.Open(binPath)
		if err != nil {
			return nil
		}

		defer func() { _ = f.Close() }()

		if f.Symbols != nil {
			for _, s := range f.Symbols {
				if s.Name != "" {
					names = append(names, s.Name)
				}
			}
		}

	case FormatMachO:
		f, err := macho.Open(binPath)
		if err != nil {
			return nil
		}

		defer func() { _ = f.Close() }()

		if f.Symtab != nil {
			for _, s := range f.Symtab.Syms {
				if s.Name != "" {
					names = append(names, s.Name)
				}
			}
		}
	}

	return names
}

// Heuristic 4: Missing Go package paths
func checkGoPackagePaths(binPath string, format BinaryFormat) Heuristic {
	h := Heuristic{
		Name:        "missing_go_paths",
		Description: "Recognizable Go package paths are missing from symbols",
		Weight:      0.15,
	}

	symbols := collectSymbolNames(binPath, format)
	if len(symbols) == 0 {
		h.Details = "No symbols found"
		return h
	}

	pathPattern := regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*/`)
	pathCount := 0

	for _, name := range symbols {
		if pathPattern.MatchString(name) {
			pathCount++
		}
	}

	ratio := float64(pathCount) / float64(len(symbols))
	h.Details = fmt.Sprintf("%d/%d symbols have recognizable package paths (%.1f%%)", pathCount, len(symbols), ratio*100)

	// If very few symbols have recognizable paths, likely garbled
	if len(symbols) > 50 && ratio < 0.05 {
		h.Detected = true
	}

	return h
}

// Heuristic 5: Missing Go build ID
func checkGoBuildID(binPath string, format BinaryFormat) Heuristic {
	h := Heuristic{
		Name:        "missing_build_id",
		Description: "Go build ID marker is missing",
		Weight:      0.10,
	}

	found := false

	switch format {
	case FormatELF:
		f, err := elf.Open(binPath)
		if err != nil {
			h.Details = fmt.Sprintf("Cannot open ELF: %v", err)
			return h
		}

		defer func() { _ = f.Close() }()

		// Check for .note.go.buildid section
		if sect := f.Section(".note.go.buildid"); sect != nil {
			found = true
			h.Details = "ELF .note.go.buildid section present"
		}
		// Also check .go.buildinfo
		if sect := f.Section(".go.buildinfo"); sect != nil {
			found = true
		}

	case FormatPE:
		f, err := pe.Open(binPath)
		if err != nil {
			h.Details = fmt.Sprintf("Cannot open PE: %v", err)
			return h
		}

		defer func() { _ = f.Close() }()

		for _, sect := range f.Sections {
			if sect.Name == ".buildid" || sect.Name == ".go.buildinfo" {
				found = true
				h.Details = fmt.Sprintf("PE section %s present", sect.Name)

				break
			}
		}

	case FormatMachO:
		f, err := macho.Open(binPath)
		if err != nil {
			h.Details = fmt.Sprintf("Cannot open Mach-O: %v", err)
			return h
		}

		defer func() { _ = f.Close() }()

		if sect := f.Section("__go_buildinfo"); sect != nil {
			found = true
			h.Details = "Mach-O __go_buildinfo section present"
		}
	}

	if !found {
		h.Detected = true
		if h.Details == "" {
			h.Details = "No Go build ID section found"
		}
	}

	return h
}

// Heuristic 6: Garble string markers
func checkGarbleStrings(binPath string) Heuristic {
	h := Heuristic{
		Name:        "garble_strings",
		Description: "References to garble tool found in binary",
		Weight:      0.15,
	}

	f, err := os.Open(binPath)
	if err != nil {
		h.Details = fmt.Sprintf("Cannot open: %v", err)
		return h
	}

	defer func() { _ = f.Close() }()

	// Read in chunks to search for garble-related strings
	markers := []string{"garble", "mvdan.cc/garble", "GARBLE_SEED", "garble:"}
	buf := make([]byte, 64*1024)

	var found []string

	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			content := string(buf[:n])
			for _, marker := range markers {
				if strings.Contains(content, marker) {
					found = append(found, marker)
				}
			}
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			break
		}
	}

	// Deduplicate found markers
	seen := make(map[string]bool)

	var unique []string

	for _, m := range found {
		if !seen[m] {
			seen[m] = true
			unique = append(unique, m)
		}
	}

	if len(unique) > 0 {
		h.Detected = true
		h.Details = fmt.Sprintf("Found markers: %s", strings.Join(unique, ", "))
	} else {
		h.Details = "No garble markers found"
	}

	return h
}
