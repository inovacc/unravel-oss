/*
Copyright (c) 2026 Security Research
*/
package nodeaddon

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/disasm"
)

// N-API export symbols that identify a Node.js native addon.
var napiExportSymbols = []string{
	"napi_register_module_v1",
	"napi_module_register",
	"node_register_module_v1",
	"node_api_module_get_api_version_v1",
	"napi_register_module",
}

// Result holds the analysis output for a .node native addon.
type Result struct {
	FilePath     string         `json:"file_path"`
	FileName     string         `json:"file_name"`
	FileSize     int64          `json:"file_size"`
	Format       string         `json:"format"`       // PE, ELF, Mach-O
	Architecture string         `json:"architecture"` // x86, x64, ARM64
	Bits         int            `json:"bits"`         // 32 or 64
	IsNAPI       bool           `json:"is_napi"`
	NAPIVersion  int            `json:"napi_version,omitempty"`
	NAPIExports  []string       `json:"napi_exports"`
	Exports      []ExportedFunc `json:"exports"`
	Imports      []ImportedLib  `json:"imports"`
	RiskScore    int            `json:"risk_score"`
	RiskFactors  []RiskFactor   `json:"risk_factors"`
	Binding      *BindingInfo   `json:"binding,omitempty"`
	CertInfo     *cert.CertInfo `json:"cert_info,omitempty"`
}

// ExportedFunc represents a single exported function from the addon.
type ExportedFunc struct {
	Name    string `json:"name"`
	Address uint64 `json:"address,omitempty"`
	IsNAPI  bool   `json:"is_napi"`
}

// ImportedLib represents a dynamically linked library and its imported functions.
type ImportedLib struct {
	Library   string   `json:"library"`
	Functions []string `json:"functions,omitempty"`
	Category  string   `json:"category"` // crypto, network, process, registry, filesystem, system
}

// RiskFactor describes a single security concern found in the addon.
type RiskFactor struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
}

// BindingInfo holds metadata about the build system used to compile the addon.
type BindingInfo struct {
	BindingGyp  bool   `json:"binding_gyp"`
	BuildSystem string `json:"build_system,omitempty"` // node-gyp, cmake-js, prebuild, node-pre-gyp
	PackageName string `json:"package_name,omitempty"`
	TargetName  string `json:"target_name,omitempty"`
}

// StringEntry represents an extracted string with entropy metadata.
type StringEntry struct {
	Value    string  `json:"value"`
	Offset   int64   `json:"offset"`
	Length   int     `json:"length"`
	Category string  `json:"category"`
	Entropy  float64 `json:"entropy"`
}

// StringsResult holds string extraction output.
type StringsResult struct {
	FilePath         string              `json:"file_path"`
	FileName         string              `json:"file_name"`
	TotalStrings     int                 `json:"total_strings"`
	ByCategory       map[string]int      `json:"by_category"`
	AvgEntropy       float64             `json:"avg_entropy"`
	HighEntropyCount int                 `json:"high_entropy_count"`
	Strings          []StringEntry       `json:"strings,omitempty"`
	TopByCategory    map[string][]string `json:"top_by_category,omitempty"`
}

// SymbolsResult holds symbol table analysis output.
type SymbolsResult struct {
	FilePath     string         `json:"file_path"`
	FileName     string         `json:"file_name"`
	TotalSymbols int            `json:"total_symbols"`
	NAPISymbols  []ExportedFunc `json:"napi_symbols"`
	Exports      []ExportedFunc `json:"exports"`
	HasNAPI      bool           `json:"has_napi"`
}

// ImportsResult holds import analysis with risk classification.
type ImportsResult struct {
	FilePath    string        `json:"file_path"`
	FileName    string        `json:"file_name"`
	Imports     []ImportedLib `json:"imports"`
	RiskScore   int           `json:"risk_score"`
	RiskFactors []RiskFactor  `json:"risk_factors"`
}

// Analyze performs full analysis of a .node native addon file.
func Analyze(path string) (*Result, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	result := &Result{
		FilePath:    absPath,
		FileName:    filepath.Base(path),
		FileSize:    fi.Size(),
		NAPIExports: []string{},
		Exports:     []ExportedFunc{},
		Imports:     []ImportedLib{},
		RiskFactors: []RiskFactor{},
	}

	// Use disasm to get binary metadata
	disResult, err := disasm.Disassemble(path, disasm.Options{MaxInstructions: 1})
	if err == nil {
		result.Format = disResult.Format
		result.Architecture = disResult.Architecture
		result.Bits = disResult.Bits
	} else {
		// Fall back to direct format detection
		result.Format, result.Architecture, result.Bits = detectFormat(path)
	}

	// Extract exports and imports directly from binary headers
	exports, imports := extractSymbols(path, result.Format)
	result.Exports = exports
	result.Imports = classifyImports(imports)

	// Check for N-API exports
	for _, exp := range result.Exports {
		if exp.IsNAPI {
			result.IsNAPI = true
			result.NAPIExports = append(result.NAPIExports, exp.Name)
		}
	}

	// Detect N-API version from exports
	result.NAPIVersion = detectNAPIVersion(result.Exports)

	// Risk assessment
	result.RiskScore, result.RiskFactors = assessRisk(result.Imports, result.Exports)

	// Check for binding metadata in sibling files
	result.Binding = detectBinding(path)

	// Certificate extraction
	certInfo, certErr := cert.ExtractCertificates(path)
	if certErr == nil && certInfo != nil {
		result.CertInfo = certInfo
	}

	return result, nil
}

// Symbols extracts and annotates the symbol table.
func Symbols(path string) (*SymbolsResult, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	format, _, _ := detectFormat(path)
	exports, _ := extractSymbols(path, format)

	result := &SymbolsResult{
		FilePath:     absPath,
		FileName:     filepath.Base(path),
		TotalSymbols: len(exports),
		NAPISymbols:  []ExportedFunc{},
		Exports:      exports,
	}

	for _, exp := range exports {
		if exp.IsNAPI {
			result.HasNAPI = true
			result.NAPISymbols = append(result.NAPISymbols, exp)
		}
	}

	return result, nil
}

// Strings extracts printable strings with entropy analysis.
func Strings(path string, minLen int) (*StringsResult, error) {
	if minLen < 4 {
		minLen = 4
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	result := &StringsResult{
		FilePath:      absPath,
		FileName:      filepath.Base(path),
		ByCategory:    make(map[string]int),
		TopByCategory: make(map[string][]string),
	}

	var (
		current     []byte
		startOffset int64
	)

	for i, b := range data {
		if b >= 0x20 && b < 0x7f {
			if len(current) == 0 {
				startOffset = int64(i)
			}
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				s := string(current)
				entropy := shannonEntropy(s)
				cat := categorizeString(s)

				result.Strings = append(result.Strings, StringEntry{
					Value:    s,
					Offset:   startOffset,
					Length:   len(current),
					Category: cat,
					Entropy:  entropy,
				})
				result.ByCategory[cat]++

				if entropy > 4.5 {
					result.HighEntropyCount++
				}

				top := result.TopByCategory[cat]
				if len(top) < 10 {
					result.TopByCategory[cat] = append(top, s)
				}
			}
			current = current[:0]
		}
	}

	// Handle trailing string
	if len(current) >= minLen {
		s := string(current)
		entropy := shannonEntropy(s)
		cat := categorizeString(s)
		result.Strings = append(result.Strings, StringEntry{
			Value:    s,
			Offset:   startOffset,
			Length:   len(current),
			Category: cat,
			Entropy:  entropy,
		})
		result.ByCategory[cat]++
		if entropy > 4.5 {
			result.HighEntropyCount++
		}
	}

	result.TotalStrings = len(result.Strings)
	if result.TotalStrings > 0 {
		var totalEntropy float64
		for _, s := range result.Strings {
			totalEntropy += s.Entropy
		}
		result.AvgEntropy = totalEntropy / float64(result.TotalStrings)
	}

	return result, nil
}

// Imports analyzes imported libraries with risk classification.
func Imports(path string) (*ImportsResult, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	format, _, _ := detectFormat(path)
	_, rawImports := extractSymbols(path, format)
	classified := classifyImports(rawImports)
	riskScore, riskFactors := assessRisk(classified, nil)

	return &ImportsResult{
		FilePath:    absPath,
		FileName:    filepath.Base(path),
		Imports:     classified,
		RiskScore:   riskScore,
		RiskFactors: riskFactors,
	}, nil
}

// detectFormat identifies the binary format using Go's debug packages.
func detectFormat(path string) (format, arch string, bits int) {
	// Try PE
	if f, err := pe.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		format = "PE"
		switch f.Machine {
		case pe.IMAGE_FILE_MACHINE_AMD64:
			arch, bits = "x64", 64
		case pe.IMAGE_FILE_MACHINE_I386:
			arch, bits = "x86", 32
		case pe.IMAGE_FILE_MACHINE_ARM64:
			arch, bits = "ARM64", 64
		default:
			arch, bits = "unknown", 0
		}
		return
	}

	// Try ELF
	if f, err := elf.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		format = "ELF"
		switch f.Machine {
		case elf.EM_X86_64:
			arch, bits = "x64", 64
		case elf.EM_386:
			arch, bits = "x86", 32
		case elf.EM_AARCH64:
			arch, bits = "ARM64", 64
		case elf.EM_ARM:
			arch, bits = "ARM", 32
		default:
			arch, bits = "unknown", 0
		}
		return
	}

	// Try Mach-O
	if f, err := macho.Open(path); err == nil {
		defer func() { _ = f.Close() }()
		format = "Mach-O"
		switch f.Cpu {
		case macho.CpuAmd64:
			arch, bits = "x64", 64
		case macho.Cpu386:
			arch, bits = "x86", 32
		case macho.CpuArm64:
			arch, bits = "ARM64", 64
		case macho.CpuArm:
			arch, bits = "ARM", 32
		default:
			arch, bits = "unknown", 0
		}
		return
	}

	return "unknown", "unknown", 0
}

// rawImport holds a library name and its imported function names.
type rawImport struct {
	Library   string
	Functions []string
}

// extractSymbols reads exports and imports from the binary.
func extractSymbols(path, format string) ([]ExportedFunc, []rawImport) {
	var exports []ExportedFunc
	var imports []rawImport

	switch format {
	case "PE":
		exports, imports = extractPESymbols(path)
	case "ELF":
		exports, imports = extractELFSymbols(path)
	case "Mach-O":
		exports, imports = extractMachOSymbols(path)
	default:
		// Try all formats
		if e, i := extractPESymbols(path); len(e) > 0 || len(i) > 0 {
			return e, i
		}
		if e, i := extractELFSymbols(path); len(e) > 0 || len(i) > 0 {
			return e, i
		}
		exports, imports = extractMachOSymbols(path)
	}

	return exports, imports
}

func extractPESymbols(path string) ([]ExportedFunc, []rawImport) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = f.Close() }()

	var exports []ExportedFunc

	// PE exports from symbol table
	for _, sym := range f.Symbols {
		if sym.SectionNumber > 0 {
			isNAPI := isNAPISymbol(sym.Name)
			exports = append(exports, ExportedFunc{
				Name:    sym.Name,
				Address: uint64(sym.Value),
				IsNAPI:  isNAPI,
			})
		}
	}

	// PE exports from export directory (optional data directory)
	if optHdr, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		if len(f.Sections) > 0 && len(optHdr.DataDirectory) > 0 {
			// Export table is DataDirectory[0]
			exportDir := optHdr.DataDirectory[0]
			if exportDir.VirtualAddress > 0 && exportDir.Size > 0 {
				for _, sec := range f.Sections {
					if sec.VirtualAddress <= exportDir.VirtualAddress &&
						exportDir.VirtualAddress < sec.VirtualAddress+sec.VirtualSize {
						data, readErr := sec.Data()
						if readErr == nil {
							names := extractPEExportNames(data, sec.VirtualAddress, exportDir.VirtualAddress, exportDir.Size)
							for _, name := range names {
								// Avoid duplicates
								found := false
								for _, e := range exports {
									if e.Name == name {
										found = true
										break
									}
								}
								if !found {
									exports = append(exports, ExportedFunc{
										Name:   name,
										IsNAPI: isNAPISymbol(name),
									})
								}
							}
						}
						break
					}
				}
			}
		}
	}

	// PE imports
	var imports []rawImport
	libs, _ := f.ImportedLibraries()
	for _, lib := range libs {
		imports = append(imports, rawImport{Library: lib})
	}

	// Try to get imported symbols per library
	syms, _ := f.ImportedSymbols()
	libFuncs := make(map[string][]string)
	for _, sym := range syms {
		parts := strings.SplitN(sym, ":", 2)
		if len(parts) == 2 {
			libFuncs[parts[0]] = append(libFuncs[parts[0]], parts[1])
		}
	}
	for i := range imports {
		if funcs, ok := libFuncs[imports[i].Library]; ok {
			imports[i].Functions = funcs
		}
	}

	return exports, imports
}

func extractELFSymbols(path string) ([]ExportedFunc, []rawImport) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = f.Close() }()

	var exports []ExportedFunc

	// Dynamic symbols (most relevant for .node shared libraries)
	dynsyms, _ := f.DynamicSymbols()
	for _, sym := range dynsyms {
		if sym.Name == "" {
			continue
		}
		// Exported = global or weak binding, defined (section != SHN_UNDEF)
		bind := elf.ST_BIND(sym.Info)
		if sym.Section != elf.SHN_UNDEF && (bind == elf.STB_GLOBAL || bind == elf.STB_WEAK) {
			exports = append(exports, ExportedFunc{
				Name:    sym.Name,
				Address: sym.Value,
				IsNAPI:  isNAPISymbol(sym.Name),
			})
		}
	}

	// Imported libraries
	var imports []rawImport
	libs, _ := f.ImportedLibraries()
	for _, lib := range libs {
		imports = append(imports, rawImport{Library: lib})
	}

	// Imported symbols (undefined dynamic symbols)
	libFuncs := make(map[string][]string)
	for _, sym := range dynsyms {
		if sym.Name != "" && sym.Section == elf.SHN_UNDEF {
			// We can't always determine which library a symbol comes from in ELF,
			// so we collect them all and assign to the first matching library or "unknown"
			libFuncs["_unresolved"] = append(libFuncs["_unresolved"], sym.Name)
		}
	}
	if unresolved, ok := libFuncs["_unresolved"]; ok && len(imports) > 0 {
		// Distribute unresolved symbols to the import list as a hint
		imports[0].Functions = unresolved
	}

	return exports, imports
}

func extractMachOSymbols(path string) ([]ExportedFunc, []rawImport) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = f.Close() }()

	var exports []ExportedFunc

	for _, sym := range f.Symtab.Syms {
		if sym.Name == "" {
			continue
		}
		// Exported symbols: external, defined (type != N_UNDF)
		name := strings.TrimPrefix(sym.Name, "_")
		if sym.Type&0x01 != 0 && sym.Sect != 0 { // N_EXT and defined
			exports = append(exports, ExportedFunc{
				Name:    name,
				Address: sym.Value,
				IsNAPI:  isNAPISymbol(name),
			})
		}
	}

	// Imported libraries
	var imports []rawImport
	libs, _ := f.ImportedLibraries()
	for _, lib := range libs {
		imports = append(imports, rawImport{Library: lib})
	}

	return exports, imports
}

// extractPEExportNames parses the PE export directory to find exported function names.
func extractPEExportNames(sectionData []byte, sectionRVA, exportRVA, exportSize uint32) []string {
	// SEC: all RVA->offset math is done in uint64 with an explicit
	// >= sectionRVA precondition. A bare uint32 subtraction underflows when the
	// attacker sets an RVA just below sectionRVA, and a uint32 add (offset+len)
	// wraps to a small value that slips past the bound — both then index out of
	// range and panic. Widening + the precondition makes the checks exact.
	if exportRVA < sectionRVA {
		return nil
	}
	offset := uint64(exportRVA) - uint64(sectionRVA)
	if offset+40 > uint64(len(sectionData)) {
		return nil
	}

	// Export directory table: NumberOfNames at offset 24, AddressOfNames at offset 32
	numNames := uint32(sectionData[offset+24]) | uint32(sectionData[offset+25])<<8 |
		uint32(sectionData[offset+26])<<16 | uint32(sectionData[offset+27])<<24
	namesRVA := uint32(sectionData[offset+32]) | uint32(sectionData[offset+33])<<8 |
		uint32(sectionData[offset+34])<<16 | uint32(sectionData[offset+35])<<24

	if numNames > 10000 { // sanity check
		return nil
	}

	if namesRVA < sectionRVA {
		return nil
	}
	namesOffset := uint64(namesRVA) - uint64(sectionRVA)
	if namesOffset+uint64(numNames)*4 > uint64(len(sectionData)) {
		return nil
	}

	var names []string
	for i := range numNames {
		base := namesOffset + uint64(i)*4
		nameRVA := uint32(sectionData[base]) | uint32(sectionData[base+1])<<8 |
			uint32(sectionData[base+2])<<16 | uint32(sectionData[base+3])<<24
		if nameRVA < sectionRVA {
			continue
		}
		nameOff64 := uint64(nameRVA) - uint64(sectionRVA)
		if nameOff64 >= uint64(len(sectionData)) {
			continue
		}
		nameOff := int(nameOff64)
		// Read null-terminated string
		end := int(nameOff)
		for end < len(sectionData) && sectionData[end] != 0 {
			end++
		}
		if end > int(nameOff) {
			names = append(names, string(sectionData[nameOff:end]))
		}
	}

	return names
}

// isNAPISymbol checks if a symbol name is a known N-API registration function.
func isNAPISymbol(name string) bool {
	return slices.Contains(napiExportSymbols, name)
}

// detectNAPIVersion infers the N-API version from exported symbols.
// Higher versions take precedence (v9 export implies v9+).
func detectNAPIVersion(exports []ExportedFunc) int {
	version := 0
	for _, e := range exports {
		if e.Name == "node_api_module_get_api_version_v1" {
			return 9 // NAPI 9+ uses this export — highest known
		}
		if e.Name == "napi_register_module_v1" && version < 1 {
			version = 1 // Base N-API
		}
	}
	return version
}

// detectBinding looks for sibling build system files.
func detectBinding(nodePath string) *BindingInfo {
	dir := filepath.Dir(nodePath)

	info := &BindingInfo{}
	found := false

	// Walk up to find binding.gyp or package.json (max 3 levels)
	for range 4 {
		if _, err := os.Stat(filepath.Join(dir, "binding.gyp")); err == nil {
			info.BindingGyp = true
			info.BuildSystem = "node-gyp"
			found = true

			// Try to read target_name from binding.gyp
			data, readErr := os.ReadFile(filepath.Join(dir, "binding.gyp"))
			if readErr == nil {
				if name := extractJSONField(data, "target_name"); name != "" {
					info.TargetName = name
				}
			}
		}

		if _, err := os.Stat(filepath.Join(dir, "CMakeLists.txt")); err == nil {
			info.BuildSystem = "cmake-js"
			found = true
		}

		pkgPath := filepath.Join(dir, "package.json")
		if data, err := os.ReadFile(pkgPath); err == nil {
			found = true
			if name := extractJSONField(data, "name"); name != "" {
				info.PackageName = name
			}
			// Check for binary field (node-pre-gyp)
			var pkg map[string]any
			if json.Unmarshal(data, &pkg) == nil {
				if _, ok := pkg["binary"]; ok {
					info.BuildSystem = "node-pre-gyp"
				}
			}
			break
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	if !found {
		return nil
	}
	return info
}

// extractJSONField does a quick JSON field extraction without full parsing.
func extractJSONField(data []byte, field string) string {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return ""
	}
	if val, ok := obj[field]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// classifyImports categorizes imported libraries by function.
func classifyImports(raw []rawImport) []ImportedLib {
	classified := make([]ImportedLib, 0, len(raw))
	for _, r := range raw {
		lib := ImportedLib{
			Library:   r.Library,
			Functions: r.Functions,
			Category:  classifyLibrary(r.Library, r.Functions),
		}
		classified = append(classified, lib)
	}
	return classified
}

// categorizeString classifies an extracted string.
func categorizeString(s string) string {
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://"):
		return "URL"
	case strings.Contains(lower, "\\") && (strings.Contains(lower, "c:") || strings.Contains(lower, "program")):
		return "FILE_PATH"
	case strings.HasPrefix(s, "/") && strings.Contains(s, "/") && !strings.Contains(s, " "):
		return "FILE_PATH"
	case strings.Contains(lower, "api") && strings.Contains(s, "/"):
		return "API_ENDPOINT"
	case strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(lower, "cannot"):
		return "ERROR_MESSAGE"
	case strings.Contains(lower, "crypt") || strings.Contains(lower, "cipher") || strings.Contains(lower, "aes") || strings.Contains(lower, "rsa"):
		return "CRYPTO"
	case strings.Contains(lower, "socket") || strings.Contains(lower, "connect") || strings.Contains(lower, "bind"):
		return "NETWORK"
	case strings.Contains(lower, "registry") || strings.Contains(lower, "hkey"):
		return "REGISTRY"
	default:
		entropy := shannonEntropy(s)
		if entropy > 4.5 {
			return "HIGH_ENTROPY"
		}
		return "GENERAL"
	}
}

// shannonEntropy calculates Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	var entropy float64
	n := float64(len(s))
	for _, count := range freq {
		p := count / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
