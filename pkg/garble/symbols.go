/*
Copyright © 2026 Security Research
*/
package garble

import (
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/garble/goresym"
)

// SymbolInfo represents a single symbol extracted from a binary.
type SymbolInfo struct {
	Name         string `json:"name"`
	Value        uint64 `json:"value"`
	Size         uint64 `json:"size"`
	Type         string `json:"type"`
	IsObfuscated bool   `json:"is_obfuscated"`
	IsRuntime    bool   `json:"is_runtime"`
	Package      string `json:"package,omitempty"`
}

// SymbolsResult holds the aggregate results of symbol analysis.
type SymbolsResult struct {
	FilePath         string       `json:"file_path"`
	FileName         string       `json:"file_name"`
	Format           string       `json:"format"`
	TotalSymbols     int          `json:"total_symbols"`
	FunctionCount    int          `json:"function_count"`
	ObjectCount      int          `json:"object_count"`
	ObfuscatedCount  int          `json:"obfuscated_count"`
	RuntimeCount     int          `json:"runtime_count"`
	ObfuscationRatio float64      `json:"obfuscation_ratio"`
	Packages         []string     `json:"packages,omitempty"`
	Symbols          []SymbolInfo `json:"symbols,omitempty"`
	TopObfuscated    []string     `json:"top_obfuscated,omitempty"`
	// SymbolSource is honest provenance for Symbols: "symtab" when the classic
	// ELF/PE/Mach-O symbol table yielded results, "pclntab" when the binary was
	// stripped and symbols were instead recovered from the Go runtime pclntab
	// (see pkg/garble/goresym), or "" when neither source produced anything.
	SymbolSource string `json:"symbol_source,omitempty"`
}

// AnalyzeSymbols parses the symbol table from a binary and analyzes for obfuscation.
func AnalyzeSymbols(binPath string) (*SymbolsResult, error) {
	format, err := detectFileFormat(binPath)
	if err != nil {
		return nil, err
	}

	result := &SymbolsResult{
		FilePath: binPath,
		FileName: filepath.Base(binPath),
		Format:   string(format),
	}

	switch format {
	case FormatELF:
		analyzeELFSymbols(binPath, result)
	case FormatPE:
		analyzePESymbols(binPath, result)
	case FormatMachO:
		analyzeMachOSymbols(binPath, result)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	if len(result.Symbols) > 0 {
		result.SymbolSource = "symtab"
	} else {
		recoverSymbolsFromPclntab(binPath, result)
	}

	// Compute statistics
	packageSet := make(map[string]bool)

	var obfuscatedNames []string

	for i := range result.Symbols {
		sym := &result.Symbols[i]
		sym.IsObfuscated = isObfuscatedName(sym.Name)
		sym.IsRuntime = isRuntimeSymbol(sym.Name)
		sym.Package = extractPackage(sym.Name)

		if sym.Package != "" {
			packageSet[sym.Package] = true
		}

		if sym.IsObfuscated {
			result.ObfuscatedCount++

			obfuscatedNames = append(obfuscatedNames, sym.Name)
		}

		if sym.IsRuntime {
			result.RuntimeCount++
		}
	}

	result.TotalSymbols = len(result.Symbols)

	// Compute obfuscation ratio (excluding runtime)
	nonRuntime := result.TotalSymbols - result.RuntimeCount
	if nonRuntime > 0 {
		result.ObfuscationRatio = float64(result.ObfuscatedCount) / float64(nonRuntime)
	}

	// Collect packages
	for pkg := range packageSet {
		result.Packages = append(result.Packages, pkg)
	}

	sort.Strings(result.Packages)

	// Top obfuscated (up to 20)
	limit := min(len(obfuscatedNames), 20)

	result.TopObfuscated = obfuscatedNames[:limit]

	return result, nil
}

// recoverSymbolsFromPclntab attempts to recover function symbols from a
// stripped Go binary's pclntab (via pkg/garble/goresym) when the classic
// ELF/PE/Mach-O symbol table yielded nothing. It degrades gracefully: any
// error, ErrNotImplemented, or empty result leaves result unchanged (Symbols
// stays empty, SymbolSource stays "") — it never fails AnalyzeSymbols.
func recoverSymbolsFromPclntab(binPath string, result *SymbolsResult) {
	goVersion := ""
	if info, err := ExtractInfo(binPath); err == nil && info != nil {
		goVersion = info.GoVersion
	}

	rec, err := goresym.Recover(context.Background(), binPath, goresym.Options{
		IncludeStdLib: false,
		GoVersion:     goVersion,
	})
	if err != nil || rec == nil || len(rec.Symbols) == 0 {
		return
	}

	for _, s := range rec.Symbols {
		result.FunctionCount++

		result.Symbols = append(result.Symbols, SymbolInfo{
			Name:  s.Name,
			Value: s.Address,
			Type:  "FUNC",
		})
	}

	result.SymbolSource = "pclntab"
}

func analyzeELFSymbols(binPath string, result *SymbolsResult) {
	f, err := elf.Open(binPath)
	if err != nil {
		return
	}

	defer func() { _ = f.Close() }()

	syms, _ := f.Symbols()
	for _, s := range syms {
		if s.Name == "" {
			continue
		}

		symType := elfSymType(s.Info)
		si := SymbolInfo{
			Name:  s.Name,
			Value: s.Value,
			Size:  s.Size,
			Type:  symType,
		}

		switch symType {
		case "FUNC":
			result.FunctionCount++
		case "OBJECT":
			result.ObjectCount++
		}

		result.Symbols = append(result.Symbols, si)
	}

	// Also check dynamic symbols
	dynSyms, _ := f.DynamicSymbols()
	for _, s := range dynSyms {
		if s.Name == "" {
			continue
		}

		symType := elfSymType(s.Info)
		si := SymbolInfo{
			Name:  s.Name,
			Value: s.Value,
			Size:  s.Size,
			Type:  symType,
		}

		switch symType {
		case "FUNC":
			result.FunctionCount++
		case "OBJECT":
			result.ObjectCount++
		}

		result.Symbols = append(result.Symbols, si)
	}
}

func analyzePESymbols(binPath string, result *SymbolsResult) {
	f, err := pe.Open(binPath)
	if err != nil {
		return
	}

	defer func() { _ = f.Close() }()

	if f.Symbols == nil {
		return
	}

	for _, s := range f.Symbols {
		if s.Name == "" {
			continue
		}

		symType := peSymType(s)
		si := SymbolInfo{
			Name:  s.Name,
			Value: uint64(s.Value),
			Type:  symType,
		}

		switch symType {
		case "FUNC":
			result.FunctionCount++
		case "OBJECT":
			result.ObjectCount++
		}

		result.Symbols = append(result.Symbols, si)
	}
}

func analyzeMachOSymbols(binPath string, result *SymbolsResult) {
	f, err := macho.Open(binPath)
	if err != nil {
		return
	}

	defer func() { _ = f.Close() }()

	if f.Symtab == nil {
		return
	}

	for _, s := range f.Symtab.Syms {
		if s.Name == "" {
			continue
		}

		si := SymbolInfo{
			Name:  s.Name,
			Value: s.Value,
			Type:  "SYMBOL",
		}

		// Mach-O symbols starting with _ are typically functions
		if strings.HasPrefix(s.Name, "_") {
			result.FunctionCount++
			si.Type = "FUNC"
		}

		result.Symbols = append(result.Symbols, si)
	}
}

// isObfuscatedName detects if a symbol name looks like a garble hash.
// Garble produces short base64-like names with mixed case and digits.
func isObfuscatedName(name string) bool {
	// Strip package prefix
	baseName := name
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		baseName = name[idx+1:]
	}
	// Strip leading underscore (Mach-O)
	baseName = strings.TrimPrefix(baseName, "_")

	if len(baseName) < 6 {
		return false
	}

	// Skip known runtime/internal patterns
	if isRuntimeSymbol(name) {
		return false
	}

	// Hashed names: alphanumeric, mixed case, no recognizable words
	if !hashNamePattern.MatchString(baseName) {
		return false
	}

	// Must have both upper and lower case, or digits mixed with letters
	hasUpper := false
	hasLower := false
	hasDigit := false

	for _, c := range baseName {
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}

		if c >= 'a' && c <= 'z' {
			hasLower = true
		}

		if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}

	// Garble hashes typically have mixed case or digits
	if (!hasUpper || !hasLower) && (!hasLower || !hasDigit) && (!hasUpper || !hasDigit) {
		return false
	}

	// Final check: not a readable English word pattern
	return !readableWordPattern.MatchString(baseName)
}

// isRuntimeSymbol checks if the symbol belongs to the Go runtime or stdlib.
func isRuntimeSymbol(name string) bool {
	for _, prefix := range runtimePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

// extractPackage extracts the package path from a symbol name.
func extractPackage(name string) string {
	// Go symbols: package/path.FuncName or package/path.(*Type).Method
	idx := strings.LastIndex(name, ".")
	if idx <= 0 {
		return ""
	}

	pkg := name[:idx]

	// Handle method receivers: package/path.(*Type)
	if paren := strings.Index(pkg, ".("); paren >= 0 {
		pkg = pkg[:paren]
	}

	return pkg
}

func elfSymType(info byte) string {
	symType := elf.ST_TYPE(info)
	switch symType {
	case elf.STT_FUNC:
		return "FUNC"
	case elf.STT_OBJECT:
		return "OBJECT"
	case elf.STT_NOTYPE:
		return "NOTYPE"
	case elf.STT_SECTION:
		return "SECTION"
	case elf.STT_FILE:
		return "FILE"
	default:
		return fmt.Sprintf("OTHER(%d)", symType)
	}
}

func peSymType(s *pe.Symbol) string {
	// PE COFF symbol classification
	if s.SectionNumber > 0 && s.Type == 0x20 {
		return "FUNC"
	}

	if s.SectionNumber > 0 && s.Type == 0x00 {
		return "OBJECT"
	}

	if s.SectionNumber == 0 {
		return "EXTERN"
	}

	return "OTHER"
}

var (
	hashNamePattern     = regexp.MustCompile(`^[a-zA-Z0-9_]{6,}$`)
	readableWordPattern = regexp.MustCompile(`(?i)^(init|main|new|get|set|put|del|add|sub|mul|div|mod|and|not|xor|run|map|len|cap|nil|err|buf|str|int|max|min|sum|avg|log|msg|pkg|cmd|arg|env|ctx|req|res|srv|app|cfg|opt|key|val|typ|src|dst|tmp|old|cur|idx|cnt|num|ptr|ref|sig|ret|out)$`)
)

var runtimePrefixes = []string{
	"runtime.",
	"runtime/",
	"go.",
	"go:",
	"go/",
	"type.",
	"type:",
	"gclocals·",
	"go.itab.",
	"go.string.",
	"go.func.",
	"sync.",
	"sync/",
	"syscall.",
	"syscall/",
	"internal/",
	"reflect.",
	"reflect/",
	"math.",
	"math/",
	"unicode.",
	"unicode/",
	"encoding.",
	"encoding/",
	"fmt.",
	"os.",
	"os/",
	"io.",
	"io/",
	"net.",
	"net/",
	"strings.",
	"bytes.",
	"strconv.",
	"errors.",
	"context.",
	"sort.",
	"time.",
	"path.",
	"path/",
	"crypto.",
	"crypto/",
	"hash.",
	"hash/",
	"compress/",
	"archive/",
	"bufio.",
	"log.",
	"log/",
	"regexp.",
	"regexp/",
	"testing.",
	"testing/",
	"debug.",
	"debug/",
	"text/",
	"html/",
	"image/",
	"mime/",
	"database/",
	"embed.",
}
