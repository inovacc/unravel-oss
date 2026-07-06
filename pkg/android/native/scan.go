/*
Copyright (c) 2026 Security Research
*/
package native

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// maxNativeLibBytes bounds the decompressed read of a single native library.
// Real .so files are large but well under 1 GiB; the cap defeats DEFLATE bombs.
// It is a var so tests can shrink it.
var maxNativeLibBytes int64 = 1 << 30 // 1 GiB

// ScanAPK analyzes all native shared libraries inside an APK file.
func ScanAPK(apkPath string) (*ScanResult, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk: %w", err)
	}
	defer func() { _ = zr.Close() }()

	result := &ScanResult{}
	abiStats := map[string]*ABISummary{}

	for _, entry := range zr.File {
		if !isNativeLib(entry.Name) {
			continue
		}

		info, err := analyzeLibrary(entry)
		if err != nil {
			continue
		}

		result.Libraries = append(result.Libraries, *info)
		result.JNIExports = append(result.JNIExports, info.JNIExports...)
		result.Findings = append(result.Findings, info.Findings...)

		summary, ok := abiStats[info.ABI]
		if !ok {
			summary = &ABISummary{ABI: info.ABI}
			abiStats[info.ABI] = summary
		}
		summary.Count++
		summary.TotalSize += info.Size
	}

	result.TotalLibs = len(result.Libraries)

	for _, s := range abiStats {
		result.ABIs = append(result.ABIs, *s)
	}
	sort.Slice(result.ABIs, func(i, j int) bool {
		return result.ABIs[i].ABI < result.ABIs[j].ABI
	})

	result.PackerDetected = detectPacker(result.Findings)

	return result, nil
}

// isNativeLib returns true if the ZIP entry path matches lib/<abi>/*.so.
func isNativeLib(name string) bool {
	if !strings.HasPrefix(name, "lib/") {
		return false
	}
	return strings.HasSuffix(name, ".so") || strings.Contains(filepath.Base(name), ".so.")
}

// analyzeLibrary reads and analyzes a single native library from a ZIP entry.
func analyzeLibrary(entry *zip.File) (*LibraryInfo, error) {
	rc, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("open entry: %w", err)
	}
	defer func() { _ = rc.Close() }()

	data, err := safeio.ReadAllLimit(rc, maxNativeLibBytes)
	if err != nil {
		return nil, fmt.Errorf("read entry: %w", err)
	}

	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse elf: %w", err)
	}
	defer func() { _ = ef.Close() }()

	parts := strings.Split(entry.Name, "/")
	abi := ""
	if len(parts) >= 3 {
		abi = parts[1]
	}

	name := filepath.Base(entry.Name)

	info := &LibraryInfo{
		Name:    name,
		ABI:     abi,
		Size:    int64(entry.UncompressedSize64),
		Machine: machineString(ef.Machine),
	}

	needed, _ := ef.DynString(elf.DT_NEEDED)
	info.Linked = needed

	info.JNIExports = extractJNIExports(ef, name, abi)
	info.Findings = scanPatterns(ef, data, name, abi)

	// Check library name against packer signatures.
	for _, p := range packerSignatures {
		if strings.Contains(name, p.signature) {
			info.Findings = append(info.Findings, Finding{
				Library:     name,
				ABI:         abi,
				Category:    "packer",
				Pattern:     p.signature,
				Severity:    p.severity,
				Description: p.description,
			})
		}
	}

	return info, nil
}

// extractJNIExports finds JNI native method exports in the dynamic symbol table.
func extractJNIExports(ef *elf.File, libName, abi string) []JNIExport {
	symbols, err := ef.DynamicSymbols()
	if err != nil {
		return nil
	}

	var exports []JNIExport
	for _, sym := range symbols {
		if !strings.HasPrefix(sym.Name, "Java_") {
			continue
		}
		exports = append(exports, JNIExport{
			Library:  libName,
			ABI:      abi,
			Symbol:   sym.Name,
			JavaName: DecodeJNIName(sym.Name),
		})
	}
	return exports
}

// DecodeJNIName converts a JNI symbol name to its Java equivalent.
// For example, "Java_com_example_Class_method" becomes "com.example.Class.method".
// The escape sequence "_1" is decoded back to a literal underscore.
func DecodeJNIName(symbol string) string {
	// Strip "Java_" prefix.
	name := strings.TrimPrefix(symbol, "Java_")

	// Handle _1 escape (literal underscore) before replacing separators.
	// Use a placeholder to avoid conflicts with the separator replacement.
	const placeholder = "\x00"
	name = strings.ReplaceAll(name, "_1", placeholder)

	// Replace remaining underscores with dots (package/class separators).
	name = strings.ReplaceAll(name, "_", ".")

	// Restore literal underscores from placeholder.
	name = strings.ReplaceAll(name, placeholder, "_")

	return name
}

// scanPatterns searches .rodata section bytes for known security patterns.
func scanPatterns(ef *elf.File, rawData []byte, libName, abi string) []Finding {
	var rodata []byte
	if section := ef.Section(".rodata"); section != nil {
		rodata, _ = section.Data()
	}

	// Fall back to raw data if .rodata is empty.
	searchData := rodata
	if len(searchData) == 0 {
		searchData = rawData
	}

	var findings []Finding

	for _, p := range antiDebugPatterns {
		if bytes.Contains(searchData, []byte(p.pattern)) {
			findings = append(findings, Finding{
				Library:     libName,
				ABI:         abi,
				Category:    "anti-debug",
				Pattern:     p.pattern,
				Severity:    p.severity,
				Description: p.description,
			})
		}
	}

	for _, p := range rootDetectionPatterns {
		if bytes.Contains(searchData, []byte(p.pattern)) {
			findings = append(findings, Finding{
				Library:     libName,
				ABI:         abi,
				Category:    "root-detection",
				Pattern:     p.pattern,
				Severity:    p.severity,
				Description: p.description,
			})
		}
	}

	for _, p := range emulatorDetectionPatterns {
		if bytes.Contains(searchData, []byte(p.pattern)) {
			findings = append(findings, Finding{
				Library:     libName,
				ABI:         abi,
				Category:    "emulator-detection",
				Pattern:     p.pattern,
				Severity:    p.severity,
				Description: p.description,
			})
		}
	}

	// Check raw data for packer signatures (these may appear anywhere).
	for _, p := range packerSignatures {
		if bytes.Contains(rawData, []byte(p.signature)) {
			findings = append(findings, Finding{
				Library:     libName,
				ABI:         abi,
				Category:    "packer",
				Pattern:     p.signature,
				Severity:    p.severity,
				Description: p.description,
			})
		}
	}

	return findings
}

// detectPacker returns the name of the first detected packer from findings.
func detectPacker(findings []Finding) string {
	for _, f := range findings {
		if f.Category == "packer" {
			// Look up the packer name from signatures.
			for _, p := range packerSignatures {
				if p.signature == f.Pattern {
					return p.name
				}
			}
		}
	}
	return ""
}

// machineString returns a human-readable string for an ELF machine type.
func machineString(m elf.Machine) string {
	switch m {
	case elf.EM_ARM:
		return "ARM"
	case elf.EM_AARCH64:
		return "AARCH64"
	case elf.EM_386:
		return "386"
	case elf.EM_X86_64:
		return "AMD64"
	case elf.EM_MIPS:
		return "MIPS"
	default:
		return m.String()
	}
}
