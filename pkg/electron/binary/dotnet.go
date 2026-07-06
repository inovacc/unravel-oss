/*
Copyright (c) 2026 Security Research
*/
package binary

import (
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	dotnetpkg "github.com/inovacc/unravel-oss/pkg/dotnet"
)

// DotNetMetadata holds .NET-specific strings extracted from PE CLR metadata.
type DotNetMetadata struct {
	IsDotNet    bool     `json:"is_dotnet"`
	Assemblies  []string `json:"assemblies,omitempty"`   // Referenced assembly names
	Namespaces  []string `json:"namespaces,omitempty"`   // Namespace strings from metadata
	TypeNames   []string `json:"type_names,omitempty"`   // Type/class names
	UserStrings []string `json:"user_strings,omitempty"` // #US heap strings (user-visible)
}

// isDotNetBinary checks whether the binary at path is a .NET PE by looking for
// sibling .deps.json / .runtimeconfig.json files, or by checking the PE CLR
// data directory entry.
func isDotNetBinary(path string) bool {
	dir := filepath.Dir(path)

	// Fast check: sibling .NET marker files
	if dotnetpkg.IsDotNetApp(dir) {
		return true
	}

	// PE CLR header check: data directory entry 14 (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
	f, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	return hasCLRHeader(f)
}

// hasCLRHeader returns true if the PE has a non-zero CLR data directory entry.
func hasCLRHeader(f *pe.File) bool {
	const comDescriptorIndex = 14

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if int(oh.NumberOfRvaAndSizes) > comDescriptorIndex {
			dd := oh.DataDirectory[comDescriptorIndex]
			return dd.VirtualAddress != 0 && dd.Size != 0
		}
	case *pe.OptionalHeader64:
		if int(oh.NumberOfRvaAndSizes) > comDescriptorIndex {
			dd := oh.DataDirectory[comDescriptorIndex]
			return dd.VirtualAddress != 0 && dd.Size != 0
		}
	}
	return false
}

// ExtractDotNetMetadata parses PE .NET metadata streams to extract assemblies,
// namespaces, type names, and user strings from the CLR metadata tables.
// Returns nil if the file is not a .NET binary.
func ExtractDotNetMetadata(path string) *DotNetMetadata {
	f, err := pe.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	if !hasCLRHeader(f) {
		return nil
	}

	meta := &DotNetMetadata{IsDotNet: true}

	// Try to find and parse the .NET metadata from sections
	for _, sec := range f.Sections {
		data, err := sec.Data()
		if err != nil || len(data) == 0 {
			continue
		}

		// Look for CLI metadata signature "BSJB" (0x42534A42)
		idx := findBSJB(data)
		if idx < 0 {
			continue
		}

		// Parse the metadata root header
		parseMetadataRoot(data[idx:], meta)
		break
	}

	// Deduplicate and limit
	meta.Assemblies = dedupLimit(meta.Assemblies, 500)
	meta.Namespaces = dedupLimit(meta.Namespaces, 500)
	meta.TypeNames = dedupLimit(meta.TypeNames, 1000)
	meta.UserStrings = dedupLimit(meta.UserStrings, 500)

	return meta
}

// findBSJB searches for the CLI metadata signature in section data.
func findBSJB(data []byte) int {
	sig := []byte{0x42, 0x53, 0x4A, 0x42} // "BSJB"
	for i := 0; i+4 <= len(data); i++ {
		if data[i] == sig[0] && data[i+1] == sig[1] && data[i+2] == sig[2] && data[i+3] == sig[3] {
			return i
		}
	}
	return -1
}

// parseMetadataRoot parses the CLI metadata root to find stream headers and
// extract strings from #Strings, #US, and #Blob heaps.
func parseMetadataRoot(data []byte, meta *DotNetMetadata) {
	if len(data) < 16 {
		return
	}

	// Skip: Signature(4) + MajorVersion(2) + MinorVersion(2) + Reserved(4) = 12
	// Then VersionLength(4) at offset 12
	if len(data) < 16 {
		return
	}
	versionLen := binary.LittleEndian.Uint32(data[12:16])
	if versionLen > 256 {
		return
	}

	// Align version length to 4 bytes
	alignedVerLen := (versionLen + 3) & ^uint32(3)

	// After version string: Flags(2) + NumberOfStreams(2)
	pos := 16 + int(alignedVerLen)
	if pos+4 > len(data) {
		return
	}

	// Skip flags
	numStreams := int(binary.LittleEndian.Uint16(data[pos+2 : pos+4]))
	pos += 4

	if numStreams > 10 {
		numStreams = 10
	}

	// Parse stream headers
	type streamHeader struct {
		offset uint32
		size   uint32
		name   string
	}

	var streams []streamHeader
	for i := 0; i < numStreams && pos+8 <= len(data); i++ {
		offset := binary.LittleEndian.Uint32(data[pos : pos+4])
		size := binary.LittleEndian.Uint32(data[pos+4 : pos+8])
		pos += 8

		// Read null-terminated stream name, padded to 4-byte boundary
		nameStart := pos
		for pos < len(data) && data[pos] != 0 {
			pos++
		}
		if pos >= len(data) {
			break
		}
		name := string(data[nameStart:pos])
		pos++ // skip null terminator
		// Align to 4 bytes
		pos = (pos + 3) & ^3

		streams = append(streams, streamHeader{offset: offset, size: size, name: name})
	}

	// Extract strings from each stream
	for _, sh := range streams {
		start := int(sh.offset)
		end := start + int(sh.size)
		if start >= len(data) || end > len(data) || start >= end {
			continue
		}
		streamData := data[start:end]

		switch sh.name {
		case "#Strings":
			extractStringsHeap(streamData, meta)
		case "#US":
			extractUSHeap(streamData, meta)
		}
	}
}

// extractStringsHeap extracts null-terminated UTF-8 strings from the #Strings heap.
// This heap contains namespace names, type names, method names, etc.
func extractStringsHeap(data []byte, meta *DotNetMetadata) {
	pos := 0
	for pos < len(data) {
		// Find next null terminator
		end := pos
		for end < len(data) && data[end] != 0 {
			end++
		}

		if end > pos {
			s := string(data[pos:end])
			if len(s) >= 3 && isPrintableASCII(s) {
				classifyMetadataString(s, meta)
			}
		}

		pos = end + 1
	}
}

// extractUSHeap extracts user strings from the #US (User Strings) heap.
// These are UTF-16LE encoded strings preceded by a compressed length.
func extractUSHeap(data []byte, meta *DotNetMetadata) {
	pos := 1 // First byte is always 0
	for pos < len(data) {
		// Read compressed length
		length, bytesRead := readCompressedUint(data[pos:])
		pos += bytesRead
		if length == 0 || pos+int(length) > len(data) {
			break
		}

		// Decode UTF-16LE (length includes a trailing byte)
		strBytes := int(length)
		if strBytes > 0 {
			strBytes-- // remove trailing indicator byte
		}
		if strBytes >= 2 {
			s := decodeUTF16LE(data[pos : pos+strBytes])
			if len(s) >= 3 {
				meta.UserStrings = append(meta.UserStrings, s)
			}
		}

		pos += int(length)
	}
}

// readCompressedUint reads a ECMA-335 compressed unsigned integer.
func readCompressedUint(data []byte) (uint32, int) {
	if len(data) == 0 {
		return 0, 0
	}
	b0 := data[0]
	if b0 < 0x80 {
		return uint32(b0), 1
	}
	if b0 < 0xC0 && len(data) >= 2 {
		return uint32(b0&0x3F)<<8 | uint32(data[1]), 2
	}
	if len(data) >= 4 {
		return uint32(b0&0x1F)<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]), 4
	}
	return 0, 1
}

// decodeUTF16LE decodes a UTF-16LE byte slice to a Go string.
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	runes := utf16.Decode(u16)
	return string(runes)
}

// classifyMetadataString classifies a string from the #Strings heap into
// namespace, type name, or assembly reference.
func classifyMetadataString(s string, meta *DotNetMetadata) {
	// Skip very short or compiler-generated strings
	if len(s) < 3 {
		return
	}
	if strings.HasPrefix(s, "<") || strings.HasPrefix(s, ".") {
		return
	}

	// Namespace: contains dots and starts with uppercase
	if strings.Contains(s, ".") && len(s) > 5 {
		parts := strings.Split(s, ".")
		allPascal := true
		for _, p := range parts {
			if len(p) == 0 || p[0] < 'A' || p[0] > 'Z' {
				allPascal = false
				break
			}
		}
		if allPascal {
			meta.Namespaces = append(meta.Namespaces, s)
			return
		}
	}

	// Assembly name patterns (e.g., "mscorlib", "System", "Newtonsoft")
	if isAssemblyName(s) {
		meta.Assemblies = append(meta.Assemblies, s)
		return
	}

	// Type/class name: PascalCase without dots
	if !strings.Contains(s, ".") && !strings.Contains(s, " ") && len(s) >= 4 && s[0] >= 'A' && s[0] <= 'Z' {
		meta.TypeNames = append(meta.TypeNames, s)
	}
}

// isAssemblyName checks if a string looks like a .NET assembly name.
func isAssemblyName(s string) bool {
	knownPrefixes := []string{
		"System", "Microsoft", "mscorlib", "netstandard",
		"WindowsBase", "PresentationCore", "PresentationFramework",
	}
	for _, prefix := range knownPrefixes {
		if s == prefix || strings.HasPrefix(s, prefix+".") {
			return true
		}
	}
	return false
}

// isPrintableASCII returns true if the string contains only printable ASCII.
func isPrintableASCII(s string) bool {
	for _, b := range s {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// filterDotNetStrings filters raw binary strings to remove .NET assembly noise,
// replacing the sample strings with more meaningful ones.
// It re-extracts strings scanning the full file and applies the dotnet filter.
func filterDotNetStrings(path string, rawStrings []string, rawTotal int, maxSamples int) ([]string, int) {
	filtered := dotnetpkg.FilterStrings(rawStrings)

	// Collect the best sample strings from the categorized results, prioritizing
	// the most useful categories.
	var result []string

	// Priority order: URLs > API routes > config keys > SQL > file paths > namespaces > class names > interesting
	sources := [][]string{
		filtered.URLs,
		filtered.APIRoutes,
		filtered.ConfigKeys,
		filtered.SQLQueries,
		filtered.FilePaths,
		filtered.Namespaces,
		filtered.ClassNames,
		filtered.Interesting,
	}

	for _, src := range sources {
		for _, s := range src {
			if len(result) >= maxSamples {
				break
			}
			result = append(result, s)
		}
		if len(result) >= maxSamples {
			break
		}
	}

	meaningfulTotal := max(rawTotal-filtered.Filtered, 0)

	return result, meaningfulTotal
}

// extractAllStrings extracts ALL printable strings from a binary (not just the first N),
// for use in .NET filtering where we need the full corpus to find meaningful ones.
func extractAllStrings(path string, maxBytes int64, minLen int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var (
		buf       = make([]byte, 64*1024)
		current   strings.Builder
		result    []string
		readBytes int64
	)

	for {
		if maxBytes > 0 && readBytes >= maxBytes {
			break
		}
		n, err := f.Read(buf)
		if n > 0 {
			if maxBytes > 0 && readBytes+int64(n) > maxBytes {
				n = int(maxBytes - readBytes)
			}
			readBytes += int64(n)
			for i := 0; i < n; i++ {
				b := buf[i]
				if b >= 0x20 && b <= 0x7e {
					current.WriteByte(b)
				} else if current.Len() >= minLen {
					result = append(result, current.String())
					current.Reset()
				} else {
					current.Reset()
				}
			}
		}
		if err != nil {
			break
		}
	}
	if current.Len() >= minLen {
		result = append(result, current.String())
	}

	return result
}

// dedupLimit deduplicates and limits a string slice.
func dedupLimit(in []string, limit int) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, min(len(in), limit))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}
