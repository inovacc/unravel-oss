/*
Copyright (c) 2026 Security Research

Package bun implements detection and decompilation of Bun standalone executables.

Bun standalone binaries (created with `bun build --compile`) embed a
StandaloneModuleGraph. On Windows PE, the data is stored in a ".bun" section
with the following layout:

	[u64 LE data_length]          — 8 bytes at section start
	[raw_bytes: data_length]      — the module graph blob:
	    [string data: paths, contents, sourcemaps, bytecode]
	    [module metadata: N × CompiledModuleGraphFile (52 bytes each)]
	    [Offsets struct (32 bytes)]
	    [trailer: "\n---- Bun! ----\n" (16 bytes)]

Offsets struct (extern, 64-bit):

	byte_count:           u64  (8 bytes)
	modules_ptr.offset:   u32  (4 bytes)
	modules_ptr.length:   u32  (4 bytes)
	entry_point_id:       u32  (4 bytes)
	compile_exec_argv.offset: u32 (4 bytes)
	compile_exec_argv.length: u32 (4 bytes)
	flags:                u32  (4 bytes)
	Total: 32 bytes

CompiledModuleGraphFile (extern):

	name:                 StringPointer (8 bytes)
	contents:             StringPointer (8 bytes)
	sourcemap:            StringPointer (8 bytes)
	bytecode:             StringPointer (8 bytes)
	module_info:          StringPointer (8 bytes)
	bytecode_origin_path: StringPointer (8 bytes)
	encoding:             u8
	loader:               u8
	module_format:        u8
	side:                 u8
	Total: 52 bytes

Reference: bun/src/StandaloneModuleGraph.zig
Reference: github.com/lafkpages/bun-decompile (MIT)
*/
package bun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Trailer is the magic string at the end of the module graph blob.
const Trailer = "\n---- Bun! ----\n"

// BunFS root prefixes used by Bun for virtual file paths.
const (
	BunFSRootUnix    = "/$bunfs/root"
	BunFSRootWindows = "B:/~BUN/root/"
	BunFSRootWinBS   = "B:\\~BUN\\root\\"
	BunFSRootOld     = "compiled://root"
)

// Version match patterns embedded in the Bun runtime portion.
const (
	VersionMatchNew = "\x1b[0m\x1b[1mbun build \x1b[0m\x1b[2mv"
	VersionMatchOld = "----- bun meta -----\nBun v"
)

// Sizes of binary structures.
const (
	offsetsSize  = 32 // Offsets struct (64-bit)
	trailerSize  = 16
	moduleSize   = 52 // CompiledModuleGraphFile
	sectionHdrSz = 8  // u64 data_length at start of PE .bun section
)

// Loader enum values from Bun.
const (
	LoaderJSX  byte = 0
	LoaderJS   byte = 1
	LoaderTSX  byte = 2
	LoaderTS   byte = 3
	LoaderCSS  byte = 4
	LoaderFile byte = 5
	LoaderJSON byte = 6
	LoaderTOML byte = 7
	LoaderWASM byte = 8
	LoaderText byte = 14
)

// BunBinary holds the analysis results for a Bun standalone executable.
type BunBinary struct {
	Path       string        `json:"path"`
	Name       string        `json:"name"`
	Size       int64         `json:"size"`
	IsBun      bool          `json:"is_bun"`
	Version    string        `json:"version,omitempty"`
	Revision   string        `json:"revision,omitempty"`
	Entrypoint string        `json:"entrypoint,omitempty"`
	FileCount  int           `json:"file_count"`
	Files      []BundledFile `json:"files,omitempty"`
	ByteCount  uint64        `json:"byte_count"`
}

// BundledFile represents a single file embedded in the Bun binary.
type BundledFile struct {
	Path         string `json:"path"`
	Size         int    `json:"size"`
	IsEntrypoint bool   `json:"is_entrypoint"`
	HasSourceMap bool   `json:"has_sourcemap,omitempty"`
	HasBytecode  bool   `json:"has_bytecode,omitempty"`
	BytecodeSize int    `json:"bytecode_size,omitempty"`
	Loader       string `json:"loader,omitempty"`
	contents     []byte
}

// Contents returns the raw file contents.
func (f *BundledFile) Contents() []byte {
	return f.contents
}

// ContentsString returns contents as a string.
func (f *BundledFile) ContentsString() string {
	return string(f.contents)
}

// IsBunBinary checks if the file is a Bun standalone executable.
// It checks for the .bun PE section (Windows) or scans for the trailer.
func IsBunBinary(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return false, err
	}

	if stat.Size() < 512 {
		return false, nil
	}

	// Check for .bun PE section
	header := make([]byte, 4096)
	n, _ := f.ReadAt(header, 0)
	header = header[:n]

	if hasBunPESection(header) {
		return true, nil
	}

	// Fall back: scan for trailer near end of file
	tailSize := min(int64(256), stat.Size())
	tail := make([]byte, tailSize)
	_, _ = f.ReadAt(tail, stat.Size()-tailSize)
	return bytes.Contains(tail, []byte(Trailer)), nil
}

// Analyze reads a Bun standalone binary and extracts metadata and bundled files.
func Analyze(path string) (*BunBinary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	result := &BunBinary{
		Path: path,
		Name: filepath.Base(path),
		Size: stat.Size(),
	}

	// Try PE .bun section first
	rawBytes, err := extractBunSectionPE(data)
	if err != nil {
		return nil, err
	}

	if rawBytes == nil {
		// Fall back: scan for trailer at end of file
		rawBytes = extractBunFromTrailer(data)
	}

	if rawBytes == nil {
		return result, nil
	}

	result.IsBun = true

	// Verify trailer at end of rawBytes
	if len(rawBytes) < trailerSize+offsetsSize {
		return result, fmt.Errorf("raw bytes too small: %d", len(rawBytes))
	}

	trailerStart := len(rawBytes) - trailerSize
	if string(rawBytes[trailerStart:]) != Trailer {
		return result, fmt.Errorf("trailer not found at expected position")
	}

	// Read Offsets struct (32 bytes before trailer)
	offsStart := trailerStart - offsetsSize
	offs := rawBytes[offsStart:trailerStart]

	byteCount := binary.LittleEndian.Uint64(offs[0:8])
	modulesPtrOffset := binary.LittleEndian.Uint32(offs[8:12])
	modulesPtrLength := binary.LittleEndian.Uint32(offs[12:16])
	entryPointID := binary.LittleEndian.Uint32(offs[16:20])
	// argv at offs[20:28] - not needed for extraction
	// flags at offs[28:32] - not needed for extraction

	result.ByteCount = byteCount

	if modulesPtrLength == 0 || modulesPtrLength%moduleSize != 0 {
		return result, fmt.Errorf("invalid modules_ptr length: %d (not divisible by %d)", modulesPtrLength, moduleSize)
	}

	moduleCount := modulesPtrLength / uint32(moduleSize)
	result.FileCount = int(moduleCount)

	// SEC: uint64 math so a uint32 offset+length wrap cannot slip past the bound.
	if uint64(modulesPtrOffset)+uint64(modulesPtrLength) > uint64(len(rawBytes)) {
		return result, fmt.Errorf("modules_ptr out of range")
	}

	// Extract version from runtime data (everything before the module graph)
	// For PE, the runtime is in the main binary before the .bun section
	// We scan the full file data for version strings
	result.Version, result.Revision = extractVersion(data)

	// Parse each module entry
	for i := range moduleCount {
		isEntrypoint := i == entryPointID

		entryOffset := int(modulesPtrOffset) + int(i)*moduleSize
		if entryOffset+moduleSize > len(rawBytes) {
			break
		}
		entry := rawBytes[entryOffset : entryOffset+moduleSize]

		nameOff := binary.LittleEndian.Uint32(entry[0:4])
		nameLen := binary.LittleEndian.Uint32(entry[4:8])
		contentsOff := binary.LittleEndian.Uint32(entry[8:12])
		contentsLen := binary.LittleEndian.Uint32(entry[12:16])
		smOff := binary.LittleEndian.Uint32(entry[16:20])
		smLen := binary.LittleEndian.Uint32(entry[20:24])
		bcOff := binary.LittleEndian.Uint32(entry[24:28])
		bcLen := binary.LittleEndian.Uint32(entry[28:32])
		// module_info at entry[32:40], bytecode_origin_path at entry[40:48]
		// encoding at entry[48], loader at entry[49], module_format at entry[50], side at entry[51]
		loader := entry[49]

		_ = smOff
		_ = bcOff

		// Read name (null-terminated in rawBytes).
		// SEC: do offset+length math in uint64. A uint32 add can wrap modulo
		// 2^32 (e.g. nameOff=0xFFFFFFFF, nameLen=2 -> 1) and slip past the bound,
		// then rawBytes[0xFFFFFFFF:1] panics. uint64 of two uint32 addends never
		// overflows; only convert to int after the check passes.
		if uint64(nameOff)+uint64(nameLen) > uint64(len(rawBytes)) {
			continue
		}
		nameLo, nameHi := int(nameOff), int(nameOff)+int(nameLen)
		filePath := strings.TrimRight(string(rawBytes[nameLo:nameHi]), "\x00")
		filePath = removeBunFSRoot(filePath)

		if isEntrypoint {
			result.Entrypoint = filePath
		}

		// Read contents
		var contents []byte
		if contentsLen > 0 && uint64(contentsOff)+uint64(contentsLen) <= uint64(len(rawBytes)) {
			cLo, cHi := int(contentsOff), int(contentsOff)+int(contentsLen)
			contents = make([]byte, contentsLen)
			copy(contents, rawBytes[cLo:cHi])
		}

		bf := BundledFile{
			Path:         filePath,
			Size:         int(contentsLen),
			IsEntrypoint: isEntrypoint,
			HasSourceMap: smLen > 0,
			HasBytecode:  bcLen > 0,
			BytecodeSize: int(bcLen),
			Loader:       loaderName(loader),
			contents:     contents,
		}

		result.Files = append(result.Files, bf)
	}

	return result, nil
}

// Extract writes all bundled files to the specified output directory.
func Extract(path string, outputDir string, verbose bool) (*BunBinary, error) {
	result, err := Analyze(path)
	if err != nil {
		return nil, err
	}

	if !result.IsBun {
		return nil, fmt.Errorf("%s is not a Bun standalone binary", path)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	for _, f := range result.Files {
		if len(f.contents) == 0 {
			continue
		}

		// SEC (path-traversal): f.Path comes straight from attacker-controlled
		// module-graph bytes. Mirror the zipapp/pyinst containment guard: reject
		// absolute paths, strip the volume name (so a `C:`-rooted entry can't
		// escape on Windows), and require the cleaned join to stay under
		// outputDir. Skip-and-continue so one poisoned entry doesn't abort
		// extraction of the rest of the sample.
		cleanRel := filepath.FromSlash(f.Path)
		if filepath.IsAbs(cleanRel) {
			slog.Warn("bun extract: skipping absolute entry path", "path", f.Path)
			continue
		}
		cleanRel = strings.TrimPrefix(cleanRel, filepath.VolumeName(cleanRel))
		outPath := filepath.Join(outputDir, cleanRel)
		rel, relErr := filepath.Rel(outputDir, outPath)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			slog.Warn("bun extract: skipping out-of-tree entry path", "path", f.Path)
			continue
		}
		dir := filepath.Dir(outPath)

		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}

		if err := os.WriteFile(outPath, f.contents, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", outPath, err)
		}

		if verbose {
			fmt.Printf("  %s (%s)\n", f.Path, formatSize(f.Size))
		}
	}

	// Write metadata
	metaPath := filepath.Join(outputDir, "UNRAVEL_META.json")
	meta := fmt.Sprintf(`{
  "source": %q,
  "bun_version": %q,
  "bun_revision": %q,
  "entrypoint": %q,
  "file_count": %d,
  "binary_size": %d
}
`, result.Name, result.Version, result.Revision, result.Entrypoint, result.FileCount, result.Size)
	if err := os.WriteFile(metaPath, []byte(meta), 0o644); err != nil {
		return nil, fmt.Errorf("write meta: %w", err)
	}

	return result, nil
}

// extractBunSectionPE finds the .bun PE section and returns raw_bytes.
func extractBunSectionPE(data []byte) ([]byte, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil, nil // not PE
	}

	peOffset := binary.LittleEndian.Uint32(data[0x3C:0x40])
	if int(peOffset)+24 > len(data) {
		return nil, nil
	}
	if string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return nil, nil
	}

	sectionCount := int(binary.LittleEndian.Uint16(data[peOffset+6 : peOffset+8]))
	optHeaderSize := int(binary.LittleEndian.Uint16(data[peOffset+20 : peOffset+22]))
	sectionsStart := int(peOffset) + 24 + optHeaderSize

	for i := range sectionCount {
		off := sectionsStart + i*40
		if off+40 > len(data) {
			break
		}

		name := strings.TrimRight(string(data[off:off+8]), "\x00")
		if name != ".bun" {
			continue
		}

		rawSize := binary.LittleEndian.Uint32(data[off+16 : off+20])
		rawOffset := binary.LittleEndian.Uint32(data[off+20 : off+24])

		sectionEnd := int(rawOffset) + int(rawSize)
		if sectionEnd > len(data) {
			return nil, fmt.Errorf(".bun section extends beyond file: offset=%d size=%d fileLen=%d", rawOffset, rawSize, len(data))
		}

		sectionData := data[rawOffset:sectionEnd]

		if len(sectionData) < sectionHdrSz {
			return nil, fmt.Errorf(".bun section too small: %d bytes", len(sectionData))
		}

		// First 8 bytes = u64 LE data_length
		dataLength := binary.LittleEndian.Uint64(sectionData[0:8])

		// SEC: compare in unsigned arithmetic. A signed int() narrowing of a
		// high-bit value (e.g. 0xFFFFFFFFFFFFFFFF -> -1 on 64-bit) would defeat
		// the bound and slice sectionData[8:7] -> slice-bounds panic. len-hdrSz
		// is non-negative here because the len(sectionData) < sectionHdrSz guard
		// above already returned.
		if dataLength > uint64(len(sectionData)-sectionHdrSz) {
			return nil, fmt.Errorf(".bun data_length (%d) exceeds section data (%d)", dataLength, len(sectionData)-sectionHdrSz)
		}

		rawBytes := sectionData[sectionHdrSz : sectionHdrSz+int(dataLength)]
		return rawBytes, nil
	}

	return nil, nil // no .bun section
}

// extractBunFromTrailer scans for the trailer at/near the end of data.
// Used for non-PE binaries or unsigned binaries where trailer is at the end.
func extractBunFromTrailer(data []byte) []byte {
	trailerBytes := []byte(Trailer)

	// Search backwards from the end
	searchStart := max(len(data)-256, 0)

	idx := bytes.LastIndex(data[searchStart:], trailerBytes)
	if idx == -1 {
		// Try a broader search
		idx = bytes.LastIndex(data, trailerBytes)
		if idx == -1 {
			return nil
		}
	} else {
		idx += searchStart
	}

	// The trailer is at the end of raw_bytes
	rawEnd := idx + trailerSize

	// Read the Offsets struct to find where raw_bytes starts
	if idx < offsetsSize {
		return nil
	}

	offs := data[idx-offsetsSize : idx]
	byteCount := binary.LittleEndian.Uint64(offs[0:8])

	if byteCount == 0 || int(byteCount) > rawEnd {
		// Try treating rawEnd as the blob size
		return data[:rawEnd]
	}

	blobStart := max(rawEnd-int(byteCount)-trailerSize, 0)

	return data[blobStart:rawEnd]
}

func hasBunPESection(header []byte) bool {
	if len(header) < 0x40 || header[0] != 'M' || header[1] != 'Z' {
		return false
	}

	peOffset := binary.LittleEndian.Uint32(header[0x3C:0x40])
	if int(peOffset)+24 > len(header) {
		return false
	}
	if string(header[peOffset:peOffset+4]) != "PE\x00\x00" {
		return false
	}

	sectionCount := int(binary.LittleEndian.Uint16(header[peOffset+6 : peOffset+8]))
	optHeaderSize := int(binary.LittleEndian.Uint16(header[peOffset+20 : peOffset+22]))
	sectionsStart := int(peOffset) + 24 + optHeaderSize

	for i := range sectionCount {
		off := sectionsStart + i*40
		if off+8 > len(header) {
			break
		}
		name := strings.TrimRight(string(header[off:off+8]), "\x00")
		if name == ".bun" {
			return true
		}
	}
	return false
}

func removeBunFSRoot(path string) string {
	for _, prefix := range []string{BunFSRootWindows, BunFSRootWinBS, BunFSRootUnix, BunFSRootOld} {
		if strings.HasPrefix(path, prefix) {
			return path[len(prefix):]
		}
	}
	// Also handle the base path without /root/
	for _, prefix := range []string{"B:/~BUN/", "B:\\~BUN\\", "/$bunfs/"} {
		if strings.HasPrefix(path, prefix) {
			return path[len(prefix):]
		}
	}
	return path
}

func extractVersion(data []byte) (version, revision string) {
	if v, r, ok := findVersion(data, VersionMatchNew, 0x1b); ok {
		return v, r
	}
	if v, r, ok := findVersion(data, VersionMatchOld, ':'); ok {
		return v, r
	}
	return "", ""
}

func findVersion(data []byte, marker string, terminator byte) (version, revision string, ok bool) {
	markerBytes := []byte(marker)
	idx := bytes.Index(data, markerBytes)
	if idx == -1 {
		return "", "", false
	}

	start := idx + len(markerBytes)
	end := start
	for end < len(data) && end-start < 100 && data[end] != terminator {
		end++
	}

	if end == start || end >= len(data) {
		return "", "", false
	}

	versionStr := string(data[start:end])

	re := regexp.MustCompile(`^(.+?)\s+\((.+?)\)`)
	matches := re.FindStringSubmatch(versionStr)
	if len(matches) >= 3 {
		return matches[1], matches[2], true
	}

	versionStr = strings.TrimSpace(versionStr)
	if len(versionStr) > 0 {
		return versionStr, "", true
	}

	return "", "", false
}

func loaderName(l byte) string {
	switch l {
	case 0:
		return "jsx"
	case 1:
		return "js"
	case 2:
		return "tsx"
	case 3:
		return "ts"
	case 4:
		return "css"
	case 5:
		return "file"
	case 6:
		return "json"
	case 7:
		return "toml"
	case 8:
		return "wasm"
	case 14:
		return "text"
	default:
		return fmt.Sprintf("unknown(%d)", l)
	}
}

func formatSize(bytes int) string {
	switch {
	case bytes >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(1024*1024))
	case bytes >= 1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024.0)
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
