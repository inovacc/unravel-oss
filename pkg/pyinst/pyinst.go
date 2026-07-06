/*
Copyright (c) 2026 Security Research

Package pyinst implements detection and extraction of PyInstaller executables.

PyInstaller bundles Python applications into standalone executables by appending
a CArchive overlay to a bootloader stub. The format is:

	[PE/ELF bootloader stub]
	[CArchive overlay]:
	    [compressed file data entries...]
	    [TOC (Table of Contents): variable-length entries]
	    [Cookie: 24 bytes (2.0) or 88 bytes (2.1+)]

Cookie (at end of archive):

	magic:           8 bytes  "MEI\014\013\012\013\016"
	lengthofPackage: 4 bytes  (i32 for 2.0, u32 for 2.1+)
	toc:             4 bytes  offset to TOC from overlay start
	tocLen:          4 bytes  size of TOC
	pyver:           4 bytes  Python version (major*100+minor or major*10+minor)
	pylibname:       64 bytes (2.1+ only) Python library name

TOC Entry (variable length):

	entrySize:       4 bytes  (i32 big-endian) total entry size including this field
	entryPos:        4 bytes  (u32) offset from overlay start
	cmprsdDataSize:  4 bytes  (u32) compressed size
	uncmprsdDataSize:4 bytes  (u32) uncompressed size
	cmprsFlag:       1 byte   1=zlib compressed, 0=raw
	typeCmprsData:   1 byte   entry type: 's'=source, 'M'/'m'=module, 'z'/'Z'=PYZ, 'd'=dep, 'o'=option
	name:            variable null-terminated string

Reference: github.com/extremecoders-re/pyinstxtractor
Reference: github.com/LookiMan/EXE2PY-Decompiler
*/
package pyinst

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// Magic is the PyInstaller CArchive magic cookie.
var Magic = []byte{'M', 'E', 'I', 014, 013, 012, 013, 016}

// maxPyinstEntryBytes is the per-entry hard ceiling on DECOMPRESSED size.
// PyInstaller TOC entries are individual Python modules/PYZ archives; 512 MiB
// is far above any legitimate entry, while stopping a zlib bomb (a tiny
// compressed stream of zeros inflating to many GiB) from OOMing the host.
// entry.UncompressedSize is attacker-controlled and must NOT be trusted as the
// bound — this fixed ceiling is the real guard. It is a var so tests can shrink
// it without allocating GiB.
var maxPyinstEntryBytes int64 = 512 << 20

// Cookie sizes for different PyInstaller versions.
const (
	Cookie20Size = 24 // PyInstaller 2.0
	Cookie21Size = 88 // PyInstaller 2.1+
)

// Entry type constants.
const (
	TypeDependency    = 'd'
	TypeRuntimeOption = 'o'
	TypePySource      = 's' // entry point script
	TypePyPackage     = 'M' // package __init__
	TypePyModule      = 'm' // module
	TypePYZ           = 'z' // PYZ archive
	TypePYZAlt        = 'Z' // PYZ archive (alternate)
)

// PyInstBinary holds analysis results.
type PyInstBinary struct {
	Path         string     `json:"path"`
	Name         string     `json:"name"`
	Size         int64      `json:"size"`
	IsPyInst     bool       `json:"is_pyinstaller"`
	PyVersion    string     `json:"python_version,omitempty"`
	PyLibName    string     `json:"python_lib,omitempty"`
	InstallerVer string     `json:"installer_version,omitempty"` // "2.0" or "2.1+"
	EntryCount   int        `json:"entry_count"`
	Entries      []TOCEntry `json:"entries,omitempty"`
	MainScripts  []string   `json:"main_scripts,omitempty"`
	OverlayPos   int64      `json:"overlay_pos"`
	CookiePos    int64      `json:"cookie_pos"`
}

// TOCEntry represents one entry in the Table of Contents.
type TOCEntry struct {
	Name             string `json:"name"`
	Position         uint32 `json:"position"` // offset from overlay start
	CompressedSize   uint32 `json:"compressed_size"`
	UncompressedSize uint32 `json:"uncompressed_size"`
	IsCompressed     bool   `json:"is_compressed"`
	TypeFlag         string `json:"type"`
	TypeDesc         string `json:"type_desc,omitempty"`
}

// IsPyInstaller checks if a file is a PyInstaller executable.
func IsPyInstaller(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return false, err
	}

	_, err = findCookie(f, stat.Size())
	return err == nil, nil
}

// Analyze reads a PyInstaller binary and extracts metadata.
func Analyze(path string) (*PyInstBinary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	result := &PyInstBinary{
		Path: path,
		Name: filepath.Base(path),
		Size: stat.Size(),
	}

	cookiePos, err := findCookieInData(data)
	if err != nil {
		return result, nil // not a PyInstaller binary
	}

	result.IsPyInst = true
	result.CookiePos = int64(cookiePos)

	// Try 2.1+ format first (88-byte cookie)
	if cookiePos+Cookie21Size <= len(data) {
		cookie := data[cookiePos:]
		if parseCookie21(cookie, result, data) {
			result.InstallerVer = "2.1+"
		} else if parseCookie20(cookie, result, data) {
			result.InstallerVer = "2.0"
		}
	} else if cookiePos+Cookie20Size <= len(data) {
		if parseCookie20(data[cookiePos:], result, data) {
			result.InstallerVer = "2.0"
		}
	}

	return result, nil
}

// Extract extracts all files from a PyInstaller binary.
func Extract(path string, outputDir string, verbose bool) (*PyInstBinary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	result, err := Analyze(path)
	if err != nil {
		return nil, err
	}

	if !result.IsPyInst {
		return nil, fmt.Errorf("%s is not a PyInstaller binary", path)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	overlayPos := result.OverlayPos

	for _, entry := range result.Entries {
		entryData := extractEntry(data, overlayPos, entry)
		if entryData == nil {
			continue
		}

		// Determine output name
		outName := sanitizeName(entry.Name)
		if outName == "" {
			continue
		}

		// Add appropriate extension
		switch entry.TypeFlag {
		case "s", "M", "m":
			if !strings.HasSuffix(outName, ".pyc") {
				outName += ".pyc"
			}
		case "z", "Z":
			if !strings.HasSuffix(outName, ".pyz") {
				outName += ".pyz"
			}
		}

		// Zip-slip guard: reject absolute paths and path traversal.
		if filepath.IsAbs(outName) {
			if verbose {
				fmt.Printf("  SKIP %s: unsafe absolute path\n", outName)
			}
			continue
		}
		outPath := filepath.Join(outputDir, filepath.FromSlash(outName))
		rel, relErr := filepath.Rel(outputDir, outPath)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			if verbose {
				fmt.Printf("  SKIP %s: unsafe path traversal\n", outName)
			}
			continue
		}
		dir := filepath.Dir(outPath)

		if err := os.MkdirAll(dir, 0o755); err != nil {
			if verbose {
				fmt.Printf("  SKIP %s: mkdir error: %v\n", outName, err)
			}
			continue
		}

		// For PYC files (s, M, m), reconstruct header if needed
		if entry.TypeFlag == "s" || entry.TypeFlag == "M" || entry.TypeFlag == "m" {
			entryData = fixPycHeader(entryData, result.PyVersion)
		}

		if err := os.WriteFile(outPath, entryData, 0o644); err != nil {
			if verbose {
				fmt.Printf("  SKIP %s: write error: %v\n", outName, err)
			}
			continue
		}

		if verbose {
			fmt.Printf("  %-50s %8d bytes  [%s]\n", outName, len(entryData), entry.TypeDesc)
		}

		// Extract PYZ archive contents
		if entry.TypeFlag == "z" || entry.TypeFlag == "Z" {
			pyzDir := filepath.Join(outputDir, strings.TrimSuffix(outName, ".pyz")+"_extracted")
			extractPYZ(entryData, pyzDir, result.PyVersion, verbose)
		}
	}

	// Write metadata
	writeMetadata(outputDir, result)

	return result, nil
}

func findCookie(f *os.File, fileSize int64) (int64, error) {
	// Search backward in 8KB chunks
	chunkSize := int64(8192)
	overlap := int64(len(Magic) - 1)

	for pos := fileSize; pos > 0; {
		readSize := chunkSize
		readStart := pos - readSize
		if readStart < 0 {
			readSize += readStart
			readStart = 0
		}

		buf := make([]byte, readSize+overlap)
		n, err := f.ReadAt(buf[:readSize], readStart)
		if err != nil && err != io.EOF {
			return 0, err
		}
		buf = buf[:n]

		idx := bytes.LastIndex(buf, Magic)
		if idx >= 0 {
			return readStart + int64(idx), nil
		}

		if readStart == 0 {
			break // searched entire file
		}

		pos = readStart + overlap
	}

	return 0, fmt.Errorf("PyInstaller magic cookie not found")
}

func findCookieInData(data []byte) (int, error) {
	idx := bytes.LastIndex(data, Magic)
	if idx < 0 {
		return 0, fmt.Errorf("PyInstaller magic cookie not found")
	}
	return idx, nil
}

func parseCookie21(cookie []byte, result *PyInstBinary, data []byte) bool {
	if len(cookie) < Cookie21Size {
		return false
	}

	// 2.1+ format: !8sIIii64s (big-endian)
	pkgLen := binary.BigEndian.Uint32(cookie[8:12])
	tocOff := binary.BigEndian.Uint32(cookie[12:16])
	tocLen := int32(binary.BigEndian.Uint32(cookie[16:20]))
	pyver := int32(binary.BigEndian.Uint32(cookie[20:24]))
	pylibname := strings.TrimRight(string(cookie[24:88]), "\x00")

	if tocLen <= 0 || tocLen > 100*1024*1024 {
		return false
	}
	if pylibname == "" {
		return false // probably not 2.1+ format
	}

	result.PyLibName = pylibname
	result.PyVersion = decodePyVer(pyver)

	// SEC: pkgLen must be within the data buffer to prevent a negative or OOB OverlayPos.
	if pkgLen == 0 || uint64(pkgLen) > uint64(len(data)) {
		return false
	}

	// Calculate overlay position
	tailBytes := int64(len(data)) - result.CookiePos - Cookie21Size
	result.OverlayPos = int64(len(data)) - int64(pkgLen) - tailBytes

	parseTOC(data, result, int64(tocOff), int(tocLen))

	return true
}

func parseCookie20(cookie []byte, result *PyInstBinary, data []byte) bool {
	if len(cookie) < Cookie20Size {
		return false
	}

	// 2.0 format: !8siiii (big-endian, signed)
	pkgLen := int32(binary.BigEndian.Uint32(cookie[8:12]))
	tocOff := int32(binary.BigEndian.Uint32(cookie[12:16]))
	tocLen := int32(binary.BigEndian.Uint32(cookie[16:20]))
	pyver := int32(binary.BigEndian.Uint32(cookie[20:24]))

	if tocLen <= 0 || tocLen > 100*1024*1024 {
		return false
	}

	// SEC: pkgLen must be positive and within the actual data buffer so that
	// int64(len(data)) - int64(pkgLen) does not produce a negative or out-of-range
	// OverlayPos (int32 sign bit → huge positive offset → OOB slice downstream).
	if pkgLen <= 0 || int64(pkgLen) > int64(len(data)) {
		return false
	}

	result.PyVersion = decodePyVer(pyver)

	tailBytes := int64(len(data)) - result.CookiePos - Cookie20Size
	result.OverlayPos = int64(len(data)) - int64(pkgLen) - tailBytes

	parseTOC(data, result, int64(tocOff), int(tocLen))

	return true
}

func parseTOC(data []byte, result *PyInstBinary, tocOff int64, tocLen int) {
	tocStart := result.OverlayPos + tocOff
	if tocStart < 0 || int(tocStart) >= len(data) {
		return
	}

	pos := int(tocStart)
	end := min(pos+tocLen, len(data))

	for pos < end {
		if pos+4 > len(data) {
			break
		}

		entrySize := int(int32(binary.BigEndian.Uint32(data[pos : pos+4])))
		if entrySize < 18 || entrySize > 65536 || pos+entrySize > end {
			break
		}

		entry := data[pos+4 : pos+entrySize]
		if len(entry) < 14 {
			break
		}

		toc := TOCEntry{
			Position:         binary.BigEndian.Uint32(entry[0:4]),
			CompressedSize:   binary.BigEndian.Uint32(entry[4:8]),
			UncompressedSize: binary.BigEndian.Uint32(entry[8:12]),
			IsCompressed:     entry[12] == 1,
			TypeFlag:         string(entry[13:14]),
		}

		name := strings.TrimRight(string(entry[14:]), "\x00")
		toc.Name = name
		toc.TypeDesc = typeDescription(toc.TypeFlag)

		result.Entries = append(result.Entries, toc)

		if toc.TypeFlag == "s" {
			// Entry point script
			if !isBootstrapScript(name) {
				result.MainScripts = append(result.MainScripts, name)
			}
		}

		pos += entrySize
	}

	result.EntryCount = len(result.Entries)
}

func extractEntry(data []byte, overlayPos int64, entry TOCEntry) []byte {
	start := overlayPos + int64(entry.Position)
	end := start + int64(entry.CompressedSize)
	if start < 0 || int(end) > len(data) || start >= end {
		return nil
	}

	raw := data[start:end]

	if entry.IsCompressed {
		r, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return raw // return compressed if can't decompress
		}
		defer func() { _ = r.Close() }()

		// SEC #20: bound the decompressed output to a hard ceiling. The zlib
		// stream may inflate to many GiB from a tiny compressed payload, and
		// entry.UncompressedSize is attacker-controlled so it cannot be trusted
		// as the bound. ReadAllLimit reads cap+1 and rejects on overflow, so a
		// lying small UncompressedSize cannot disable the guard. Skip the
		// poisoned entry (return nil) rather than aborting the whole extract.
		decompressed, err := safeio.ReadAllLimit(r, maxPyinstEntryBytes)
		if err != nil {
			if errors.Is(err, safeio.ErrLimitExceeded) {
				slog.Warn("pyinst: skipping entry exceeding decompression cap",
					"name", entry.Name, "cap", maxPyinstEntryBytes)
				return nil
			}
			return raw
		}
		return decompressed
	}

	return raw
}

// fixPycHeader ensures a PYC file has a valid header.
// PyInstaller 5.3+ strips the header from stored .pyc files.
func fixPycHeader(data []byte, pyver string) []byte {
	if len(data) < 4 {
		return data
	}

	// Check if header is already present (magic number ends with \r\n)
	if len(data) >= 4 && data[2] == '\r' && data[3] == '\n' {
		return data // header intact
	}

	// Need to reconstruct header
	// Use a generic Python 3.x magic and zero timestamps
	// The actual magic depends on the Python version
	header := pycMagic(pyver)

	result := make([]byte, 0, len(header)+len(data))
	result = append(result, header...)
	result = append(result, data...)
	return result
}

func pycMagic(pyver string) []byte {
	// Return appropriate PYC header based on Python version
	// Format: 2-byte magic + \r\n + flags/timestamp
	switch {
	case strings.HasPrefix(pyver, "3.13"):
		// Python 3.13: magic 3571
		return []byte{0xf3, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case strings.HasPrefix(pyver, "3.12"):
		return []byte{0xcb, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case strings.HasPrefix(pyver, "3.11"):
		return []byte{0xa7, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case strings.HasPrefix(pyver, "3.10"):
		return []byte{0x6f, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case strings.HasPrefix(pyver, "3.9"):
		return []byte{0x61, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case strings.HasPrefix(pyver, "3.8"):
		return []byte{0x55, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case strings.HasPrefix(pyver, "3.7"):
		return []byte{0x42, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case strings.HasPrefix(pyver, "3.6"):
		return []byte{0x33, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case strings.HasPrefix(pyver, "3.5"):
		return []byte{0x17, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case strings.HasPrefix(pyver, "3.4"):
		return []byte{0xee, 0x0c, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	default:
		// Generic Python 3.8+ (16-byte header)
		return []byte{0x55, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	}
}

// extractPYZ extracts the contents of a PYZ archive.
func extractPYZ(data []byte, outputDir string, pyver string, verbose bool) {
	if len(data) < 12 {
		return
	}

	// PYZ header: magic(4) + pycMagic(4) + tocPosition(4)
	if string(data[:4]) != "PYZ\x00" {
		return
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return
	}

	// The PYZ TOC is a marshaled Python object at the given position.
	// Since we can't easily unmarshal Python objects in Go, we extract
	// what we can and note that full PYZ extraction requires Python.
	if verbose {
		fmt.Printf("  PYZ archive detected (%d bytes) — full extraction requires Python marshal\n", len(data))
		fmt.Printf("  Use: python -c \"import marshal,zlib; ...\" for deep PYZ extraction\n")
	}

	// Write the raw PYZ for later processing with Python
	pyzPath := filepath.Join(outputDir, "_raw.pyz")
	_ = os.WriteFile(pyzPath, data, 0o644)

	// Write a helper Python script for extraction
	script := fmt.Sprintf(`#!/usr/bin/env python3
"""Auto-generated PYZ extractor. Run with the same Python version as the target (%s)."""
import marshal, zlib, struct, os, sys

pyz_path = %q
with open(pyz_path, 'rb') as f:
    magic = f.read(4)
    assert magic == b'PYZ\x00', f"Not a PYZ archive: {magic!r}"
    pyc_magic = f.read(4)
    toc_pos = struct.unpack('!i', f.read(4))[0]
    f.seek(toc_pos)
    try:
        toc = marshal.load(f)
    except Exception as e:
        print(f"Failed to unmarshal TOC: {e}")
        sys.exit(1)

    if isinstance(toc, list):
        toc = dict(toc)

    out_dir = os.path.dirname(pyz_path)
    count = 0
    for name, (ispkg, pos, length) in toc.items():
        f.seek(pos)
        raw = f.read(length)
        try:
            decompressed = zlib.decompress(raw)
        except:
            ext = '.pyc.encrypted'
            decompressed = raw
        else:
            ext = '.pyc'

        parts = name.replace('.', os.sep)
        if ispkg:
            outpath = os.path.join(out_dir, parts, '__init__' + ext)
        else:
            outpath = os.path.join(out_dir, parts + ext)

        os.makedirs(os.path.dirname(outpath), exist_ok=True)

        # Add PYC header
        with open(outpath, 'wb') as out:
            out.write(pyc_magic)
            out.write(b'\x00' * 12)  # timestamp + size (Python 3.7+)
            out.write(decompressed)

        count += 1

    print(f"Extracted {count} modules from PYZ archive")
`, pyver, filepath.ToSlash(pyzPath))

	scriptPath := filepath.Join(outputDir, "extract_pyz.py")
	_ = os.WriteFile(scriptPath, []byte(script), 0o644)
}

func decodePyVer(ver int32) string {
	if ver >= 100 {
		return fmt.Sprintf("%d.%d", ver/100, ver%100)
	}
	return fmt.Sprintf("%d.%d", ver/10, ver%10)
}

func typeDescription(t string) string {
	switch t {
	case "d":
		return "dependency"
	case "o":
		return "runtime-option"
	case "s":
		return "source"
	case "M":
		return "package"
	case "m":
		return "module"
	case "z", "Z":
		return "PYZ"
	case "b":
		return "binary"
	case "x":
		return "data"
	case "n":
		return "namespace-pkg"
	default:
		return "data"
	}
}

func isBootstrapScript(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{
		"pyiboot01_bootstrap",
		"pyi_rth_",
		"pyimod",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func sanitizeName(name string) string {
	// Remove path traversal and null bytes
	name = strings.ReplaceAll(name, "\x00", "")
	name = strings.ReplaceAll(name, "..", "_")
	name = filepath.Clean(name)
	return name
}

func writeMetadata(outputDir string, result *PyInstBinary) {
	var meta strings.Builder
	meta.WriteString(fmt.Sprintf(`{
  "source": %q,
  "is_pyinstaller": true,
  "python_version": %q,
  "python_lib": %q,
  "installer_version": %q,
  "entry_count": %d,
  "main_scripts": [`, result.Name, result.PyVersion, result.PyLibName, result.InstallerVer, result.EntryCount))

	for i, s := range result.MainScripts {
		if i > 0 {
			meta.WriteString(",")
		}
		meta.WriteString(fmt.Sprintf("%q", s))
	}

	meta.WriteString(fmt.Sprintf(`],
  "overlay_position": %d,
  "cookie_position": %d
}
`, result.OverlayPos, result.CookiePos))

	metaPath := filepath.Join(outputDir, "UNRAVEL_META.json")
	_ = os.WriteFile(metaPath, []byte(meta.String()), 0o644)
}
