/*
Copyright (c) 2026 Security Research
*/
package nsis

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildMinimalPE constructs a minimal valid PE file that debug/pe.Open can parse,
// with one .text section of sectionRawSize bytes. After the section data, the
// caller-supplied overlay bytes are appended. The PE uses optional header size 0
// so debug/pe treats it as having no optional header.
func buildMinimalPE(t *testing.T, overlay []byte, sectionRawSize uint32) string {
	t.Helper()

	// Layout:
	//   0x00: DOS header (64 bytes), e_lfanew = 64
	//   0x40: PE signature (4 bytes)
	//   0x44: COFF header (20 bytes) - 1 section, SizeOfOptionalHeader=0
	//   0x58: Section header (40 bytes) - .text
	//   0x80: padding to PointerToRawData (aligned to 0x80 = 128)
	//   0x80: section raw data (sectionRawSize bytes)
	//   0x80+sectionRawSize: overlay

	const (
		dosSize    = 64
		peSigSize  = 4
		coffSize   = 20
		secHdrSize = 40
		hdrEnd     = dosSize + peSigSize + coffSize + secHdrSize // 128 = 0x80
	)

	sectionOffset := uint32(hdrEnd) // section data starts right after headers
	if sectionRawSize < 1 {
		sectionRawSize = 16
	}

	totalSize := int(sectionOffset) + int(sectionRawSize) + len(overlay)
	buf := make([]byte, totalSize)

	// DOS header
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], dosSize) // e_lfanew -> 64

	// PE signature at offset 64
	off := dosSize
	buf[off] = 'P'
	buf[off+1] = 'E'
	buf[off+2] = 0
	buf[off+3] = 0

	// COFF header at offset 68
	coff := off + peSigSize
	binary.LittleEndian.PutUint16(buf[coff:], 0x14C) // Machine: i386
	binary.LittleEndian.PutUint16(buf[coff+2:], 1)   // NumberOfSections
	binary.LittleEndian.PutUint16(buf[coff+16:], 0)  // SizeOfOptionalHeader = 0

	// Section header at offset 88
	sec := coff + coffSize
	copy(buf[sec:], ".text\x00\x00\x00")                        // Name
	binary.LittleEndian.PutUint32(buf[sec+8:], sectionRawSize)  // VirtualSize
	binary.LittleEndian.PutUint32(buf[sec+12:], 0x1000)         // VirtualAddress
	binary.LittleEndian.PutUint32(buf[sec+16:], sectionRawSize) // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[sec+20:], sectionOffset)  // PointerToRawData

	// Section data is zeros (already zeroed)

	// Overlay
	copy(buf[int(sectionOffset)+int(sectionRawSize):], overlay)

	tmp := filepath.Join(t.TempDir(), "test.exe")
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		t.Fatalf("write PE: %v", err)
	}

	return tmp
}

// buildNSISOverlay builds an NSIS overlay blob:
//
//	flags(4) + DEADBEEF(4) + headerSize(4) + scriptSize(4) + extra...
func buildNSISOverlay(flags uint32, headerSize uint32, scriptSize uint32, extra []byte) []byte {
	buf := make([]byte, 16+len(extra))
	binary.LittleEndian.PutUint32(buf[0:], flags)
	binary.LittleEndian.PutUint32(buf[4:], nsisMagic)
	binary.LittleEndian.PutUint32(buf[8:], headerSize)
	binary.LittleEndian.PutUint32(buf[12:], scriptSize)
	copy(buf[16:], extra)
	return buf
}

func TestIsNSIS_RegularFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "regular.txt")
	if err := os.WriteFile(tmp, []byte("hello world"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	if IsNSIS(tmp) {
		t.Error("expected false for regular text file")
	}
}

func TestIsNSIS_NonExistent(t *testing.T) {
	if IsNSIS("/nonexistent/file.exe") {
		t.Error("expected false for non-existent file")
	}
}

func TestIsNSIS_PEWithoutNSIS(t *testing.T) {
	// PE with no overlay (section fills to end of file)
	path := buildMinimalPE(t, nil, 64)
	if IsNSIS(path) {
		t.Error("expected false for PE without NSIS overlay")
	}
}

func TestIsNSIS_PEWithNSISMagic(t *testing.T) {
	overlay := buildNSISOverlay(0x00, 1024, 512, nil)
	path := buildMinimalPE(t, overlay, 64)
	if !IsNSIS(path) {
		t.Error("expected true for PE with NSIS magic overlay")
	}
}

func TestIsNSIS_PEWithNullsoftMarker(t *testing.T) {
	// Overlay has NullsoftInst string but no DEADBEEF magic
	overlay := make([]byte, 128)
	copy(overlay[16:], []byte("NullsoftInst"))
	path := buildMinimalPE(t, overlay, 64)
	if !IsNSIS(path) {
		t.Error("expected true for PE with NullsoftInst marker")
	}
}

func TestIsNSIS_PEWithOverlayNoMagic(t *testing.T) {
	// Overlay exists but has no NSIS signatures
	overlay := make([]byte, 128)
	for i := range overlay {
		overlay[i] = 0x41 // 'A'
	}
	path := buildMinimalPE(t, overlay, 64)
	if IsNSIS(path) {
		t.Error("expected false for PE with non-NSIS overlay")
	}
}

func TestInfo_NonExistent(t *testing.T) {
	_, err := Info("/nonexistent/path/file.exe")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestInfo_NotPE(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "notpe.bin")
	if err := os.WriteFile(tmp, []byte("this is not a PE file at all"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err := Info(tmp)
	if err == nil {
		t.Error("expected error for non-PE file")
	}
}

func TestInfo_PENoOverlay(t *testing.T) {
	// PE where section ends exactly at file end -> overlay offset == file size
	path := buildMinimalPE(t, nil, 64)
	_, err := Info(path)
	if err == nil {
		t.Error("expected error for PE with no overlay")
	}
}

func TestInfo_PEWithNSISOverlay_Zlib(t *testing.T) {
	// flags=0x00 -> compression=zlib, not solid
	extra := []byte("Uninstall this application\x00https://example.com/update\x00C:\\Program Files\\App\\test.dll\x00")
	overlay := buildNSISOverlay(0x00, 2048, 1024, extra)
	// Pad overlay to be > 16 bytes before magic so magicOffset >= 12 triggers version heuristic
	padded := make([]byte, 16)
	padded = append(padded, overlay...)
	path := buildMinimalPE(t, padded, 64)

	result, err := Info(path)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Compression != "zlib" {
		t.Errorf("compression = %q, want zlib", result.Compression)
	}
	if result.IsSolid {
		t.Error("expected IsSolid=false")
	}
	if !result.HasUninstall {
		t.Error("expected HasUninstall=true")
	}
	if result.HeaderSize != 2048 {
		t.Errorf("HeaderSize = %d, want 2048", result.HeaderSize)
	}
	if result.ScriptSize != 1024 {
		t.Errorf("ScriptSize = %d, want 1024", result.ScriptSize)
	}
	if result.NSISVersion != "NSIS 2.x" {
		t.Errorf("NSISVersion = %q, want NSIS 2.x", result.NSISVersion)
	}
	if result.DataSize <= 0 {
		t.Error("expected positive DataSize")
	}
	if result.FileName == "" {
		t.Error("expected non-empty FileName")
	}
	// Check that strings were extracted
	if len(result.Strings) == 0 {
		t.Error("expected extracted strings")
	}
}

func TestInfo_PEWithNSISOverlay_Bzip2(t *testing.T) {
	// flags=0x01 -> bzip2
	extra := []byte("some data padding to fill\x00")
	overlay := buildNSISOverlay(0x01, 512, 256, extra)
	padded := make([]byte, 16)
	padded = append(padded, overlay...)
	path := buildMinimalPE(t, padded, 64)

	result, err := Info(path)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Compression != "bzip2" {
		t.Errorf("compression = %q, want bzip2", result.Compression)
	}
}

func TestInfo_PEWithNSISOverlay_LZMA_Solid(t *testing.T) {
	// flags=0x12 -> compression=lzma (0x02), solid (bit 4 set)
	overlay := buildNSISOverlay(0x12, 4096, 2048, nil)
	padded := make([]byte, 16)
	padded = append(padded, overlay...)
	path := buildMinimalPE(t, padded, 64)

	result, err := Info(path)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Compression != "lzma" {
		t.Errorf("compression = %q, want lzma", result.Compression)
	}
	if !result.IsSolid {
		t.Error("expected IsSolid=true")
	}
	if result.NSISVersion != "NSIS 3.x" {
		t.Errorf("NSISVersion = %q, want NSIS 3.x", result.NSISVersion)
	}
}

func TestInfo_PEWithNSISOverlay_UnknownCompression(t *testing.T) {
	// flags=0x05 -> compression=unknown(5)
	overlay := buildNSISOverlay(0x05, 100, 50, nil)
	padded := make([]byte, 16)
	padded = append(padded, overlay...)
	path := buildMinimalPE(t, padded, 64)

	result, err := Info(path)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Compression != "unknown(5)" {
		t.Errorf("compression = %q, want unknown(5)", result.Compression)
	}
}

func TestInfo_PEWithNullsoftMarkerOnly(t *testing.T) {
	// Overlay has NullsoftInst but no DEADBEEF magic
	overlay := make([]byte, 128)
	copy(overlay[32:], []byte("NullsoftInst"))
	path := buildMinimalPE(t, overlay, 64)

	result, err := Info(path)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.NSISVersion != "NSIS (version unknown)" {
		t.Errorf("NSISVersion = %q, want NSIS (version unknown)", result.NSISVersion)
	}
}

func TestInfo_PEWithNoNSISSignature(t *testing.T) {
	// Overlay with no magic and no NullsoftInst -> error
	overlay := make([]byte, 128)
	for i := range overlay {
		overlay[i] = 0x41
	}
	path := buildMinimalPE(t, overlay, 64)

	_, err := Info(path)
	if err == nil {
		t.Error("expected error for overlay without NSIS signature")
	}
}

func TestInfo_MagicAtOffset0(t *testing.T) {
	// Magic at very start of overlay (offset 0), so magicOffset=0 < 4
	// This means flags can't be read, falls through to NullsoftInst check
	overlay := make([]byte, 64)
	binary.LittleEndian.PutUint32(overlay[0:], nsisMagic)
	// No NullsoftInst marker -> should error
	path := buildMinimalPE(t, overlay, 64)

	_, err := Info(path)
	if err == nil {
		t.Error("expected error when magic at offset 0 and no NullsoftInst")
	}
}

func TestExtract_NonExistent(t *testing.T) {
	_, err := Extract("/nonexistent/path/file.exe", t.TempDir())
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestExtract_No7z(t *testing.T) {
	if Is7zAvailable() {
		t.Skip("7z is available, cannot test missing-7z path")
	}

	tmp := filepath.Join(t.TempDir(), "test.exe")
	if err := os.WriteFile(tmp, []byte("MZ"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := Extract(tmp, t.TempDir())
	if err == nil {
		t.Error("expected error when 7z not available")
	}
}

func TestExtract_DefaultOutputDir(t *testing.T) {
	if Is7zAvailable() {
		t.Skip("7z available; would actually extract")
	}

	tmp := filepath.Join(t.TempDir(), "setup.exe")
	if err := os.WriteFile(tmp, []byte("MZ"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// With empty outputDir, Extract generates one from filename
	_, err := Extract(tmp, "")
	if err == nil {
		t.Error("expected error (7z missing)")
	}
}

func TestIs7zAvailable(t *testing.T) {
	_ = Is7zAvailable()
}

func TestFindOverlayOffset_NotPE(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "notpe.bin")
	if err := os.WriteFile(tmp, []byte("not a PE file"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := findOverlayOffset(tmp)
	if err == nil {
		t.Error("expected error for non-PE file")
	}
}

func TestFindOverlayOffset_ValidPE(t *testing.T) {
	path := buildMinimalPE(t, []byte("overlay data here"), 64)
	off, err := findOverlayOffset(path)
	if err != nil {
		t.Fatalf("findOverlayOffset: %v", err)
	}

	// Section at offset 128 (0x80), raw size 64 -> overlay at 192
	expected := int64(128 + 64)
	if off != expected {
		t.Errorf("offset = %d, want %d", off, expected)
	}
}

func TestExtractNotableStrings_Basic(t *testing.T) {
	// Build a buffer with notable strings separated by null bytes
	parts := []string{
		"C:\\Program Files\\MyApp\\app.exe",
		"https://example.com/api/v1",
		"HKEY_CURRENT_USER\\Software\\MyApp",
		"kernel32.dll",
		"$INSTDIR\\resources",
		"short",   // too short (<8 chars) -> excluded
		"aaaaaaa", // 7 chars, not notable
	}

	var buf []byte
	for _, p := range parts {
		buf = append(buf, []byte(p)...)
		buf = append(buf, 0x00) // null separator
	}

	result := extractNotableStrings(buf)
	if len(result) != 5 {
		t.Errorf("got %d strings, want 5: %v", len(result), result)
	}
}

func TestExtractNotableStrings_Dedup(t *testing.T) {
	s := "C:\\Program Files\\App\\setup.exe"
	var buf []byte
	for range 5 {
		buf = append(buf, []byte(s)...)
		buf = append(buf, 0x00)
	}

	result := extractNotableStrings(buf)
	if len(result) != 1 {
		t.Errorf("expected 1 deduped string, got %d", len(result))
	}
}

func TestExtractNotableStrings_Limit50(t *testing.T) {
	var buf []byte
	for i := range 60 {
		s := []byte("C:\\unique\\path" + string(rune('A'+i%26)) + string(rune('a'+i/26)) + "\\file.exe")
		buf = append(buf, s...)
		buf = append(buf, 0x00)
	}

	result := extractNotableStrings(buf)
	if len(result) > 50 {
		t.Errorf("expected max 50, got %d", len(result))
	}
}

func TestExtractNotableStrings_Empty(t *testing.T) {
	result := extractNotableStrings(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 strings for nil input, got %d", len(result))
	}
}

func TestExtractNotableStrings_NoNullTerminator(t *testing.T) {
	// String at end of buffer without null terminator should still be flushed
	buf := []byte("https://example.com/endpoint")
	result := extractNotableStrings(buf)
	if len(result) != 1 {
		t.Errorf("expected 1 string, got %d: %v", len(result), result)
	}
}

func TestIsNotableString(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{`C:\Program Files\App`, true},
		{`https://example.com`, true},
		{`http://example.com`, true},
		{`kernel32.dll`, true},
		{`setup.exe`, true},
		{`HKEY_LOCAL_MACHINE`, true},
		{`software\microsoft`, true},
		{`$INSTDIR\app.exe`, true},
		{`$outdir/test`, true},
		{`$pluginsdir`, true},
		{`uninstall string`, true},
		{`nsisdl plugin`, true},
		{`nsexec calls`, true},
		{`randomstring`, false},
		{`justaword`, false},
		{`path/to/file`, true}, // has forward slash
	}

	for _, tt := range tests {
		got := isNotableString(tt.input)
		if got != tt.want {
			t.Errorf("isNotableString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
