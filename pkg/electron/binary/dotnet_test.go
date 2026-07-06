/*
Copyright (c) 2026 Security Research
*/
package binary

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// isDotNetBinary
// ---------------------------------------------------------------------------

func TestIsDotNetBinary_WithDepsJSON(t *testing.T) {
	dir := t.TempDir()

	// Create a minimal PE file
	pePath := filepath.Join(dir, "app.exe")
	writeFakePE(t, pePath, false)

	// Without .deps.json, should not be detected
	if isDotNetBinary(pePath) {
		t.Error("expected false without .deps.json sibling")
	}

	// Create a .deps.json sibling
	depsPath := filepath.Join(dir, "app.deps.json")
	if err := os.WriteFile(depsPath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	if !isDotNetBinary(pePath) {
		t.Error("expected true with .deps.json sibling")
	}
}

func TestIsDotNetBinary_WithRuntimeConfig(t *testing.T) {
	dir := t.TempDir()
	pePath := filepath.Join(dir, "app.exe")
	writeFakePE(t, pePath, false)

	rcPath := filepath.Join(dir, "app.runtimeconfig.json")
	if err := os.WriteFile(rcPath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	if !isDotNetBinary(pePath) {
		t.Error("expected true with .runtimeconfig.json sibling")
	}
}

func TestIsDotNetBinary_NonDotNet(t *testing.T) {
	dir := t.TempDir()
	pePath := filepath.Join(dir, "app.exe")
	writeFakePE(t, pePath, false)

	if isDotNetBinary(pePath) {
		t.Error("expected false for non-.NET PE without markers")
	}
}

// ---------------------------------------------------------------------------
// filterDotNetStrings
// ---------------------------------------------------------------------------

func TestFilterDotNetStrings_RemovesNoise(t *testing.T) {
	noise := []string{
		// Assembly opcodes
		"mov eax, [rbx+0x10]",
		"push rbp",
		"pop rdi",
		"call 0x401000",
		"ret ",
		"jmp label1",
		"xor eax, eax",
		"lea rax, [rsp+0x20]",
		// Hex blobs
		"0xDEADBEEF",
		"4a6f686e446f65313233343536373839",
		// Repeated chars
		"AAAAAAAA",
		"--------",
		// Too short
		"ab",
		"xyz",
		// Binary noise — no vowels
		"bcdfjklm",
		// .NET compiler noise
		"CompilerGenerated_stuff",
		"<Module>",
		// Pure numbers
		"12345678",
	}

	meaningful := []string{
		"https://api.surfshark.com/v1/auth",
		"ConnectionString",
		"/api/v1/users",
		"System.Net.Http.HttpClient",
		"ApplicationSettings",
		"Failed to connect to server",
		"C:\\Program Files\\Surfshark\\config.json",
		"SELECT * FROM users WHERE id = @id",
	}

	allStrings := append(noise, meaningful...)

	filtered, total := filterDotNetStrings("", allStrings, len(allStrings), 25)

	// All meaningful strings should be preserved
	if total <= 0 {
		t.Errorf("expected positive meaningful total, got %d", total)
	}

	// Check that filtered output contains meaningful strings (not noise)
	filteredSet := make(map[string]bool)
	for _, s := range filtered {
		filteredSet[s] = true
	}

	for _, m := range meaningful {
		if !filteredSet[m] {
			t.Errorf("expected meaningful string %q to be in filtered output", m)
		}
	}

	// Check that noise strings are NOT in filtered output
	for _, n := range noise {
		if filteredSet[n] {
			t.Errorf("expected noise string %q to NOT be in filtered output", n)
		}
	}
}

func TestFilterDotNetStrings_PrioritizesURLs(t *testing.T) {
	strings := []string{
		"SomeClassName",
		"https://example.com/api/v1",
		"AnotherClass",
		"/api/health",
	}

	filtered, _ := filterDotNetStrings("", strings, len(strings), 25)

	if len(filtered) == 0 {
		t.Fatal("expected non-empty filtered output")
	}

	// URL should come first due to priority ordering
	if filtered[0] != "https://example.com/api/v1" {
		t.Errorf("expected URL first, got %q", filtered[0])
	}
}

// ---------------------------------------------------------------------------
// ExtractDotNetMetadata
// ---------------------------------------------------------------------------

func TestExtractDotNetMetadata_NilForNonDotNet(t *testing.T) {
	dir := t.TempDir()
	pePath := filepath.Join(dir, "plain.exe")
	writeFakePE(t, pePath, false)

	meta := ExtractDotNetMetadata(pePath)
	if meta != nil {
		t.Error("expected nil metadata for non-.NET PE")
	}
}

func TestExtractDotNetMetadata_WithCLRHeader(t *testing.T) {
	dir := t.TempDir()
	pePath := filepath.Join(dir, "dotnet.exe")
	writeFakePEWithCLR(t, pePath)

	meta := ExtractDotNetMetadata(pePath)
	if meta == nil {
		t.Fatal("expected non-nil metadata for .NET PE")
	}
	if !meta.IsDotNet {
		t.Error("expected IsDotNet=true")
	}
}

// ---------------------------------------------------------------------------
// extractAllStrings
// ---------------------------------------------------------------------------

func TestExtractAllStrings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")

	// Write binary data with embedded strings
	data := []byte{0x00, 0x01}
	data = append(data, []byte("Hello World")...)
	data = append(data, 0x00)
	data = append(data, []byte("Short")...)
	data = append(data, 0x00)
	data = append(data, []byte("abc")...) // too short for minLen=6
	data = append(data, 0x00)
	data = append(data, []byte("LongEnoughString")...)
	data = append(data, 0x00)

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	strs := extractAllStrings(path, 1024, 6)

	if len(strs) != 2 {
		t.Fatalf("expected 2 strings (minLen=6), got %d: %v", len(strs), strs)
	}
	if strs[0] != "Hello World" {
		t.Errorf("strs[0] = %q, want %q", strs[0], "Hello World")
	}
	if strs[1] != "LongEnoughString" {
		t.Errorf("strs[1] = %q, want %q", strs[1], "LongEnoughString")
	}
}

func TestExtractAllStrings_MaxBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")

	data := []byte("FirstString\x00")
	// Add data past 20 bytes to test maxBytes cutoff
	for len(data) < 20 {
		data = append(data, 0x00)
	}
	data = append(data, []byte("SecondString\x00")...)

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	strs := extractAllStrings(path, 15, 6)

	if len(strs) != 1 {
		t.Fatalf("expected 1 string with maxBytes=15, got %d: %v", len(strs), strs)
	}
	if strs[0] != "FirstString" {
		t.Errorf("strs[0] = %q, want %q", strs[0], "FirstString")
	}
}

// ---------------------------------------------------------------------------
// dedupLimit
// ---------------------------------------------------------------------------

func TestDedupLimit(t *testing.T) {
	tests := []struct {
		name  string
		in    []string
		limit int
		want  int
	}{
		{"empty", nil, 10, 0},
		{"no dups", []string{"a", "b", "c"}, 10, 3},
		{"with dups", []string{"a", "b", "a", "c", "b"}, 10, 3},
		{"limited", []string{"a", "b", "c", "d"}, 2, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupLimit(tt.in, tt.limit)
			if len(got) != tt.want {
				t.Errorf("dedupLimit(%v, %d) len = %d, want %d", tt.in, tt.limit, len(got), tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// writeFakePE writes a minimal valid PE file (MZ header + COFF + optional header).
func writeFakePE(t *testing.T, path string, _ bool) {
	t.Helper()

	buf := make([]byte, 512)

	// DOS header: MZ magic
	buf[0] = 'M'
	buf[1] = 'Z'
	// e_lfanew: offset to PE signature
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x80)

	// PE signature at 0x80
	copy(buf[0x80:], []byte("PE\x00\x00"))

	// COFF header at 0x84
	binary.LittleEndian.PutUint16(buf[0x84:], 0x8664) // Machine: AMD64
	binary.LittleEndian.PutUint16(buf[0x86:], 0)      // NumberOfSections
	binary.LittleEndian.PutUint16(buf[0x94:], 0xF0)   // SizeOfOptionalHeader

	// Optional header at 0x98
	binary.LittleEndian.PutUint16(buf[0x98:], 0x20B) // PE32+ magic
	// NumberOfRvaAndSizes at offset 0x98 + 108 = 0x104
	binary.LittleEndian.PutUint32(buf[0x104:], 16)

	// Data directories start at 0x98 + 112 = 0x108
	// 14th entry (COM Descriptor) at offset 0x108 + 14*8 = 0x108 + 112 = 0x178
	// Leave it at zero for non-.NET

	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
}

// writeFakePEWithCLR writes a minimal PE file with a non-zero CLR data directory entry.
func writeFakePEWithCLR(t *testing.T, path string) {
	t.Helper()

	buf := make([]byte, 512)

	// DOS header: MZ magic
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x80)

	// PE signature
	copy(buf[0x80:], []byte("PE\x00\x00"))

	// COFF header
	binary.LittleEndian.PutUint16(buf[0x84:], 0x8664) // Machine: AMD64
	binary.LittleEndian.PutUint16(buf[0x86:], 0)      // NumberOfSections
	binary.LittleEndian.PutUint16(buf[0x94:], 0xF0)   // SizeOfOptionalHeader

	// Optional header
	binary.LittleEndian.PutUint16(buf[0x98:], 0x20B) // PE32+ magic
	binary.LittleEndian.PutUint32(buf[0x104:], 16)   // NumberOfRvaAndSizes

	// COM Descriptor data directory (14th entry)
	// Offset: 0x108 + 14*8 = 0x178
	binary.LittleEndian.PutUint32(buf[0x178:], 0x2000) // VirtualAddress (non-zero)
	binary.LittleEndian.PutUint32(buf[0x17C:], 72)     // Size (non-zero)

	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
}
