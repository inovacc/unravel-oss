/* Copyright (c) 2026 Security Research */
package binary

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// --- findVersionString tests ---

func TestFindVersionString(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		key  string
		want string
	}{
		{
			name: "key not found",
			data: []byte("no version info here"),
			key:  "ProductName",
			want: "",
		},
		{
			name: "simple ASCII value",
			data: buildVersionEntry("ProductName", "MyApp"),
			key:  "ProductName",
			want: "MyApp",
		},
		{
			name: "empty value after key",
			data: buildVersionEntry("ProductName", ""),
			key:  "ProductName",
			want: "",
		},
		{
			name: "different keys",
			data: func() []byte {
				d := buildVersionEntry("CompanyName", "Acme Corp")
				d = append(d, buildVersionEntry("ProductName", "Widget")...)
				return d
			}(),
			key:  "ProductName",
			want: "Widget",
		},
		{
			name: "ProductVersion with dots",
			data: buildVersionEntry("ProductVersion", "1.2.3.4"),
			key:  "ProductVersion",
			want: "1.2.3.4",
		},
		{
			name: "FileDescription with spaces",
			data: buildVersionEntry("FileDescription", "My File Description"),
			key:  "FileDescription",
			want: "My File Description",
		},
		{
			name: "non-ASCII character replaced with question mark",
			data: func() []byte {
				key := utf16Encode("ProductName")
				// null terminator + padding to align
				entry := append(key, 0x00, 0x00)
				// Align to 4 bytes
				for len(entry)%4 != 0 {
					entry = append(entry, 0x00)
				}
				// Add a non-ASCII UTF-16LE char: U+00E9 (é) = 0xE9, 0x00
				// followed by ASCII 'x' and null terminator
				entry = append(entry, 0xE9, 0x00) // é -> should be ASCII, hi==0, lo=0xE9 >= 0x7f -> '?'
				entry = append(entry, 'x', 0x00)
				entry = append(entry, 0x00, 0x00)
				return entry
			}(),
			key:  "ProductName",
			want: "?x",
		},
		{
			name: "high byte non-zero replaced with question mark",
			data: func() []byte {
				key := utf16Encode("ProductName")
				entry := append(key, 0x00, 0x00)
				for len(entry)%4 != 0 {
					entry = append(entry, 0x00)
				}
				// Add char with high byte set: e.g. U+4E2D (中) = 0x2D, 0x4E
				entry = append(entry, 0x2D, 0x4E)
				entry = append(entry, 0x00, 0x00)
				return entry
			}(),
			key:  "ProductName",
			want: "?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findVersionString(tt.data, tt.key)
			if got != tt.want {
				t.Errorf("findVersionString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindVersionString_Truncated(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		key  string
		want string
	}{
		{
			name: "data ends right after key (no room for null terminator)",
			data: utf16Encode("ProductName"),
			key:  "ProductName",
			want: "",
		},
		{
			name: "data ends after null terminator but before value",
			data: func() []byte {
				key := utf16Encode("ProductName")
				// Just add the 2-byte null terminator, then nothing
				return append(key, 0x00, 0x00)
			}(),
			key:  "ProductName",
			want: "",
		},
		{
			name: "data ends after alignment padding",
			data: func() []byte {
				key := utf16Encode("ProductName")
				entry := append(key, 0x00, 0x00)
				// Add some padding but not enough for a value
				for len(entry)%4 != 0 {
					entry = append(entry, 0x00)
				}
				return entry
			}(),
			key:  "ProductName",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findVersionString(tt.data, tt.key)
			if got != tt.want {
				t.Errorf("findVersionString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindVersionString_AlignmentVariants(t *testing.T) {
	// Test that alignment to 4-byte boundary works for different key lengths
	keys := []string{"A", "AB", "ABC", "ABCD", "ABCDE"}
	for _, key := range keys {
		t.Run("key="+key, func(t *testing.T) {
			data := buildVersionEntry(key, "value")
			got := findVersionString(data, key)
			if got != "value" {
				t.Errorf("findVersionString(key=%q) = %q, want %q", key, got, "value")
			}
		})
	}
}

// --- extractPEVersionInfo tests ---

func TestExtractPEVersionInfo(t *testing.T) {
	t.Run("file not found", func(t *testing.T) {
		bi := &Info{}
		extractPEVersionInfo("/nonexistent/path", bi)
		if bi.ProductName != "" || bi.CompanyName != "" {
			t.Error("expected empty fields for nonexistent file")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "empty.exe")
		if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
			t.Fatal(err)
		}
		bi := &Info{}
		extractPEVersionInfo(path, bi)
		if bi.ProductName != "" {
			t.Error("expected empty ProductName for empty file")
		}
	})

	t.Run("file with version info", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "versioned.exe")

		// Build a file containing version string entries with proper alignment.
		// Each entry must be aligned on a 4-byte boundary within the file.
		var data []byte
		data = append(data, bytes.Repeat([]byte{0x00}, 100)...) // padding (100 bytes = 4-byte aligned)
		appendAligned := func(d *[]byte, entry []byte) {
			// Pad to 4-byte alignment before appending
			for len(*d)%4 != 0 {
				*d = append(*d, 0x00)
			}
			*d = append(*d, entry...)
		}
		appendAligned(&data, buildVersionEntry("ProductName", "TestApp"))
		appendAligned(&data, buildVersionEntry("ProductVersion", "2.0.1"))
		appendAligned(&data, buildVersionEntry("FileDescription", "Test Application"))
		appendAligned(&data, buildVersionEntry("CompanyName", "TestCo"))

		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}

		bi := &Info{}
		extractPEVersionInfo(path, bi)

		if bi.ProductName != "TestApp" {
			t.Errorf("ProductName = %q, want %q", bi.ProductName, "TestApp")
		}
		if bi.ProductVersion != "2.0.1" {
			t.Errorf("ProductVersion = %q, want %q", bi.ProductVersion, "2.0.1")
		}
		if bi.FileDescription != "Test Application" {
			t.Errorf("FileDescription = %q, want %q", bi.FileDescription, "Test Application")
		}
		if bi.CompanyName != "TestCo" {
			t.Errorf("CompanyName = %q, want %q", bi.CompanyName, "TestCo")
		}
	})

	t.Run("large file reads only last 256KB", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "large.exe")

		// Create a file larger than 256KB with version info at the end.
		// Ensure the version data starts at a 4-byte aligned offset within
		// the last 256KB window that extractPEVersionInfo reads.
		padding := make([]byte, 300*1024) // 300KB padding (4-byte aligned)
		versionData := buildVersionEntry("ProductName", "BigApp")

		var data []byte
		data = append(data, padding...)
		// Pad to 4-byte alignment before version entry
		for len(data)%4 != 0 {
			data = append(data, 0x00)
		}
		data = append(data, versionData...)

		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}

		bi := &Info{}
		extractPEVersionInfo(path, bi)

		if bi.ProductName != "BigApp" {
			t.Errorf("ProductName = %q, want %q (version info at end of large file)", bi.ProductName, "BigApp")
		}
	})

	t.Run("large file with version info only in first part (not found)", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "large_start.exe")

		// Put version info at the start, then pad to >256KB
		versionData := buildVersionEntry("ProductName", "EarlyApp")
		padding := make([]byte, 300*1024)

		var data []byte
		data = append(data, versionData...)
		data = append(data, padding...)

		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}

		bi := &Info{}
		extractPEVersionInfo(path, bi)

		// Version info is in the first part, but we only read the last 256KB
		// so it should NOT be found
		if bi.ProductName != "" {
			t.Errorf("ProductName = %q, want empty (version info is before the read window)", bi.ProductName)
		}
	})
}

// --- Analyze function tests (Windows-compatible) ---

func TestAnalyze_WithPEBinary(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE binary tests only on Windows")
	}

	binPath := buildTestBinary(t)
	dir := filepath.Dir(binPath)

	infos := Analyze(dir, false)

	if len(infos) == 0 {
		t.Fatal("expected at least one binary result from Analyze")
	}

	found := false
	for _, info := range infos {
		if info.Name == filepath.Base(binPath) {
			found = true
			if info.Type != "PE" {
				t.Errorf("Type = %q, want PE", info.Type)
			}
			if info.SizeBytes <= 0 {
				t.Error("expected SizeBytes > 0")
			}
			if info.Arch == "" {
				t.Error("expected non-empty Arch for PE")
			}
			break
		}
	}

	if !found {
		t.Errorf("test binary %q not found in Analyze results", filepath.Base(binPath))
	}
}

func TestAnalyze_VerboseOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE binary tests only on Windows")
	}

	binPath := buildTestBinary(t)
	dir := filepath.Dir(binPath)

	infos := Analyze(dir, true)
	if len(infos) == 0 {
		t.Fatal("expected at least one result")
	}
}

func TestAnalyze_SortedBySizeDescWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE binary tests only on Windows")
	}

	binPath := buildTestBinary(t)
	dir := filepath.Dir(binPath)

	infos := Analyze(dir, false)

	for i := 1; i < len(infos); i++ {
		if infos[i-1].SizeBytes < infos[i].SizeBytes {
			t.Errorf("results not sorted by size desc: index %d (%d) < index %d (%d)",
				i-1, infos[i-1].SizeBytes, i, infos[i].SizeBytes)
		}
	}
}

func TestAnalyze_SortStable_SameSize(t *testing.T) {
	// Test the name-based tiebreaker in sorting
	dir := t.TempDir()

	// Create two PE files of the same size
	data := make([]byte, 128*1024)
	data[0] = 'M'
	data[1] = 'Z'

	if err := os.WriteFile(filepath.Join(dir, "beta.exe"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "alpha.exe"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	infos := Analyze(dir, false)

	if len(infos) < 2 {
		// PE parsing may fail on these fake binaries, that's ok
		t.Skip("fake PE binaries not recognized")
	}

	// Same-sized files should be sorted by name ascending
	if infos[0].SizeBytes == infos[1].SizeBytes {
		if infos[0].Name > infos[1].Name {
			t.Errorf("same-size files should be sorted by name: %q > %q", infos[0].Name, infos[1].Name)
		}
	}
}

func TestAnalyze_SkipsNonBinaryMagic(t *testing.T) {
	dir := t.TempDir()

	// Large file with no binary magic
	data := make([]byte, 128*1024)
	for i := range data {
		data[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(dir, "notbin"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	infos := Analyze(dir, false)
	for _, info := range infos {
		if info.Name == "notbin" {
			t.Error("Analyze should skip files without binary magic")
		}
	}
}

func TestAnalyze_ELFBinaryOnAnyOS(t *testing.T) {
	dir := t.TempDir()

	// Create a large enough file (>64KB) with valid ELF header and .so extension
	elfData := buildMinimalELF64()
	data := make([]byte, 128*1024)
	copy(data, elfData)

	if err := os.WriteFile(filepath.Join(dir, "libtest.so"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	infos := Analyze(dir, false)
	found := false
	for _, info := range infos {
		if info.Name == "libtest.so" {
			found = true
			if info.Type != "ELF" {
				t.Errorf("Type = %q, want ELF", info.Type)
			}
			// Arch should be non-empty for a valid ELF
			if info.Arch == "" {
				t.Error("expected non-empty Arch for ELF")
			}
			break
		}
	}
	if !found {
		t.Error("expected to find libtest.so in Analyze results")
	}
}

func TestAnalyze_MachOBinaryOnAnyOS(t *testing.T) {
	dir := t.TempDir()

	// Create a large enough file (>64KB) with valid Mach-O header and .dylib extension
	machoData := buildMinimalMachO64()
	data := make([]byte, 128*1024)
	copy(data, machoData)

	if err := os.WriteFile(filepath.Join(dir, "libtest.dylib"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	infos := Analyze(dir, false)
	found := false
	for _, info := range infos {
		if info.Name == "libtest.dylib" {
			found = true
			if info.Type != "Mach-O" {
				t.Errorf("Type = %q, want Mach-O", info.Type)
			}
			if info.Arch == "" {
				t.Error("expected non-empty Arch for Mach-O")
			}
			break
		}
	}
	if !found {
		t.Error("expected to find libtest.dylib in Analyze results")
	}
}

func TestAnalyzeSingleFile_ELFSyntheticOnAnyOS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.elf")

	elfData := buildMinimalELF64()
	data := make([]byte, 128*1024)
	copy(data, elfData)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzeSingleFile(path, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for ELF")
	}
	if result.Type != "ELF" {
		t.Errorf("Type = %q, want ELF", result.Type)
	}
	if result.Arch == "" {
		t.Error("expected non-empty Arch")
	}
}

func TestAnalyzeSingleFile_MachOSyntheticOnAnyOS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.macho")

	machoData := buildMinimalMachO64()
	data := make([]byte, 128*1024)
	copy(data, machoData)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzeSingleFile(path, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for Mach-O")
	}
	if result.Type != "Mach-O" {
		t.Errorf("Type = %q, want Mach-O", result.Type)
	}
	if result.Arch == "" {
		t.Error("expected non-empty Arch")
	}
}

func TestAnalyzeSingleFile_VerboseOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verbose_test")

	elfData := buildMinimalELF64()
	data := make([]byte, 128*1024)
	copy(data, elfData)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// verbose=true should print without panicking
	result, err := AnalyzeSingleFile(path, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestAnalyze_VerboseWithMixedTypes(t *testing.T) {
	dir := t.TempDir()

	// Create ELF, Mach-O, and PE files
	elfData := buildMinimalELF64()
	machoData := buildMinimalMachO64()

	elf := make([]byte, 128*1024)
	copy(elf, elfData)
	if err := os.WriteFile(filepath.Join(dir, "test.so"), elf, 0o644); err != nil {
		t.Fatal(err)
	}

	mo := make([]byte, 128*1024)
	copy(mo, machoData)
	if err := os.WriteFile(filepath.Join(dir, "test.dylib"), mo, 0o644); err != nil {
		t.Fatal(err)
	}

	pe := make([]byte, 128*1024)
	pe[0] = 'M'
	pe[1] = 'Z'
	if err := os.WriteFile(filepath.Join(dir, "test.exe"), pe, 0o644); err != nil {
		t.Fatal(err)
	}

	// verbose=true with multiple types should not panic
	infos := Analyze(dir, true)
	if len(infos) < 2 {
		t.Logf("got %d results (some fake binaries may not parse fully)", len(infos))
	}
}

func TestAnalyze_MultipleBinaryExtensions(t *testing.T) {
	dir := t.TempDir()

	// Create files with various recognized extensions
	exts := []string{".exe", ".dll", ".so", ".dylib", ".bin"}
	peHeader := make([]byte, 128*1024)
	peHeader[0] = 'M'
	peHeader[1] = 'Z'

	for _, ext := range exts {
		if err := os.WriteFile(filepath.Join(dir, "test"+ext), peHeader, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// These should at least be visited (PE parsing may fail on fake data, but no panics)
	infos := Analyze(dir, false)
	_ = infos // just verify no panic
}

// --- AnalyzeSingleFile Windows-compatible tests ---

func TestAnalyzeSingleFile_PEOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE binary tests only on Windows")
	}

	binPath := buildTestBinary(t)

	result, err := AnalyzeSingleFile(binPath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for PE binary")
	}

	if result.Type != "PE" {
		t.Errorf("Type = %q, want PE", result.Type)
	}
	if result.Arch == "" {
		t.Error("expected non-empty Arch")
	}
	if len(result.Imports) == 0 {
		t.Log("no imports found (may be statically linked)")
	}
}

func TestAnalyzeSingleFile_VerboseOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE binary tests only on Windows")
	}

	binPath := buildTestBinary(t)

	result, err := AnalyzeSingleFile(binPath, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// --- elfImports / machoImports with synthetic binaries ---

func TestElfImports_SyntheticMinimalELF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minimal.elf")

	// Build a minimal valid ELF64 header
	elf := buildMinimalELF64()
	if err := os.WriteFile(path, elf, 0o644); err != nil {
		t.Fatal(err)
	}

	arch, libs := elfImports(path)
	// Minimal ELF should parse without panic
	// It may or may not return a valid arch depending on how minimal it is
	_ = arch
	_ = libs
}

func TestMachoImports_SyntheticValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.macho")

	// Build a minimal valid Mach-O 64-bit file
	data := buildMinimalMachO64()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	arch, libs := machoImports(path)
	// If parsing succeeds, arch should be non-empty
	if arch != "" {
		t.Logf("arch = %q, libs = %v", arch, libs)
	}
	// Main assertion: no panic
}

func TestMachoImports_SyntheticNotMacho(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notmacho")

	// Write Mach-O magic but invalid content
	data := []byte{0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x00, 0x00, 0x00}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	arch, libs := machoImports(path)
	if arch != "" {
		t.Logf("arch = %q (may parse partial header)", arch)
	}
	_ = libs // no panic is the main assertion
}

func TestMachoImports_NotMacho(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "textfile")
	if err := os.WriteFile(path, []byte("definitely not a mach-o file"), 0o644); err != nil {
		t.Fatal(err)
	}

	arch, libs := machoImports(path)
	if arch != "" {
		t.Errorf("expected empty arch for non-Mach-O file, got %q", arch)
	}
	if libs != nil {
		t.Errorf("expected nil libs for non-Mach-O file, got %v", libs)
	}
}

func TestPeImports_NotPE(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "textfile.exe")
	if err := os.WriteFile(path, []byte("not a PE file"), 0o644); err != nil {
		t.Fatal(err)
	}

	arch, imports := peImports(path)
	if arch != "" {
		t.Errorf("expected empty arch for non-PE file, got %q", arch)
	}
	if imports != nil {
		t.Errorf("expected nil imports for non-PE file, got %v", imports)
	}
}

// --- runToolSuite tests for other binary types ---

func TestRunToolSuite_MachO(t *testing.T) {
	if _, err := exec.LookPath("objdump"); err != nil {
		t.Skip("objdump not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.dylib")
	data := make([]byte, 256)
	data[0] = 0xcf
	data[1] = 0xfa
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	bi := Info{
		Path: path,
		Name: "fake.dylib",
		Type: "Mach-O",
	}

	results := runToolSuite(bi)
	if len(results) == 0 {
		t.Error("expected non-empty tool results for Mach-O")
	}

	// Mach-O falls through to default case with objdump + nm
	nameSet := make(map[string]bool)
	for _, r := range results {
		nameSet[r.Name] = true
	}
	if !nameSet["objdump"] {
		t.Error("expected objdump in Mach-O tool suite results")
	}
}

func TestRunToolSuite_UnknownType(t *testing.T) {
	if _, err := exec.LookPath("objdump"); err != nil {
		t.Skip("objdump not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "unknown.bin")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	bi := Info{
		Path: path,
		Name: "unknown.bin",
		Type: "Unknown",
	}

	results := runToolSuite(bi)
	if len(results) == 0 {
		t.Error("expected non-empty tool results for unknown type")
	}
}

// --- utf16Encode tests ---

func TestUtf16Encode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []byte
	}{
		{
			name:  "empty string",
			input: "",
			want:  []byte{},
		},
		{
			name:  "single char",
			input: "A",
			want:  []byte{'A', 0x00},
		},
		{
			name:  "hello",
			input: "Hello",
			want:  []byte{'H', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := utf16Encode(tt.input)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("utf16Encode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- extractStrings edge cases ---

func TestExtractStrings_OnlyNonPrintable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonprint.bin")

	data := make([]byte, 256)
	for i := range data {
		data[i] = 0x01 // non-printable
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	total, urlCount, urls, samples := extractStrings(path, 1024, 4, 10, 10)
	if total != 0 {
		t.Errorf("expected 0 strings from non-printable data, got %d", total)
	}
	if urlCount != 0 {
		t.Errorf("expected 0 URLs, got %d", urlCount)
	}
	if len(urls) != 0 {
		t.Errorf("expected empty URL list, got %v", urls)
	}
	if len(samples) != 0 {
		t.Errorf("expected empty samples list, got %v", samples)
	}
}

func TestExtractStrings_ExactlyAtMaxBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.bin")

	// Write exactly 10 printable bytes
	data := []byte("ABCDEFGHIJ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Set maxBytes to exactly match the file size
	total, _, _, _ := extractStrings(path, 10, 4, 10, 10)
	if total != 1 {
		t.Errorf("expected 1 string from exact-length data, got %d", total)
	}
}

func TestExtractStrings_MultipleURLsInOneString(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multiurl.bin")

	content := []byte("visit https://example.com and https://test.org for info")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	_, urlCount, sampleURLs, _ := extractStrings(path, 1024, 4, 10, 10)
	if urlCount < 1 {
		t.Errorf("expected urlCount >= 1, got %d", urlCount)
	}
	if len(sampleURLs) < 2 {
		t.Errorf("expected at least 2 sample URLs, got %d: %v", len(sampleURLs), sampleURLs)
	}
}

// --- runTool edge cases ---

func TestRunTool_Error(t *testing.T) {
	// Use a tool that exists but will fail with bad arguments
	if runtime.GOOS == "windows" {
		// On Windows, "cmd" exists but "/c exit 1" will return error
		result := runTool("cmd", []string{"/c", "exit", "1"}, 1024)
		if result.Status != "error" {
			t.Logf("Status = %q (may vary by platform)", result.Status)
		}
	} else {
		result := runTool("false", []string{}, 1024)
		if result.Status != "error" {
			t.Errorf("Status = %q, want %q", result.Status, "error")
		}
	}
}

func TestRunTool_OutputTruncation(t *testing.T) {
	// Run a command that produces known output
	var result ToolResult
	if runtime.GOOS == "windows" {
		result = runTool("cmd", []string{"/c", "echo", "hello world"}, 5)
	} else {
		result = runTool("echo", []string{"hello world"}, 5)
	}

	if result.Status == "missing" {
		t.Skip("echo/cmd not available")
	}

	if result.Status == "ok" && len(result.Output) > 5+len("\n...[truncated]") {
		t.Errorf("output not truncated to limit: len=%d", len(result.Output))
	}
}

// --- Helper functions ---

// buildVersionEntry creates a synthetic PE version string table entry
// with proper UTF-16LE encoding, null terminator, and 4-byte alignment.
// The entry's total length is padded to a multiple of 4 so that consecutive
// entries remain properly aligned when the first entry starts at a 4-byte
// aligned offset.
func buildVersionEntry(key, value string) []byte {
	keyUTF16 := utf16Encode(key)
	entry := make([]byte, 0, len(keyUTF16)+len(value)*2+16)

	// Key in UTF-16LE
	entry = append(entry, keyUTF16...)

	// Null terminator (2 bytes for UTF-16)
	entry = append(entry, 0x00, 0x00)

	// Align to 4-byte boundary
	for len(entry)%4 != 0 {
		entry = append(entry, 0x00)
	}

	// Value in UTF-16LE
	for i := 0; i < len(value); i++ {
		entry = append(entry, value[i], 0x00)
	}

	// Null terminator for value
	entry = append(entry, 0x00, 0x00)

	// Pad total entry length to 4-byte boundary
	for len(entry)%4 != 0 {
		entry = append(entry, 0x00)
	}

	return entry
}

// buildMinimalMachO64 creates a minimal valid Mach-O 64-bit executable.
// The header satisfies debug/macho.Open's parsing requirements.
func buildMinimalMachO64() []byte {
	// Mach-O 64-bit header: magic(4) + cputype(4) + cpusubtype(4) + filetype(4) +
	// ncmds(4) + sizeofcmds(4) + flags(4) + reserved(4) = 32 bytes
	buf := make([]byte, 32)

	// MH_MAGIC_64 = 0xFEEDFACF (little-endian)
	binary.LittleEndian.PutUint32(buf[0:], 0xFEEDFACF)
	// CPU_TYPE_X86_64 = 0x01000007
	binary.LittleEndian.PutUint32(buf[4:], 0x01000007)
	// CPU_SUBTYPE_ALL = 3
	binary.LittleEndian.PutUint32(buf[8:], 3)
	// MH_EXECUTE = 2
	binary.LittleEndian.PutUint32(buf[12:], 2)
	// ncmds = 0 (no load commands)
	binary.LittleEndian.PutUint32(buf[16:], 0)
	// sizeofcmds = 0
	binary.LittleEndian.PutUint32(buf[20:], 0)
	// flags = 0
	binary.LittleEndian.PutUint32(buf[24:], 0)
	// reserved = 0
	binary.LittleEndian.PutUint32(buf[28:], 0)

	return buf
}

// buildMinimalELF64 creates a minimal valid ELF64 file header.
func buildMinimalELF64() []byte {
	buf := make([]byte, 64) // ELF64 header is 64 bytes

	// Magic number
	buf[0] = 0x7f
	buf[1] = 'E'
	buf[2] = 'L'
	buf[3] = 'F'

	// ELF class: 64-bit
	buf[4] = 2

	// Data encoding: little-endian
	buf[5] = 1

	// Version
	buf[6] = 1

	// OS/ABI
	buf[7] = 0

	// Type: ET_EXEC
	binary.LittleEndian.PutUint16(buf[16:], 2)

	// Machine: EM_X86_64
	binary.LittleEndian.PutUint16(buf[18:], 0x3E)

	// Version
	binary.LittleEndian.PutUint32(buf[20:], 1)

	// ELF header size
	binary.LittleEndian.PutUint16(buf[52:], 64)

	return buf
}
