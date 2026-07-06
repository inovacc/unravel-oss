/*
Copyright (c) 2026 Security Research
*/
package nodeaddon

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// shannonEntropy — edge branches not hit by existing tests
// ---------------------------------------------------------------------------

func TestShannonEntropyHighEntropy(t *testing.T) {
	// A string with all distinct chars should have high entropy.
	s := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
	e := shannonEntropy(s)
	if e < 4.0 {
		t.Errorf("expected high entropy for diverse string, got %f", e)
	}
}

// ---------------------------------------------------------------------------
// categorizeString — branches not covered by the existing table
// ---------------------------------------------------------------------------

func TestCategorizeStringAdditionalBranches(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// ws:// protocol
		{"ws://localhost:8080/chat", "URL"},
		// wss:// protocol
		{"wss://example.com/socket", "URL"},
		// API endpoint branch: contains "api" and "/"
		{"GET /api/v1/users", "API_ENDPOINT"},
		// "failed" triggers ERROR_MESSAGE
		{"operation failed with code 5", "ERROR_MESSAGE"},
		// "cannot" triggers ERROR_MESSAGE
		{"cannot open file", "ERROR_MESSAGE"},
		// "rsa" triggers CRYPTO
		{"rsa encryption key", "CRYPTO"},
		// "crypt" (generic) triggers CRYPTO
		{"crypt_r implementation", "CRYPTO"},
		// "registry" triggers REGISTRY
		{"registry key path", "REGISTRY"},
		// "hkey" triggers REGISTRY
		{"HKEY_CURRENT_USER", "REGISTRY"},
		// High entropy string — all unique ASCII printable chars
		{"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~abcdefghijABCDEFGHIJ0123456789", "HIGH_ENTROPY"},
		// General fallback
		{"just a normal string here", "GENERAL"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := categorizeString(tt.input)
			if got != tt.want {
				t.Errorf("categorizeString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractJSONField
// ---------------------------------------------------------------------------

func TestExtractJSONField(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		field string
		want  string
	}{
		{
			name:  "existing string field",
			data:  []byte(`{"name":"my-addon","version":"1.0"}`),
			field: "name",
			want:  "my-addon",
		},
		{
			name:  "missing field",
			data:  []byte(`{"version":"1.0"}`),
			field: "name",
			want:  "",
		},
		{
			name:  "non-string field",
			data:  []byte(`{"count":42}`),
			field: "count",
			want:  "",
		},
		{
			name:  "invalid JSON",
			data:  []byte(`not-json`),
			field: "name",
			want:  "",
		},
		{
			name:  "empty JSON object",
			data:  []byte(`{}`),
			field: "name",
			want:  "",
		},
		{
			name:  "target_name field",
			data:  []byte(`{"targets":[{"target_name":"myaddon"}],"target_name":"myaddon"}`),
			field: "target_name",
			want:  "myaddon",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSONField(tt.data, tt.field)
			if got != tt.want {
				t.Errorf("extractJSONField(%q) = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// classifyImports
// ---------------------------------------------------------------------------

func TestClassifyImports(t *testing.T) {
	raw := []rawImport{
		{Library: "ws2_32.dll", Functions: []string{"connect", "send"}},
		{Library: "bcrypt.dll", Functions: nil},
		{Library: "libunknown.so", Functions: nil},
	}
	got := classifyImports(raw)
	if len(got) != len(raw) {
		t.Fatalf("classifyImports: expected %d results, got %d", len(raw), len(got))
	}
	if got[0].Category != "network" {
		t.Errorf("ws2_32.dll: want category=network, got %q", got[0].Category)
	}
	if got[1].Category != "crypto" {
		t.Errorf("bcrypt.dll: want category=crypto, got %q", got[1].Category)
	}
	// Functions should be preserved
	if len(got[0].Functions) != 2 {
		t.Errorf("ws2_32.dll: expected 2 functions, got %d", len(got[0].Functions))
	}
}

func TestClassifyImportsEmpty(t *testing.T) {
	got := classifyImports(nil)
	if len(got) != 0 {
		t.Errorf("classifyImports(nil): expected empty, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// classifyLibrary — function-name-based branches
// ---------------------------------------------------------------------------

func TestClassifyLibraryFunctionBased(t *testing.T) {
	tests := []struct {
		name      string
		library   string
		functions []string
		want      string
	}{
		{
			name:      "process inject via function",
			library:   "unknown.dll",
			functions: []string{"CreateRemoteThread"},
			want:      "process",
		},
		{
			name:      "registry via function",
			library:   "unknown.dll",
			functions: []string{"RegOpenKeyEx"},
			want:      "registry",
		},
		{
			name:      "hook/key via function",
			library:   "unknown.dll",
			functions: []string{"SetWindowsHookEx"},
			want:      "input",
		},
		{
			name:      "crypto mining via function",
			library:   "unknown.dll",
			functions: []string{"RandomX"},
			want:      "crypto",
		},
		// Generic name-pattern branches
		{
			name:      "ssl in name",
			library:   "libssl.so.1.1",
			functions: nil,
			want:      "crypto",
		},
		{
			name:      "http in name",
			library:   "libhttp.so",
			functions: nil,
			want:      "network",
		},
		{
			name:      "sock in name",
			library:   "libsock.so",
			functions: nil,
			want:      "network",
		},
		{
			name:      "pthread in name",
			library:   "libpthread.so.0",
			functions: nil,
			want:      "system",
		},
		{
			name:      "msvcrt in name",
			library:   "msvcrt.dll",
			functions: nil,
			want:      "runtime",
		},
		{
			name:      "stdc++ in name",
			library:   "libstdc++.so.6",
			functions: nil,
			want:      "runtime",
		},
		{
			name:      "libm.so exactly",
			library:   "libm.so",
			functions: nil,
			want:      "runtime",
		},
		{
			name:      "libm.so versioned",
			library:   "libm.so.6",
			functions: nil,
			want:      "runtime",
		},
		{
			name:      "napi in name",
			library:   "libnapi.so",
			functions: nil,
			want:      "node",
		},
		{
			name:      "v8 in name",
			library:   "libv8.so",
			functions: nil,
			want:      "node",
		},
		{
			name:      "fs in name",
			library:   "libfs.so",
			functions: nil,
			want:      "filesystem",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyLibrary(tt.library, tt.functions)
			if got != tt.want {
				t.Errorf("classifyLibrary(%q, fns=%v) = %q, want %q", tt.library, tt.functions, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// assessRisk — additional branches
// ---------------------------------------------------------------------------

func TestAssessRiskProcess(t *testing.T) {
	imports := []ImportedLib{
		{Library: "psapi.dll", Category: "process"},
	}
	exports := []ExportedFunc{{Name: "napi_register_module_v1", IsNAPI: true}}
	score, factors := assessRisk(imports, exports)
	if score < 15 {
		t.Errorf("assessRisk with process import: expected score >= 15, got %d", score)
	}
	found := false
	for _, f := range factors {
		if f.Name == "Process Manipulation" {
			found = true
		}
	}
	if !found {
		t.Errorf("assessRisk: expected 'Process Manipulation' factor, got %v", factors)
	}
}

func TestAssessRiskRegistryAccess(t *testing.T) {
	imports := []ImportedLib{
		{Library: "advapi32.dll", Category: "registry"},
	}
	exports := []ExportedFunc{{Name: "napi_register_module_v1", IsNAPI: true}}
	score, factors := assessRisk(imports, exports)
	if score < 5 {
		t.Errorf("assessRisk with registry import: expected score >= 5, got %d", score)
	}
	found := false
	for _, f := range factors {
		if f.Name == "Registry Access" {
			found = true
		}
	}
	if !found {
		t.Errorf("assessRisk: expected 'Registry Access' factor, got %v", factors)
	}
}

func TestAssessRiskCap100(t *testing.T) {
	// Stack many dangerous functions to exceed 100
	imports := []ImportedLib{
		{
			Library:  "malware.dll",
			Category: "process",
			Functions: []string{
				"CreateRemoteThread", // +30
				"VirtualAllocEx",     // +25
				"WriteProcessMemory", // +30
				"NtCreateThreadEx",   // +30
				"SetWindowsHookEx",   // +25
				"GetAsyncKeyState",   // +20
			},
		},
	}
	exports := []ExportedFunc{{Name: "napi_register_module_v1", IsNAPI: true}}
	score, _ := assessRisk(imports, exports)
	if score != 100 {
		t.Errorf("assessRisk: score should be capped at 100, got %d", score)
	}
}

func TestAssessRiskNilExports(t *testing.T) {
	// When exports is nil, the "Missing N-API Exports" check is skipped
	imports := []ImportedLib{{Library: "libc.so", Category: "runtime"}}
	score, factors := assessRisk(imports, nil)
	for _, f := range factors {
		if f.Name == "Missing N-API Exports" {
			t.Errorf("assessRisk(nil exports): should NOT produce Missing N-API Exports factor, got %v", factors)
		}
	}
	_ = score
}

// ---------------------------------------------------------------------------
// extractPEExportNames — raw byte slice tests
// ---------------------------------------------------------------------------

func TestExtractPEExportNamesOffBounds(t *testing.T) {
	// Slice too small to contain export directory — should return nil
	got := extractPEExportNames([]byte{0x00, 0x01}, 0, 0, 10)
	if got != nil {
		t.Errorf("expected nil for too-small data, got %v", got)
	}
}

func TestExtractPEExportNamesSanityCheck(t *testing.T) {
	// Build a minimal export directory with numNames > 10000 (sanity check limit)
	data := make([]byte, 64)
	sectionRVA := uint32(0x1000)
	exportRVA := uint32(0x1000)
	// Write numNames = 99999 at offset 24
	binary.LittleEndian.PutUint32(data[24:], 99999)
	got := extractPEExportNames(data, sectionRVA, exportRVA, 40)
	if got != nil {
		t.Errorf("expected nil for numNames > 10000, got %v", got)
	}
}

func TestExtractPEExportNamesNamesOffBounds(t *testing.T) {
	// namesRVA points outside section data
	data := make([]byte, 64)
	sectionRVA := uint32(0x1000)
	exportRVA := uint32(0x1000)
	// numNames = 2
	binary.LittleEndian.PutUint32(data[24:], 2)
	// namesRVA points to RVA 0x9000 (far beyond our 64-byte section)
	binary.LittleEndian.PutUint32(data[32:], 0x9000)
	got := extractPEExportNames(data, sectionRVA, exportRVA, 40)
	if got != nil {
		t.Errorf("expected nil for out-of-bounds namesRVA, got %v", got)
	}
}

func TestExtractPEExportNamesValidEntry(t *testing.T) {
	// Build a minimal but valid export directory inside a section.
	// Layout:
	//   offset 0..39    = export directory (40 bytes)
	//   offset 40..47   = name RVA table (2 entries × 4 bytes)
	//   offset 48..63   = two null-terminated strings "hello\0" and "world\0"
	sectionRVA := uint32(0x1000)
	sectionBase := sectionRVA

	// String data sits at section offset 48 and 55
	str1RVA := sectionBase + 48
	str2RVA := sectionBase + 55

	namesRVA := sectionBase + 40 // name pointer table is at offset 40

	data := make([]byte, 70)

	// numNames = 2 at offset 24
	binary.LittleEndian.PutUint32(data[24:], 2)
	// AddressOfNames (namesRVA) at offset 32
	binary.LittleEndian.PutUint32(data[32:], namesRVA)

	// Fill name pointer table
	binary.LittleEndian.PutUint32(data[40:], str1RVA)
	binary.LittleEndian.PutUint32(data[44:], str2RVA)

	// Write strings
	copy(data[48:], "hello\x00")
	copy(data[55:], "world\x00")

	got := extractPEExportNames(data, sectionRVA, sectionRVA, 40)
	if len(got) != 2 {
		t.Fatalf("expected 2 names, got %d: %v", len(got), got)
	}
	if got[0] != "hello" {
		t.Errorf("expected got[0]=%q, got %q", "hello", got[0])
	}
	if got[1] != "world" {
		t.Errorf("expected got[1]=%q, got %q", "world", got[1])
	}
}

func TestExtractPEExportNamesSkipsOutOfBoundsNameRVA(t *testing.T) {
	// One name RVA is in-bounds, one is beyond section data.
	sectionRVA := uint32(0x1000)
	namesRVA := sectionRVA + 40

	data := make([]byte, 60)

	binary.LittleEndian.PutUint32(data[24:], 2)        // numNames = 2
	binary.LittleEndian.PutUint32(data[32:], namesRVA) // AddressOfNames

	str1RVA := sectionRVA + 50
	badRVA := sectionRVA + 0x9000 // far out of bounds

	binary.LittleEndian.PutUint32(data[40:], str1RVA)
	binary.LittleEndian.PutUint32(data[44:], badRVA)

	copy(data[50:], "ok\x00")

	got := extractPEExportNames(data, sectionRVA, sectionRVA, 40)
	// The bad RVA entry is silently skipped
	if len(got) != 1 || got[0] != "ok" {
		t.Errorf("expected [ok], got %v", got)
	}
}

// ---------------------------------------------------------------------------
// detectBinding
// ---------------------------------------------------------------------------

func TestDetectBindingNotFound(t *testing.T) {
	dir := t.TempDir()
	nodePath := filepath.Join(dir, "addon.node")
	if err := os.WriteFile(nodePath, []byte("placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := detectBinding(nodePath)
	if got != nil {
		t.Errorf("detectBinding in empty dir: expected nil, got %+v", got)
	}
}

func TestDetectBindingWithBindingGyp(t *testing.T) {
	dir := t.TempDir()
	gypContent := []byte(`{"targets":[{"target_name":"myaddon","sources":["src/main.cc"]}],"target_name":"myaddon"}`)
	if err := os.WriteFile(filepath.Join(dir, "binding.gyp"), gypContent, 0o644); err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(dir, "build", "Release", "addon.node")
	if err := os.MkdirAll(filepath.Dir(nodePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodePath, []byte("placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := detectBinding(nodePath)
	if got == nil {
		t.Fatal("detectBinding with binding.gyp: expected non-nil")
	}
	if !got.BindingGyp {
		t.Errorf("expected BindingGyp=true")
	}
	if got.BuildSystem != "node-gyp" {
		t.Errorf("expected BuildSystem=node-gyp, got %q", got.BuildSystem)
	}
	if got.TargetName != "myaddon" {
		t.Errorf("expected TargetName=myaddon, got %q", got.TargetName)
	}
}

func TestDetectBindingWithPackageJSON(t *testing.T) {
	dir := t.TempDir()
	pkgContent := []byte(`{"name":"my-native-pkg","version":"1.0.0"}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), pkgContent, 0o644); err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(dir, "addon.node")
	if err := os.WriteFile(nodePath, []byte("placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := detectBinding(nodePath)
	if got == nil {
		t.Fatal("detectBinding with package.json: expected non-nil")
	}
	if got.PackageName != "my-native-pkg" {
		t.Errorf("expected PackageName=my-native-pkg, got %q", got.PackageName)
	}
}

func TestDetectBindingWithNodePreGyp(t *testing.T) {
	dir := t.TempDir()
	pkgContent := []byte(`{"name":"my-pkg","binary":{"module_name":"myaddon"}}`)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), pkgContent, 0o644); err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(dir, "addon.node")
	if err := os.WriteFile(nodePath, []byte("placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := detectBinding(nodePath)
	if got == nil {
		t.Fatal("detectBinding with node-pre-gyp: expected non-nil")
	}
	if got.BuildSystem != "node-pre-gyp" {
		t.Errorf("expected BuildSystem=node-pre-gyp, got %q", got.BuildSystem)
	}
}

func TestDetectBindingWithCMake(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "CMakeLists.txt"), []byte("cmake_minimum_required(VERSION 3.0)"), 0o644); err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(dir, "addon.node")
	if err := os.WriteFile(nodePath, []byte("placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := detectBinding(nodePath)
	if got == nil {
		t.Fatal("detectBinding with CMakeLists.txt: expected non-nil")
	}
	if got.BuildSystem != "cmake-js" {
		t.Errorf("expected BuildSystem=cmake-js, got %q", got.BuildSystem)
	}
}

// ---------------------------------------------------------------------------
// Strings — file-based tests (no binary format needed)
// ---------------------------------------------------------------------------

func TestStringsBasic(t *testing.T) {
	dir := t.TempDir()
	// Mix of printable and non-printable bytes with several strings
	content := []byte("hello world\x00\x01\x02this is a test string\x00more data here for extraction\xff")
	path := filepath.Join(dir, "test.node")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Strings(path, 4)
	if err != nil {
		t.Fatalf("Strings() error: %v", err)
	}
	if result.TotalStrings == 0 {
		t.Errorf("expected at least one string")
	}
	if result.FileName != "test.node" {
		t.Errorf("expected FileName=test.node, got %q", result.FileName)
	}
	if result.AvgEntropy <= 0 {
		t.Errorf("expected AvgEntropy > 0, got %f", result.AvgEntropy)
	}
	if result.ByCategory == nil {
		t.Errorf("expected non-nil ByCategory")
	}
}

func TestStringsMinLenEnforced(t *testing.T) {
	dir := t.TempDir()
	// Only strings shorter than default min (4)
	content := []byte("ab\x00cd\x00")
	path := filepath.Join(dir, "short.node")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	// minLen < 4 should be bumped to 4 → nothing found
	result, err := Strings(path, 2)
	if err != nil {
		t.Fatalf("Strings() error: %v", err)
	}
	if result.TotalStrings != 0 {
		t.Errorf("expected 0 strings for all-short content, got %d", result.TotalStrings)
	}
}

func TestStringsHighEntropy(t *testing.T) {
	dir := t.TempDir()
	// String with entropy > 4.5: use a long diverse string
	highEntStr := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	content := append([]byte(highEntStr), 0x00)
	path := filepath.Join(dir, "highent.node")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Strings(path, 4)
	if err != nil {
		t.Fatalf("Strings() error: %v", err)
	}
	if result.HighEntropyCount == 0 {
		t.Errorf("expected HighEntropyCount > 0 for high-entropy string")
	}
}

func TestStringsTrailingString(t *testing.T) {
	dir := t.TempDir()
	// Content that ends with a printable string (no null terminator)
	content := []byte("\x00\x01trailing printable text here")
	path := filepath.Join(dir, "trailing.node")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Strings(path, 4)
	if err != nil {
		t.Fatalf("Strings() error: %v", err)
	}
	if result.TotalStrings == 0 {
		t.Errorf("expected trailing string to be captured")
	}
}

func TestStringsFileNotFound(t *testing.T) {
	_, err := Strings("/nonexistent/path/addon.node", 4)
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestStringsURLCategory(t *testing.T) {
	dir := t.TempDir()
	// Include a URL string so the URL category is exercised
	content := []byte("\x00https://example.com/api/endpoint\x00")
	path := filepath.Join(dir, "url.node")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Strings(path, 4)
	if err != nil {
		t.Fatalf("Strings() error: %v", err)
	}
	if result.ByCategory["URL"] == 0 {
		t.Errorf("expected URL category count > 0, got %v", result.ByCategory)
	}
}

func TestStringsTopByCategory(t *testing.T) {
	dir := t.TempDir()
	// Write >10 general strings to trigger the top-10 cap
	var content []byte
	for range 15 {
		content = append(content, []byte("generalstringvalue")...)
		content = append(content, 0x00)
	}
	path := filepath.Join(dir, "many.node")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Strings(path, 4)
	if err != nil {
		t.Fatalf("Strings() error: %v", err)
	}
	// TopByCategory for GENERAL should be capped at 10
	if top, ok := result.TopByCategory["GENERAL"]; ok && len(top) > 10 {
		t.Errorf("TopByCategory GENERAL: expected at most 10, got %d", len(top))
	}
}

// ---------------------------------------------------------------------------
// Symbols — plain file (no valid binary format → graceful empty result)
// ---------------------------------------------------------------------------

func TestSymbolsPlainFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "addon.node")
	if err := os.WriteFile(path, []byte("not a real binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Symbols(path)
	if err != nil {
		t.Fatalf("Symbols() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Symbols() returned nil result")
	}
	if result.FileName != "addon.node" {
		t.Errorf("expected FileName=addon.node, got %q", result.FileName)
	}
	// No valid symbols in a plain text file
	if result.HasNAPI {
		t.Errorf("expected HasNAPI=false for plain text file")
	}
}

// ---------------------------------------------------------------------------
// Imports — plain file
// ---------------------------------------------------------------------------

func TestImportsPlainFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "addon.node")
	if err := os.WriteFile(path, []byte("not a real binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Imports(path)
	if err != nil {
		t.Fatalf("Imports() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Imports() returned nil result")
	}
	if result.FileName != "addon.node" {
		t.Errorf("expected FileName=addon.node, got %q", result.FileName)
	}
}

// ---------------------------------------------------------------------------
// Analyze — error path (file not found)
// ---------------------------------------------------------------------------

func TestAnalyzeFileNotFound(t *testing.T) {
	_, err := Analyze("/nonexistent/path/addon.node")
	if err == nil {
		t.Error("Analyze() with non-existent file: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Analyze — plain file (no valid binary, exercises fallback detectFormat path)
// ---------------------------------------------------------------------------

func TestAnalyzePlainFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "addon.node")
	if err := os.WriteFile(path, []byte("not a real binary file data here"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Analyze(path)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Analyze() returned nil result")
	}
	if result.FileName != "addon.node" {
		t.Errorf("expected FileName=addon.node, got %q", result.FileName)
	}
	if result.NAPIExports == nil {
		t.Errorf("NAPIExports should not be nil")
	}
}

// ---------------------------------------------------------------------------
// detectFormat — with a real minimal ELF (Linux x64) byte sequence
// ---------------------------------------------------------------------------

func buildMinimalELFx64() []byte {
	// Minimal ELF64 header (64 bytes) for EM_X86_64
	// Magic + class + data + version + OS/ABI + padding
	hdr := make([]byte, 64)
	copy(hdr[0:], []byte{0x7f, 'E', 'L', 'F'}) // magic
	hdr[4] = 2                                 // ELFCLASS64
	hdr[5] = 1                                 // ELFDATA2LSB
	hdr[6] = 1                                 // EV_CURRENT
	hdr[7] = 0                                 // ELFOSABI_NONE
	// e_type = ET_DYN (3) at offset 16
	binary.LittleEndian.PutUint16(hdr[16:], 3)
	// e_machine = EM_X86_64 (62) at offset 18
	binary.LittleEndian.PutUint16(hdr[18:], 62)
	// e_version = 1 at offset 20
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	// e_ehsize = 64 at offset 52
	binary.LittleEndian.PutUint16(hdr[52:], 64)
	return hdr
}

func TestDetectFormatELF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.node")
	if err := os.WriteFile(path, buildMinimalELFx64(), 0o644); err != nil {
		t.Fatal(err)
	}

	format, arch, bits := detectFormat(path)
	if format != "ELF" {
		t.Errorf("expected format=ELF, got %q", format)
	}
	if arch != "x64" {
		t.Errorf("expected arch=x64, got %q", arch)
	}
	if bits != 64 {
		t.Errorf("expected bits=64, got %d", bits)
	}
}

func TestDetectFormatUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.node")
	if err := os.WriteFile(path, []byte("random bytes not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	format, arch, bits := detectFormat(path)
	if format != "unknown" {
		t.Errorf("expected format=unknown, got %q", format)
	}
	if arch != "unknown" {
		t.Errorf("expected arch=unknown, got %q", arch)
	}
	if bits != 0 {
		t.Errorf("expected bits=0, got %d", bits)
	}
}

// ---------------------------------------------------------------------------
// detectNAPIVersion — edge: v1 export but version stays at 1
// ---------------------------------------------------------------------------

func TestDetectNAPIVersionMultipleV1(t *testing.T) {
	exports := []ExportedFunc{
		{Name: "napi_register_module_v1", IsNAPI: true},
		{Name: "napi_register_module_v1", IsNAPI: true}, // duplicate
	}
	got := detectNAPIVersion(exports)
	if got != 1 {
		t.Errorf("expected version=1, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// JSON marshaling of result types (ensures field tags are correct)
// ---------------------------------------------------------------------------

func TestResultJSONRoundtrip(t *testing.T) {
	r := &Result{
		FilePath:     "/tmp/addon.node",
		FileName:     "addon.node",
		FileSize:     1024,
		Format:       "ELF",
		Architecture: "x64",
		Bits:         64,
		IsNAPI:       true,
		NAPIVersion:  1,
		NAPIExports:  []string{"napi_register_module_v1"},
		Exports:      []ExportedFunc{{Name: "napi_register_module_v1", IsNAPI: true}},
		Imports:      []ImportedLib{{Library: "libc.so", Category: "runtime"}},
		RiskScore:    20,
		RiskFactors:  []RiskFactor{{Name: "test", Severity: "LOW", Description: "desc"}},
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	var r2 Result
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}
	if r2.FileName != r.FileName {
		t.Errorf("FileName mismatch: %q vs %q", r2.FileName, r.FileName)
	}
	if r2.IsNAPI != r.IsNAPI {
		t.Errorf("IsNAPI mismatch")
	}
	if r2.RiskScore != r.RiskScore {
		t.Errorf("RiskScore mismatch: %d vs %d", r2.RiskScore, r.RiskScore)
	}
}

func TestSymbolsResultJSON(t *testing.T) {
	r := &SymbolsResult{
		FilePath:     "/tmp/addon.node",
		FileName:     "addon.node",
		TotalSymbols: 1,
		HasNAPI:      true,
		NAPISymbols:  []ExportedFunc{{Name: "napi_register_module_v1", IsNAPI: true}},
		Exports:      []ExportedFunc{{Name: "napi_register_module_v1", IsNAPI: true}},
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal SymbolsResult: %v", err)
	}
	var r2 SymbolsResult
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("json.Unmarshal SymbolsResult: %v", err)
	}
	if r2.HasNAPI != r.HasNAPI {
		t.Errorf("HasNAPI mismatch")
	}
}

func TestImportsResultJSON(t *testing.T) {
	r := &ImportsResult{
		FilePath:  "/tmp/addon.node",
		FileName:  "addon.node",
		Imports:   []ImportedLib{{Library: "ws2_32.dll", Category: "network"}},
		RiskScore: 10,
		RiskFactors: []RiskFactor{{
			Name:        "Network + Crypto",
			Description: "desc",
			Severity:    "MEDIUM",
		}},
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal ImportsResult: %v", err)
	}
	var r2 ImportsResult
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("json.Unmarshal ImportsResult: %v", err)
	}
	if len(r2.Imports) != 1 {
		t.Errorf("expected 1 import, got %d", len(r2.Imports))
	}
}

func TestStringsResultJSON(t *testing.T) {
	r := &StringsResult{
		FilePath:         "/tmp/addon.node",
		FileName:         "addon.node",
		TotalStrings:     2,
		ByCategory:       map[string]int{"GENERAL": 2},
		AvgEntropy:       3.5,
		HighEntropyCount: 0,
		Strings: []StringEntry{
			{Value: "hello", Offset: 0, Length: 5, Category: "GENERAL", Entropy: 2.1},
		},
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal StringsResult: %v", err)
	}
	var r2 StringsResult
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("json.Unmarshal StringsResult: %v", err)
	}
	if r2.TotalStrings != r.TotalStrings {
		t.Errorf("TotalStrings mismatch: %d vs %d", r2.TotalStrings, r.TotalStrings)
	}
}

// ---------------------------------------------------------------------------
// extractSymbols — default (unknown format) path exercised with plain text
// ---------------------------------------------------------------------------

func TestExtractSymbolsUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "addon.node")
	if err := os.WriteFile(path, []byte("not a real binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	exports, imports := extractSymbols(path, "unknown")
	// Should not panic; results may be empty
	_ = exports
	_ = imports
}

func TestExtractSymbolsExplicitFormats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "addon.node")
	if err := os.WriteFile(path, []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"PE", "ELF", "Mach-O"} {
		exports, imports := extractSymbols(path, format)
		// None should panic; results may be empty for non-matching files
		_ = exports
		_ = imports
	}
}
