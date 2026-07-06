/* Copyright (c) 2026 Security Research */
package binary

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDetectBinaryType(t *testing.T) {
	tests := []struct {
		name   string
		header []byte
		want   string
	}{
		{
			name:   "PE binary",
			header: []byte{'M', 'Z', 0x00, 0x00},
			want:   "PE",
		},
		{
			name:   "ELF binary",
			header: []byte{0x7f, 'E', 'L', 'F'},
			want:   "ELF",
		},
		{
			name:   "Mach-O 64-bit",
			header: []byte{0xcf, 0xfa, 0xed, 0xfe},
			want:   "Mach-O",
		},
		{
			name:   "Mach-O fat binary",
			header: []byte{0xca, 0xfe, 0xba, 0xbe},
			want:   "Mach-O",
		},
		{
			name:   "Mach-O 32-bit",
			header: []byte{0xfe, 0xed, 0xfa, 0xce},
			want:   "Mach-O",
		},
		{
			name:   "unknown format",
			header: []byte{0x00, 0x00, 0x00, 0x00},
			want:   "",
		},
		{
			name:   "too short",
			header: []byte{0x7f},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "testbin")

			if err := os.WriteFile(path, tt.header, 0o644); err != nil {
				t.Fatal(err)
			}

			got := detectBinaryType(path)
			if got != tt.want {
				t.Errorf("detectBinaryType() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("nonexistent file", func(t *testing.T) {
		got := detectBinaryType("/nonexistent/path/binary")
		if got != "" {
			t.Errorf("detectBinaryType() = %q, want empty", got)
		}
	})
}

func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		limit int
		want  []string
	}{
		{
			name:  "deduplicates",
			input: []string{"a", "b", "a", "c", "b"},
			limit: 10,
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "respects limit",
			input: []string{"a", "b", "c", "d"},
			limit: 2,
			want:  []string{"a", "b"},
		},
		{
			name:  "skips empty strings",
			input: []string{"", "a", "", "b"},
			limit: 10,
			want:  []string{"a", "b"},
		},
		{
			name:  "empty input",
			input: nil,
			limit: 10,
			want:  []string{},
		},
		{
			name:  "zero limit returns all unique",
			input: []string{"a", "b", "c"},
			limit: 0,
			want:  []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uniqueStrings(tt.input, tt.limit)

			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got: %v", len(got), len(tt.want), got)
			}

			for i, s := range got {
				if s != tt.want[i] {
					t.Errorf("index %d = %q, want %q", i, s, tt.want[i])
				}
			}
		})
	}
}

func TestTrimOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		limit int
		want  string
	}{
		{
			name:  "within limit unchanged",
			input: "short",
			limit: 100,
			want:  "short",
		},
		{
			name:  "truncated at limit",
			input: "abcdefghij",
			limit: 5,
			want:  "abcde\n...[truncated]",
		},
		{
			name:  "zero limit returns full string",
			input: "anything",
			limit: 0,
			want:  "anything",
		},
		{
			name:  "negative limit returns full string",
			input: "anything",
			limit: -1,
			want:  "anything",
		},
		{
			name:  "exact limit unchanged",
			input: "exact",
			limit: 5,
			want:  "exact",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimOutput(tt.input, tt.limit)
			if got != tt.want {
				t.Errorf("trimOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// buildTestBinary compiles a minimal Go binary in the given directory and returns its path.
func buildTestBinary(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")

	if err := os.WriteFile(src, []byte(`package main
import "fmt"
func main() { fmt.Println("https://example.com/test") }
`), 0o644); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "testbin")
	cmd := exec.Command("go", "build", "-o", binPath, src)
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	return binPath
}

func TestAnalyzeSingleFile_NonExistent(t *testing.T) {
	_, err := AnalyzeSingleFile("/nonexistent/binary", false)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestAnalyzeSingleFile_NonBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "text.txt")

	if err := os.WriteFile(path, []byte("just some text"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzeSingleFile(path, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != nil {
		t.Error("expected nil result for non-binary file")
	}
}

func TestAnalyzeSingleFile_ELF(t *testing.T) {
	binPath := buildTestBinary(t)

	result, err := AnalyzeSingleFile(binPath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result for native binary")
	}

	expectedType := "ELF"
	if runtime.GOOS == "windows" {
		expectedType = "PE"
	}
	if result.Type != expectedType {
		t.Errorf("Type = %q, want %q", result.Type, expectedType)
	}

	if result.Arch == "" {
		t.Error("expected non-empty Arch")
	}

	if result.SizeBytes <= 0 {
		t.Error("expected SizeBytes > 0")
	}

	if result.Name != "testbin" {
		t.Errorf("Name = %q, want %q", result.Name, "testbin")
	}

	if result.SizeMB <= 0 {
		t.Error("expected SizeMB > 0")
	}
}

func TestAnalyzeSingleFile_Strings(t *testing.T) {
	binPath := buildTestBinary(t)

	result, err := AnalyzeSingleFile(binPath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.StringsTotal <= 0 {
		t.Error("expected StringsTotal > 0 for Go binary")
	}
}

func TestExtractStrings_URLs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "urlfile.bin")

	// Write a file with a URL embedded
	content := []byte("prefix https://example.com/api/v1 suffix")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	_, urlCount, sampleURLs, _ := extractStrings(path, 1024, 4, 10, 10)
	if urlCount < 1 {
		t.Errorf("expected urlCount >= 1, got %d", urlCount)
	}

	found := false
	for _, u := range sampleURLs {
		if strings.Contains(u, "example.com") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected to find example.com URL in samples: %v", sampleURLs)
	}
}

func TestExtractStrings_MaxBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.bin")

	// Write a 10KB file
	data := make([]byte, 10240)
	for i := range data {
		data[i] = 'A'
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Read only 100 bytes
	total, _, _, _ := extractStrings(path, 100, 4, 10, 10)

	// With only 100 bytes read, we should have limited strings
	if total > 100 {
		t.Errorf("expected limited strings with maxBytes=100, got %d", total)
	}
}

func TestExtractStrings_MinLen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minlen.bin")

	// Write short strings separated by null bytes
	content := []byte("ab\x00cdef\x00gh\x00ijklmn\x00")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	// MinLen=4 should filter out "ab" and "gh"
	total, _, _, _ := extractStrings(path, 1024, 4, 10, 10)

	// Only "cdef" and "ijklmn" should pass the minLen=4 filter
	if total != 2 {
		t.Errorf("expected 2 strings with minLen=4, got %d", total)
	}
}

func TestRunTool_Missing(t *testing.T) {
	result := runTool("nonexistent_tool_xyz_123", []string{}, 1024)
	if result.Status != "missing" {
		t.Errorf("Status = %q, want %q", result.Status, "missing")
	}
}

func TestRunToolCommandOnly(t *testing.T) {
	// Test with a tool that should exist on the host (cross-platform: cmd on
	// Windows, ls elsewhere). runToolCommandOnly resolves via PATH only.
	existing := "ls"
	if runtime.GOOS == "windows" {
		existing = "cmd"
	}
	result := runToolCommandOnly(existing, existing+" <binary>")
	if result.Status != "skipped" {
		t.Errorf("%s status = %q, want %q", existing, result.Status, "skipped")
	}

	// Test with missing tool
	result = runToolCommandOnly("nonexistent_tool_xyz_123", "nonexistent <binary>")
	if result.Status != "missing" {
		t.Errorf("missing tool status = %q, want %q", result.Status, "missing")
	}
}

func TestElfImports(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF binaries only available on linux")
	}

	binPath := buildTestBinary(t)

	arch, libs := elfImports(binPath)

	if arch == "" {
		t.Error("expected non-empty arch for ELF binary")
	}

	// libs may be empty for statically linked Go binaries — just verify no panic
	_ = libs
}

func TestElfImports_InvalidPath(t *testing.T) {
	arch, libs := elfImports("/nonexistent/path/binary")
	if arch != "" {
		t.Errorf("expected empty arch for nonexistent file, got %q", arch)
	}
	if libs != nil {
		t.Errorf("expected nil libs for nonexistent file, got %v", libs)
	}
}

func TestElfImports_NotELF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fakebinary")
	if err := os.WriteFile(path, []byte("not an ELF file at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	arch, libs := elfImports(path)
	if arch != "" {
		t.Errorf("expected empty arch for non-ELF file, got %q", arch)
	}
	if libs != nil {
		t.Errorf("expected nil libs for non-ELF file, got %v", libs)
	}
}

func TestPeImports_InvalidPath(t *testing.T) {
	arch, imports := peImports("/nonexistent/path/binary.exe")
	if arch != "" {
		t.Errorf("expected empty arch for nonexistent file, got %q", arch)
	}
	if imports != nil {
		t.Errorf("expected nil imports for nonexistent file, got %v", imports)
	}
}

func TestMachoImports_InvalidPath(t *testing.T) {
	arch, libs := machoImports("/nonexistent/path/binary")
	if arch != "" {
		t.Errorf("expected empty arch for nonexistent file, got %q", arch)
	}
	if libs != nil {
		t.Errorf("expected nil libs for nonexistent file, got %v", libs)
	}
}

func TestAnalyzeSingleFile_Verbose(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF binaries only available on linux")
	}

	binPath := buildTestBinary(t)

	// verbose=true should not panic or error
	result, err := AnalyzeSingleFile(binPath, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestAnalyzeSingleFile_PathAndName(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF binaries only available on linux")
	}

	binPath := buildTestBinary(t)

	result, err := AnalyzeSingleFile(binPath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.Path != binPath {
		t.Errorf("Path = %q, want %q", result.Path, binPath)
	}
	if result.Name != filepath.Base(binPath) {
		t.Errorf("Name = %q, want %q", result.Name, filepath.Base(binPath))
	}
	if result.SizeMB <= 0 {
		t.Error("expected SizeMB > 0")
	}
}

func TestAnalyzeSingleFile_URLsInBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF binaries only available on linux")
	}

	// buildTestBinary embeds "https://example.com/test" in the source
	binPath := buildTestBinary(t)

	result, err := AnalyzeSingleFile(binPath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.URLCount <= 0 {
		t.Error("expected URLCount > 0 — binary was built with an embedded URL")
	}
}

func TestAnalyze_WithRealBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF binaries only available on linux")
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
			if info.Type != "ELF" {
				t.Errorf("Type = %q, want ELF", info.Type)
			}
			if info.SizeBytes <= 0 {
				t.Error("expected SizeBytes > 0")
			}
			break
		}
	}

	if !found {
		t.Errorf("test binary %q not found in Analyze results", filepath.Base(binPath))
	}
}

func TestAnalyze_SkipsTinyFiles(t *testing.T) {
	dir := t.TempDir()

	// Write a tiny ELF-magic file that is below the 64KB threshold
	tiny := filepath.Join(dir, "small")
	data := make([]byte, 1024)
	data[0] = 0x7f
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	if err := os.WriteFile(tiny, data, 0o644); err != nil {
		t.Fatal(err)
	}

	infos := Analyze(dir, false)
	for _, info := range infos {
		if info.Name == "small" {
			t.Error("Analyze should skip files smaller than 64KB")
		}
	}
}

func TestAnalyze_SkipsUnknownExtensions(t *testing.T) {
	dir := t.TempDir()

	// Write a large-enough file with ELF magic but a .txt extension
	path := filepath.Join(dir, "notabinary.txt")
	data := make([]byte, 128*1024)
	data[0] = 0x7f
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	infos := Analyze(dir, false)
	for _, info := range infos {
		if info.Name == "notabinary.txt" {
			t.Error("Analyze should skip files with unrecognized extensions")
		}
	}
}

func TestAnalyze_Verbose(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF binaries only available on linux")
	}

	binPath := buildTestBinary(t)
	dir := filepath.Dir(binPath)

	// verbose=true should not panic
	infos := Analyze(dir, true)
	if len(infos) == 0 {
		t.Fatal("expected at least one result")
	}
}

func TestAnalyze_SortedBySizeDesc(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF binaries only available on linux")
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

func TestAnalyze_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	infos := Analyze(dir, false)
	if infos != nil {
		t.Errorf("expected nil result for empty directory, got %v", infos)
	}
}

func TestAnalyze_NonExistentDirectory(t *testing.T) {
	infos := Analyze("/nonexistent/directory/path", false)
	// Walk silently ignores errors, should return nil or empty
	if len(infos) != 0 {
		t.Errorf("expected no results for nonexistent directory, got %d", len(infos))
	}
}

func TestRunToolSuite_ELF(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF binaries only available on linux")
	}
	if _, err := exec.LookPath("readelf"); err != nil {
		t.Skip("readelf not installed")
	}

	binPath := buildTestBinary(t)

	bi := Info{
		Path: binPath,
		Name: filepath.Base(binPath),
		Type: "ELF",
	}

	results := runToolSuite(bi)

	if len(results) == 0 {
		t.Error("expected non-empty tool results")
	}

	nameSet := make(map[string]bool)
	for _, r := range results {
		nameSet[r.Name] = true
		if r.Name == "" {
			t.Error("expected non-empty tool name in all results")
		}
		if r.Command == "" {
			t.Error("expected non-empty command in all results")
		}
		if r.Status == "" {
			t.Error("expected non-empty status in all results")
		}
	}

	// ELF-specific tools should be present
	for _, expected := range []string{"readelf", "ldd", "nm"} {
		if !nameSet[expected] {
			t.Errorf("expected tool %q in ELF tool suite results", expected)
		}
	}
}

func TestRunToolSuite_PE(t *testing.T) {
	if _, err := exec.LookPath("objdump"); err != nil {
		t.Skip("objdump not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.exe")
	// Write minimal PE magic header padded to a valid-looking size
	data := make([]byte, 256)
	data[0] = 'M'
	data[1] = 'Z'
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	bi := Info{
		Path: path,
		Name: "fake.exe",
		Type: "PE",
	}

	results := runToolSuite(bi)
	if len(results) == 0 {
		t.Error("expected non-empty tool results for PE")
	}

	nameSet := make(map[string]bool)
	for _, r := range results {
		nameSet[r.Name] = true
	}

	// PE-specific tool
	if !nameSet["objdump"] {
		t.Error("expected objdump in PE tool suite results")
	}
}

func TestExtractStrings_NonExistentFile(t *testing.T) {
	total, urlCount, urls, samples := extractStrings("/nonexistent/file", 1024, 4, 10, 10)
	if total != 0 || urlCount != 0 || urls != nil || samples != nil {
		t.Errorf("expected zero results for nonexistent file, got total=%d urlCount=%d urls=%v samples=%v",
			total, urlCount, urls, samples)
	}
}

func TestExtractStrings_SampleLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manystrs.bin")

	// Generate many distinct strings separated by null bytes
	var buf []byte
	for i := range 100 {
		buf = append(buf, fmt.Appendf(nil, "stringvalue%04d", i)...)
		buf = append(buf, 0x00)
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, _, samples := extractStrings(path, 1024*1024, 4, 5, 5)
	if len(samples) > 5 {
		t.Errorf("expected at most 5 sample strings, got %d", len(samples))
	}
}

func TestExtractStrings_URLSampleLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manyurls.bin")

	// Embed more URLs than the limit allows
	var buf []byte
	for i := range 20 {
		buf = append(buf, fmt.Appendf(nil, "https://example.com/path/%04d", i)...)
		buf = append(buf, 0x00)
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	_, urlCount, sampleURLs, _ := extractStrings(path, 1024*1024, 4, 5, 25)
	if urlCount < 5 {
		t.Errorf("expected urlCount >= 5, got %d", urlCount)
	}
	if len(sampleURLs) > 5 {
		t.Errorf("expected at most 5 sample URLs, got %d", len(sampleURLs))
	}
}
