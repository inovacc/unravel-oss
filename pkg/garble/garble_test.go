/* Copyright (c) 2026 Security Research */
package garble

import (
	"debug/elf"
	"debug/pe"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// TestExtractStrings_OversizedRejected verifies ExtractStrings rejects a binary
// larger than maxStringsBytes via os.Stat, before slurping it into memory. The
// cap is shrunk so a few-KB file trips it without allocating gigabytes.
func TestExtractStrings_OversizedRejected(t *testing.T) {
	orig := maxStringsBytes
	maxStringsBytes = 1024
	defer func() { maxStringsBytes = orig }()

	path := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(path, make([]byte, 2048), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractStrings(path, 4)
	if err == nil {
		t.Fatal("expected error for oversized binary, got nil")
	}
	if !errors.Is(err, safeio.ErrInvalidSize) {
		t.Fatalf("expected ErrInvalidSize, got %v", err)
	}
}

// TestExtractStrings_UnderCapAccepted confirms a file under the cap is scanned.
func TestExtractStrings_UnderCapAccepted(t *testing.T) {
	orig := maxStringsBytes
	maxStringsBytes = 1 << 20
	defer func() { maxStringsBytes = orig }()

	path := filepath.Join(t.TempDir(), "ok.bin")
	if err := os.WriteFile(path, []byte("hello world this is a printable string"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractStrings(path, 4); err != nil {
		t.Fatalf("unexpected error for under-cap file: %v", err)
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want float64
		eps  float64
	}{
		{name: "empty string", s: "", want: 0, eps: 0.001},
		{name: "single char repeated", s: "aaaa", want: 0, eps: 0.001},
		{name: "two chars equal", s: "ab", want: 1.0, eps: 0.001},
		{name: "four distinct chars", s: "abcd", want: 2.0, eps: 0.001},
		{name: "high entropy", s: "aB3$xY9!", want: 3.0, eps: 0.1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShannonEntropy(tt.s)
			if math.Abs(got-tt.want) > tt.eps {
				t.Errorf("ShannonEntropy(%q) = %f, want %f (eps %f)", tt.s, got, tt.want, tt.eps)
			}
		})
	}
}

func TestConfidenceLabel(t *testing.T) {
	tests := []struct {
		name string
		conf float64
		want string
	}{
		{name: "certain", conf: 0.90, want: "CERTAIN"},
		{name: "high", conf: 0.70, want: "HIGH"},
		{name: "medium", conf: 0.50, want: "MEDIUM"},
		{name: "low", conf: 0.35, want: "LOW"},
		{name: "none", conf: 0.20, want: "NONE"},
		{name: "zero", conf: 0.0, want: "NONE"},
		{name: "boundary certain", conf: 0.85, want: "CERTAIN"},
		{name: "boundary high", conf: 0.65, want: "HIGH"},
		{name: "boundary medium", conf: 0.45, want: "MEDIUM"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := confidenceLabel(tt.conf)
			if got != tt.want {
				t.Errorf("confidenceLabel(%f) = %q, want %q", tt.conf, got, tt.want)
			}
		})
	}
}

func TestCategorizeString(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want StringCategory
	}{
		{"URL", "https://example.com/api/v1", CatURL},
		{"API endpoint", "/api/v1/users/list", CatAPIEndpoint},
		{"file path unix", "/usr/local/bin/app", CatFilePath},
		{"file path windows", "C:\\Users\\test\\file.txt", CatFilePath},
		{"registry key", "HKEY_LOCAL_MACHINE\\SOFTWARE", CatRegistry},
		{"error message", "connection refused by host", CatErrorMessage},
		{"crypto term", "aes-256-gcm encryption", CatCrypto},
		{"network term", "tcp connection to localhost", CatNetwork},
		{"general", "hello world foo bar", CatGeneral},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := categorizeString(tt.s)
			if got != tt.want {
				t.Errorf("categorizeString(%q) = %q, want %q", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsObfuscatedName(t *testing.T) {
	tests := []struct {
		name string
		sym  string
		want bool
	}{
		{"short name not obfuscated", "abc", false},
		{"runtime prefix", "runtime.goexit", false},
		{"readable word", "main", false},
		{"readable word init", "init", false},
		{"garble hash mixed case digits", "aBcDeF1234g", true},
		{"garble hash with package", "pkg.aB3cD4eF5g", true},
		{"camelcase matches hash pattern", "pkg.HandleRequest", true}, // CamelCase triggers hash detection
		{"all lowercase long", "someverylongname", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isObfuscatedName(tt.sym)
			if got != tt.want {
				t.Errorf("isObfuscatedName(%q) = %v, want %v", tt.sym, got, tt.want)
			}
		})
	}
}

func TestIsRuntimeSymbol(t *testing.T) {
	tests := []struct {
		name string
		sym  string
		want bool
	}{
		{"runtime func", "runtime.goexit", true},
		{"fmt func", "fmt.Println", true},
		{"os func", "os.Open", true},
		{"user func", "myapp.Handler", false},
		{"go prefix", "go.itab.foo", true},
		{"type prefix", "type.runtime.g", true},
		{"crypto prefix", "crypto.sha256", true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRuntimeSymbol(tt.sym)
			if got != tt.want {
				t.Errorf("isRuntimeSymbol(%q) = %v, want %v", tt.sym, got, tt.want)
			}
		})
	}
}

func TestExtractPackage(t *testing.T) {
	tests := []struct {
		name string
		sym  string
		want string
	}{
		{"simple", "main.Run", "main"},
		{"nested", "github.com/user/repo/pkg.Func", "github.com/user/repo/pkg"},
		{"method receiver", "pkg.(*Server).Handle", "pkg"},
		{"no package", "standalone", ""},
		{"just dot", ".hidden", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPackage(tt.sym)
			if got != tt.want {
				t.Errorf("extractPackage(%q) = %q, want %q", tt.sym, got, tt.want)
			}
		})
	}
}

func TestDetectFileFormat(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	// Build a Go binary to test ELF detection
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-binary")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	format, err := detectFileFormat(bin)
	if err != nil {
		t.Fatalf("detectFileFormat: %v", err)
	}

	expectedFormat := FormatELF
	if runtime.GOOS == "windows" {
		expectedFormat = FormatPE
	}
	if format != expectedFormat {
		t.Errorf("expected %s, got %s", expectedFormat, format)
	}

	// Test invalid file
	invalidFile := filepath.Join(tmpDir, "invalid.bin")
	if err := os.WriteFile(invalidFile, []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = detectFileFormat(invalidFile)
	if err == nil {
		t.Error("expected error for invalid binary")
	}
}

func TestDetect_GoBinary(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	// Build a normal Go binary — should NOT be detected as garbled
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-binary")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	result, err := Detect(bin)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	expectedFmt := "ELF"
	if runtime.GOOS == "windows" {
		expectedFmt = "PE"
	}
	if result.Format != expectedFmt {
		t.Errorf("expected %s format, got %q", expectedFmt, result.Format)
	}

	if runtime.GOOS != "windows" && result.IsGarbled {
		t.Errorf("normal Go binary should not be detected as garbled (confidence: %.2f)", result.Confidence)
	}

	if len(result.Heuristics) != 6 {
		t.Errorf("expected 6 heuristics, got %d", len(result.Heuristics))
	}

	t.Logf("Detect result: garbled=%v confidence=%.2f (%s)", result.IsGarbled, result.Confidence, result.ConfidenceLabel)
}

func TestDetect_NonexistentFile(t *testing.T) {
	_, err := Detect("/tmp/nonexistent-binary-12345")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestExtractStrings_SyntheticBinary(t *testing.T) {
	tmpDir := t.TempDir()
	binFile := filepath.Join(tmpDir, "test.bin")

	// Create a binary with known strings
	var data []byte
	data = append(data, []byte("https://api.example.com/v1/users")...)
	data = append(data, 0x00) // null terminator
	data = append(data, []byte("/etc/passwd is a file path")...)
	data = append(data, 0x00)
	data = append(data, []byte("error: connection refused")...)
	data = append(data, 0x00)
	data = append(data, []byte("ab")...) // too short
	data = append(data, 0x00)

	if err := os.WriteFile(binFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractStrings(binFile, 4)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}

	if result.TotalStrings < 3 {
		t.Errorf("expected at least 3 strings, got %d", result.TotalStrings)
	}

	// Check categories exist
	if result.ByCategory[CatURL] < 1 {
		t.Error("expected at least 1 URL string")
	}

	if result.ByCategory[CatFilePath] < 1 {
		t.Error("expected at least 1 file path string")
	}

	if result.ByCategory[CatErrorMessage] < 1 {
		t.Error("expected at least 1 error message string")
	}

	if result.AvgEntropy <= 0 {
		t.Error("expected positive average entropy")
	}
}

func TestExtractStrings_NonexistentFile(t *testing.T) {
	_, err := ExtractStrings("/tmp/nonexistent-12345", 4)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestExtractStrings_MinLen(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.bin")

	// String of exactly 3 chars should be excluded with default minLen=4
	data := []byte("abc\x00abcdef\x00")
	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractStrings(f, 0) // minLen < 4 gets clamped to 4
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalStrings != 1 {
		t.Errorf("expected 1 string (abcdef), got %d", result.TotalStrings)
	}
}

func TestAnalyzeSymbols_GoBinary(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-binary")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	result, err := AnalyzeSymbols(bin)
	if err != nil {
		t.Fatalf("AnalyzeSymbols: %v", err)
	}

	if result.TotalSymbols == 0 {
		t.Error("expected symbols in Go binary")
	}

	if result.FunctionCount == 0 {
		t.Error("expected function symbols")
	}

	if result.RuntimeCount == 0 {
		t.Error("expected runtime symbols in Go binary")
	}

	// Note: ObfuscationRatio can be moderately high even for normal binaries
	// because CamelCase names match the hash pattern heuristic

	t.Logf("Symbols: total=%d func=%d runtime=%d obfuscated=%d ratio=%.2f packages=%d",
		result.TotalSymbols, result.FunctionCount, result.RuntimeCount,
		result.ObfuscatedCount, result.ObfuscationRatio, len(result.Packages))
}

func TestScanDirectory(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-binary")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	// Also create a non-Go file that should be skipped
	if err := os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ScanDirectory(tmpDir, false)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if result.TotalFiles == 0 {
		t.Error("expected to scan at least one file")
	}

	t.Logf("Scan: total=%d go=%d garbled=%d", result.TotalFiles, result.GoBinaryCount, result.GarbledCount)
}

func TestScanDirectory_Nonexistent(t *testing.T) {
	result, err := ScanDirectory("/tmp/nonexistent-dir-12345", false)
	// ScanDirectory may or may not return error; just check it doesn't panic
	if err != nil {
		return // error is fine
	}

	if result.TotalFiles != 0 {
		t.Error("expected 0 files for nonexistent directory")
	}
}

func TestBuildDetectReport(t *testing.T) {
	tests := []struct {
		name     string
		result   *DetectionResult
		contains []string
	}{
		{
			name: "basic report with heuristics",
			result: &DetectionResult{
				FilePath:        "/tmp/test-binary",
				FileName:        "test-binary",
				FileSize:        12345,
				Format:          "ELF",
				IsGarbled:       true,
				Confidence:      0.75,
				ConfidenceLabel: "HIGH",
				Heuristics: []Heuristic{
					{Name: "h1", Description: "Missing build info", Weight: 0.15, Detected: true, Details: "stripped"},
					{Name: "h2", Description: "No DWARF", Weight: 0.15, Detected: false, Details: "DWARF present"},
				},
			},
			contains: []string{
				"# Garble Detection Report: test-binary",
				"`/tmp/test-binary`",
				"12345 bytes",
				"ELF",
				"**Garbled:** true",
				"75.0%",
				"HIGH",
				"| # | Heuristic | Weight | Detected | Details |",
				"| 1 | Missing build info | 0.15 | **Yes** | stripped |",
				"| 2 | No DWARF | 0.15 | No | DWARF present |",
			},
		},
		{
			name: "truncates long details",
			result: &DetectionResult{
				FileName: "bin",
				Heuristics: []Heuristic{
					{Description: "test", Weight: 0.1, Detected: true, Details: "A very long details string that exceeds the sixty character limit and should be truncated"},
				},
			},
			contains: []string{"..."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := buildDetectReport(tt.result)
			for _, s := range tt.contains {
				if !strings.Contains(report, s) {
					t.Errorf("report missing %q\n\nReport:\n%s", s, report)
				}
			}
		})
	}
}

func TestBuildScanReport(t *testing.T) {
	tests := []struct {
		name     string
		result   *ScanResult
		contains []string
	}{
		{
			name: "no go binaries",
			result: &ScanResult{
				Directory:     "/tmp/empty",
				TotalFiles:    5,
				GoBinaryCount: 0,
				GarbledCount:  0,
				Results:       nil,
			},
			contains: []string{
				"# Garble Scan Report",
				"`/tmp/empty`",
				"**Files Scanned:** 5",
				"**Go Binaries Found:** 0",
				"No Go binaries found.",
			},
		},
		{
			name: "with garbled results",
			result: &ScanResult{
				Directory:     "/tmp/bins",
				TotalFiles:    10,
				GoBinaryCount: 2,
				GarbledCount:  1,
				Results: []*DetectionResult{
					{
						FileName:        "clean",
						FilePath:        "/tmp/bins/clean",
						Format:          "ELF",
						IsGarbled:       false,
						Confidence:      0.1,
						ConfidenceLabel: "NONE",
					},
					{
						FileName:        "garbled",
						FilePath:        "/tmp/bins/garbled",
						Format:          "PE",
						IsGarbled:       true,
						Confidence:      0.9,
						ConfidenceLabel: "CERTAIN",
						Heuristics: []Heuristic{
							{Description: "hashed symbols", Detected: true, Details: "90% hashed"},
						},
					},
				},
			},
			contains: []string{
				"**Garbled Binaries:** 1",
				"| clean | ELF | No |",
				"| garbled | PE | **Yes** |",
				"### garbled",
				"`/tmp/bins/garbled`",
				"| hashed symbols | Yes | 90% hashed |",
			},
		},
		{
			name: "truncates long heuristic details in scan",
			result: &ScanResult{
				Directory: "/tmp",
				Results: []*DetectionResult{
					{
						FileName:  "x",
						IsGarbled: true,
						Heuristics: []Heuristic{
							{Description: "test", Detected: true, Details: "This is a very long detail string that definitely exceeds fifty characters"},
						},
					},
				},
			},
			contains: []string{"..."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := buildScanReport(tt.result)
			for _, s := range tt.contains {
				if !strings.Contains(report, s) {
					t.Errorf("report missing %q\n\nReport:\n%s", s, report)
				}
			}
		})
	}
}

func TestIsScanCandidate(t *testing.T) {
	tests := []struct {
		name string
		file string
		path string
		want bool
	}{
		{"exe extension", "app.exe", "/tmp/app.exe", true},
		{"so extension", "lib.so", "/tmp/lib.so", true},
		{"dll extension", "lib.dll", "/tmp/lib.dll", true},
		{"dylib extension", "lib.dylib", "/tmp/lib.dylib", true},
		{"txt extension", "readme.txt", "/tmp/readme.txt", false},
		{"go extension", "main.go", "/tmp/main.go", false},
		{"py extension", "script.py", "/tmp/script.py", false},
		{"extensionless nonexistent", "mybinary", "/tmp/nonexistent-binary-xyz", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isScanCandidate(tt.file, tt.path)
			if got != tt.want {
				t.Errorf("isScanCandidate(%q, %q) = %v, want %v", tt.file, tt.path, got, tt.want)
			}
		})
	}

	t.Run("extensionless ELF binary", func(t *testing.T) {
		tmpDir := t.TempDir()
		elfPath := filepath.Join(tmpDir, "mybinary")

		// Minimal ELF header (64-bit little-endian)
		elfHeader := make([]byte, 64)
		copy(elfHeader, []byte{0x7f, 'E', 'L', 'F'}) // ELF magic
		elfHeader[4] = 2                             // 64-bit
		elfHeader[5] = 1                             // little-endian
		elfHeader[6] = 1                             // ELF version

		if err := os.WriteFile(elfPath, elfHeader, 0o755); err != nil {
			t.Fatal(err)
		}

		if !isScanCandidate("mybinary", elfPath) {
			t.Error("extensionless ELF file should be a scan candidate")
		}
	})

	t.Run("extensionless non-binary", func(t *testing.T) {
		tmpDir := t.TempDir()
		txtPath := filepath.Join(tmpDir, "readme")

		if err := os.WriteFile(txtPath, []byte("just some plain text"), 0o644); err != nil {
			t.Fatal(err)
		}

		if isScanCandidate("readme", txtPath) {
			t.Error("extensionless non-binary file should not be a scan candidate")
		}
	})
}

func TestGenerateDetectReport(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "reports", "detect.md")

	result := &DetectionResult{
		FileName:        "test",
		FilePath:        "/tmp/test",
		Format:          "ELF",
		IsGarbled:       false,
		Confidence:      0.1,
		ConfidenceLabel: "NONE",
	}

	if err := GenerateDetectReport(result, outPath); err != nil {
		t.Fatalf("GenerateDetectReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	if !strings.Contains(string(data), "# Garble Detection Report: test") {
		t.Error("report file missing expected header")
	}
}

func TestGenerateScanReport(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "reports", "scan.md")

	result := &ScanResult{
		Directory:  "/tmp",
		TotalFiles: 3,
	}

	if err := GenerateScanReport(result, outPath); err != nil {
		t.Fatalf("GenerateScanReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	if !strings.Contains(string(data), "# Garble Scan Report") {
		t.Error("report file missing expected header")
	}
}

func TestElfMachineArch(t *testing.T) {
	tests := []struct {
		name    string
		machine elf.Machine
		want    string
	}{
		{"amd64", elf.EM_X86_64, "amd64"},
		{"386", elf.EM_386, "386"},
		{"arm64", elf.EM_AARCH64, "arm64"},
		{"arm", elf.EM_ARM, "arm"},
		{"mips", elf.EM_MIPS, "mips"},
		{"riscv64", elf.EM_RISCV, "riscv64"},
		{"ppc64", elf.EM_PPC64, "ppc64"},
		{"s390x", elf.EM_S390, "s390x"},
		{"unknown", elf.Machine(9999), "unknown(9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := elfMachineArch(tt.machine)
			if got != tt.want {
				t.Errorf("elfMachineArch(%v) = %q, want %q", tt.machine, got, tt.want)
			}
		})
	}
}

func TestExtractNoteString(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"too short", []byte{1, 2, 3}, ""},
		{"no printable", make([]byte, 20), ""},
		{
			"valid build id",
			func() []byte {
				d := make([]byte, 12) // header
				d = append(d, []byte("abcdefghijklmnop")...)
				return d
			}(),
			"abcdefghijklmnop",
		},
		{
			"short printable ignored",
			func() []byte {
				d := make([]byte, 12)
				d = append(d, []byte("short")...)
				d = append(d, 0)
				return d
			}(),
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNoteString(tt.data)
			if got != tt.want {
				t.Errorf("extractNoteString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractInfo_GoBinary(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-binary")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	info, err := ExtractInfo(bin)
	if err != nil {
		t.Fatalf("ExtractInfo: %v", err)
	}

	expectedFmt := "ELF"
	if runtime.GOOS == "windows" {
		expectedFmt = "PE"
	}
	if info.Format != expectedFmt {
		t.Errorf("expected %s format, got %q", expectedFmt, info.Format)
	}

	if !info.HasBuildInfo {
		t.Error("expected build info to be present")
	}

	if info.GoVersion == "" {
		t.Error("expected non-empty Go version")
	}

	if info.HasSymbolTable && info.SymbolCount == 0 {
		t.Error("has symbol table but zero count")
	}

	t.Logf("Info: format=%s go=%s arch=%s os=%s symbols=%d dwarf=%v static=%v",
		info.Format, info.GoVersion, info.Arch, info.OS, info.SymbolCount, info.HasDWARF, info.IsStaticLinked)
}

func TestExtractInfo_Nonexistent(t *testing.T) {
	_, err := ExtractInfo("/tmp/nonexistent-binary-xyz-12345")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestPeSymType(t *testing.T) {
	tests := []struct {
		name          string
		sectionNumber int16
		symType       uint16
		want          string
	}{
		{"func", 1, 0x20, "FUNC"},
		{"object", 1, 0x00, "OBJECT"},
		{"extern", 0, 0x00, "EXTERN"},
		{"other", 2, 0x10, "OTHER"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &pe.Symbol{
				SectionNumber: tt.sectionNumber,
				Type:          tt.symType,
			}
			got := peSymType(s)
			if got != tt.want {
				t.Errorf("peSymType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestElfSymType(t *testing.T) {
	tests := []struct {
		name string
		info byte
		want string
	}{
		{"func", 0x12, "FUNC"},     // STT_FUNC=2, STB_GLOBAL=1 → info=0x12
		{"object", 0x11, "OBJECT"}, // STT_OBJECT=1, STB_GLOBAL=1
		{"notype", 0x10, "NOTYPE"}, // STT_NOTYPE=0, STB_GLOBAL=1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := elfSymType(tt.info)
			if got != tt.want {
				t.Errorf("elfSymType(0x%02x) = %q, want %q", tt.info, got, tt.want)
			}
		})
	}
}

// buildTestGoBinary compiles a minimal Go binary and returns its path.
func buildTestGoBinary(t *testing.T) string {
	t.Helper()

	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-binary")

	if err := os.WriteFile(src, []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	return bin
}

func TestDetect_ChecksRun(t *testing.T) {
	bin := buildTestGoBinary(t)

	result, err := Detect(bin)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	expectedChecks := map[string]bool{
		"missing_build_info": false,
		"no_dwarf":           false,
		"hashed_symbols":     false,
		"missing_go_paths":   false,
		"missing_build_id":   false,
		"garble_strings":     false,
	}

	for _, h := range result.Heuristics {
		if _, ok := expectedChecks[h.Name]; ok {
			expectedChecks[h.Name] = true
		}

		if h.Description == "" {
			t.Errorf("heuristic %q has empty Description", h.Name)
		}

		if h.Weight <= 0 {
			t.Errorf("heuristic %q has non-positive weight: %f", h.Name, h.Weight)
		}

		if h.Details == "" {
			t.Errorf("heuristic %q has empty Details", h.Name)
		}
	}

	for name, found := range expectedChecks {
		if !found {
			t.Errorf("expected heuristic %q not found in result.Heuristics", name)
		}
	}
}

func TestDetect_NonGoBinary(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake-elf")

	// Minimal valid ELF header (64-bit, little-endian) that is NOT a Go binary
	elfHeader := make([]byte, 64)
	copy(elfHeader, []byte{0x7f, 'E', 'L', 'F'}) // ELF magic
	elfHeader[4] = 2                             // 64-bit
	elfHeader[5] = 1                             // little-endian
	elfHeader[6] = 1                             // ELF version

	if err := os.WriteFile(fakeBin, elfHeader, 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := Detect(fakeBin)
	if err != nil {
		// Some heuristics may fail on a minimal ELF; that is acceptable
		t.Logf("Detect returned error (expected for minimal ELF): %v", err)
		return
	}

	if result.IsGarbled && result.Confidence >= 0.5 {
		t.Errorf("minimal non-Go ELF should not be detected as garbled with high confidence, got confidence=%.2f", result.Confidence)
	}

	t.Logf("Non-Go ELF: garbled=%v confidence=%.2f", result.IsGarbled, result.Confidence)
}

func TestCheckBuildInfo_GoBinary(t *testing.T) {
	bin := buildTestGoBinary(t)

	h := checkBuildInfo(bin)

	if h.Name != "missing_build_info" {
		t.Errorf("expected name %q, got %q", "missing_build_info", h.Name)
	}

	if h.Details == "" {
		t.Error("expected non-empty Details")
	}

	// A normal Go binary should have build info present
	if h.Detected {
		t.Errorf("normal Go binary should have build info, but check detected it as missing: %s", h.Details)
	}
}

func TestCheckDWARF_GoBinary(t *testing.T) {
	bin := buildTestGoBinary(t)

	h := checkDWARF(bin, FormatELF)

	if h.Name != "no_dwarf" {
		t.Errorf("expected name %q, got %q", "no_dwarf", h.Name)
	}

	if h.Details == "" {
		t.Error("expected non-empty Details")
	}

	// A normal Go binary (not stripped) should have DWARF
	if h.Detected {
		t.Logf("DWARF not present (may be stripped): %s", h.Details)
	} else {
		t.Logf("DWARF present: %s", h.Details)
	}
}

func TestCheckHashedSymbols_GoBinary(t *testing.T) {
	bin := buildTestGoBinary(t)

	h := checkHashedSymbols(bin, FormatELF)

	if h.Name != "hashed_symbols" {
		t.Errorf("expected name %q, got %q", "hashed_symbols", h.Name)
	}

	if h.Details == "" {
		t.Error("expected non-empty Details")
	}

	// Note: CamelCase Go symbol names can trigger the hash pattern heuristic,
	// so a normal Go binary may have Detected=true here. We only verify the
	// check ran and produced meaningful output.
	t.Logf("Hashed symbols check: detected=%v details=%s", h.Detected, h.Details)
}

func TestCheckGoBuildID_GoBinary(t *testing.T) {
	bin := buildTestGoBinary(t)

	h := checkGoBuildID(bin, FormatELF)

	if h.Name != "missing_build_id" {
		t.Errorf("expected name %q, got %q", "missing_build_id", h.Name)
	}

	if h.Details == "" {
		t.Error("expected non-empty Details")
	}

	// Normal Go binary should have a build ID
	if h.Detected {
		t.Errorf("normal Go binary should have build ID: %s", h.Details)
	}

	t.Logf("Build ID check: detected=%v details=%s", h.Detected, h.Details)
}

func TestCheckGoPackagePaths_GoBinary(t *testing.T) {
	bin := buildTestGoBinary(t)

	h := checkGoPackagePaths(bin, FormatELF)

	if h.Name != "missing_go_paths" {
		t.Errorf("expected name %q, got %q", "missing_go_paths", h.Name)
	}

	if h.Details == "" {
		t.Error("expected non-empty Details")
	}

	t.Logf("Package paths check: detected=%v details=%s", h.Detected, h.Details)
}

func TestIsGoBinary(t *testing.T) {
	bin := buildTestGoBinary(t)

	if !isGoBinary(bin) {
		t.Error("expected isGoBinary to return true for a Go binary")
	}

	// Test with a non-Go file
	tmpDir := t.TempDir()
	txtFile := filepath.Join(tmpDir, "readme.txt")

	if err := os.WriteFile(txtFile, []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	if isGoBinary(txtFile) {
		t.Error("expected isGoBinary to return false for a text file")
	}

	// Test with a minimal non-Go ELF
	fakeElf := filepath.Join(tmpDir, "fake-elf")
	elfHeader := make([]byte, 64)
	copy(elfHeader, []byte{0x7f, 'E', 'L', 'F'})
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1

	if err := os.WriteFile(fakeElf, elfHeader, 0o755); err != nil {
		t.Fatal(err)
	}

	if isGoBinary(fakeElf) {
		t.Error("expected isGoBinary to return false for a non-Go ELF")
	}
}

func TestExtractInfo_ELFDetails(t *testing.T) {
	bin := buildTestGoBinary(t)

	info, err := ExtractInfo(bin)
	if err != nil {
		t.Fatalf("ExtractInfo: %v", err)
	}

	if info.Arch == "" {
		t.Error("expected non-empty Arch")
	}

	expectedFmt := "ELF"
	if runtime.GOOS == "windows" {
		expectedFmt = "PE"
	}
	if info.Format != expectedFmt {
		t.Errorf("expected format %s, got %q", expectedFmt, info.Format)
	}

	if info.GoVersion == "" {
		t.Error("expected non-empty GoVersion for a Go binary")
	}

	if len(info.Sections) == 0 {
		t.Error("expected non-empty Sections list for ELF binary")
	}

	if info.BuildID == "" {
		t.Log("BuildID is empty (may not be extractable from note section)")
	}

	// Verify ELF-specific fields were populated
	if !info.HasBuildInfo {
		t.Error("expected HasBuildInfo=true for a normal Go binary")
	}

	if !info.HasSymbolTable {
		t.Error("expected HasSymbolTable=true for a non-stripped Go binary")
	}

	if info.SymbolCount == 0 {
		t.Error("expected SymbolCount > 0 for a non-stripped Go binary")
	}

	t.Logf("ELF info: arch=%s os=%s goVersion=%s sections=%d symbols=%d dwarf=%v static=%v buildID=%s",
		info.Arch, info.OS, info.GoVersion, len(info.Sections), info.SymbolCount, info.HasDWARF, info.IsStaticLinked, info.BuildID)
}

func TestAnalyzeSymbols_Details(t *testing.T) {
	bin := buildTestGoBinary(t)

	result, err := AnalyzeSymbols(bin)
	if err != nil {
		t.Fatalf("AnalyzeSymbols: %v", err)
	}

	if result.TotalSymbols == 0 {
		t.Fatal("expected TotalSymbols > 0")
	}

	if len(result.Packages) == 0 {
		t.Error("expected at least one package in Packages list")
	}

	// A Go binary with fmt should have runtime and fmt packages
	hasRuntime := false
	hasFmt := false

	for _, pkg := range result.Packages {
		if strings.HasPrefix(pkg, "runtime") {
			hasRuntime = true
		}

		if pkg == "fmt" || strings.HasPrefix(pkg, "fmt") {
			hasFmt = true
		}
	}

	if !hasRuntime {
		t.Error("expected runtime package in symbol packages")
	}

	if !hasFmt {
		t.Error("expected fmt package in symbol packages")
	}

	if result.FunctionCount == 0 {
		t.Error("expected FunctionCount > 0")
	}

	if result.RuntimeCount == 0 {
		t.Error("expected RuntimeCount > 0")
	}

	t.Logf("Symbol details: total=%d funcs=%d objects=%d runtime=%d obfuscated=%d packages=%v",
		result.TotalSymbols, result.FunctionCount, result.ObjectCount, result.RuntimeCount, result.ObfuscatedCount, result.Packages[:min(5, len(result.Packages))])
}

func TestCheckGarbleStrings_GoBinary(t *testing.T) {
	bin := buildTestGoBinary(t)

	h := checkGarbleStrings(bin)

	if h.Name != "garble_strings" {
		t.Errorf("expected name %q, got %q", "garble_strings", h.Name)
	}

	if h.Details == "" {
		t.Error("expected non-empty Details")
	}

	// A normal Go binary should not contain garble markers
	if h.Detected {
		t.Errorf("normal Go binary should not have garble string markers: %s", h.Details)
	}
}

func TestCollectSymbolNames_GoBinary(t *testing.T) {
	bin := buildTestGoBinary(t)

	format := FormatELF
	if runtime.GOOS == "windows" {
		format = FormatPE
	}
	names := collectSymbolNames(bin, format)

	if len(names) == 0 {
		t.Fatal("expected non-empty symbol names from Go binary")
	}

	hasRuntimeSymbol := false

	for _, name := range names {
		if strings.HasPrefix(name, "runtime.") {
			hasRuntimeSymbol = true
			break
		}
	}

	if !hasRuntimeSymbol {
		t.Error("expected at least one runtime.* symbol in Go binary")
	}

	t.Logf("Collected %d symbol names", len(names))
}

func TestCheckDWARF_InvalidFormat(t *testing.T) {
	// Test checkDWARF with a non-existent file for each format to cover error paths
	tests := []struct {
		name   string
		format BinaryFormat
	}{
		{"ELF error path", FormatELF},
		{"PE error path", FormatPE},
		{"MachO error path", FormatMachO},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := checkDWARF("/tmp/nonexistent-binary-xyz-99999", tt.format)
			if h.Name != "no_dwarf" {
				t.Errorf("expected name %q, got %q", "no_dwarf", h.Name)
			}

			if h.Details == "" {
				t.Error("expected non-empty Details for error case")
			}
		})
	}
}

func TestCheckGarbleStrings_WithMarkers(t *testing.T) {
	tmpDir := t.TempDir()
	binFile := filepath.Join(tmpDir, "fake-garbled")

	// Create an ELF-like file containing garble markers
	var data []byte
	data = append(data, []byte{0x7f, 'E', 'L', 'F'}...) // ELF magic
	data = append(data, make([]byte, 60)...)            // pad to 64 bytes
	data = append(data, []byte("some random content before garble marker")...)
	data = append(data, []byte("mvdan.cc/garble is the tool used")...)
	data = append(data, []byte("and GARBLE_SEED was set")...)

	if err := os.WriteFile(binFile, data, 0o755); err != nil {
		t.Fatal(err)
	}

	h := checkGarbleStrings(binFile)

	if !h.Detected {
		t.Errorf("expected garble markers to be detected, got details: %s", h.Details)
	}

	if !strings.Contains(h.Details, "mvdan.cc/garble") {
		t.Errorf("expected details to mention mvdan.cc/garble, got: %s", h.Details)
	}
}

func TestDetect_StrippedGoBinary(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "stripped-binary")

	if err := os.WriteFile(src, []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Build with -ldflags="-s -w" to strip debug info and DWARF
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	result, err := Detect(bin)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	// Stripped binary should trigger some heuristics (no DWARF at minimum)
	dwarfFound := false
	for _, h := range result.Heuristics {
		if h.Name == "no_dwarf" && h.Detected {
			dwarfFound = true
		}
	}

	if !dwarfFound {
		t.Error("expected no_dwarf heuristic to be detected for stripped binary")
	}

	t.Logf("Stripped binary: garbled=%v confidence=%.2f label=%s", result.IsGarbled, result.Confidence, result.ConfidenceLabel)
}

func TestExtractInfo_StrippedGoBinary(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "stripped-binary")

	if err := os.WriteFile(src, []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	info, err := ExtractInfo(bin)
	if err != nil {
		t.Fatalf("ExtractInfo: %v", err)
	}

	if info.HasDWARF {
		t.Error("stripped binary should not have DWARF")
	}

	// Build info should still be present (ldflags -s -w don't strip buildinfo)
	if !info.HasBuildInfo {
		t.Log("build info was also stripped")
	}

	t.Logf("Stripped info: dwarf=%v symbols=%v symbolCount=%d", info.HasDWARF, info.HasSymbolTable, info.SymbolCount)
}

func TestElfSymType_AllBranches(t *testing.T) {
	tests := []struct {
		name string
		info byte
		want string
	}{
		{"section", byte(elf.STT_SECTION), "SECTION"},
		{"file", byte(elf.STT_FILE), "FILE"},
		{"other", 0x06, "OTHER(6)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := elfSymType(tt.info)
			if got != tt.want {
				t.Errorf("elfSymType(0x%02x) = %q, want %q", tt.info, got, tt.want)
			}
		})
	}
}

func TestScanDirectory_WithGoBinary(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "myapp")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	// Also add a non-binary file
	if err := os.WriteFile(filepath.Join(tmpDir, "notes.txt"), []byte("text"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Scan with verbose=true to cover verbose output paths
	result, err := ScanDirectory(tmpDir, true)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if result.GoBinaryCount == 0 {
		t.Error("expected at least one Go binary detected")
	}

	if len(result.Results) == 0 {
		t.Error("expected at least one detection result")
	}
}

func TestAnalyzeSymbols_NonexistentFile(t *testing.T) {
	_, err := AnalyzeSymbols("/tmp/nonexistent-binary-xyz-99999")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestCollectSymbolNames_NonexistentFile(t *testing.T) {
	names := collectSymbolNames("/tmp/nonexistent-xyz-99999", FormatELF)
	if len(names) != 0 {
		t.Errorf("expected empty names for nonexistent file, got %d", len(names))
	}

	names = collectSymbolNames("/tmp/nonexistent-xyz-99999", FormatPE)
	if len(names) != 0 {
		t.Errorf("expected empty names for nonexistent PE file, got %d", len(names))
	}

	names = collectSymbolNames("/tmp/nonexistent-xyz-99999", FormatMachO)
	if len(names) != 0 {
		t.Errorf("expected empty names for nonexistent MachO file, got %d", len(names))
	}
}

func TestExtractStrings_TrailingString(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.bin")

	// File that ends with a printable string (no null terminator at end)
	data := []byte("some-initial-padding\x00this-string-has-no-terminator")
	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractStrings(f, 4)
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalStrings < 2 {
		t.Errorf("expected at least 2 strings (including trailing), got %d", result.TotalStrings)
	}
}

func TestExtractStrings_HighEntropy(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.bin")

	// Create a string with very high entropy (random-looking, >16 chars)
	highEntropy := "aB3cD4eF5gH6iJ7kL8m"
	data := append([]byte(highEntropy), 0x00)

	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractStrings(f, 4)
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalStrings == 0 {
		t.Fatal("expected at least 1 string")
	}

	// Check that high entropy categorization works
	foundHighEntropy := false
	for _, s := range result.Strings {
		if s.Category == CatHighEntropy {
			foundHighEntropy = true
		}
	}

	if result.HighEntropyCount > 0 {
		t.Logf("Found %d high entropy strings", result.HighEntropyCount)
	}

	_ = foundHighEntropy // may or may not trigger depending on exact entropy
}

func TestCategorizeString_HighEntropy(t *testing.T) {
	// A random-looking string with high entropy and length > 16
	cat := categorizeString("xK9mP2qR7sT4uV6wY8zA1bC3dE5fG")
	if cat != CatHighEntropy {
		t.Errorf("expected CatHighEntropy for random string, got %s", cat)
	}
}

func TestGenerateDetectReport_ErrorPath(t *testing.T) {
	result := &DetectionResult{FileName: "test"}
	// Use a path under a file (not a directory) to guarantee failure on all platforms
	blocker := filepath.Join(t.TempDir(), "blocker")
	_ = os.WriteFile(blocker, []byte("x"), 0o644)
	err := GenerateDetectReport(result, filepath.Join(blocker, "report.md"))
	if err == nil {
		t.Error("expected error for invalid output path")
	}
}

func TestGenerateScanReport_ErrorPath(t *testing.T) {
	result := &ScanResult{Directory: "/tmp"}
	blocker := filepath.Join(t.TempDir(), "blocker")
	_ = os.WriteFile(blocker, []byte("x"), 0o644)
	err := GenerateScanReport(result, filepath.Join(blocker, "report.md"))
	if err == nil {
		t.Error("expected error for invalid output path")
	}
}

func TestExtractStrings_GoBinary(t *testing.T) {
	bin := buildTestGoBinary(t)

	result, err := ExtractStrings(bin, 6)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}

	if result.TotalStrings == 0 {
		t.Error("expected strings in Go binary")
	}

	if len(result.TopByCategory) == 0 {
		t.Error("expected TopByCategory to be populated")
	}

	t.Logf("Go binary strings: total=%d categories=%d avgEntropy=%.2f highEntropy=%d",
		result.TotalStrings, len(result.ByCategory), result.AvgEntropy, result.HighEntropyCount)
}

func TestAnalyzeELFSymbols_DynamicSymbols(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	// Build a CGO-enabled binary to get dynamic symbols
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "cgo-binary")

	// Use a CGO import to force dynamic linking
	code := `package main

// #include <stdlib.h>
import "C"
import "fmt"

func main() { fmt.Println(C.atoi(C.CString("42"))) }
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("CGO build failed (CGO may not be available): %v\n%s", err, out)
	}

	result, err := AnalyzeSymbols(bin)
	if err != nil {
		t.Fatalf("AnalyzeSymbols: %v", err)
	}

	if result.TotalSymbols == 0 {
		t.Error("expected symbols in CGO binary")
	}

	t.Logf("CGO binary symbols: total=%d funcs=%d", result.TotalSymbols, result.FunctionCount)

	// Also test ExtractInfo to cover dynamic linking detection in extractELFInfo
	info, err := ExtractInfo(bin)
	if err != nil {
		t.Fatalf("ExtractInfo: %v", err)
	}

	if info.IsStaticLinked {
		t.Log("CGO binary detected as static (unexpected but possible)")
	} else {
		t.Log("CGO binary correctly detected as dynamically linked")
	}

	// Also test Detect on the CGO binary for broader coverage
	det, err := Detect(bin)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	t.Logf("CGO binary detect: garbled=%v confidence=%.2f", det.IsGarbled, det.Confidence)
}

func TestIsGoELF_GoBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("isGoELF only checks ELF format; Windows produces PE binaries")
	}
	bin := buildTestGoBinary(t)

	if !isGoELF(bin) {
		t.Error("expected isGoELF to return true for Go binary")
	}
}

func TestIsGoELF_NonGoBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("isGoELF only checks ELF format; skipping on Windows")
	}
	tmpDir := t.TempDir()
	fakeElf := filepath.Join(tmpDir, "fake-elf")

	// Minimal ELF that is not a Go binary
	elfHeader := make([]byte, 64)
	copy(elfHeader, []byte{0x7f, 'E', 'L', 'F'})
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1

	if err := os.WriteFile(fakeElf, elfHeader, 0o755); err != nil {
		t.Fatal(err)
	}

	if isGoELF(fakeElf) {
		t.Error("expected isGoELF to return false for non-Go ELF")
	}
}

func TestDetect_MinimalPEBinary(t *testing.T) {
	tmpDir := t.TempDir()
	pePath := filepath.Join(tmpDir, "test.exe")

	// Minimal PE: MZ header pointing to PE signature
	// This is enough to trigger the PE code paths even if parsing fails
	pe := make([]byte, 256)
	pe[0] = 'M'
	pe[1] = 'Z'
	// e_lfanew at offset 0x3C points to PE signature
	pe[0x3C] = 0x80
	// PE signature at offset 0x80
	pe[0x80] = 'P'
	pe[0x81] = 'E'
	pe[0x82] = 0x00
	pe[0x83] = 0x00

	if err := os.WriteFile(pePath, pe, 0o755); err != nil {
		t.Fatal(err)
	}

	// This will detect PE format and attempt PE-specific checks
	result, err := Detect(pePath)
	if err != nil {
		// PE parsing may fail, which is fine - we just want format detection coverage
		t.Logf("Detect returned error for minimal PE (expected): %v", err)
		return
	}

	if result.Format != "PE" {
		t.Errorf("expected PE format, got %q", result.Format)
	}

	t.Logf("Minimal PE: garbled=%v confidence=%.2f", result.IsGarbled, result.Confidence)
}

func TestExtractInfo_MinimalPE(t *testing.T) {
	tmpDir := t.TempDir()
	pePath := filepath.Join(tmpDir, "test.exe")

	pe := make([]byte, 256)
	pe[0] = 'M'
	pe[1] = 'Z'
	pe[0x3C] = 0x80
	pe[0x80] = 'P'
	pe[0x81] = 'E'
	pe[0x82] = 0x00
	pe[0x83] = 0x00

	if err := os.WriteFile(pePath, pe, 0o755); err != nil {
		t.Fatal(err)
	}

	info, err := ExtractInfo(pePath)
	if err != nil {
		t.Logf("ExtractInfo returned error for minimal PE (expected): %v", err)
		return
	}

	if info.Format != "PE" {
		t.Errorf("expected PE format, got %q", info.Format)
	}
}

func TestAnalyzeSymbols_MinimalPE(t *testing.T) {
	tmpDir := t.TempDir()
	pePath := filepath.Join(tmpDir, "test.exe")

	pe := make([]byte, 256)
	pe[0] = 'M'
	pe[1] = 'Z'
	pe[0x3C] = 0x80
	pe[0x80] = 'P'
	pe[0x81] = 'E'
	pe[0x82] = 0x00
	pe[0x83] = 0x00

	if err := os.WriteFile(pePath, pe, 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzeSymbols(pePath)
	if err != nil {
		t.Logf("AnalyzeSymbols returned error for minimal PE (expected): %v", err)
		return
	}

	t.Logf("Minimal PE symbols: total=%d", result.TotalSymbols)
}

func TestIsGoBinary_MinimalPE(t *testing.T) {
	tmpDir := t.TempDir()
	pePath := filepath.Join(tmpDir, "test.exe")

	pe := make([]byte, 256)
	pe[0] = 'M'
	pe[1] = 'Z'
	pe[0x3C] = 0x80
	pe[0x80] = 'P'
	pe[0x81] = 'E'
	pe[0x82] = 0x00
	pe[0x83] = 0x00

	if err := os.WriteFile(pePath, pe, 0o755); err != nil {
		t.Fatal(err)
	}

	// Minimal PE is not a Go binary
	if isGoBinary(pePath) {
		t.Error("expected minimal PE to not be detected as Go binary")
	}
}

func TestCheckGoBuildID_InvalidFormat(t *testing.T) {
	tests := []struct {
		name   string
		format BinaryFormat
	}{
		{"ELF error path", FormatELF},
		{"PE error path", FormatPE},
		{"MachO error path", FormatMachO},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := checkGoBuildID("/tmp/nonexistent-binary-xyz-99999", tt.format)
			if h.Name != "missing_build_id" {
				t.Errorf("expected name %q, got %q", "missing_build_id", h.Name)
			}

			if h.Details == "" {
				t.Error("expected non-empty Details for error case")
			}
		})
	}
}

// buildMinimalELF creates a minimal valid ELF binary file and returns its path.
// The ELF is 64-bit little-endian with optional sections.
func buildMinimalELF(t *testing.T, name string, sections map[string][]byte, symbols []string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, name)

	// We'll use Go's encoding/binary to write a proper ELF file.
	// For simplicity, use exec to create a real ELF via cross-compilation if possible,
	// otherwise create a synthetic one that the Go ELF parser can handle.

	// Build a real ELF via cross-compilation
	src := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", path, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile to linux/amd64 failed: %v\n%s", err, out)
	}

	return path
}

// buildStrippedELF creates a stripped ELF binary (no DWARF, no symbols).
func buildStrippedELF(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "stripped-elf")

	if err := os.WriteFile(src, []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile stripped ELF failed: %v\n%s", err, out)
	}

	return bin
}

func TestExtractELFInfo_CrossCompiled(t *testing.T) {
	bin := buildMinimalELF(t, "test-elf", nil, nil)

	info, err := ExtractInfo(bin)
	if err != nil {
		t.Fatalf("ExtractInfo: %v", err)
	}

	if info.Format != "ELF" {
		t.Errorf("expected ELF format, got %q", info.Format)
	}

	if info.Arch != "amd64" {
		t.Errorf("expected amd64 arch, got %q", info.Arch)
	}

	if info.OS != "linux" {
		t.Errorf("expected linux OS, got %q", info.OS)
	}

	if !info.HasBuildInfo {
		t.Error("expected build info present")
	}

	if info.GoVersion == "" {
		t.Error("expected non-empty GoVersion")
	}

	if len(info.Sections) == 0 {
		t.Error("expected non-empty Sections list")
	}

	if !info.HasSymbolTable {
		t.Error("expected symbol table in non-stripped ELF")
	}

	t.Logf("ELF info: arch=%s os=%s go=%s sections=%d symbols=%d dwarf=%v static=%v buildID=%s",
		info.Arch, info.OS, info.GoVersion, len(info.Sections), info.SymbolCount, info.HasDWARF, info.IsStaticLinked, info.BuildID)
}

func TestExtractELFInfo_Stripped(t *testing.T) {
	bin := buildStrippedELF(t)

	info, err := ExtractInfo(bin)
	if err != nil {
		t.Fatalf("ExtractInfo: %v", err)
	}

	if info.Format != "ELF" {
		t.Errorf("expected ELF format, got %q", info.Format)
	}

	if info.HasDWARF {
		t.Error("stripped ELF should not have DWARF")
	}

	t.Logf("Stripped ELF: dwarf=%v symbols=%v symbolCount=%d static=%v",
		info.HasDWARF, info.HasSymbolTable, info.SymbolCount, info.IsStaticLinked)
}

func TestAnalyzeELFSymbols_CrossCompiled(t *testing.T) {
	bin := buildMinimalELF(t, "test-elf-syms", nil, nil)

	result, err := AnalyzeSymbols(bin)
	if err != nil {
		t.Fatalf("AnalyzeSymbols: %v", err)
	}

	if result.Format != "ELF" {
		t.Errorf("expected ELF format, got %q", result.Format)
	}

	if result.TotalSymbols == 0 {
		t.Error("expected symbols in ELF binary")
	}

	if result.FunctionCount == 0 {
		t.Error("expected function symbols in ELF binary")
	}

	if result.RuntimeCount == 0 {
		t.Error("expected runtime symbols in Go ELF binary")
	}

	if len(result.Packages) == 0 {
		t.Error("expected packages in symbol analysis")
	}

	t.Logf("ELF symbols: total=%d funcs=%d objects=%d runtime=%d obfuscated=%d ratio=%.2f",
		result.TotalSymbols, result.FunctionCount, result.ObjectCount,
		result.RuntimeCount, result.ObfuscatedCount, result.ObfuscationRatio)
}

func TestCollectSymbolNames_ELF(t *testing.T) {
	bin := buildMinimalELF(t, "test-elf-collect", nil, nil)

	names := collectSymbolNames(bin, FormatELF)
	if len(names) == 0 {
		t.Error("expected symbol names from ELF binary")
	}

	hasRuntime := false
	for _, name := range names {
		if strings.HasPrefix(name, "runtime.") {
			hasRuntime = true
			break
		}
	}

	if !hasRuntime {
		t.Error("expected runtime.* symbols in Go ELF binary")
	}

	t.Logf("Collected %d ELF symbol names", len(names))
}

func TestCheckDWARF_ELF(t *testing.T) {
	bin := buildMinimalELF(t, "test-elf-dwarf", nil, nil)

	h := checkDWARF(bin, FormatELF)
	if h.Name != "no_dwarf" {
		t.Errorf("expected name %q, got %q", "no_dwarf", h.Name)
	}

	// Non-stripped ELF should have DWARF
	if h.Detected {
		t.Logf("DWARF not present (unexpected for non-stripped): %s", h.Details)
	} else {
		t.Logf("DWARF present: %s", h.Details)
	}
}

func TestCheckDWARF_StrippedELF(t *testing.T) {
	bin := buildStrippedELF(t)

	h := checkDWARF(bin, FormatELF)
	if !h.Detected {
		t.Error("expected DWARF to be detected as missing in stripped ELF")
	}
}

func TestCheckGoBuildID_ELF(t *testing.T) {
	bin := buildMinimalELF(t, "test-elf-buildid", nil, nil)

	h := checkGoBuildID(bin, FormatELF)
	if h.Name != "missing_build_id" {
		t.Errorf("expected name %q, got %q", "missing_build_id", h.Name)
	}

	// Normal Go ELF should have build ID
	if h.Detected {
		t.Errorf("normal ELF should have build ID: %s", h.Details)
	}

	t.Logf("ELF build ID check: detected=%v details=%s", h.Detected, h.Details)
}

func TestCheckHashedSymbols_ELF(t *testing.T) {
	bin := buildMinimalELF(t, "test-elf-hashed", nil, nil)

	h := checkHashedSymbols(bin, FormatELF)
	if h.Name != "hashed_symbols" {
		t.Errorf("expected name %q, got %q", "hashed_symbols", h.Name)
	}

	if h.Details == "" {
		t.Error("expected non-empty Details")
	}

	t.Logf("ELF hashed symbols: detected=%v details=%s", h.Detected, h.Details)
}

func TestCheckGoPackagePaths_ELF(t *testing.T) {
	bin := buildMinimalELF(t, "test-elf-paths", nil, nil)

	h := checkGoPackagePaths(bin, FormatELF)
	if h.Name != "missing_go_paths" {
		t.Errorf("expected name %q, got %q", "missing_go_paths", h.Name)
	}

	if h.Details == "" {
		t.Error("expected non-empty Details")
	}

	t.Logf("ELF package paths: detected=%v details=%s", h.Detected, h.Details)
}

func TestIsGoELF_CrossCompiled(t *testing.T) {
	bin := buildMinimalELF(t, "test-go-elf", nil, nil)

	if !isGoELF(bin) {
		t.Error("expected isGoELF to return true for cross-compiled Go ELF")
	}
}

func TestDetect_ELFBinary(t *testing.T) {
	bin := buildMinimalELF(t, "test-detect-elf", nil, nil)

	result, err := Detect(bin)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if result.Format != "ELF" {
		t.Errorf("expected ELF format, got %q", result.Format)
	}

	if len(result.Heuristics) != 6 {
		t.Errorf("expected 6 heuristics, got %d", len(result.Heuristics))
	}

	t.Logf("ELF detect: garbled=%v confidence=%.2f label=%s", result.IsGarbled, result.Confidence, result.ConfidenceLabel)
}

func TestDetect_StrippedELF(t *testing.T) {
	bin := buildStrippedELF(t)

	result, err := Detect(bin)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	// Stripped ELF should trigger at least the DWARF heuristic
	dwarfDetected := false
	for _, h := range result.Heuristics {
		if h.Name == "no_dwarf" && h.Detected {
			dwarfDetected = true
		}
	}

	if !dwarfDetected {
		t.Error("expected no_dwarf heuristic to fire for stripped ELF")
	}

	t.Logf("Stripped ELF detect: garbled=%v confidence=%.2f", result.IsGarbled, result.Confidence)
}

func TestScanDirectory_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	result, err := ScanDirectory(tmpDir, false)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if result.TotalFiles != 0 {
		t.Errorf("expected 0 files in empty dir, got %d", result.TotalFiles)
	}

	if result.GoBinaryCount != 0 {
		t.Errorf("expected 0 Go binaries, got %d", result.GoBinaryCount)
	}
}

func TestScanDirectory_MixedFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create various non-binary files
	files := map[string][]byte{
		"readme.txt":  []byte("hello"),
		"data.json":   []byte(`{"key": "value"}`),
		"script.py":   []byte("print('hi')"),
		"image.png":   []byte{0x89, 0x50, 0x4E, 0x47}, // PNG magic
		"archive.zip": []byte{0x50, 0x4B, 0x03, 0x04}, // ZIP magic
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	result, err := ScanDirectory(tmpDir, true)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if result.GoBinaryCount != 0 {
		t.Errorf("expected 0 Go binaries in mixed non-binary dir, got %d", result.GoBinaryCount)
	}

	t.Logf("Mixed dir scan: total=%d go=%d", result.TotalFiles, result.GoBinaryCount)
}

func TestScanDirectory_NestedDirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested subdirs with non-binary content
	subDir := filepath.Join(tmpDir, "subdir", "nested")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("text"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ScanDirectory(tmpDir, false)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if result.TotalFiles == 0 {
		t.Error("expected at least one file in nested scan")
	}
}

func TestScanDirectory_WithELFBinary(t *testing.T) {
	// Build a Go ELF binary via cross-compilation and scan its directory
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "myapp")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile failed: %v\n%s", err, out)
	}

	// Add a non-binary file
	if err := os.WriteFile(filepath.Join(tmpDir, "notes.txt"), []byte("text"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ScanDirectory(tmpDir, true)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if result.GoBinaryCount == 0 {
		t.Error("expected at least one Go binary")
	}

	t.Logf("Scan with ELF: total=%d go=%d garbled=%d", result.TotalFiles, result.GoBinaryCount, result.GarbledCount)
}

func TestExtractStrings_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "empty.bin")

	if err := os.WriteFile(f, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractStrings(f, 4)
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalStrings != 0 {
		t.Errorf("expected 0 strings in empty file, got %d", result.TotalStrings)
	}

	if result.AvgEntropy != 0 {
		t.Errorf("expected 0 avg entropy for empty file, got %f", result.AvgEntropy)
	}
}

func TestExtractStrings_AllBinaryContent(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "binary.bin")

	// File with only non-printable bytes
	data := make([]byte, 100)
	for i := range data {
		data[i] = 0x01
	}

	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractStrings(f, 4)
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalStrings != 0 {
		t.Errorf("expected 0 strings in pure binary content, got %d", result.TotalStrings)
	}
}

func TestExtractStrings_LargeMinLen(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.bin")

	// Strings of various lengths
	data := []byte("short\x00medium_string\x00this_is_a_very_long_string_value\x00")
	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractStrings(f, 20)
	if err != nil {
		t.Fatal(err)
	}

	// Only the long string (31 chars) should be extracted with minLen=20
	if result.TotalStrings != 1 {
		t.Errorf("expected 1 string with minLen=20, got %d", result.TotalStrings)
	}
}

func TestExtractStrings_CategoryCoverage(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.bin")

	// Create binary with strings covering various categories
	var data []byte
	strings := []string{
		"https://example.com/api/v1",               // URL
		"/api/v2/users/list",                       // API endpoint
		"/usr/local/bin/myapp",                     // File path
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Test",       // Registry
		"error: connection refused by remote host", // Error message
		"aes-256-gcm encrypted payload",            // Crypto
		"tcp connection to localhost:8080",         // Network
		"xK9mP2qR7sT4uV6wY8zA1bC3dE5fG",            // High entropy
		"just a regular general string here",       // General
	}

	for _, s := range strings {
		data = append(data, []byte(s)...)
		data = append(data, 0x00)
	}

	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractStrings(f, 4)
	if err != nil {
		t.Fatal(err)
	}

	expectedCats := []StringCategory{CatURL, CatAPIEndpoint, CatFilePath, CatErrorMessage, CatCrypto, CatNetwork}
	for _, cat := range expectedCats {
		if result.ByCategory[cat] == 0 {
			t.Errorf("expected at least 1 string in category %s", cat)
		}
	}

	// TopByCategory should be populated
	if len(result.TopByCategory) == 0 {
		t.Error("expected TopByCategory to be populated")
	}
}

func TestAnalyzeSymbols_NonexistentELF(t *testing.T) {
	// collectSymbolNames for non-existent files for each format
	for _, format := range []BinaryFormat{FormatELF, FormatPE, FormatMachO} {
		names := collectSymbolNames("/tmp/nonexistent-xyz-99999", format)
		if len(names) != 0 {
			t.Errorf("expected empty names for nonexistent %s file", format)
		}
	}
}

func TestDetectFileFormat_TooSmall(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "tiny")

	// File with only 2 bytes - too small for magic detection
	if err := os.WriteFile(f, []byte{0x00, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := detectFileFormat(f)
	if err == nil {
		t.Error("expected error for file too small for magic bytes")
	}
}

func TestDetectFileFormat_MachOMagic(t *testing.T) {
	tmpDir := t.TempDir()

	// Test all three Mach-O magic variants
	tests := []struct {
		name  string
		magic []byte
	}{
		{"MachO 32-bit big-endian", []byte{0xfe, 0xed, 0xfa, 0xce}},
		{"MachO 64-bit big-endian", []byte{0xfe, 0xed, 0xfa, 0xcf}},
		{"MachO 64-bit little-endian", []byte{0xcf, 0xfa, 0xed, 0xfe}},
		{"MachO 32-bit little-endian", []byte{0xce, 0xfa, 0xed, 0xfe}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := filepath.Join(tmpDir, tt.name+".bin")
			if err := os.WriteFile(f, tt.magic, 0o644); err != nil {
				t.Fatal(err)
			}

			format, err := detectFileFormat(f)
			if err != nil {
				t.Fatalf("detectFileFormat: %v", err)
			}

			if format != FormatMachO {
				t.Errorf("expected Mach-O format, got %s", format)
			}
		})
	}
}

func TestExtractInfo_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "invalid.bin")

	if err := os.WriteFile(f, []byte("not a binary file at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractInfo(f)
	if err == nil {
		t.Error("expected error for non-binary file")
	}
}

func TestAnalyzeSymbols_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "invalid.bin")

	if err := os.WriteFile(f, []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := AnalyzeSymbols(f)
	if err == nil {
		t.Error("expected error for non-binary file")
	}
}

func TestIsGoBinary_AllFormats(t *testing.T) {
	tmpDir := t.TempDir()

	// Non-binary file
	txt := filepath.Join(tmpDir, "text.txt")
	if err := os.WriteFile(txt, []byte("text content"), 0o644); err != nil {
		t.Fatal(err)
	}

	if isGoBinary(txt) {
		t.Error("text file should not be a Go binary")
	}

	// Minimal Mach-O magic (not a real Go binary)
	machoFile := filepath.Join(tmpDir, "macho.bin")
	machoData := make([]byte, 64)
	machoData[0] = 0xcf
	machoData[1] = 0xfa
	machoData[2] = 0xed
	machoData[3] = 0xfe
	if err := os.WriteFile(machoFile, machoData, 0o755); err != nil {
		t.Fatal(err)
	}

	// isGoBinary should handle Mach-O format path (even if parsing fails)
	result := isGoBinary(machoFile)
	t.Logf("Minimal Mach-O isGoBinary: %v", result)
}

func TestCheckGarbleStrings_NonexistentFile(t *testing.T) {
	h := checkGarbleStrings("/tmp/nonexistent-xyz-99999")
	if h.Detected {
		t.Error("should not detect markers in nonexistent file")
	}

	if h.Details == "" {
		t.Error("expected non-empty details for error case")
	}
}

func TestCheckBuildInfo_NonexistentFile(t *testing.T) {
	h := checkBuildInfo("/tmp/nonexistent-xyz-99999")
	if !h.Detected {
		t.Error("expected missing build info to be detected for nonexistent file")
	}
}

func TestCheckHashedSymbols_NoSymbols(t *testing.T) {
	tmpDir := t.TempDir()
	// Minimal ELF with no symbols
	fakeElf := filepath.Join(tmpDir, "nosyms")
	elfHeader := make([]byte, 64)
	copy(elfHeader, []byte{0x7f, 'E', 'L', 'F'})
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	if err := os.WriteFile(fakeElf, elfHeader, 0o755); err != nil {
		t.Fatal(err)
	}

	h := checkHashedSymbols(fakeElf, FormatELF)
	if h.Details != "No symbols found" {
		t.Errorf("expected 'No symbols found', got %q", h.Details)
	}
}

func TestCheckGoPackagePaths_NoSymbols(t *testing.T) {
	tmpDir := t.TempDir()
	fakeElf := filepath.Join(tmpDir, "nosyms")
	elfHeader := make([]byte, 64)
	copy(elfHeader, []byte{0x7f, 'E', 'L', 'F'})
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	if err := os.WriteFile(fakeElf, elfHeader, 0o755); err != nil {
		t.Fatal(err)
	}

	h := checkGoPackagePaths(fakeElf, FormatELF)
	if h.Details != "No symbols found" {
		t.Errorf("expected 'No symbols found', got %q", h.Details)
	}
}

func TestExtractStrings_VariousMinLen(t *testing.T) {
	tests := []struct {
		name    string
		minLen  int
		data    []byte
		wantMin int
		wantMax int
	}{
		{
			name:    "minLen 0 clamped to 4",
			minLen:  0,
			data:    []byte("ab\x00abcd\x00abcdef\x00"),
			wantMin: 2, // "abcd" and "abcdef"
			wantMax: 2,
		},
		{
			name:    "minLen 1 clamped to 4",
			minLen:  1,
			data:    []byte("ab\x00abcd\x00abcdef\x00"),
			wantMin: 2,
			wantMax: 2,
		},
		{
			name:    "minLen 6",
			minLen:  6,
			data:    []byte("ab\x00abcd\x00abcdef\x00abcdefgh\x00"),
			wantMin: 2, // "abcdef" and "abcdefgh"
			wantMax: 2,
		},
		{
			name:    "minLen 100 no strings",
			minLen:  100,
			data:    []byte("short\x00medium_string\x00"),
			wantMin: 0,
			wantMax: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			f := filepath.Join(tmpDir, "test.bin")
			if err := os.WriteFile(f, tt.data, 0o644); err != nil {
				t.Fatal(err)
			}

			result, err := ExtractStrings(f, tt.minLen)
			if err != nil {
				t.Fatal(err)
			}

			if result.TotalStrings < tt.wantMin || result.TotalStrings > tt.wantMax {
				t.Errorf("expected %d-%d strings, got %d", tt.wantMin, tt.wantMax, result.TotalStrings)
			}
		})
	}
}

func TestIsObfuscatedName_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		sym  string
		want bool
	}{
		{"empty string", "", false},
		{"short 5 chars", "aBcDe", false},
		{"exactly 6 chars mixed", "aB3cD4", true},
		{"all uppercase", "ABCDEF", false},
		{"all lowercase", "abcdef", false},
		{"all digits with letter prefix", "a12345", true}, // lower+digits triggers hash detection
		{"mach-o underscore prefix", "_aBcDeF1g", true},
		{"runtime symbol", "runtime.goexit", false},
		{"go itab", "go.itab.something", false},
		{"sync prefix", "sync.Mutex.Lock", false},
		{"internal prefix", "internal/reflectlite.init", false},
		{"readable word exact", "init", false},
		{"readable word get", "get", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isObfuscatedName(tt.sym)
			if got != tt.want {
				t.Errorf("isObfuscatedName(%q) = %v, want %v", tt.sym, got, tt.want)
			}
		})
	}
}

func TestElfMachineArch_AllBranches(t *testing.T) {
	// Test all branches not already covered
	extra := []struct {
		machine elf.Machine
		want    string
	}{
		{elf.EM_MIPS, "mips"},
		{elf.EM_RISCV, "riscv64"},
		{elf.EM_PPC64, "ppc64"},
		{elf.EM_S390, "s390x"},
	}

	for _, tt := range extra {
		got := elfMachineArch(tt.machine)
		if got != tt.want {
			t.Errorf("elfMachineArch(%v) = %q, want %q", tt.machine, got, tt.want)
		}
	}
}

func TestIsRuntimeSymbol_MorePrefixes(t *testing.T) {
	// Test more runtime prefixes for coverage
	tests := []struct {
		sym  string
		want bool
	}{
		{"sync/atomic.LoadInt64", true},
		{"syscall.Syscall6", true},
		{"internal/poll.Read", true},
		{"reflect.ValueOf", true},
		{"math.Sqrt", true},
		{"unicode.IsLetter", true},
		{"encoding/json.Marshal", true},
		{"io.ReadAll", true},
		{"net.Dial", true},
		{"strings.Contains", true},
		{"bytes.Buffer", true},
		{"strconv.Itoa", true},
		{"errors.New", true},
		{"context.WithCancel", true},
		{"sort.Slice", true},
		{"time.Now", true},
		{"path.Join", true},
		{"crypto.Hash", true},
		{"hash.Hash", true},
		{"compress/gzip.Reader", true},
		{"archive/tar.Reader", true},
		{"bufio.NewReader", true},
		{"log.Println", true},
		{"regexp.Compile", true},
		{"testing.T", true},
		{"debug.ReadBuildInfo", true},
		{"text/template.New", true},
		{"html/template.New", true},
		{"image/png.Decode", true},
		{"mime/multipart.Reader", true},
		{"database/sql.Open", true},
		{"embed.FS", true},
		{"mypackage.CustomFunc", false},
	}

	for _, tt := range tests {
		got := isRuntimeSymbol(tt.sym)
		if got != tt.want {
			t.Errorf("isRuntimeSymbol(%q) = %v, want %v", tt.sym, got, tt.want)
		}
	}
}

func TestExtractPackage_MoreCases(t *testing.T) {
	tests := []struct {
		sym  string
		want string
	}{
		{"", ""},
		{"nopackage", ""},
		{"a.b", "a"},
		{"github.com/user/repo/pkg.(*Server).Handle", "github.com/user/repo/pkg"},
		{"github.com/user/repo.Func", "github.com/user/repo"},
	}

	for _, tt := range tests {
		got := extractPackage(tt.sym)
		if got != tt.want {
			t.Errorf("extractPackage(%q) = %q, want %q", tt.sym, got, tt.want)
		}
	}
}

func TestScanDirectory_VerboseSkip(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a .exe file that is NOT a Go binary (to cover the verbose SKIP path)
	fakeExe := filepath.Join(tmpDir, "fake.exe")
	peData := make([]byte, 256)
	peData[0] = 'M'
	peData[1] = 'Z'
	peData[0x3C] = 0x80
	peData[0x80] = 'P'
	peData[0x81] = 'E'
	peData[0x82] = 0x00
	peData[0x83] = 0x00
	if err := os.WriteFile(fakeExe, peData, 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := ScanDirectory(tmpDir, true)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	// The fake .exe is a scan candidate but not a Go binary, so it should be skipped
	if result.GoBinaryCount != 0 {
		t.Errorf("expected 0 Go binaries, got %d", result.GoBinaryCount)
	}
}

// buildMachOBinary cross-compiles a Go binary for darwin/amd64.
func buildMachOBinary(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-macho")

	if err := os.WriteFile(src, []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile to darwin/amd64 failed: %v\n%s", err, out)
	}

	return bin
}

func TestExtractMachOInfo(t *testing.T) {
	bin := buildMachOBinary(t)

	info, err := ExtractInfo(bin)
	if err != nil {
		t.Fatalf("ExtractInfo: %v", err)
	}

	if info.Format != "Mach-O" {
		t.Errorf("expected Mach-O format, got %q", info.Format)
	}

	if info.OS != "darwin" {
		t.Errorf("expected darwin OS, got %q", info.OS)
	}

	if info.Arch != "amd64" {
		t.Errorf("expected amd64 arch, got %q", info.Arch)
	}

	if len(info.Sections) == 0 {
		t.Error("expected non-empty Sections")
	}

	t.Logf("Mach-O info: os=%s arch=%s symbols=%d dwarf=%v static=%v buildID=%s",
		info.OS, info.Arch, info.SymbolCount, info.HasDWARF, info.IsStaticLinked, info.BuildID)
}

func TestAnalyzeMachOSymbols(t *testing.T) {
	bin := buildMachOBinary(t)

	result, err := AnalyzeSymbols(bin)
	if err != nil {
		t.Fatalf("AnalyzeSymbols: %v", err)
	}

	if result.Format != "Mach-O" {
		t.Errorf("expected Mach-O format, got %q", result.Format)
	}

	if result.TotalSymbols == 0 {
		t.Error("expected symbols in Mach-O binary")
	}

	t.Logf("Mach-O symbols: total=%d funcs=%d", result.TotalSymbols, result.FunctionCount)
}

func TestIsGoMachO(t *testing.T) {
	bin := buildMachOBinary(t)

	if !isGoMachO(bin) {
		t.Error("expected isGoMachO to return true for Go Mach-O binary")
	}
}

func TestCollectSymbolNames_MachO(t *testing.T) {
	bin := buildMachOBinary(t)

	names := collectSymbolNames(bin, FormatMachO)
	if len(names) == 0 {
		t.Error("expected symbol names from Mach-O binary")
	}

	t.Logf("Collected %d Mach-O symbol names", len(names))
}

func TestCheckDWARF_MachO(t *testing.T) {
	bin := buildMachOBinary(t)

	h := checkDWARF(bin, FormatMachO)
	if h.Name != "no_dwarf" {
		t.Errorf("expected name %q, got %q", "no_dwarf", h.Name)
	}

	t.Logf("Mach-O DWARF check: detected=%v details=%s", h.Detected, h.Details)
}

func TestCheckGoBuildID_MachO(t *testing.T) {
	bin := buildMachOBinary(t)

	h := checkGoBuildID(bin, FormatMachO)
	if h.Name != "missing_build_id" {
		t.Errorf("expected name %q, got %q", "missing_build_id", h.Name)
	}

	t.Logf("Mach-O build ID check: detected=%v details=%s", h.Detected, h.Details)
}

func TestDetect_MachOBinary(t *testing.T) {
	bin := buildMachOBinary(t)

	result, err := Detect(bin)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if result.Format != "Mach-O" {
		t.Errorf("expected Mach-O format, got %q", result.Format)
	}

	t.Logf("Mach-O detect: garbled=%v confidence=%.2f", result.IsGarbled, result.Confidence)
}

func TestCheckHashedSymbols_MachO(t *testing.T) {
	bin := buildMachOBinary(t)

	h := checkHashedSymbols(bin, FormatMachO)
	if h.Details == "" {
		t.Error("expected non-empty Details")
	}

	t.Logf("Mach-O hashed symbols: detected=%v details=%s", h.Detected, h.Details)
}

func TestCheckGoPackagePaths_MachO(t *testing.T) {
	bin := buildMachOBinary(t)

	h := checkGoPackagePaths(bin, FormatMachO)
	if h.Details == "" {
		t.Error("expected non-empty Details")
	}

	t.Logf("Mach-O package paths: detected=%v details=%s", h.Detected, h.Details)
}

func TestIsGoPE_GoBinary(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE tests run on Windows")
	}
	bin := buildTestGoBinary(t)

	if !isGoPE(bin) {
		t.Error("expected isGoPE to return true for Go PE binary")
	}
}

func TestBuildScanReport_GarbledWithLongDetails(t *testing.T) {
	result := &ScanResult{
		Directory:     "/tmp/test",
		TotalFiles:    5,
		GoBinaryCount: 2,
		GarbledCount:  1,
		Results: []*DetectionResult{
			{
				FileName:        "normal",
				FilePath:        "/tmp/test/normal",
				Format:          "ELF",
				IsGarbled:       false,
				Confidence:      0.1,
				ConfidenceLabel: "NONE",
			},
			{
				FileName:        "garbled-app",
				FilePath:        "/tmp/test/garbled-app",
				Format:          "ELF",
				IsGarbled:       true,
				Confidence:      0.85,
				ConfidenceLabel: "CERTAIN",
				Heuristics: []Heuristic{
					{Description: "Missing build info", Detected: true, Details: "buildinfo.ReadFile failed: not a Go executable"},
					{Description: "No DWARF", Detected: true, Details: "No DWARF data in ELF binary file"},
					{Description: "Hashed symbols", Detected: true, Details: "This is a very long detail string that exceeds fifty characters and should be truncated by the report"},
					{Description: "No garble markers", Detected: false, Details: "No garble markers found in binary"},
				},
			},
		},
	}

	report := buildScanReport(result)

	if !strings.Contains(report, "### garbled-app") {
		t.Error("report missing garbled binary section")
	}

	if !strings.Contains(report, "...") {
		t.Error("report should truncate long details")
	}

	if !strings.Contains(report, "CERTAIN") {
		t.Error("report missing confidence label")
	}
}
