/* Copyright (c) 2026 Security Research */
package manifest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFindMainBinary_ELF(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test creates fake ELF binaries; Windows does not recognize ELF executables")
	}
	dir := t.TempDir()

	// Create a small ELF binary
	smallELF := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 2000)...)
	_ = os.WriteFile(filepath.Join(dir, "small"), smallELF, 0o755)

	// Create a large ELF binary (should be picked as main)
	largeELF := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 10000)...)
	_ = os.WriteFile(filepath.Join(dir, "mainapp"), largeELF, 0o755)

	got := findMainBinary(dir)
	if filepath.Base(got) != "mainapp" {
		t.Errorf("findMainBinary() = %q, want mainapp (largest binary)", got)
	}
}

func TestFindMainBinary_SubdirELF(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test creates fake ELF binaries; Windows does not recognize ELF executables")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "app")
	_ = os.MkdirAll(sub, 0o755)

	elf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 5000)...)
	_ = os.WriteFile(filepath.Join(sub, "myapp"), elf, 0o755)

	got := findMainBinary(dir)
	if got == "" {
		t.Fatal("findMainBinary() returned empty, expected binary in subdirectory")
	}
	if filepath.Base(got) != "myapp" {
		t.Errorf("findMainBinary() = %q, want myapp", got)
	}
}

func TestFindMainBinary_ParentFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test creates fake ELF binaries; Windows does not recognize ELF executables")
	}
	dir := t.TempDir()

	// Binary in parent dir, detection matched a child dir
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 5000)...)
	_ = os.WriteFile(filepath.Join(dir, "app"), elf, 0o755)

	sub := filepath.Join(dir, "child")
	_ = os.MkdirAll(sub, 0o755)

	got := findMainBinary(sub)
	if got == "" {
		t.Fatal("findMainBinary() returned empty, expected parent directory fallback")
	}
	if filepath.Base(got) != "app" {
		t.Errorf("findMainBinary() = %q, want app from parent", got)
	}
}

func TestFindMainBinary_ASAR_Fallback(t *testing.T) {
	dir := t.TempDir()
	resDir := filepath.Join(dir, "resources")
	_ = os.MkdirAll(resDir, 0o755)
	_ = os.WriteFile(filepath.Join(resDir, "app.asar"), []byte("asar-content"), 0o644)

	got := findMainBinary(dir)
	if filepath.Base(got) != "app.asar" {
		t.Errorf("findMainBinary() = %q, want app.asar fallback", got)
	}
}

func TestFindMainBinary_WindowsExe(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app.exe"), []byte("MZ-fake"), 0o755)

	got := findMainBinary(dir)
	if filepath.Base(got) != "app.exe" {
		t.Errorf("findMainBinary() = %q, want app.exe", got)
	}
}

func TestFindMainBinary_Empty(t *testing.T) {
	dir := t.TempDir()
	got := findMainBinary(dir)
	if got != "" {
		t.Errorf("findMainBinary() = %q, want empty for dir with no binaries", got)
	}
}

func TestFindMainBinary_SkipsExtFiles(t *testing.T) {
	dir := t.TempDir()

	// File with extension should be skipped even if it's ELF
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 5000)...)
	_ = os.WriteFile(filepath.Join(dir, "libfoo.so"), elf, 0o755)

	got := findMainBinary(dir)
	if got != "" {
		t.Errorf("findMainBinary() = %q, want empty (should skip files with extensions)", got)
	}
}

func TestIsNativeBinary(t *testing.T) {
	dir := t.TempDir()

	elf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 100)...)
	elfPath := filepath.Join(dir, "elf")
	_ = os.WriteFile(elfPath, elf, 0o644)

	if !isNativeBinary(elfPath) {
		t.Error("isNativeBinary() = false for ELF, want true")
	}

	textPath := filepath.Join(dir, "text")
	_ = os.WriteFile(textPath, []byte("hello world"), 0o644)

	if isNativeBinary(textPath) {
		t.Error("isNativeBinary() = true for text file, want false")
	}
}

func TestDetectorDetect(t *testing.T) {
	m := Default()
	d := NewDetector(m, false)

	t.Run("electron app directory", func(t *testing.T) {
		dir := t.TempDir()
		resDir := filepath.Join(dir, "resources")
		_ = os.MkdirAll(resDir, 0o755)
		_ = os.WriteFile(filepath.Join(resDir, "app.asar"), []byte("asar-content"), 0o644)

		result, err := d.Detect(dir)
		if err != nil {
			t.Fatalf("Detect() error: %v", err)
		}
		if result.Type != "electron" {
			t.Errorf("Detect() Type = %q, want electron", result.Type)
		}
		if result.Score < 50 {
			t.Errorf("Detect() Score = %d, want >= 50", result.Score)
		}
	})

	t.Run("unknown directory", func(t *testing.T) {
		dir := t.TempDir()
		result, err := d.Detect(dir)
		if err != nil {
			t.Fatalf("Detect() error: %v", err)
		}
		if result.Type != "unknown" {
			t.Errorf("Detect() Type = %q, want unknown", result.Type)
		}
	})
}

func TestEvaluateCondition(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "exists.txt")
	_ = os.WriteFile(tmpFile, []byte("data"), 0o644)
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		condition string
		vars      map[string]string
		want      bool
	}{
		{
			name:      "empty condition",
			condition: "",
			want:      true,
		},
		{
			name:      "file exists",
			condition: "file_exists:" + tmpFile,
			want:      true,
		},
		{
			name:      "file does not exist",
			condition: "file_exists:/nonexistent/path",
			want:      false,
		},
		{
			name:      "dir exists",
			condition: "dir_exists:" + tmpDir,
			want:      true,
		},
		{
			name:      "dir does not exist",
			condition: "dir_exists:" + filepath.Join(tmpDir, "surely_nonexistent_subdir_xyz"),
			want:      false,
		},
		{
			name:      "unknown condition passes",
			condition: "unknown_condition",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvaluateCondition(tt.condition, tt.vars); got != tt.want {
				t.Errorf("EvaluateCondition(%q) = %v, want %v", tt.condition, got, tt.want)
			}
		})
	}
}

func TestCheckSignature(t *testing.T) {
	d := NewDetector(Default(), false)

	tests := []struct {
		name string
		data []byte
		rule SignatureRule
		want bool
	}{
		{
			name: "string match found",
			data: []byte("contains Electron Framework here"),
			rule: SignatureRule{Pattern: "Electron Framework", Type: "string"},
			want: true,
		},
		{
			name: "string match not found",
			data: []byte("nothing relevant"),
			rule: SignatureRule{Pattern: "Electron Framework", Type: "string"},
			want: false,
		},
		{
			name: "regex match found",
			data: []byte("version 1.2.3"),
			rule: SignatureRule{Pattern: `version \d+\.\d+\.\d+`, Type: "regex"},
			want: true,
		},
		{
			name: "regex match not found",
			data: []byte("no version here"),
			rule: SignatureRule{Pattern: `version \d+\.\d+\.\d+`, Type: "regex"},
			want: false,
		},
		{
			name: "invalid regex",
			data: []byte("anything"),
			rule: SignatureRule{Pattern: `[invalid`, Type: "regex"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.checkSignature(tt.data, tt.rule); got != tt.want {
				t.Errorf("checkSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `version: "2.0"
name: "test-manifest"
description: "A test manifest"
detection:
  - name: testapp
    display_name: Test App
    priority: 1
    rules:
      files:
        - pattern: "*.txt"
          weight: 10
      threshold: 5
`
	path := filepath.Join(dir, "test.yaml")
	_ = os.WriteFile(path, []byte(yamlContent), 0o644)

	m, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if m.Version != "2.0" {
		t.Errorf("Load() Version = %q, want %q", m.Version, "2.0")
	}
	if m.Name != "test-manifest" {
		t.Errorf("Load() Name = %q, want %q", m.Name, "test-manifest")
	}
	if len(m.Detection) != 1 {
		t.Fatalf("Load() Detection length = %d, want 1", len(m.Detection))
	}
	if m.Detection[0].Name != "testapp" {
		t.Errorf("Load() Detection[0].Name = %q, want %q", m.Detection[0].Name, "testapp")
	}
}

func TestLoadDefault_NotFound(t *testing.T) {
	orig, _ := os.Getwd()
	dir := t.TempDir()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	_, err := LoadDefault()
	if err == nil {
		t.Error("LoadDefault() expected error when no manifests/ directory exists, got nil")
	}
}

func TestDefaultManifestHasRules(t *testing.T) {
	m := Default()
	if m.Name == "" {
		t.Error("Default() returned manifest with empty name")
	}
	if len(m.Detection) == 0 {
		t.Error("Default() returned manifest with no detection rules")
	}
}

func TestLoad_Errors(t *testing.T) {
	t.Run("nonexistent file", func(t *testing.T) {
		_, err := Load("/nonexistent/path/manifest.yaml")
		if err == nil {
			t.Error("Load() expected error for nonexistent file")
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.yaml")
		_ = os.WriteFile(path, []byte(":\n  :\n    - {{invalid"), 0o644)
		_, err := Load(path)
		if err == nil {
			t.Error("Load() expected error for invalid YAML")
		}
	})
}

func TestEvaluateCondition_WithVars(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	_ = os.WriteFile(tmpFile, []byte("data"), 0o644)

	tests := []struct {
		name      string
		condition string
		vars      map[string]string
		want      bool
	}{
		{
			name:      "file_exists with variable expansion",
			condition: "file_exists:${DIR}/test.txt",
			vars:      map[string]string{"DIR": tmpDir},
			want:      true,
		},
		{
			name:      "dir_exists with variable expansion",
			condition: "dir_exists:${DIR}",
			vars:      map[string]string{"DIR": tmpDir},
			want:      true,
		},
		{
			name:      "dir_exists on file returns false",
			condition: "dir_exists:" + tmpFile,
			vars:      nil,
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvaluateCondition(tt.condition, tt.vars); got != tt.want {
				t.Errorf("EvaluateCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckFileRule_ContentMatch(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"key": "electron"}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "other.json"), []byte(`{"key": "none"}`), 0o644)

	d := NewDetector(Default(), false)

	t.Run("content match found", func(t *testing.T) {
		rule := FileRule{Pattern: "*.json", Weight: 10, ContentMatch: "electron"}
		found, _ := d.checkFileRule(dir, rule)
		if !found {
			t.Error("checkFileRule() = false, want true for matching content")
		}
	})

	t.Run("content match not found", func(t *testing.T) {
		rule := FileRule{Pattern: "*.json", Weight: 10, ContentMatch: "tauri"}
		found, _ := d.checkFileRule(dir, rule)
		if found {
			t.Error("checkFileRule() = true, want false for non-matching content")
		}
	})

	t.Run("no files match pattern", func(t *testing.T) {
		rule := FileRule{Pattern: "*.xyz", Weight: 10}
		found, _ := d.checkFileRule(dir, rule)
		if found {
			t.Error("checkFileRule() = true, want false for no matching files")
		}
	})
}

func TestReadBinaryData_File(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "binary")
	data := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 2000)...)
	_ = os.WriteFile(binPath, data, 0o755)

	d := NewDetector(Default(), false)

	// readBinaryData with a file path (not directory)
	got := d.readBinaryData(binPath)
	if len(got) == 0 {
		t.Error("readBinaryData() returned empty for valid binary file")
	}

	// readBinaryData with nonexistent path
	got = d.readBinaryData("/nonexistent/path")
	if got != nil {
		t.Error("readBinaryData() expected nil for nonexistent path")
	}
}

func TestDetect_Verbose(t *testing.T) {
	m := Default()
	d := NewDetector(m, true)

	dir := t.TempDir()
	resDir := filepath.Join(dir, "resources")
	_ = os.MkdirAll(resDir, 0o755)
	_ = os.WriteFile(filepath.Join(resDir, "app.asar"), []byte("asar-content"), 0o644)

	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != "electron" {
		t.Errorf("Detect() Type = %q, want electron", result.Type)
	}
}

func TestDetect_WithBinarySignature(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test creates fake ELF binary; Windows does not recognize ELF executables")
	}
	dir := t.TempDir()

	// Create an ELF binary containing "Electron Framework"
	elfData := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 2000)...)
	elfData = append(elfData, []byte("Electron Framework 30.0.1")...)
	_ = os.WriteFile(filepath.Join(dir, "electron"), elfData, 0o755)

	m := Default()
	// Add version extraction for electron
	m.VersionExt = map[string]VersionExtraction{
		"electron": {
			BinaryPatterns: []VersionPattern{
				{Regex: `Electron Framework (\d+\.\d+\.\d+)`, Group: 1},
			},
		},
	}

	d := NewDetector(m, false)
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != "electron" {
		t.Errorf("Detect() Type = %q, want electron", result.Type)
	}
	if result.Version != "30.0.1" {
		t.Errorf("Detect() Version = %q, want 30.0.1", result.Version)
	}
}

func TestExtractVersion_NoMatch(t *testing.T) {
	dir := t.TempDir()
	elfData := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 2000)...)
	_ = os.WriteFile(filepath.Join(dir, "app"), elfData, 0o755)

	d := NewDetector(Default(), false)
	ext := VersionExtraction{
		BinaryPatterns: []VersionPattern{
			{Regex: `NoMatch (\d+)`, Group: 1},
			{Regex: `[invalid`, Group: 0}, // invalid regex
		},
	}
	got := d.extractVersion(dir, ext)
	if got != "" {
		t.Errorf("extractVersion() = %q, want empty", got)
	}
}

func TestIsNativeBinary_MachO(t *testing.T) {
	dir := t.TempDir()

	// Mach-O 32-bit magic: 0xfeedface
	machoPath := filepath.Join(dir, "macho32")
	_ = os.WriteFile(machoPath, []byte{0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0}, 0o644)
	if !isNativeBinary(machoPath) {
		t.Error("isNativeBinary() = false for Mach-O 32-bit, want true")
	}

	// Mach-O 64-bit magic: 0xcffaedfe
	macho64Path := filepath.Join(dir, "macho64")
	_ = os.WriteFile(macho64Path, []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}, 0o644)
	if !isNativeBinary(macho64Path) {
		t.Error("isNativeBinary() = false for Mach-O 64-bit, want true")
	}

	// Nonexistent file
	if isNativeBinary("/nonexistent/file") {
		t.Error("isNativeBinary() = true for nonexistent file, want false")
	}

	// Too-short file
	shortPath := filepath.Join(dir, "short")
	_ = os.WriteFile(shortPath, []byte{0x7f}, 0o644)
	if isNativeBinary(shortPath) {
		t.Error("isNativeBinary() = true for too-short file, want false")
	}
}

func TestLargestNativeBinary_SkipsDotDirs(t *testing.T) {
	dir := t.TempDir()
	hidden := filepath.Join(dir, ".hidden")
	_ = os.MkdirAll(hidden, 0o755)

	elf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 5000)...)
	_ = os.WriteFile(filepath.Join(hidden, "app"), elf, 0o755)

	got := largestNativeBinary(dir, 1)
	if got != "" {
		t.Errorf("largestNativeBinary() = %q, want empty (should skip dot dirs)", got)
	}
}

func TestLargestNativeBinary_SkipsSmallFiles(t *testing.T) {
	dir := t.TempDir()
	// ELF but under 1024 bytes
	smallElf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 500)...)
	_ = os.WriteFile(filepath.Join(dir, "tiny"), smallElf, 0o755)

	got := largestNativeBinary(dir, 0)
	if got != "" {
		t.Errorf("largestNativeBinary() = %q, want empty (file too small)", got)
	}
}

func TestLargestNativeBinary_SkipsNonExecutable(t *testing.T) {
	dir := t.TempDir()
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 5000)...)
	_ = os.WriteFile(filepath.Join(dir, "noexec"), elf, 0o644) // no execute bit

	got := largestNativeBinary(dir, 0)
	if got != "" {
		t.Errorf("largestNativeBinary() = %q, want empty (not executable)", got)
	}
}

func TestDetect_HigherScoreWins(t *testing.T) {
	m := &Manifest{
		Detection: []DetectionRule{
			{Name: "low", DisplayName: "Low", Priority: 1, Rules: DetectionRules{
				Files:     []FileRule{{Pattern: "*.txt", Weight: 10}},
				Threshold: 5,
			}},
			{Name: "high", DisplayName: "High", Priority: 2, Rules: DetectionRules{
				Files:     []FileRule{{Pattern: "*.txt", Weight: 20}, {Pattern: "*.log", Weight: 20}},
				Threshold: 5,
			}},
		},
	}

	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "file.log"), []byte("x"), 0o644)

	d := NewDetector(m, false)
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != "high" {
		t.Errorf("Detect() Type = %q, want high (higher score)", result.Type)
	}
}
