/* Copyright (c) 2026 Security Research */
package asar

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name string
		size int64
		want string
	}{
		{name: "zero bytes", size: 0, want: "0 B"},
		{name: "bytes", size: 512, want: "512 B"},
		{name: "one KB", size: 1024, want: "1.00 KB"},
		{name: "kilobytes", size: 1536, want: "1.50 KB"},
		{name: "one MB", size: 1024 * 1024, want: "1.00 MB"},
		{name: "megabytes", size: 5 * 1024 * 1024, want: "5.00 MB"},
		{name: "one GB", size: 1024 * 1024 * 1024, want: "1.00 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatBytes(tt.size)
			if got != tt.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.size, got, tt.want)
			}
		})
	}
}

func TestCollectFiles(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]*FileEntry
		prefix    string
		wantCount int
		wantDirs  int
	}{
		{
			name:      "nil files",
			files:     nil,
			prefix:    "",
			wantCount: 0,
			wantDirs:  0,
		},
		{
			name: "single file",
			files: map[string]*FileEntry{
				"app.js": {Size: 100, Offset: "0"},
			},
			prefix:    "",
			wantCount: 1,
			wantDirs:  0,
		},
		{
			name: "directory with files",
			files: map[string]*FileEntry{
				"src": {
					Files: map[string]*FileEntry{
						"main.js": {Size: 200, Offset: "0"},
						"util.js": {Size: 150, Offset: "200"},
					},
				},
			},
			prefix:    "",
			wantCount: 3,
			wantDirs:  1,
		},
		{
			name: "with prefix",
			files: map[string]*FileEntry{
				"index.js": {Size: 50, Offset: "0"},
			},
			prefix:    "app",
			wantCount: 1,
			wantDirs:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CollectFiles(tt.files, tt.prefix)
			if len(got) != tt.wantCount {
				t.Errorf("CollectFiles() returned %d entries, want %d", len(got), tt.wantCount)
			}
			dirCount := 0
			for _, f := range got {
				if f.IsDir {
					dirCount++
				}
			}
			if dirCount != tt.wantDirs {
				t.Errorf("CollectFiles() returned %d dirs, want %d", dirCount, tt.wantDirs)
			}
		})
	}
}

func TestOpenAndParse(t *testing.T) {
	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"app.js":       {Size: 13, Offset: "0"},
		"package.json": {Size: 2, Offset: "13"},
	}, []byte("console.log(1){}"))

	f, header, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}

	defer func() { _ = f.Close() }()

	if header == nil {
		t.Fatal("expected non-nil header")
	}

	if len(header.Files) != 2 {
		t.Errorf("expected 2 files in header, got %d", len(header.Files))
	}

	if dataOffset <= 0 {
		t.Errorf("expected positive data offset, got %d", dataOffset)
	}
}

func TestOpenAndParse_NonexistentFile(t *testing.T) {
	_, _, _, _, err := OpenAndParse("/tmp/nonexistent-asar-12345.asar")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestOpenAndParse_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "invalid.asar")

	if err := os.WriteFile(f, []byte("not an asar file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, _, _, err := OpenAndParse(f)
	if err == nil {
		t.Error("expected error for invalid asar file")
	}
}

func TestReadFileContent(t *testing.T) {
	content := []byte("hello world!!")
	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"test.txt": {Size: int64(len(content)), Offset: "0"},
	}, content)

	f, _, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}

	defer func() { _ = f.Close() }()

	data, err := ReadFileContent(f, dataOffset, 0, int64(len(content)))
	if err != nil {
		t.Fatalf("ReadFileContent: %v", err)
	}

	if string(data) != string(content) {
		t.Errorf("ReadFileContent = %q, want %q", data, content)
	}
}

func TestSearch(t *testing.T) {
	content := []byte("var apiKey = 'secret123'; console.log(apiKey);")
	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"app.js": {Size: int64(len(content)), Offset: "0"},
	}, content)

	f, header, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}

	defer func() { _ = f.Close() }()

	result := Search(f, header, dataOffset, "apiKey")

	if result.Total == 0 {
		t.Error("expected at least 1 match for 'apiKey'")
	}

	if len(result.Matches) == 0 {
		t.Error("expected match entries")
	}
}

func TestSearch_NoMatch(t *testing.T) {
	content := []byte("hello world nothing special here")
	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"readme.txt": {Size: int64(len(content)), Offset: "0"},
	}, content)

	f, header, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}

	defer func() { _ = f.Close() }()

	result := Search(f, header, dataOffset, "nonexistent_pattern_xyz")

	if result.Total != 0 {
		t.Errorf("expected 0 matches, got %d", result.Total)
	}
}

func TestExtract(t *testing.T) {
	content := []byte("file content here")
	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"test.txt": {Size: int64(len(content)), Offset: "0"},
	}, content)

	f, header, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}

	defer func() { _ = f.Close() }()

	outDir := filepath.Join(t.TempDir(), "extracted")
	report := Extract(f, header, dataOffset, outDir, asarFile, false)

	if report.Files == 0 {
		t.Error("expected at least 1 extracted file")
	}

	if len(report.Errors) > 0 {
		t.Errorf("unexpected errors: %v", report.Errors)
	}

	// Verify extracted file exists
	extractedFile := filepath.Join(outDir, "test.txt")
	data, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}

	if string(data) != string(content) {
		t.Errorf("extracted content = %q, want %q", data, content)
	}
}

// buildTestASAR creates a minimal valid ASAR archive for testing.
func buildTestASAR(t *testing.T, files map[string]*FileEntry, data []byte) string {
	t.Helper()

	tmpDir := t.TempDir()
	asarPath := filepath.Join(tmpDir, "test.asar")

	header := Header{Files: files}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}

	// ASAR format:
	// 4 bytes: header size (uint32 LE) = 16 + len(headerJSON) padded to 4 bytes
	// 4 bytes: something (uint32 LE)
	// 4 bytes: something (uint32 LE)
	// 4 bytes: header string size (uint32 LE)
	// N bytes: header JSON string
	// padding to 4-byte boundary
	// M bytes: data

	headerSize := uint32(len(headerJSON))
	// Pickle format: the header is wrapped in a "pickle" structure
	// Total pickle size = 8 + 4 + headerSize (padded to 4)
	paddedHeaderSize := (headerSize + 3) & ^uint32(3)

	var buf []byte

	// Pickle header
	pickleSize := uint32(4 + paddedHeaderSize)
	totalSize := uint32(4 + pickleSize)

	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, totalSize)
	buf = append(buf, tmp...)

	binary.LittleEndian.PutUint32(tmp, pickleSize+4)
	buf = append(buf, tmp...)

	binary.LittleEndian.PutUint32(tmp, pickleSize)
	buf = append(buf, tmp...)

	binary.LittleEndian.PutUint32(tmp, headerSize)
	buf = append(buf, tmp...)

	buf = append(buf, headerJSON...)

	// Pad to 4-byte boundary
	padding := int(paddedHeaderSize - headerSize)
	for range padding {
		buf = append(buf, 0)
	}

	// Append data
	buf = append(buf, data...)

	if err := os.WriteFile(asarPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	return asarPath
}

// casesPath resolves a path relative to the cases/ directory at the project root.
func casesPath(t *testing.T, relPath string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("could not find project root")
		}
		dir = parent
	}
	p := filepath.Join(dir, "cases", relPath)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		t.Skipf("test case not available: %s", p)
	}
	return p
}

func TestGolden_OpenAndParse_SlackAsar(t *testing.T) {
	asarPath := casesPath(t, "linux/input/slack/216/usr/lib/slack/resources/app.asar")

	f, header, _, dataOffset, err := OpenAndParse(asarPath)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}
	defer func() { _ = f.Close() }()

	if header == nil {
		t.Fatal("expected non-nil header")
	}
	if dataOffset <= 0 {
		t.Errorf("expected positive dataOffset, got %d", dataOffset)
	}
	if len(header.Files) == 0 {
		t.Error("expected files in header")
	}
}

func TestGolden_Search_SlackAsar(t *testing.T) {
	asarPath := casesPath(t, "linux/input/slack/216/usr/lib/slack/resources/app.asar")

	f, header, _, dataOffset, err := OpenAndParse(asarPath)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}
	defer func() { _ = f.Close() }()

	result := Search(f, header, dataOffset, "package.json")
	// Slack ASAR should contain references to "package.json"
	if result.Total == 0 {
		t.Error("expected at least 1 match for 'package.json' in Slack ASAR")
	}
}

func TestGolden_CollectFiles_SlackAsar(t *testing.T) {
	asarPath := casesPath(t, "linux/input/slack/216/usr/lib/slack/resources/app.asar")

	f, header, _, _, err := OpenAndParse(asarPath)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}
	defer func() { _ = f.Close() }()

	files := CollectFiles(header.Files, "")
	if len(files) < 100 {
		t.Errorf("expected > 100 files in Slack ASAR, got %d", len(files))
	}
}

func TestOpenAndParse_TruncatedHeader(t *testing.T) {
	tmpDir := t.TempDir()
	// File with only 10 bytes -- not enough for the 16-byte header prefix
	f := filepath.Join(tmpDir, "truncated.asar")
	if err := os.WriteFile(f, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, _, _, err := OpenAndParse(f)
	if err == nil {
		t.Error("expected error for truncated header")
	}
}

func TestOpenAndParse_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "badjson.asar")

	// Build a header that points to invalid JSON
	invalidJSON := []byte("not json{{{")
	headerSize := uint32(len(invalidJSON))
	paddedHeaderSize := (headerSize + 3) & ^uint32(3)
	pSize := uint32(4 + paddedHeaderSize)
	totalSize := uint32(4 + pSize)

	var buf []byte
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, totalSize)
	buf = append(buf, tmp...)
	binary.LittleEndian.PutUint32(tmp, pSize+4)
	buf = append(buf, tmp...)
	binary.LittleEndian.PutUint32(tmp, pSize)
	buf = append(buf, tmp...)
	binary.LittleEndian.PutUint32(tmp, headerSize)
	buf = append(buf, tmp...)
	buf = append(buf, invalidJSON...)

	if err := os.WriteFile(f, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, _, _, err := OpenAndParse(f)
	if err == nil {
		t.Error("expected error for invalid JSON header")
	}
}

func TestReadFileContent_MultipleFiles(t *testing.T) {
	content1 := []byte("first file")
	content2 := []byte("second file data")
	allContent := append(content1, content2...)

	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"a.txt": {Size: int64(len(content1)), Offset: "0"},
		"b.txt": {Size: int64(len(content2)), Offset: fmt.Sprintf("%d", len(content1))},
	}, allContent)

	f, _, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}
	defer func() { _ = f.Close() }()

	data1, err := ReadFileContent(f, dataOffset, 0, int64(len(content1)))
	if err != nil {
		t.Fatalf("ReadFileContent(a.txt): %v", err)
	}
	if string(data1) != "first file" {
		t.Errorf("a.txt content = %q, want %q", data1, "first file")
	}

	data2, err := ReadFileContent(f, dataOffset, int64(len(content1)), int64(len(content2)))
	if err != nil {
		t.Fatalf("ReadFileContent(b.txt): %v", err)
	}
	if string(data2) != "second file data" {
		t.Errorf("b.txt content = %q, want %q", data2, "second file data")
	}
}

func TestSearch_CaseInsensitive(t *testing.T) {
	content := []byte("var ApiKey = 'test';")
	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"app.js": {Size: int64(len(content)), Offset: "0"},
	}, content)

	f, header, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}
	defer func() { _ = f.Close() }()

	result := Search(f, header, dataOffset, "apikey")
	if result.Total == 0 {
		t.Error("expected case-insensitive match for 'apikey'")
	}
}

func TestExtract_WithDirectory(t *testing.T) {
	content := []byte("file in subdir")
	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"src": {
			Files: map[string]*FileEntry{
				"main.js": {Size: int64(len(content)), Offset: "0"},
			},
		},
	}, content)

	f, header, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}
	defer func() { _ = f.Close() }()

	outDir := filepath.Join(t.TempDir(), "extracted")
	report := Extract(f, header, dataOffset, outDir, asarFile, false)

	if report.Directories == 0 {
		t.Error("expected at least 1 directory")
	}
	if report.Files == 0 {
		t.Error("expected at least 1 file")
	}

	extractedFile := filepath.Join(outDir, "src", "main.js")
	data, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(data) != "file in subdir" {
		t.Errorf("content = %q, want %q", data, "file in subdir")
	}
}

func TestExtract_Verbose(t *testing.T) {
	content := []byte("verbose test")
	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"v.txt": {Size: int64(len(content)), Offset: "0"},
	}, content)

	f, header, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}
	defer func() { _ = f.Close() }()

	outDir := filepath.Join(t.TempDir(), "extracted")
	report := Extract(f, header, dataOffset, outDir, asarFile, true)
	if report.Files != 1 {
		t.Errorf("expected 1 file, got %d", report.Files)
	}
}

func TestExtractContexts(t *testing.T) {
	content := "line1\nline2 secret here\nline3\nline4 secret again\nline5"
	contexts := extractContexts(content, "secret", 3)
	if len(contexts) != 2 {
		t.Errorf("expected 2 contexts, got %d", len(contexts))
	}
	if len(contexts) > 0 && contexts[0].Line != 2 {
		t.Errorf("first match line = %d, want 2", contexts[0].Line)
	}
}

func TestCollectFiles_UnpackedFile(t *testing.T) {
	files := map[string]*FileEntry{
		"unpacked.js": {Size: 100, Offset: "0", Unpacked: true},
		"normal.js":   {Size: 50, Offset: "100"},
	}

	got := CollectFiles(files, "")
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}

	unpackedFound := false
	for _, f := range got {
		if f.Path == "unpacked.js" && f.Unpacked {
			unpackedFound = true
		}
	}
	if !unpackedFound {
		t.Error("expected to find unpacked file with Unpacked=true")
	}
}

func TestExtract_WithUnpackedFile(t *testing.T) {
	// Create an ASAR with an unpacked file entry, plus the .unpacked directory
	content := []byte("packed data")
	unpackedContent := []byte("unpacked data here")

	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"packed.txt":   {Size: int64(len(content)), Offset: "0"},
		"unpacked.txt": {Size: int64(len(unpackedContent)), Unpacked: true},
	}, content)

	// Create the .unpacked directory with the file
	unpackedDir := asarFile + ".unpacked"
	_ = os.MkdirAll(unpackedDir, 0o755)
	_ = os.WriteFile(filepath.Join(unpackedDir, "unpacked.txt"), unpackedContent, 0o644)

	f, header, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}
	defer func() { _ = f.Close() }()

	outDir := filepath.Join(t.TempDir(), "extracted")
	report := Extract(f, header, dataOffset, outDir, asarFile, false)

	if report.Files < 2 {
		t.Errorf("expected 2 files extracted, got %d", report.Files)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "unpacked.txt"))
	if err != nil {
		t.Fatalf("read unpacked: %v", err)
	}
	if string(data) != "unpacked data here" {
		t.Errorf("unpacked content = %q, want %q", data, "unpacked data here")
	}
}

func TestReadFileContent_LargeSizeCapped(t *testing.T) {
	// ReadFileContent caps at 10MB; just verify it doesn't fail with large size param
	content := []byte("small data")
	asarFile := buildTestASAR(t, map[string]*FileEntry{
		"t.txt": {Size: int64(len(content)), Offset: "0"},
	}, content)

	f, _, _, dataOffset, err := OpenAndParse(asarFile)
	if err != nil {
		t.Fatalf("OpenAndParse: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Request more than what's available (but less than 10MB)
	// This will try to read len(content) bytes from the actual file
	data, err := ReadFileContent(f, dataOffset, 0, int64(len(content)))
	if err != nil {
		t.Fatalf("ReadFileContent: %v", err)
	}
	if string(data) != "small data" {
		t.Errorf("content = %q, want 'small data'", data)
	}
}

func TestCollectFiles_DeepNesting(t *testing.T) {
	files := map[string]*FileEntry{
		"a": {
			Files: map[string]*FileEntry{
				"b": {
					Files: map[string]*FileEntry{
						"c.txt": {Size: 10, Offset: "0"},
					},
				},
			},
		},
	}

	got := CollectFiles(files, "")
	// Should have: a (dir), a/b (dir), a/b/c.txt (file) = 3
	if len(got) != 3 {
		t.Errorf("expected 3 entries for deep nesting, got %d", len(got))
	}

	// Find the deepest file
	found := false
	for _, f := range got {
		if strings.HasSuffix(f.Path, "c.txt") {
			found = true
		}
	}

	if !found {
		t.Error("expected to find c.txt in collected files")
	}
}
