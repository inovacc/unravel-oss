package zipapp

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// helper: build an in-memory ZIP archive from a map of filename→content.
func buildZIP(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// helper: write bytes to a temp file and return its path.
func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

func TestIsZipAppBinary(t *testing.T) {
	mainContent := "import sys\nprint('hello')\n"

	tests := []struct {
		name    string
		data    []byte
		want    bool
		wantErr bool
	}{
		{
			name: "valid zipapp with __main__.py",
			data: buildZIP(t, map[string]string{
				"__main__.py": mainContent,
				"lib/util.py": "# util",
			}),
			want: true,
		},
		{
			name: "zip without __main__.py",
			data: buildZIP(t, map[string]string{
				"app.py":  "# app",
				"util.py": "# util",
			}),
			want: false,
		},
		{
			name: "plain text (not a ZIP)",
			data: []byte("hello world, this is not a zip file"),
			want: false,
		},
		{
			name: "empty file",
			data: []byte{},
			want: false,
		},
		{
			name: "PE stub + zipapp",
			data: append([]byte("MZ\x00\x00PESTUBDATA_PADDING_"), buildZIP(t, map[string]string{
				"__main__.py": mainContent,
			})...),
			want: true,
		},
		{
			name: "shebang + zipapp",
			data: append([]byte("#!/usr/bin/env python3\n"), buildZIP(t, map[string]string{
				"__main__.py": mainContent,
			})...),
			want: true,
		},
		{
			name: "random binary data (no PK signature)",
			data: []byte{0xff, 0xfe, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTempFile(t, dir, "test.bin", tt.data)

			got, err := IsZipAppBinary(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IsZipAppBinary() err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("IsZipAppBinary() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("nonexistent file returns error", func(t *testing.T) {
		_, err := IsZipAppBinary("/nonexistent/path/file.bin")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}

func TestAnalyze(t *testing.T) {
	mainContent := "import sys\nprint('hello')\n"

	tests := []struct {
		name       string
		data       []byte
		wantApp    bool
		wantPE     bool
		wantSheb   bool
		wantShbStr string
		wantFiles  int
		wantMain   string
	}{
		{
			name: "valid zipapp",
			data: buildZIP(t, map[string]string{
				"__main__.py": mainContent,
				"lib/util.py": "# util module",
			}),
			wantApp:   true,
			wantFiles: 2,
			wantMain:  mainContent,
		},
		{
			name: "zip without __main__.py",
			data: buildZIP(t, map[string]string{
				"app.py": "# app",
			}),
			wantApp:   false,
			wantFiles: 1,
		},
		{
			name: "PE stub + zipapp",
			data: append([]byte("MZ\x00\x00STUBDATA__"), buildZIP(t, map[string]string{
				"__main__.py": mainContent,
			})...),
			wantApp:   true,
			wantPE:    true,
			wantFiles: 1,
			wantMain:  mainContent,
		},
		{
			name: "shebang + zipapp",
			data: append([]byte("#!/usr/bin/python3\n"), buildZIP(t, map[string]string{
				"__main__.py": mainContent,
			})...),
			wantApp:    true,
			wantSheb:   true,
			wantShbStr: "/usr/bin/python3",
			wantFiles:  1,
			wantMain:   mainContent,
		},
		{
			name:      "non-zip data",
			data:      []byte("just plain text, nothing special here"),
			wantApp:   false,
			wantFiles: 0,
		},
		{
			name:      "empty file",
			data:      []byte{},
			wantApp:   false,
			wantFiles: 0,
		},
		{
			name: "zipapp with multiple files",
			data: buildZIP(t, map[string]string{
				"__main__.py":     "print('hi')",
				"pkg/__init__.py": "",
				"pkg/core.py":     "class Core: pass",
				"pkg/utils.py":    "def helper(): pass",
			}),
			wantApp:   true,
			wantFiles: 4,
			wantMain:  "print('hi')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTempFile(t, dir, "test.pyz", tt.data)

			result, err := Analyze(path)
			if err != nil {
				t.Fatalf("Analyze() error: %v", err)
			}
			if result == nil {
				t.Fatal("Analyze() returned nil")
			}

			if result.IsZipApp != tt.wantApp {
				t.Errorf("IsZipApp = %v, want %v", result.IsZipApp, tt.wantApp)
			}
			if result.HasPEStub != tt.wantPE {
				t.Errorf("HasPEStub = %v, want %v", result.HasPEStub, tt.wantPE)
			}
			if result.HasShebang != tt.wantSheb {
				t.Errorf("HasShebang = %v, want %v", result.HasShebang, tt.wantSheb)
			}
			if tt.wantShbStr != "" && result.Shebang != tt.wantShbStr {
				t.Errorf("Shebang = %q, want %q", result.Shebang, tt.wantShbStr)
			}
			if result.FileCount != tt.wantFiles {
				t.Errorf("FileCount = %d, want %d", result.FileCount, tt.wantFiles)
			}
			if tt.wantMain != "" && result.MainPy != tt.wantMain {
				t.Errorf("MainPy = %q, want %q", result.MainPy, tt.wantMain)
			}

			// Verify basic metadata
			if result.Name != "test.pyz" {
				t.Errorf("Name = %q, want %q", result.Name, "test.pyz")
			}
			if result.Size != int64(len(tt.data)) {
				t.Errorf("Size = %d, want %d", result.Size, len(tt.data))
			}
		})
	}

	t.Run("nonexistent file returns error", func(t *testing.T) {
		_, err := Analyze("/nonexistent/path/nofile.pyz")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}

func TestExtract(t *testing.T) {
	mainContent := "import sys\nprint('hello')\n"
	utilContent := "def helper(): return 42"

	tests := []struct {
		name      string
		data      []byte
		wantErr   bool
		wantFiles map[string]string // expected extracted files → content
	}{
		{
			name: "extract valid zipapp",
			data: buildZIP(t, map[string]string{
				"__main__.py": mainContent,
				"lib/util.py": utilContent,
			}),
			wantFiles: map[string]string{
				"__main__.py": mainContent,
				"lib/util.py": utilContent,
			},
		},
		{
			name: "extract zipapp with nested dirs",
			data: buildZIP(t, map[string]string{
				"__main__.py":      mainContent,
				"pkg/sub/deep.py":  "# deep",
				"pkg/sub/other.py": "# other",
			}),
			wantFiles: map[string]string{
				"__main__.py":      mainContent,
				"pkg/sub/deep.py":  "# deep",
				"pkg/sub/other.py": "# other",
			},
		},
		{
			name:    "not a zipapp returns error",
			data:    []byte("just text"),
			wantErr: true,
		},
		{
			name: "zip without __main__.py returns error",
			data: buildZIP(t, map[string]string{
				"app.py": "# app",
			}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			srcPath := writeTempFile(t, dir, "app.pyz", tt.data)
			outDir := filepath.Join(dir, "out")

			result, err := Extract(srcPath, outDir, false)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Extract() err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if result == nil {
				t.Fatal("Extract() returned nil result")
			}
			if !result.IsZipApp {
				t.Error("Extract() result.IsZipApp = false, want true")
			}

			// Verify extracted files on disk
			for relPath, wantContent := range tt.wantFiles {
				fullPath := filepath.Join(outDir, filepath.FromSlash(relPath))
				got, err := os.ReadFile(fullPath)
				if err != nil {
					t.Errorf("expected file %s not found: %v", relPath, err)
					continue
				}
				if string(got) != wantContent {
					t.Errorf("file %s content = %q, want %q", relPath, got, wantContent)
				}
			}

			// Check metadata file was written
			metaPath := filepath.Join(outDir, "UNRAVEL_META.json")
			if _, err := os.Stat(metaPath); err != nil {
				t.Errorf("metadata file not created: %v", err)
			}
		})
	}

	t.Run("extract with verbose", func(t *testing.T) {
		dir := t.TempDir()
		data := buildZIP(t, map[string]string{
			"__main__.py": mainContent,
		})
		srcPath := writeTempFile(t, dir, "app.pyz", data)
		outDir := filepath.Join(dir, "out")

		result, err := Extract(srcPath, outDir, true)
		if err != nil {
			t.Fatalf("Extract(verbose=true) error: %v", err)
		}
		if result == nil || !result.IsZipApp {
			t.Error("expected valid zipapp result")
		}
	})

	t.Run("nonexistent source returns error", func(t *testing.T) {
		_, err := Extract("/nonexistent/file.pyz", t.TempDir(), false)
		if err == nil {
			t.Fatal("expected error for nonexistent source")
		}
	})
}

func TestAnalyze_TotalSize(t *testing.T) {
	content1 := "x = 1"  // 5 bytes
	content2 := "y = 22" // 6 bytes
	data := buildZIP(t, map[string]string{
		"__main__.py": content1,
		"other.py":    content2,
	})

	dir := t.TempDir()
	path := writeTempFile(t, dir, "size.pyz", data)

	result, err := Analyze(path)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	wantTotal := int64(len(content1) + len(content2))
	if result.TotalSize != wantTotal {
		t.Errorf("TotalSize = %d, want %d", result.TotalSize, wantTotal)
	}
}

func TestAnalyze_ZipOffset(t *testing.T) {
	prefix := []byte("#!/usr/bin/env python3\n")
	zipData := buildZIP(t, map[string]string{
		"__main__.py": "print('hi')",
	})
	data := append(prefix, zipData...)

	dir := t.TempDir()
	path := writeTempFile(t, dir, "offset.pyz", data)

	result, err := Analyze(path)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result.ZipOffset != int64(len(prefix)) {
		t.Errorf("ZipOffset = %d, want %d", result.ZipOffset, len(prefix))
	}
}

func TestFindZipStart(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{
			name: "PK at start",
			data: []byte{'P', 'K', 0x03, 0x04, 0x00},
			want: 0,
		},
		{
			name: "PK after prefix",
			data: append([]byte("PREFIXDATA"), []byte{'P', 'K', 0x03, 0x04}...),
			want: 10,
		},
		{
			name: "no PK signature",
			data: []byte("no zip here"),
			want: -1,
		},
		{
			name: "empty data",
			data: []byte{},
			want: -1,
		},
		{
			name: "partial PK only",
			data: []byte{'P', 'K', 0x03}, // missing 0x04
			want: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findZipStart(tt.data)
			if got != tt.want {
				t.Errorf("findZipStart() = %d, want %d", got, tt.want)
			}
		})
	}
}
