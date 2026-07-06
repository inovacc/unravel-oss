/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractFromDir(t *testing.T) {
	dir := t.TempDir()
	// Create CSS and HTML files
	_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte(".a { color: red; }"), 0644)
	_ = os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "sub", "deep.css"), []byte(".b { color: blue; }"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "page.html"), []byte("<style>.c{}</style>"), 0644)

	sheets, htmlFiles, err := extractFromDir(dir, Options{})
	if err != nil {
		t.Fatalf("extractFromDir: %v", err)
	}
	if len(sheets) < 2 {
		t.Errorf("expected at least 2 CSS files, got %d", len(sheets))
	}
	if len(htmlFiles) < 1 {
		t.Errorf("expected at least 1 HTML file, got %d", len(htmlFiles))
	}
	for _, s := range sheets {
		if s.Source != SourceFile {
			t.Errorf("expected source %q, got %q", SourceFile, s.Source)
		}
		if len(s.Content) == 0 {
			t.Errorf("expected non-empty content for %s", s.Path)
		}
	}
}

func TestExtractFromTauri(t *testing.T) {
	dir := t.TempDir()
	// Create tauri.conf.json
	conf := `{"build": {"frontendDist": "../dist"}}`
	_ = os.MkdirAll(filepath.Join(dir, "src-tauri"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "src-tauri", "tauri.conf.json"), []byte(conf), 0644)
	// Create dist with CSS
	_ = os.MkdirAll(filepath.Join(dir, "dist"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "dist", "app.css"), []byte(".app { margin: 0; }"), 0644)

	sheets, _, err := extractFromTauri(dir, Options{})
	if err != nil {
		t.Fatalf("extractFromTauri: %v", err)
	}
	if len(sheets) < 1 {
		t.Errorf("expected at least 1 CSS file, got %d", len(sheets))
	}
}

func TestExtractFromTauriFallback(t *testing.T) {
	dir := t.TempDir()
	// No tauri.conf.json, but dist/ exists
	_ = os.MkdirAll(filepath.Join(dir, "dist"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "dist", "style.css"), []byte("body{}"), 0644)

	sheets, _, err := extractFromTauri(dir, Options{})
	if err != nil {
		t.Fatalf("extractFromTauri fallback: %v", err)
	}
	if len(sheets) < 1 {
		t.Errorf("expected at least 1 CSS file from fallback, got %d", len(sheets))
	}
}

func TestExtractEntryPoint(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.css"), []byte(".x { color: red; }"), 0644)

	result, err := Extract(dir, Options{})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Stats.TotalFiles == 0 {
		t.Error("expected TotalFiles > 0")
	}
}
