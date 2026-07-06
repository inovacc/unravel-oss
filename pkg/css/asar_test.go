/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractFromASARFallbackDir(t *testing.T) {
	// Test the file-discovery logic with a directory (real ASAR creation is complex)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte(".a{}"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "theme.scss"), []byte("$var: red;"), 0644)
	_ = os.MkdirAll(filepath.Join(dir, "components"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "components", "button.css"), []byte(".btn{}"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<style>.x{}</style>"), 0644)

	sheets, htmlFiles, err := extractFromASAR(dir, Options{})
	if err != nil {
		t.Fatalf("extractFromASAR: %v", err)
	}
	if len(sheets) < 3 {
		t.Errorf("expected at least 3 style files, got %d", len(sheets))
	}
	if len(htmlFiles) < 1 {
		t.Errorf("expected at least 1 HTML file, got %d", len(htmlFiles))
	}
}
