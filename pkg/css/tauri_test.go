/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractFromTauriWithConfig(t *testing.T) {
	dir := t.TempDir()
	tauriDir := filepath.Join(dir, "src-tauri")
	_ = os.MkdirAll(tauriDir, 0755)
	conf := `{"build": {"frontendDist": "../dist"}}`
	_ = os.WriteFile(filepath.Join(tauriDir, "tauri.conf.json"), []byte(conf), 0644)
	distDir := filepath.Join(dir, "dist")
	_ = os.MkdirAll(distDir, 0755)
	_ = os.WriteFile(filepath.Join(distDir, "app.css"), []byte(".app{}"), 0644)

	sheets, _, err := extractFromTauri(dir, Options{})
	if err != nil {
		t.Fatalf("extractFromTauri: %v", err)
	}
	if len(sheets) < 1 {
		t.Errorf("expected at least 1 CSS file, got %d", len(sheets))
	}
}

func TestExtractFromTauriFallbackDist(t *testing.T) {
	dir := t.TempDir()
	distDir := filepath.Join(dir, "dist")
	_ = os.MkdirAll(distDir, 0755)
	_ = os.WriteFile(filepath.Join(distDir, "style.css"), []byte("body{}"), 0644)

	sheets, _, err := extractFromTauri(dir, Options{})
	if err != nil {
		t.Fatalf("extractFromTauri: %v", err)
	}
	if len(sheets) < 1 {
		t.Errorf("expected at least 1 CSS from fallback, got %d", len(sheets))
	}
}
