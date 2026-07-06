package knowledge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun_ValidFile(t *testing.T) {
	// Create a temp JS file with some content
	tmp := t.TempDir()
	jsFile := filepath.Join(tmp, "app.js")
	content := `const express = require('express');
const app = express();
app.get('/api/users', (req, res) => { res.json([]); });
app.listen(3000);`
	if err := os.WriteFile(jsFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(tmp, "output")
	result, err := Run(jsFile, Options{OutputDir: outDir})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Assert manifest.json written to output dir
	manifestPath := filepath.Join(outDir, "manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Errorf("expected manifest.json at %s", manifestPath)
	}
}

func TestRun_JSONOnly(t *testing.T) {
	// Create a temp JS file
	tmp := t.TempDir()
	jsFile := filepath.Join(tmp, "app.js")
	if err := os.WriteFile(jsFile, []byte(`console.log("hello");`), 0644); err != nil {
		t.Fatal(err)
	}

	// Call Run without OutputDir
	result, err := Run(jsFile, Options{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestRun_MissingFile(t *testing.T) {
	_, err := Run("/nonexistent/path/to/file.js", Options{})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
