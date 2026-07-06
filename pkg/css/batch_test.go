/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBatchExtract_MultiplePaths(t *testing.T) {
	// Create two temp directories with CSS files.
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir1, "a.css"), []byte("body { color: red; }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "b.css"), []byte("h1 { font-size: 2em; }"), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := BatchExtract([]string{dir1, dir2}, Options{})
	if err != nil {
		t.Fatalf("BatchExtract: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for i, r := range results {
		if r == nil {
			t.Fatalf("result[%d] is nil", i)
		}
		if r.Stats.CSSFiles == 0 {
			t.Errorf("result[%d]: expected CSS files > 0", i)
		}
	}
}

func TestBatchExtract_MixedSuccessFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "style.css"), []byte("p { margin: 0; }"), 0o644); err != nil {
		t.Fatal(err)
	}

	nonexistent := filepath.Join(t.TempDir(), "does-not-exist")

	results, err := BatchExtract([]string{dir, nonexistent}, Options{})
	if err != nil {
		t.Fatalf("BatchExtract: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// First should succeed.
	if results[0].Stats.CSSFiles == 0 {
		t.Error("first result should have CSS files")
	}

	// Second should have errors.
	if len(results[1].Errors) == 0 {
		t.Error("second result should have errors for nonexistent path")
	}
}

func TestBatchExtract_Empty(t *testing.T) {
	results, err := BatchExtract(nil, Options{})
	if err != nil {
		t.Fatalf("BatchExtract: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil for empty paths, got %d results", len(results))
	}
}

func TestBatchExtract_WithOutputDir(t *testing.T) {
	dir := t.TempDir()
	outDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "style.css"), []byte("a { color: blue; }"), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := BatchExtract([]string{dir}, Options{OutputDir: outDir})
	if err != nil {
		t.Fatalf("BatchExtract: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestWriteManifest(t *testing.T) {
	outDir := t.TempDir()
	result := &Result{
		Components: []Component{
			{Name: "header", Dir: "components/header"},
		},
		ImportGraph: map[string][]string{
			"main.css": {"reset.css", "vars.css"},
		},
		Stats: ExtractionStats{
			TotalFiles: 5,
			CSSFiles:   3,
			HTMLFiles:  2,
		},
	}

	if err := WriteManifest(result, outDir); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	manifestPath := filepath.Join(outDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	if len(m.Components) != 1 {
		t.Errorf("expected 1 component, got %d", len(m.Components))
	}
	if len(m.ImportGraph) != 1 {
		t.Errorf("expected 1 import graph entry, got %d", len(m.ImportGraph))
	}
	if m.Stats.TotalFiles != 5 {
		t.Errorf("expected 5 total files, got %d", m.Stats.TotalFiles)
	}
}

func TestWriteManifest_NilResult(t *testing.T) {
	if err := WriteManifest(nil, t.TempDir()); err == nil {
		t.Error("expected error for nil result")
	}
}
