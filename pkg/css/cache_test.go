/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCachedExtract_NoCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "style.css"), []byte("body { margin: 0; }"), 0o644); err != nil {
		t.Fatal(err)
	}

	// With NoCache=true, should still produce a result (just skip cache).
	result, err := CachedExtract(dir, Options{NoCache: true})
	if err != nil {
		t.Fatalf("CachedExtract: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Stats.CSSFiles == 0 {
		t.Error("expected CSS files > 0")
	}
}

func TestCachedExtract_BasicFlow(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.css"), []byte("h1 { color: red; }"), 0o644); err != nil {
		t.Fatal(err)
	}

	// First call: cache miss, should extract.
	result1, err := CachedExtract(dir, Options{NoCache: true})
	if err != nil {
		t.Fatalf("first CachedExtract: %v", err)
	}
	if result1 == nil {
		t.Fatal("expected non-nil result")
	}
	if result1.Stats.CSSFiles != 1 {
		t.Errorf("expected 1 CSS file, got %d", result1.Stats.CSSFiles)
	}
}

func TestCacheKey_Deterministic(t *testing.T) {
	dir := t.TempDir()
	cssFile := filepath.Join(dir, "test.css")
	if err := os.WriteFile(cssFile, []byte("a { color: blue; }"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := Options{Normalize: true, Deduplicate: true}
	key1 := cacheKey(dir, opts)
	key2 := cacheKey(dir, opts)

	if key1 != key2 {
		t.Error("cacheKey should be deterministic for same input")
	}
}

func TestCacheKey_DifferentOptions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.css"), []byte("a {}"), 0o644); err != nil {
		t.Fatal(err)
	}

	key1 := cacheKey(dir, Options{Normalize: true})
	key2 := cacheKey(dir, Options{Normalize: false})

	if key1 == key2 {
		t.Error("cacheKey should differ for different options")
	}
}
