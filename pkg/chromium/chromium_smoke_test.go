/*
Copyright (c) 2026 Security Research
*/
package chromium

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtract_EmptyProfile(t *testing.T) {
	src := t.TempDir()
	out := filepath.Join(t.TempDir(), "out")
	res, err := Extract(ExtractorConfig{
		AppName:    "smoketest",
		SourcePath: src,
		OutputPath: out,
	})
	if err != nil {
		t.Fatalf("Extract empty profile: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	if res.AppName != "smoketest" {
		t.Errorf("AppName: got %q want smoketest", res.AppName)
	}
	if res.FileCount != 0 {
		t.Errorf("FileCount: got %d want 0 on empty profile", res.FileCount)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("output dir not created: %v", err)
	}
}

func TestExtract_BadOutputPath(t *testing.T) {
	// Source exists, output points at a file (not dir) — mkdir must fail.
	src := t.TempDir()
	outFile := filepath.Join(t.TempDir(), "blocker.txt")
	if err := os.WriteFile(outFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	// On Windows, MkdirAll on an existing file path returns an error.
	// On Unix, behavior is similar. Either way, this exercises the error
	// branch in Extract.
	out := filepath.Join(outFile, "subdir")
	if _, err := Extract(ExtractorConfig{
		AppName: "x", SourcePath: src, OutputPath: out,
	}); err == nil {
		t.Skip("platform allowed nested-into-file mkdir; can't exercise error branch here")
	}
}

func TestExtractCookies_NoFile(t *testing.T) {
	// Function is void; just verify it doesn't panic on missing cookies.
	res := &ExtractionResult{Cookies: []CookieInfo{}}
	ExtractCookies(filepath.Join(t.TempDir(), "no-such-file"), res)
	if len(res.Cookies) != 0 {
		t.Errorf("Cookies: got %d want 0", len(res.Cookies))
	}
}

func TestExtractBlobStorage_MissingDir(t *testing.T) {
	cfg := ExtractorConfig{
		SourcePath: filepath.Join(t.TempDir(), "no-such-source"),
		OutputPath: t.TempDir(),
	}
	res := &ExtractionResult{Files: []ExtractedFile{}}
	ExtractBlobStorage(cfg, res) // void; must not panic
}

func TestExtractDatabases_MissingDir(t *testing.T) {
	cfg := ExtractorConfig{
		SourcePath: filepath.Join(t.TempDir(), "no-such-source"),
		OutputPath: t.TempDir(),
	}
	res := &ExtractionResult{Databases: []DatabaseInfo{}}
	ExtractDatabases(cfg, res) // void; must not panic
}
