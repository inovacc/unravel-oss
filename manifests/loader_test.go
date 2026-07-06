/*
Copyright (c) 2026 Security Research
*/
package manifests

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCapabilities_OK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.yaml")
	body := []byte(`version: 1
weights:
  internetClient: 99
auto_critical_namespaces: [rescap]
unknown_capability:
  bucket: high
  weight: 50
signature_multipliers:
  unsigned: 2.0
  trusted-microsoft: 0.8
trusted_microsoft_max_bucket: high
buckets:
  - { name: low, max: 25 }
  - { name: critical, max: 100 }
`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadCapabilities(path)
	if err != nil {
		t.Fatalf("LoadCapabilities: %v", err)
	}
	if cfg.Weights["internetClient"] != 99 {
		t.Errorf("Weights[internetClient]=%d want 99", cfg.Weights["internetClient"])
	}
	if cfg.UnknownCapability.Bucket != "high" {
		t.Errorf("UnknownCapability.Bucket=%q want high", cfg.UnknownCapability.Bucket)
	}
	if cfg.SignatureMultipliers["unsigned"] != 2.0 {
		t.Errorf("SignatureMultipliers[unsigned]=%v want 2.0", cfg.SignatureMultipliers["unsigned"])
	}
	if cfg.TrustedMicrosoftMaxLevel != "high" {
		t.Errorf("TrustedMicrosoftMaxLevel=%q want high", cfg.TrustedMicrosoftMaxLevel)
	}
}

func TestLoadCapabilities_Missing(t *testing.T) {
	_, err := LoadCapabilities("/nonexistent/path/caps.yaml")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected fs.ErrNotExist, got %v", err)
	}
}

func TestLoadCapabilities_Empty(t *testing.T) {
	_, err := LoadCapabilities("")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected fs.ErrNotExist for empty path, got %v", err)
	}
}

func TestLoadCapabilities_PathTraversal(t *testing.T) {
	_, err := LoadCapabilities("../../etc/passwd")
	if err == nil {
		t.Error("expected error on traversal path, got nil")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Error("traversal should error specifically, not via fs.ErrNotExist")
	}
}

func TestLoadCapabilities_Malformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("weights:\n  internetClient: [not, a, number]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCapabilities(path)
	if err == nil {
		t.Error("expected error on type-mismatched yaml")
	}
}

func TestLoadCapabilities_NotRegular(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadCapabilities(dir) // directory, not a file
	if err == nil {
		t.Error("expected error when path is a directory")
	}
}
