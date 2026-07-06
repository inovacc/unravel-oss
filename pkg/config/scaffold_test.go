package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestScaffoldCreatesWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")

	created, resolved, err := Scaffold(path)
	if err != nil {
		t.Fatalf("Scaffold: %v", err)
	}
	if !created {
		t.Fatalf("created = false, want true for missing file")
	}
	if resolved != path {
		t.Fatalf("resolved = %q, want %q", resolved, path)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scaffolded file: %v", err)
	}
	if !bytes.Equal(got, exampleConfig) {
		t.Fatalf("scaffolded content does not match embedded example")
	}
}

func TestScaffoldLeavesExistingUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	sentinel := []byte("database:\n  host: keep-me\n")
	if err := os.WriteFile(path, sentinel, 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	created, _, err := Scaffold(path)
	if err != nil {
		t.Fatalf("Scaffold: %v", err)
	}
	if created {
		t.Fatalf("created = true, want false for existing file")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Fatalf("existing config was overwritten")
	}
}

func TestExampleMatchesRepoFile(t *testing.T) {
	root, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("read repo-root config.example.yaml: %v", err)
	}
	if !bytes.Equal(root, exampleConfig) {
		t.Fatalf("embedded config.example.yaml differs from repo-root config.example.yaml; keep them identical")
	}
}
