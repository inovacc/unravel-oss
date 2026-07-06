package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
)

// writeKnowledgeJSON writes a minimal knowledge.json (no platform field) into
// dir and returns dir.
func writeKnowledgeJSON(t *testing.T, dir string, fields map[string]any) {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "knowledge.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFingerprintInputs_LoneArtifactSynthesizes(t *testing.T) {
	dir := t.TempDir()
	writeKnowledgeJSON(t, dir, map[string]any{}) // NO platform, NO package_id

	in, err := loadFingerprintInputs(dir, "/some/where/app.dll")
	if err != nil {
		t.Fatalf("expected synthesis, got error: %v", err)
	}
	if in.Platform != "windows-pe" {
		t.Errorf("Platform = %q, want windows-pe", in.Platform)
	}
	if in.DisplayName != "app.dll" {
		t.Errorf("DisplayName = %q, want app.dll", in.DisplayName)
	}
	// The synthesized inputs must satisfy the Fingerprint contract.
	if _, _, err := identity.Fingerprint(in); err != nil {
		t.Errorf("Fingerprint rejected synthesized inputs: %v", err)
	}
}

func TestLoadFingerprintInputs_NoSrcPathStillErrors(t *testing.T) {
	dir := t.TempDir()
	writeKnowledgeJSON(t, dir, map[string]any{}) // no platform

	if _, err := loadFingerprintInputs(dir, ""); err == nil {
		t.Fatal("expected error when platform missing and srcPath empty")
	}
}

func TestLoadFingerprintInputs_ExplicitPlatformWins(t *testing.T) {
	dir := t.TempDir()
	writeKnowledgeJSON(t, dir, map[string]any{"platform": "electron", "display_name": "Cluely"})

	in, err := loadFingerprintInputs(dir, "/ignored/app.dll")
	if err != nil {
		t.Fatal(err)
	}
	if in.Platform != "electron" {
		t.Errorf("Platform = %q, want electron (explicit must not be overridden)", in.Platform)
	}
}
