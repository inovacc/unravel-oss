/*
Copyright (c) 2026 Security Research
*/
package regressions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRubricMissingFileFallsBackToDefaults(t *testing.T) {
	rules, err := LoadRubric(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(rules) != len(DefaultRules()) {
		t.Fatalf("expected default rules, got %d", len(rules))
	}
}

func TestLoadRubricEmptyPathReturnsDefaults(t *testing.T) {
	rules, err := LoadRubric("")
	if err != nil || len(rules) == 0 {
		t.Fatalf("LoadRubric(\"\") err=%v rules=%d", err, len(rules))
	}
}

func TestLoadRubricMergesUserOverride(t *testing.T) {
	body := `schema_version: 1
rules:
  - id: custom-rule-1
    dimension: structural
    severity: FLAG
    match:
      key: "communication/endpoints.json"
      condition: array_length_increased
`
	p := writeTemp(t, "r.yaml", body)
	rules, err := LoadRubric(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	var foundCustom, foundDefault bool
	for _, r := range rules {
		if r.ID == "custom-rule-1" {
			foundCustom = true
			if r.Source != SourceRubric {
				t.Errorf("custom rule Source=%q want %q", r.Source, SourceRubric)
			}
		}
		if r.ID == "csp-unsafe-inline-added" {
			foundDefault = true
		}
	}
	if !foundCustom || !foundDefault {
		t.Fatalf("merge missing rules: custom=%v default=%v", foundCustom, foundDefault)
	}
}

func TestLoadRubricRejectsUnknownFields(t *testing.T) {
	body := `schema_version: 1
rules:
  - id: x
    dimension: security_config
    severity: BLOCK
    match: { key: "k", condition: removed }
    EXTRA_FIELD: nope
`
	p := writeTemp(t, "r.yaml", body)
	_, err := LoadRubric(p)
	if err == nil {
		t.Fatalf("expected error for unknown field")
	}
}

func TestLoadRubricRejectsBadSeverity(t *testing.T) {
	body := `schema_version: 1
rules:
  - id: x
    dimension: security_config
    severity: CRITICAL
    match: { key: "k", condition: removed }
`
	p := writeTemp(t, "r.yaml", body)
	_, err := LoadRubric(p)
	if err == nil || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("expected severity error, got %v", err)
	}
}

func TestLoadRubricRejectsBadDimension(t *testing.T) {
	body := `schema_version: 1
rules:
  - id: x
    dimension: foobar
    severity: BLOCK
    match: { key: "k", condition: removed }
`
	p := writeTemp(t, "r.yaml", body)
	_, err := LoadRubric(p)
	if err == nil || !strings.Contains(err.Error(), "dimension") {
		t.Fatalf("expected dimension error, got %v", err)
	}
}

func TestLoadRubricRejectsLargeFile(t *testing.T) {
	big := strings.Repeat("a", maxRubricSize+10)
	p := writeTemp(t, "r.yaml", big)
	_, err := LoadRubric(p)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestLoadRubricRejectsDuplicateID(t *testing.T) {
	body := `schema_version: 1
rules:
  - id: dup
    dimension: structural
    severity: FLAG
    match: { key: "k", condition: array_length_increased }
  - id: dup
    dimension: structural
    severity: BLOCK
    match: { key: "k", condition: array_length_increased }
`
	p := writeTemp(t, "r.yaml", body)
	_, err := LoadRubric(p)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}
