/*
Copyright (c) 2026 Security Research
*/
package regressions

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRulesContainsBaseline(t *testing.T) {
	rules := DefaultRules()
	if len(rules) < 4 {
		t.Fatalf("DefaultRules returned %d rules, want >= 4", len(rules))
	}
	want := map[string]string{
		"csp-unsafe-inline-added":    SeverityBlock,
		"dangerous-permission-added": SeverityBlock,
		"sandbox-flag-removed":       SeverityBlock,
		"telemetry-sdk-added":        SeverityFlag,
	}
	got := make(map[string]string)
	for _, r := range rules {
		got[r.ID] = r.Severity
		if r.Source != SourceHardcoded {
			t.Errorf("rule %s has Source=%q, want %q", r.ID, r.Source, SourceHardcoded)
		}
	}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("rule %s: severity=%q, want %q", id, got[id], sev)
		}
	}
}

func TestEmbeddedDefaultLoadsCleanly(t *testing.T) {
	// Calling DefaultRules twice should be safe (sync.Once cache).
	a := DefaultRules()
	b := DefaultRules()
	if len(a) != len(b) {
		t.Fatalf("DefaultRules not stable: %d != %d", len(a), len(b))
	}
}

func TestRubricsKeptInSync(t *testing.T) {
	// pkg/knowledge/regressions/kb-regressions.yaml (embedded) MUST be
	// byte-identical to manifests/kb-regressions.yaml (user-discoverable).
	pkgFile := "kb-regressions.yaml"
	manifestFile := filepath.Join("..", "..", "..", "manifests", "kb-regressions.yaml")

	a, err := os.ReadFile(pkgFile)
	if err != nil {
		t.Fatalf("read embedded yaml: %v", err)
	}
	b, err := os.ReadFile(manifestFile)
	if err != nil {
		t.Fatalf("read manifests yaml: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("rubrics drifted — re-copy manifests/kb-regressions.yaml to pkg/knowledge/regressions/kb-regressions.yaml")
	}
}
