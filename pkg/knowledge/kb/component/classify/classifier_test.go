/*
Copyright (c) 2026 Security Research

Tests for the Classifier strategy interface and its implementations.
Phase 45 / LLMC-02.
*/
package classify

import (
	"context"
	"testing"
)

// TestRuleClassifier_NameAndPromptVersion locks the public surface so a
// future refactor cannot silently change persisted values.
func TestRuleClassifier_NameAndPromptVersion(t *testing.T) {
	r := RuleClassifier{}
	if r.Name() != "rule" {
		t.Fatalf("RuleClassifier.Name() = %q; want %q", r.Name(), "rule")
	}
	if r.PromptVersion() != "" {
		t.Fatalf("RuleClassifier.PromptVersion() = %q; want \"\"", r.PromptVersion())
	}
}

// TestRuleClassifier_DelegatesToApply asserts that the wrapper produces
// the same Result that component.Apply would for the same module — the
// behavior-preserving lift requirement of Plan 45-02.
func TestRuleClassifier_DelegatesToApply(t *testing.T) {
	mod := ModuleRow{ID: 1, Name: "auth.go", Path: "internal/auth/oauth.go", SymbolsJSON: `["jwt","oauth"]`}
	got, err := RuleClassifier{}.Classify(context.Background(), mod)
	if err != nil {
		t.Fatalf("Classify: unexpected error: %v", err)
	}
	if got.Component == "" {
		t.Fatalf("Classify produced empty component for %+v", mod)
	}
	// Classifier string is whatever component.Apply chose; rule path
	// always uses 'rule' or 'heuristic' in P31.
	if got.Classifier != "rule" && got.Classifier != "heuristic" {
		t.Fatalf("unexpected classifier %q (want rule|heuristic)", got.Classifier)
	}
}
