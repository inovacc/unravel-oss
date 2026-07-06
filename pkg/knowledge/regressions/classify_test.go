/*
Copyright (c) 2026 Security Research
*/
package regressions

import (
	"context"
	"testing"
)

func TestClassifyAttachesSeverity(t *testing.T) {
	snap := Snapshot{
		SecurityConfig: &SecurityConfig{
			CSPAdditions: []string{"'unsafe-inline'"},
		},
	}
	got := Classify(snap, DefaultRules())
	var found bool
	for _, r := range got {
		if r.RuleID == "csp-unsafe-inline-added" {
			found = true
			if r.Severity != SeverityBlock {
				t.Errorf("severity=%q want BLOCK", r.Severity)
			}
			if r.Source != SourceHardcoded {
				t.Errorf("source=%q want hardcoded", r.Source)
			}
		}
	}
	if !found {
		t.Fatalf("expected csp-unsafe-inline-added regression, got %+v", got)
	}
}

func TestClassifyDangerousPermission(t *testing.T) {
	snap := Snapshot{
		Permissions: &Permissions{
			AndroidAdded: []AndroidPermission{
				{Name: "INTERNET", Dangerous: false},
				{Name: "READ_SMS", Dangerous: true},
			},
		},
	}
	got := Classify(snap, DefaultRules())
	var found bool
	for _, r := range got {
		if r.RuleID == "dangerous-permission-added" {
			found = true
			if r.Severity != SeverityBlock {
				t.Errorf("severity=%q want BLOCK", r.Severity)
			}
			if len(r.Evidence) != 1 || r.Evidence[0] != "READ_SMS" {
				t.Errorf("evidence=%v want [READ_SMS]", r.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected dangerous-permission-added")
	}
}

func TestClassifySandboxRemoved(t *testing.T) {
	snap := Snapshot{
		SecurityConfig: &SecurityConfig{
			WebPrefsChanged: map[string]ValueChange{
				"sandbox": {Old: true, New: false},
			},
		},
	}
	got := Classify(snap, DefaultRules())
	var found bool
	for _, r := range got {
		if r.RuleID == "sandbox-flag-removed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected sandbox-flag-removed; got %+v", got)
	}
}

func TestClassifyTelemetryGrew(t *testing.T) {
	snap := Snapshot{
		Structural: &Structural{
			TelemetryCountOld: 1,
			TelemetryCountNew: 2,
			TelemetryAdded:    []string{"sentry"},
		},
	}
	got := Classify(snap, DefaultRules())
	var found bool
	for _, r := range got {
		if r.RuleID == "telemetry-sdk-added" {
			found = true
			if r.Severity != SeverityFlag {
				t.Errorf("severity=%q want FLAG", r.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected telemetry-sdk-added FLAG")
	}
}

func TestClassifyEmptySnapshotNoRegressions(t *testing.T) {
	snap := Snapshot{}
	got := Classify(snap, DefaultRules())
	if len(got) != 0 {
		t.Fatalf("expected zero regressions, got %d", len(got))
	}
}

func TestAIHookSkippedWhenDisabled(t *testing.T) {
	snap := Snapshot{}
	out := AISecondOpinion(context.Background(), snap, nil, nil)
	if out != nil {
		t.Fatalf("expected nil when mcp client is nil, got %v", out)
	}
}

type stubMCP struct {
	called bool
}

func (s *stubMCP) Classify(_ context.Context, _ []byte) ([]Regression, error) {
	s.called = true
	return []Regression{{RuleID: "ai-suggested", Dimension: DimText, Severity: SeverityFlag, Message: "ai noticed"}}, nil
}

func TestAIHookTagsSourceAI(t *testing.T) {
	mcp := &stubMCP{}
	out := AISecondOpinion(context.Background(), Snapshot{}, nil, mcp)
	if !mcp.called {
		t.Fatal("mcp not invoked")
	}
	if len(out) != 1 || out[0].Source != SourceAI {
		t.Fatalf("expected ai-tagged regression, got %+v", out)
	}
}
