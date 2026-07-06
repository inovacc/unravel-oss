/*
Copyright (c) 2026 Security Research
*/
package forensic

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func sampleReport() *Report {
	return &Report{
		AppID: "demo",
		Findings: []Finding{
			{Category: "network", Title: "Plaintext HTTP", Severity: "critical"},
			{Category: "secrets", Title: "Hardcoded API key", Severity: "high"},
			{Category: "manifest", Title: "Debuggable build", Severity: "medium"},
			{Category: "telemetry", Title: "Verbose telemetry SDK", Severity: "medium"},
			{Category: "telemetry", Title: "Stealth attribution", Severity: "low"},
			{Category: "manifest", Title: "Allows backup", Severity: "low"},
			{Category: "info", Title: "App-name set", Severity: "info"},
			{Category: "alpha", Title: "Cleartext traffic", Severity: "high"},
			{Category: "beta", Title: "Exposed activity", Severity: "high"},
			{Category: "gamma", Title: "Storage permission", Severity: "medium"},
		},
	}
}

func TestBuildFindingsInput_Bounded(t *testing.T) {
	r := sampleReport()
	in := BuildFindingsInput(r)

	if got, want := in.RiskCounts["block"], 4; got != want {
		t.Errorf("block count = %d, want %d", got, want)
	}
	if got, want := in.RiskCounts["flag"], 3; got != want {
		t.Errorf("flag count = %d, want %d", got, want)
	}
	if got, want := in.RiskCounts["pass"], 3; got != want {
		t.Errorf("pass count = %d, want %d", got, want)
	}

	if len(in.TopFindings) != 5 {
		t.Fatalf("TopFindings len = %d, want 5 (D-12 cap)", len(in.TopFindings))
	}

	// All BLOCK entries should sort before any FLAG entry.
	for i := range 4 {
		if in.TopFindings[i].Severity != "BLOCK" {
			t.Errorf("TopFindings[%d].Severity = %q, want BLOCK", i, in.TopFindings[i].Severity)
		}
	}
	if in.TopFindings[4].Severity != "FLAG" {
		t.Errorf("TopFindings[4].Severity = %q, want FLAG", in.TopFindings[4].Severity)
	}

	// Tie-break: BLOCK entries must be sorted alphabetically by Type.
	wantTypes := []string{"alpha", "beta", "network", "secrets"}
	for i, want := range wantTypes {
		if got := in.TopFindings[i].Type; got != want {
			t.Errorf("TopFindings[%d].Type = %q, want %q", i, got, want)
		}
	}
}

func TestBuildFindingsInput_NilReport(t *testing.T) {
	in := BuildFindingsInput(nil)
	if in.RiskCounts["block"] != 0 || in.RiskCounts["flag"] != 0 || in.RiskCounts["pass"] != 0 {
		t.Errorf("nil report should yield zeroed counts, got %+v", in.RiskCounts)
	}
	if len(in.TopFindings) != 0 {
		t.Errorf("nil report should yield empty TopFindings, got %d", len(in.TopFindings))
	}
}

func TestBuildPrompt_HasSentinels(t *testing.T) {
	body, err := BuildPrompt(sampleReport())
	if err != nil {
		t.Fatalf("BuildPrompt: %v", err)
	}
	if !strings.Contains(body, UserFindingsBegin) {
		t.Error("missing USER_FINDINGS_BEGIN sentinel in rendered prompt")
	}
	if !strings.Contains(body, UserFindingsEnd) {
		t.Error("missing USER_FINDINGS_END sentinel in rendered prompt")
	}
	if !strings.Contains(body, `"risk_counts"`) {
		t.Error("rendered prompt missing risk_counts payload")
	}
	// Findings JSON must appear *between* the data sentinels — note the
	// sentinel literals appear twice: once in the prompt's instructions
	// section (describing them) and once around the actual data. We want
	// the LAST occurrence, which is the data delimiter.
	begin := strings.LastIndex(body, UserFindingsBegin)
	end := strings.LastIndex(body, UserFindingsEnd)
	if begin < 0 || end < 0 || end <= begin {
		t.Fatalf("sentinels malformed: begin=%d end=%d", begin, end)
	}
	inner := body[begin:end]
	if !strings.Contains(inner, `"top_findings"`) {
		t.Error("findings JSON not bracketed between sentinels")
	}
}

func TestParseMCPResponse_Valid(t *testing.T) {
	original := ExecSummary{
		TLDR: "Three high-severity findings dominate risk posture.",
		TopRisks: []TopRisk{
			{Title: "Plaintext HTTP", Severity: "BLOCK", CWE: 319},
			{Title: "Hardcoded API key", Severity: "BLOCK", CWE: 798},
		},
		RemediationPriorities: []string{
			"Enforce TLS for all endpoints",
			"Remove hardcoded credentials and rotate keys",
		},
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}
	got, err := ParseMCPResponse(raw)
	if err != nil {
		t.Fatalf("ParseMCPResponse: %v", err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", got, original)
	}
}

func TestParseMCPResponse_Malformed(t *testing.T) {
	if _, err := ParseMCPResponse([]byte("{not valid json")); err == nil {
		t.Error("expected error on malformed JSON")
	}
	if _, err := ParseMCPResponse(nil); err == nil {
		t.Error("expected error on nil input")
	}
}

func TestParseMCPResponse_Truncates(t *testing.T) {
	oversize := ExecSummary{
		TopRisks: []TopRisk{
			{Title: "1", Severity: "BLOCK"},
			{Title: "2", Severity: "BLOCK"},
			{Title: "3", Severity: "BLOCK"},
			{Title: "4", Severity: "BLOCK"},
			{Title: "5", Severity: "BLOCK"},
			{Title: "6", Severity: "FLAG"},
			{Title: "7", Severity: "FLAG"},
		},
		RemediationPriorities: []string{"a", "b", "c", "d", "e", "f", "g"},
	}
	raw, _ := json.Marshal(oversize)
	got, err := ParseMCPResponse(raw)
	if err != nil {
		t.Fatalf("ParseMCPResponse: %v", err)
	}
	if len(got.TopRisks) != 5 {
		t.Errorf("TopRisks len = %d, want 5 (D-14 cap)", len(got.TopRisks))
	}
	if len(got.RemediationPriorities) != 5 {
		t.Errorf("RemediationPriorities len = %d, want 5 (D-14 cap)", len(got.RemediationPriorities))
	}
}

func TestComputeCacheKey_Deterministic(t *testing.T) {
	findings := []byte(`{"risk_counts":{"block":1}}`)
	k1 := ComputeCacheKey(findings, "claude-sonnet-4")
	k2 := ComputeCacheKey(findings, "claude-sonnet-4")
	if k1 != k2 {
		t.Errorf("cache key not deterministic: %s vs %s", k1, k2)
	}
	if len(k1) != 64 {
		t.Errorf("cache key length = %d, want 64 (sha256 hex)", len(k1))
	}
	// Different model → different key (D-26 model-id discrimination).
	k3 := ComputeCacheKey(findings, "claude-opus-4")
	if k1 == k3 {
		t.Errorf("cache key should differ between models, got identical: %s", k1)
	}
	// Different findings → different key.
	k4 := ComputeCacheKey([]byte(`{"risk_counts":{"block":2}}`), "claude-sonnet-4")
	if k1 == k4 {
		t.Errorf("cache key should differ between findings, got identical: %s", k1)
	}
}

func TestCacheLookupStore_RoundTrip(t *testing.T) {
	// store.CacheDir() reads LOCALAPPDATA on Windows (and falls back to
	// $HOME/.local/share otherwise). Setting both keeps the test portable.
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	want := ExecSummary{
		TLDR:                  "Cached summary content.",
		TopRisks:              []TopRisk{{Title: "Risk A", Severity: "BLOCK", CWE: 319}},
		RemediationPriorities: []string{"Mitigate Risk A"},
	}
	key := ComputeCacheKey([]byte("findings-fixture"), "test-model")

	if _, ok := CacheLookup(key); ok {
		t.Fatal("unexpected pre-existing cache entry")
	}
	if err := CacheStore(key, want); err != nil {
		t.Fatalf("CacheStore: %v", err)
	}
	got, ok := CacheLookup(key)
	if !ok {
		t.Fatal("CacheLookup miss after CacheStore")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}
