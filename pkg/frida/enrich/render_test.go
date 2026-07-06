// Copyright (c) 2026 Security Research
package enrich

import (
	"strings"
	"testing"
)

func TestRenderArtifacts_BuildsHeaderAndJSDoc(t *testing.T) {
	resp := newStubResp()
	body, criteria, err := renderArtifacts(sampleScript, resp, "ssl.frida.js")
	if err != nil {
		t.Fatalf("renderArtifacts: %v", err)
	}
	if !strings.Contains(body, "[unravel-enriched header]") {
		t.Errorf("missing header marker")
	}
	if !strings.Contains(body, "Hook: sslHook") {
		t.Errorf("missing per-hook JSDoc")
	}
	if criteria.SchemaVersion != 1 {
		t.Errorf("schema_version=%d want 1", criteria.SchemaVersion)
	}
	if criteria.Script != "ssl.frida.js" {
		t.Errorf("script basename mismatch: %q", criteria.Script)
	}
	if len(criteria.Hooks) != 1 || criteria.Hooks[0].ID != "sslHook" {
		t.Errorf("hooks shape unexpected: %+v", criteria.Hooks)
	}
	// args[0] present + return present should produce 2 criteria.
	if got := len(criteria.Hooks[0].Criteria); got != 2 {
		t.Errorf("expected 2 criteria, got %d", got)
	}
}

func TestRenderArtifacts_StripJSDocBreakers(t *testing.T) {
	resp := newStubResp()
	resp.Hooks[0].Summary = "evil */ break"
	body, _, err := renderArtifacts(sampleScript, resp, "ssl.frida.js")
	if err != nil {
		t.Fatalf("renderArtifacts: %v", err)
	}
	// `*/` must be neutered in JSDoc prose so it cannot terminate the block.
	if strings.Contains(body, "evil */ break") {
		t.Errorf("renderer failed to strip raw `*/` from JSDoc prose")
	}
}

func TestRenderArtifacts_IdempotentOnReRun(t *testing.T) {
	resp := newStubResp()
	first, _, _ := renderArtifacts(sampleScript, resp, "ssl.frida.js")
	second, _, _ := renderArtifacts(first, resp, "ssl.frida.js")
	// Header marker should appear at most once.
	if got := strings.Count(second, enrichHeaderMarker); got != 1 {
		t.Errorf("expected exactly one header on re-run, got %d", got)
	}
}
