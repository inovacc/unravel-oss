/*
Copyright (c) 2026 Security Research
*/

package ingest

import (
	"strings"
	"testing"
)

func factsByCategory(rows []FactRow, cat string) []FactRow {
	var out []FactRow
	for _, r := range rows {
		if r.Category == cat {
			out = append(out, r)
		}
	}
	return out
}

func TestExtractFacts_DepsCapsURLs(t *testing.T) {
	in := map[string]any{
		"framework": "electron",
		"dependencies": []any{
			map[string]any{"name": "react", "version": "18.2.0"},
			map[string]any{"name": "lodash", "version": "4.17.21"},
			"axios",
		},
		"uwp_analyze": map[string]any{
			"capabilities": []any{
				map[string]any{"namespace": "rescap", "name": "runFullTrust"},
				map[string]any{"name": "internetClient"},
			},
		},
		"urls": []any{
			"https://api.example.com/v1/users",
		},
	}
	rows := ExtractFacts(in, "myapp")

	if got := len(factsByCategory(rows, "dep")); got != 3 {
		t.Errorf("dep count: got=%d want=3", got)
	}
	if got := len(factsByCategory(rows, "capability")); got != 2 {
		t.Errorf("capability count: got=%d want=2", got)
	}
	if got := len(factsByCategory(rows, "url")); got != 1 {
		t.Errorf("url count: got=%d want=1", got)
	}
	// url key should be the host
	urlRows := factsByCategory(rows, "url")
	if len(urlRows) > 0 && urlRows[0].Key != "api.example.com" {
		t.Errorf("url key: got=%q want=api.example.com", urlRows[0].Key)
	}
}

func TestExtractFacts_FrameworkRow(t *testing.T) {
	in := map[string]any{"framework": "tauri"}
	rows := ExtractFacts(in, "myapp")
	fw := factsByCategory(rows, "framework")
	if len(fw) != 1 {
		t.Fatalf("framework count: got=%d want=1", len(fw))
	}
	if fw[0].Value != "tauri" {
		t.Errorf("framework value: got=%q want=tauri", fw[0].Value)
	}
}

func TestExtractFacts_RiskEmittedWhenScored(t *testing.T) {
	in := map[string]any{
		"uwp_analyze": map[string]any{
			"score": map[string]any{"value": 72, "level": "high"},
		},
	}
	rows := ExtractFacts(in, "myapp")
	risk := factsByCategory(rows, "risk")
	if len(risk) != 1 {
		t.Fatalf("risk count: got=%d want=1", len(risk))
	}
	if !strings.Contains(risk[0].Value, "72") {
		t.Errorf("risk value: got=%q want substring 72", risk[0].Value)
	}
}

func TestExtractFacts_NoRiskWhenAbsent(t *testing.T) {
	in := map[string]any{"framework": "tauri"}
	rows := ExtractFacts(in, "myapp")
	if got := len(factsByCategory(rows, "risk")); got != 0 {
		t.Errorf("risk count: got=%d want=0 (CanonicalizeRisk returned nil score)", got)
	}
}

func TestExtractFacts_NilSafe(t *testing.T) {
	if rows := ExtractFacts(nil, "myapp"); rows != nil {
		t.Errorf("nil knowledge.json → got=%v want=nil", rows)
	}
	if rows := ExtractFacts(map[string]any{}, ""); rows != nil {
		t.Errorf("empty app → got=%v want=nil", rows)
	}
}

func TestExtractFacts_AuthProviders(t *testing.T) {
	in := map[string]any{
		"auth": map[string]any{
			"providers": []any{"oauth2", "saml"},
		},
	}
	rows := ExtractFacts(in, "myapp")
	if got := len(factsByCategory(rows, "auth")); got != 2 {
		t.Errorf("auth count: got=%d want=2", got)
	}
}

func TestExtractFacts_CertFingerprint(t *testing.T) {
	in := map[string]any{
		"certificates": []any{
			map[string]any{
				"fingerprint": "abcdef0123456789aaaabbbbccccdddd",
				"subject":     "CN=Example",
			},
		},
	}
	rows := ExtractFacts(in, "myapp")
	cert := factsByCategory(rows, "cert")
	if len(cert) != 1 {
		t.Fatalf("cert count: got=%d want=1", len(cert))
	}
}
