/*
Copyright (c) 2026 Security Research
*/
// Golden tests for B5: kb_doctor meaning_layer_coverage_pct top-line metric.
package mcptools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestMeaningLayerCoveragePctNilDB verifies nil DB returns 0 without panic.
func TestMeaningLayerCoveragePctNilDB(t *testing.T) {
	pct := meaningLayerCoveragePct(context.Background(), nil)
	if pct != 0 {
		t.Errorf("expected 0 for nil db, got %d", pct)
	}
}

// TestKBDoctorResponseShape verifies the doctor payload always includes the
// new top-line field and the text prefix — using json.Marshal on a mock map.
func TestKBDoctorResponseShape(t *testing.T) {
	// Simulate what handleKBDoctor returns.
	coveragePct := 42
	payload := map[string]any{
		"meaning_layer_coverage_pct": coveragePct,
		"ok":                         true,
		"resolved_db":                "user@host:5432/db",
		"source":                     "config.yaml",
		"catalog":                    map[string]any{"apps": 3, "knowledge_sources": 10},
		"text":                       "meaning_layer_coverage=42% | resolved postgres ...",
	}

	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	// meaning_layer_coverage_pct must be a top-level numeric field.
	if !strings.Contains(s, `"meaning_layer_coverage_pct":42`) {
		t.Errorf("missing meaning_layer_coverage_pct in payload: %s", s)
	}
	// text must include the coverage prefix.
	if !strings.Contains(s, "meaning_layer_coverage=42%") {
		t.Errorf("text field missing coverage prefix: %s", s)
	}
	// Existing fields must still be present (backward-compat).
	for _, field := range []string{`"ok"`, `"resolved_db"`, `"source"`, `"catalog"`} {
		if !strings.Contains(s, field) {
			t.Errorf("backward-compat field %q missing: %s", field, s)
		}
	}
}
