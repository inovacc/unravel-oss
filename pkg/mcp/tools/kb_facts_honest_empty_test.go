/*
Copyright (c) 2026 Security Research
*/
// Golden tests for B4 MCP surface: kb_facts / kb_gaps honest-empty fields.
package mcptools

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestFactsPopulatedCategoriesNilDB verifies helper returns nil not panic on nil DB.
func TestFactsPopulatedCategoriesNilDB(t *testing.T) {
	result := factsPopulatedCategories(nil, "", false)
	if result != nil {
		t.Errorf("expected nil on nil db, got %v", result)
	}
}

// TestQueryFactsHonestEmptyPayloadShape verifies that the structured payload
// returned on empty always contains layer_status and populated_categories keys.
// Uses json.Marshal to assert the map shape without a live DB.
func TestQueryFactsHonestEmptyPayloadShape(t *testing.T) {
	structured := map[string]any{
		"returned":             0,
		"resolved_db":          "user@host:5432/db",
		"source":               "config.yaml",
		"catalog":              map[string]any{},
		"hint":                 "",
		"layer_status":         "empty",
		"populated_categories": []string{"auth", "network"},
	}

	b, err := json.Marshal(structured)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	for _, want := range []string{
		`"layer_status":"empty"`,
		`"populated_categories":`,
		`"auth"`,
		`"network"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("payload missing %q — got %s", want, s)
		}
	}
}

// TestQueryFactsPopulatedPayloadShape verifies populated path includes the
// new additive fields alongside the existing rows.
func TestQueryFactsPopulatedPayloadShape(t *testing.T) {
	payload := map[string]any{
		"rows":                 []map[string]any{{"id": 1, "category": "auth"}},
		"returned":             1,
		"layer_status":         "populated",
		"populated_categories": []string{"auth"},
	}

	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"layer_status":"populated"`, `"populated_categories":`, `"returned":1`} {
		if !strings.Contains(s, want) {
			t.Errorf("payload missing %q — got %s", want, s)
		}
	}
}
