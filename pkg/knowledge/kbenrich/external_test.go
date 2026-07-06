/*
Copyright (c) 2026 Security Research
*/

package kbenrich

import (
	"encoding/json"
	"testing"
)

// TestNormalizeArrayOfObjects covers the schema-drift normaliser used by
// WriteEnrichmentJSON. Subagent output observed during the 50-module scale
// test sometimes emitted inputs/outputs as ["string","string"] instead of
// [{name,type,...}] objects; normalise() must collapse those to [].
func TestNormalizeArrayOfObjects(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", ``, `[]`},
		{"empty array", `[]`, `[]`},
		{"string array drift", `["context","args"]`, `[]`},
		{"mixed", `["bad",{"name":"good","type":"string"}]`, `[{"name":"good","type":"string"}]`},
		{"all objects", `[{"name":"a","type":"int"},{"name":"b","type":"str"}]`, `[{"name":"a","type":"int"},{"name":"b","type":"str"}]`},
		{"malformed", `not json`, `[]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeArrayOfObjects(json.RawMessage(tc.in))
			if string(got) != tc.want {
				t.Errorf("normalizeArrayOfObjects(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestValidRolesContract locks the role enum so future expansions are
// deliberate. Mirrors the contract the unravel-enricher subagent
// frontmatter promises to callers.
func TestValidRolesContract(t *testing.T) {
	required := []string{
		"send", "receive", "auth", "pair", "storage", "sync",
		"protocol", "crypto", "media", "presence", "call",
		"ui", "telemetry", "util", "other", "vendored-library",
	}
	for _, r := range required {
		if !validRoles[r] {
			t.Errorf("validRoles missing required member %q", r)
		}
	}
	if validRoles["bogus"] {
		t.Error("validRoles accepts unknown 'bogus' role")
	}
}
