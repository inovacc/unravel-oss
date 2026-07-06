package backfill

import "testing"

func TestIsNoisy(t *testing.T) {
	tests := []struct {
		name        string
		symbolsJSON string
		wantNoisy   bool
	}{
		// ── §2.4 verbatim noise examples ─────────────────────────────────
		{
			name:        "keyword methods — return switch",
			symbolsJSON: `{"methods":["return","switch"]}`,
			wantNoisy:   true,
		},
		{
			name:        "regex character class as log_tag",
			symbolsJSON: `{"log_tags":["A-Z"]}`,
			wantNoisy:   false, // "A-Z" is NOT in brackets → not a char class
		},
		{
			name:        "regex character class in brackets",
			symbolsJSON: `{"log_tags":["[A-Z]"]}`,
			wantNoisy:   true,
		},
		{
			name:        "regex digit class",
			symbolsJSON: `{"tags":["[0-9]"]}`,
			wantNoisy:   true,
		},
		{
			name:        "regex whitespace class",
			symbolsJSON: `{"tags":["[\\s]"]}`,
			wantNoisy:   true,
		},

		// ── empty / blank ─────────────────────────────────────────────────
		{
			name:        "empty string",
			symbolsJSON: "",
			wantNoisy:   true,
		},
		{
			name:        "whitespace only",
			symbolsJSON: "   ",
			wantNoisy:   true,
		},
		{
			name:        "null JSON",
			symbolsJSON: "null",
			wantNoisy:   true, // unmarshals to nil map → len 0
		},

		// ── all-empty arrays ──────────────────────────────────────────────
		{
			name:        "all empty arrays",
			symbolsJSON: `{"functions":[],"classes":[],"imports":[]}`,
			wantNoisy:   true,
		},

		// ── corrupt JSON ──────────────────────────────────────────────────
		{
			name:        "malformed JSON",
			symbolsJSON: `{"methods":["foo"`,
			wantNoisy:   true,
		},

		// ── clean examples — should NOT be flagged ────────────────────────
		{
			name:        "real function names",
			symbolsJSON: `{"functions":["handleMessage","encryptPayload","fetchContact"]}`,
			wantNoisy:   false,
		},
		{
			name:        "real class and imports",
			symbolsJSON: `{"classes":["MessageStore","ContactCache"],"imports":["./crypto","react"]}`,
			wantNoisy:   false,
		},
		{
			name:        "urls array is fine",
			symbolsJSON: `{"urls":["/api/messages","/api/contacts"]}`,
			wantNoisy:   false,
		},
		{
			name:        "mixed clean — one non-empty array",
			symbolsJSON: `{"functions":["doAuth"],"classes":[]}`,
			wantNoisy:   false,
		},
		{
			name:        "single keyword in imports is fine",
			symbolsJSON: `{"imports":["return-value"]}`,
			wantNoisy:   false, // imports not checked for keywords
		},

		// ── additional keyword coverage ───────────────────────────────────
		{
			name:        "multiple keywords as methods",
			symbolsJSON: `{"methods":["if","for","while"]}`,
			wantNoisy:   true,
		},
		{
			name:        "Go keyword in types",
			symbolsJSON: `{"types":["func","struct"]}`,
			wantNoisy:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsNoisy(tc.symbolsJSON)
			if got != tc.wantNoisy {
				t.Errorf("IsNoisy(%q) = %v, want %v", tc.symbolsJSON, got, tc.wantNoisy)
			}
		})
	}
}
