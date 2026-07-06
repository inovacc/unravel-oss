/*
Copyright (c) 2026 Security Research
*/

// P58 — Citation type round-trip tests + newCitation helper tests.
//
// Decisions honored:
//   - decision 2: Citation{File, Line omitempty, Hash omitempty}
//   - decision 3: Evidence.Citation is *Citation pointer with json:"citation,omitempty"
//   - decision 5: Scorecard.CitationsOK has NO omitempty
//   - decision 6: DimScore.MissingCitations has json:"missing_citations,omitempty"
//   - decision 7: newCitation never computes fresh sha256
package scorecard

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestCitationJSONRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		c    Citation
		want string // canonical JSON form
	}{
		{"file_only", Citation{File: "evidence/x.md"}, `{"file":"evidence/x.md"}`},
		{"file_and_line", Citation{File: "evidence/x.md", Line: 42}, `{"file":"evidence/x.md","line":42}`},
		{"all_three", Citation{File: "evidence/x.md", Line: 7, Hash: "abc123"}, `{"file":"evidence/x.md","line":7,"hash":"abc123"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.c)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(b) != tc.want {
				t.Errorf("marshal = %s, want %s", b, tc.want)
			}
			var got Citation
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got != tc.c {
				t.Errorf("round-trip mismatch: %+v vs %+v", got, tc.c)
			}
		})
	}
}

func TestEvidenceJSON_OmitEmptyCitation(t *testing.T) {
	// Decision 3: Evidence with Citation=nil must not emit "citation" key —
	// preserves D-10 byte-shape for pre-P58 fixtures.
	ev := Evidence{Kind: "field", Path: "Detection"}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "citation") {
		t.Errorf("citation key leaked despite nil pointer: %s", b)
	}
}

func TestEvidenceJSON_WithCitation(t *testing.T) {
	ev := Evidence{Kind: "field", Path: "Detection", Citation: &Citation{File: "evidence/x.md", Line: 3}}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"kind":"field","path":"Detection","citation":{"file":"evidence/x.md","line":3}}`
	if string(b) != want {
		t.Errorf("marshal = %s, want %s", b, want)
	}
}

func TestScorecardJSON_CitationsOK_NoOmitempty(t *testing.T) {
	// Decision 5: CitationsOK is a gate state — must always be emitted, even
	// when false (its zero value).
	sc := Scorecard{KbID: "x", Dimensions: []DimScore{}, Coverage: 0, CitationsOK: false}
	b, err := json.Marshal(sc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"citations_ok":false`) {
		t.Errorf("citations_ok=false elided: %s", b)
	}
	sc.CitationsOK = true
	b, _ = json.Marshal(sc)
	if !strings.Contains(string(b), `"citations_ok":true`) {
		t.Errorf("citations_ok=true missing: %s", b)
	}
}

func TestDimScoreJSON_MissingCitations_Omitempty(t *testing.T) {
	// Decision 6: MissingCitations omitempty so zero-state dims stay
	// byte-identical to pre-P58.
	d := DimScore{ID: "x", Name: "X", Score: 80}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "missing_citations") {
		t.Errorf("missing_citations leaked despite zero: %s", b)
	}
	d.MissingCitations = 3
	b, _ = json.Marshal(d)
	if !strings.Contains(string(b), `"missing_citations":3`) {
		t.Errorf("missing_citations not emitted: %s", b)
	}
}

func TestNewCitation_ForwardSlashNormalization(t *testing.T) {
	// Pitfall 3: Windows path separators must be normalized to forward slashes
	// before landing in JSON.
	kb := filepath.Join(string(filepath.Separator)+"tmp", "kb")
	abs := filepath.Join(kb, "evidence", "framework.md")
	c := newCitation(kb, abs, 0)
	if c == nil {
		t.Fatalf("newCitation returned nil")
	}
	if strings.Contains(c.File, `\`) {
		t.Errorf("File contains backslash: %q", c.File)
	}
	if c.File != "evidence/framework.md" {
		t.Errorf("File = %q, want evidence/framework.md", c.File)
	}
}

func TestNewCitation_EmptyAbsPath(t *testing.T) {
	if c := newCitation("/tmp/kb", "", 0); c != nil {
		t.Errorf("expected nil for empty absPath, got %+v", c)
	}
}

func TestNewCitation_FallbackBasenameWhenNotUnderRoot(t *testing.T) {
	c := newCitation("/totally/different/root", "/var/data/evidence.md", 0)
	if c == nil {
		t.Fatalf("nil")
	}
	// Either a relative ../-prefixed path or basename — but no backslashes.
	if strings.Contains(c.File, `\`) {
		t.Errorf("backslash leaked: %q", c.File)
	}
	if c.File == "" {
		t.Errorf("empty File")
	}
}

func TestNewCitation_NegativeLineClamped(t *testing.T) {
	c := newCitation("/kb", "/kb/x.md", -1)
	if c.Line != 0 {
		t.Errorf("Line = %d, want 0", c.Line)
	}
}

// TestByteShape_Pre58FixtureRoundTrip is the D-10 byte-shape pin (decision 3).
//
// A scorecard with no Citations attached and zero MissingCitations on every
// dim must serialize byte-identically to a hand-pinned pre-P58 reference,
// EXCEPT for the always-emitted "citations_ok" field. We construct a small
// 2-dim scorecard and compare against the canonical shape.
//
// This is the contract test: P58 is byte-additive. Existing knowledge.json
// consumers see one new top-level key (citations_ok) and otherwise zero
// shape change unless citations are explicitly attached.
func TestByteShape_Pre58FixtureRoundTrip(t *testing.T) {
	sc := Scorecard{
		KbID: "kb-test",
		Dimensions: []DimScore{
			{ID: "identity", Name: "Identity", Score: 80, Evidence: []Evidence{
				{Kind: "field", Path: "Detection"},
			}},
			{ID: "wire", Name: "Wire formats", Score: 20, Evidence: []Evidence{
				{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"},
			}},
		},
		Coverage:    1,
		CitationsOK: true,
	}
	got, err := json.Marshal(sc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Canonical pre-P58 shape (Evidence keys: kind/source/path/detail; no
	// citation; no missing_citations) plus the always-emitted citations_ok.
	want := `{"kb_id":"kb-test","dimensions":[` +
		`{"id":"identity","name":"Identity","score":80,"evidence":[{"kind":"field","path":"Detection"}]},` +
		`{"id":"wire","name":"Wire formats","score":20,"evidence":[{"kind":"missing","source":"runtime","detail":"no runtime capture (P57)"}]}` +
		`],"coverage":1,"citations_ok":true}`
	if string(got) != want {
		t.Errorf("byte-shape mismatch.\n got: %s\nwant: %s", got, want)
	}

	// And confirm round-trip back into P58 types is lossless.
	var sc2 Scorecard
	if err := json.Unmarshal(got, &sc2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	b2, _ := json.Marshal(sc2)
	if string(b2) != string(got) {
		t.Errorf("round-trip not byte-identical:\n a: %s\n b: %s", got, b2)
	}
}
