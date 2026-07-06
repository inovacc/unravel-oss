/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper: write a temp JSON file and return its path.
func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// helper: build a SessionResult with the given event lines.
func makeCapture(events []string) map[string]any {
	return map[string]any{
		"package_name": "com.example.app",
		"scripts": []map[string]any{
			{
				"script_name": "test",
				"output":      events,
				"errors":      []string{},
			},
		},
	}
}

func TestValidate_SyntheticFixtures(t *testing.T) {
	report, err := Validate("testdata/synthetic_criteria.json", "testdata/synthetic_capture.json")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if report.Summary.Total == 0 {
		t.Fatalf("expected >0 findings")
	}
	if report.Summary.Block == 0 {
		t.Fatalf("expected at least one BLOCK (absent.hook.never_fires)")
	}
}

func TestEqualsOperator(t *testing.T) {
	dir := t.TempDir()
	cap := makeCapture([]string{
		`[FRIDA-EVENT] {"v":1,"ts":"t","hook_id":"h1","phase":"enter","args":["yes"]}`,
	})
	cp := writeJSON(t, dir, "cap.json", cap)
	tests := []struct {
		name string
		val  string
		want string
	}{
		{"match", "yes", SeverityPass},
		{"mismatch", "no", SeverityFlag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crit := map[string]any{
				"version": 1,
				"script":  "s",
				"hooks": map[string]any{
					"h1": map[string]any{
						"criteria": []map[string]any{
							{"op": "equals", "target": "args[0]", "value": tt.val},
						},
					},
				},
			}
			cf := writeJSON(t, dir, "cri_"+tt.name+".json", crit)
			r, err := Validate(cf, cp)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if r.Findings[0].Severity != tt.want {
				t.Errorf("severity = %s, want %s (msg=%s)", r.Findings[0].Severity, tt.want, r.Findings[0].Message)
			}
		})
	}
}

func TestPresentOperator(t *testing.T) {
	dir := t.TempDir()
	cap := makeCapture([]string{
		`[FRIDA-EVENT] {"v":1,"hook_id":"h1","phase":"enter","args":["abc"]}`,
		`[FRIDA-EVENT] {"v":1,"hook_id":"h2","phase":"enter","args":[""]}`,
	})
	cp := writeJSON(t, dir, "cap.json", cap)
	crit := map[string]any{
		"version": 1, "script": "s",
		"hooks": map[string]any{
			"h1": map[string]any{"criteria": []map[string]any{{"op": "present", "target": "args[0]"}}},
			"h2": map[string]any{"criteria": []map[string]any{{"op": "present", "target": "args[0]"}}},
		},
	}
	cf := writeJSON(t, dir, "cri.json", crit)
	r, err := Validate(cf, cp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// h1 PASS, h2 FLAG (empty string)
	var h1, h2 Finding
	for _, f := range r.Findings {
		switch f.HookID {
		case "h1":
			h1 = f
		case "h2":
			h2 = f
		}
	}
	if h1.Severity != SeverityPass {
		t.Errorf("h1 severity = %s, want PASS", h1.Severity)
	}
	if h2.Severity != SeverityFlag {
		t.Errorf("h2 severity = %s, want FLAG", h2.Severity)
	}
}

func TestInRangeOperator(t *testing.T) {
	dir := t.TempDir()
	cap := makeCapture([]string{
		`[FRIDA-EVENT] {"v":1,"hook_id":"h1","phase":"enter","ret":42}`,
		`[FRIDA-EVENT] {"v":1,"hook_id":"h2","phase":"enter","ret":999}`,
	})
	cp := writeJSON(t, dir, "cap.json", cap)
	crit := map[string]any{
		"version": 1, "script": "s",
		"hooks": map[string]any{
			"h1": map[string]any{"criteria": []map[string]any{{"op": "in-range", "target": "ret", "min": 0, "max": 100}}},
			"h2": map[string]any{"criteria": []map[string]any{{"op": "in-range", "target": "ret", "min": 0, "max": 100}}},
		},
	}
	cf := writeJSON(t, dir, "cri.json", crit)
	r, err := Validate(cf, cp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for _, f := range r.Findings {
		if f.HookID == "h1" && f.Severity != SeverityPass {
			t.Errorf("h1 want PASS, got %s", f.Severity)
		}
		if f.HookID == "h2" && f.Severity != SeverityFlag {
			t.Errorf("h2 want FLAG, got %s", f.Severity)
		}
	}
}

func TestRegexOperator(t *testing.T) {
	dir := t.TempDir()
	cap := makeCapture([]string{
		`[FRIDA-EVENT] {"v":1,"hook_id":"h1","phase":"enter","args":["hello-world"]}`,
		`[FRIDA-EVENT] {"v":1,"hook_id":"h2","phase":"enter","args":["BADCHARS!@#"]}`,
	})
	cp := writeJSON(t, dir, "cap.json", cap)
	crit := map[string]any{
		"version": 1, "script": "s",
		"hooks": map[string]any{
			"h1": map[string]any{"criteria": []map[string]any{{"op": "regex", "target": "args[0]", "pattern": "^[a-z-]+$"}}},
			"h2": map[string]any{"criteria": []map[string]any{{"op": "regex", "target": "args[0]", "pattern": "^[a-z-]+$"}}},
		},
	}
	cf := writeJSON(t, dir, "cri.json", crit)
	r, err := Validate(cf, cp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for _, f := range r.Findings {
		if f.HookID == "h1" && f.Severity != SeverityPass {
			t.Errorf("h1 want PASS, got %s", f.Severity)
		}
		if f.HookID == "h2" && f.Severity != SeverityFlag {
			t.Errorf("h2 want FLAG, got %s", f.Severity)
		}
	}
}

func TestRegexInvalidPattern(t *testing.T) {
	dir := t.TempDir()
	cap := makeCapture([]string{`[FRIDA-EVENT] {"v":1,"hook_id":"h1","phase":"enter","args":["x"]}`})
	cp := writeJSON(t, dir, "cap.json", cap)
	crit := map[string]any{
		"version": 1, "script": "s",
		"hooks": map[string]any{
			"h1": map[string]any{"criteria": []map[string]any{{"op": "regex", "target": "args[0]", "pattern": "[invalid("}}},
		},
	}
	cf := writeJSON(t, dir, "cri.json", crit)
	// MUST not panic — Pitfall 4.
	r, err := Validate(cf, cp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if r.Findings[0].Severity != SeverityFlag {
		t.Errorf("invalid regex want FLAG, got %s", r.Findings[0].Severity)
	}
}

func TestFrequencyCountOperator(t *testing.T) {
	dir := t.TempDir()
	cap := makeCapture([]string{
		`[FRIDA-EVENT] {"v":1,"hook_id":"hot","phase":"enter"}`,
		`[FRIDA-EVENT] {"v":1,"hook_id":"hot","phase":"enter"}`,
		`[FRIDA-EVENT] {"v":1,"hook_id":"hot","phase":"enter"}`,
	})
	cp := writeJSON(t, dir, "cap.json", cap)
	tests := []struct {
		name     string
		min, max float64
		hook     string
		want     string
	}{
		{"in-range", 1, 5, "hot", SeverityPass},
		{"too-many", 1, 2, "hot", SeverityFlag},
		{"never-fired", 1, 5, "cold", SeverityBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crit := map[string]any{
				"version": 1, "script": "s",
				"hooks": map[string]any{
					tt.hook: map[string]any{"criteria": []map[string]any{
						{"op": "frequency-count", "hook_id": tt.hook, "min": tt.min, "max": tt.max},
					}},
				},
			}
			cf := writeJSON(t, dir, "cri_"+tt.name+".json", crit)
			r, err := Validate(cf, cp)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if r.Findings[0].Severity != tt.want {
				t.Errorf("severity = %s, want %s (msg=%s)", r.Findings[0].Severity, tt.want, r.Findings[0].Message)
			}
		})
	}
}

func TestSeverityAggregation(t *testing.T) {
	r, err := Validate("testdata/synthetic_criteria.json", "testdata/synthetic_capture.json")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if r.Summary.Total != r.Summary.Block+r.Summary.Flag+r.Summary.Pass {
		t.Errorf("severity counts must sum to total: %+v", r.Summary)
	}
}

func TestStrictJSONDecoder_UnknownFields(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version":1,"script":"s","hooks":{},"unknown_field":42}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cap := makeCapture([]string{})
	cp := writeJSON(t, dir, "cap.json", cap)
	if _, err := Validate(bad, cp); err == nil {
		t.Errorf("expected error for unknown fields, got nil")
	}
}

func TestStrictJSONDecoder_OversizeRejected(t *testing.T) {
	dir := t.TempDir()
	huge := filepath.Join(dir, "huge.json")
	// 1 MiB + slop of valid JSON wrapping.
	pad := strings.Repeat("a", maxJSONBytes+10)
	body := `{"version":1,"script":"` + pad + `","hooks":{}}`
	if err := os.WriteFile(huge, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cap := makeCapture([]string{})
	cp := writeJSON(t, dir, "cap.json", cap)
	if _, err := Validate(huge, cp); err == nil {
		t.Errorf("expected size-cap rejection, got nil")
	}
}

func TestPathTraversalRejected(t *testing.T) {
	if _, err := Validate("../../etc/passwd", "../../etc/passwd"); err == nil {
		t.Errorf("expected traversal rejection, got nil")
	}
}

func TestMissingHook_Block(t *testing.T) {
	dir := t.TempDir()
	cap := makeCapture([]string{}) // no events at all
	cp := writeJSON(t, dir, "cap.json", cap)
	crit := map[string]any{
		"version": 1, "script": "s",
		"hooks": map[string]any{
			"h1": map[string]any{"criteria": []map[string]any{
				{"op": "frequency-count", "hook_id": "h1", "min": 1, "max": 10},
			}},
		},
	}
	cf := writeJSON(t, dir, "cri.json", crit)
	r, err := Validate(cf, cp)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if r.Findings[0].Severity != SeverityBlock {
		t.Errorf("missing hook want BLOCK, got %s", r.Findings[0].Severity)
	}
}

func TestNoEmojis_InRenderedMarkdown(t *testing.T) {
	r, err := Validate("testdata/synthetic_criteria.json", "testdata/synthetic_capture.json")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	md := RenderMarkdown(r)
	for _, ru := range md {
		if ru > 0x1F000 {
			t.Errorf("found emoji rune %U in rendered markdown", ru)
		}
	}
	// Ensure required text-only badge is present.
	if !strings.Contains(md, "**[BLOCK]**") {
		t.Errorf("missing BLOCK badge in rendered markdown")
	}
}
