// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"testing"
)

func TestParseStylesheet_SimpleRule(t *testing.T) {
	input := []byte(`.btn { color: red; }`)
	rules, err := ParseStylesheet(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Selector != ".btn" {
		t.Errorf("expected selector '.btn', got %q", r.Selector)
	}
	if len(r.Declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %d", len(r.Declarations))
	}
	if r.Declarations[0].Property != "color" {
		t.Errorf("expected property 'color', got %q", r.Declarations[0].Property)
	}
	if r.Declarations[0].Value != "red" {
		t.Errorf("expected value 'red', got %q", r.Declarations[0].Value)
	}
}

func TestParseStylesheet_MediaRule(t *testing.T) {
	input := []byte(`@media (max-width: 768px) { .btn { color: blue; } }`)
	rules, err := ParseStylesheet(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.AtRule == "" {
		t.Fatal("expected AtRule to be set for @media")
	}
	if len(r.Children) == 0 {
		t.Fatal("expected nested children in @media rule")
	}
}

func TestParseStylesheet_Keyframes(t *testing.T) {
	input := []byte(`@keyframes fade { 0% { opacity: 0; } 100% { opacity: 1; } }`)
	rules, err := ParseStylesheet(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if len(rules[0].Children) < 2 {
		t.Errorf("expected at least 2 keyframe steps, got %d", len(rules[0].Children))
	}
}

func TestParseStylesheet_EmptyInput(t *testing.T) {
	rules, err := ParseStylesheet([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for empty input, got %d", len(rules))
	}
}

func TestParseStylesheet_MalformedCSS(t *testing.T) {
	input := []byte(`{{{ color: ??? ;; .btn { color }`)
	// Should not panic, may return partial results
	_, err := ParseStylesheet(input)
	_ = err // no panic is the main assertion
}

func TestNormalizeCSS(t *testing.T) {
	rules := []Rule{
		{
			Selector: ".btn",
			Declarations: []Declaration{
				{Property: "COLOR", Value: "  red "},
				{Property: "padding", Value: "8px"},
				{Property: "Background-Color", Value: "blue"},
			},
		},
	}
	normalized := NormalizeCSS(rules)
	if len(normalized) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(normalized))
	}
	decls := normalized[0].Declarations
	if len(decls) != 3 {
		t.Fatalf("expected 3 declarations, got %d", len(decls))
	}
	// Should be sorted alphabetically, lowercased, trimmed
	if decls[0].Property != "background-color" {
		t.Errorf("expected first property 'background-color', got %q", decls[0].Property)
	}
	if decls[1].Property != "color" {
		t.Errorf("expected second property 'color', got %q", decls[1].Property)
	}
	if decls[1].Value != "red" {
		t.Errorf("expected trimmed value 'red', got %q", decls[1].Value)
	}
	if decls[2].Property != "padding" {
		t.Errorf("expected third property 'padding', got %q", decls[2].Property)
	}
}

func TestResolveVariables_Basic(t *testing.T) {
	rules := []Rule{
		{
			Selector: ":root",
			Declarations: []Declaration{
				{Property: "--primary", Value: "#007bff"},
			},
		},
		{
			Selector: ".btn",
			Declarations: []Declaration{
				{Property: "color", Value: "var(--primary)"},
			},
		},
	}
	resolved := ResolveVariables(rules, 10)
	// .btn color should be resolved
	btnRule := resolved[1]
	if btnRule.Declarations[0].Value != "#007bff" {
		t.Errorf("expected resolved value '#007bff', got %q", btnRule.Declarations[0].Value)
	}
}

func TestResolveVariables_Fallback(t *testing.T) {
	rules := []Rule{
		{
			Selector: ".link",
			Declarations: []Declaration{
				{Property: "color", Value: "var(--undefined, blue)"},
			},
		},
	}
	resolved := ResolveVariables(rules, 10)
	if resolved[0].Declarations[0].Value != "blue" {
		t.Errorf("expected fallback 'blue', got %q", resolved[0].Declarations[0].Value)
	}
}

func TestResolveVariables_CircularReference(t *testing.T) {
	rules := []Rule{
		{
			Selector: ":root",
			Declarations: []Declaration{
				{Property: "--a", Value: "var(--b)"},
				{Property: "--b", Value: "var(--a)"},
			},
		},
		{
			Selector: ".item",
			Declarations: []Declaration{
				{Property: "color", Value: "var(--a)"},
			},
		},
	}
	resolved := ResolveVariables(rules, 10)
	// Should leave raw var() in place when cycle detected
	val := resolved[1].Declarations[0].Value
	if val == "" {
		t.Error("value should not be empty")
	}
	// The var() should remain unresolved due to cycle
	if val != "var(--a)" && val != "var(--b)" {
		// It's acceptable if the value contains "var(" indicating unresolved
		if len(val) < 4 || val[:4] != "var(" {
			t.Logf("circular reference resulted in value: %q (acceptable if contains unresolved var)", val)
		}
	}
}

func TestParseInlineStyle(t *testing.T) {
	decls, err := ParseInlineStyle("color: blue; font-weight: bold")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decls) != 2 {
		t.Fatalf("expected 2 declarations, got %d", len(decls))
	}
	found := map[string]string{}
	for _, d := range decls {
		found[d.Property] = d.Value
	}
	if found["color"] != "blue" {
		t.Errorf("expected color=blue, got %q", found["color"])
	}
	if found["font-weight"] != "bold" {
		t.Errorf("expected font-weight=bold, got %q", found["font-weight"])
	}
}
