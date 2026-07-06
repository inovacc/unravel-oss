// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindUnusedRules_UsedClass(t *testing.T) {
	rules := []Rule{
		{Selector: ".btn", Declarations: []Declaration{{Property: "color", Value: "red"}}},
	}
	htmlFile := writeTestHTML(t, `<button class="btn">Click</button>`)
	defer os.Remove(htmlFile)

	used, unused, err := FindUnusedRules(rules, []string{htmlFile})
	if err != nil {
		t.Fatal(err)
	}
	if len(used) != 1 {
		t.Errorf("expected 1 used rule, got %d", len(used))
	}
	if len(unused) != 0 {
		t.Errorf("expected 0 unused rules, got %d", len(unused))
	}
}

func TestFindUnusedRules_UnusedClass(t *testing.T) {
	rules := []Rule{
		{Selector: ".unused-class", Declarations: []Declaration{{Property: "color", Value: "red"}}},
	}
	htmlFile := writeTestHTML(t, `<div class="other">Content</div>`)
	defer os.Remove(htmlFile)

	used, unused, err := FindUnusedRules(rules, []string{htmlFile})
	if err != nil {
		t.Fatal(err)
	}
	if len(used) != 0 {
		t.Errorf("expected 0 used rules, got %d", len(used))
	}
	if len(unused) != 1 {
		t.Errorf("expected 1 unused rule, got %d", len(unused))
	}
}

func TestFindUnusedRules_ElementSelectors(t *testing.T) {
	rules := []Rule{
		{Selector: "div", Declarations: []Declaration{{Property: "margin", Value: "0"}}},
		{Selector: "p", Declarations: []Declaration{{Property: "color", Value: "black"}}},
		{Selector: "h1", Declarations: []Declaration{{Property: "font-size", Value: "2em"}}},
	}
	htmlFile := writeTestHTML(t, `<span>Hello</span>`)
	defer os.Remove(htmlFile)

	used, unused, err := FindUnusedRules(rules, []string{htmlFile})
	if err != nil {
		t.Fatal(err)
	}
	// Element selectors are always considered used (conservative)
	if len(used) != 3 {
		t.Errorf("expected 3 used rules (element selectors always used), got %d used, %d unused", len(used), len(unused))
	}
}

func TestFindUnusedRules_PseudoSelectors(t *testing.T) {
	rules := []Rule{
		{Selector: ".btn:hover", Declarations: []Declaration{{Property: "color", Value: "blue"}}},
		{Selector: ".btn::before", Declarations: []Declaration{{Property: "content", Value: "''"}}},
	}
	htmlFile := writeTestHTML(t, `<button class="btn">Click</button>`)
	defer os.Remove(htmlFile)

	used, unused, err := FindUnusedRules(rules, []string{htmlFile})
	if err != nil {
		t.Fatal(err)
	}
	// Base selector .btn is used, so pseudo variants should be used too
	if len(used) != 2 {
		t.Errorf("expected 2 used rules (pseudo with used base), got %d used, %d unused", len(used), len(unused))
	}
}

func TestFindUnusedRules_AtRules(t *testing.T) {
	rules := []Rule{
		{AtRule: "@keyframes fadeIn", Children: []Rule{{Selector: "from"}, {Selector: "to"}}},
		{AtRule: "@media (max-width: 768px)", Children: []Rule{{Selector: ".container"}}},
	}
	htmlFile := writeTestHTML(t, `<div>Content</div>`)
	defer os.Remove(htmlFile)

	used, unused, err := FindUnusedRules(rules, []string{htmlFile})
	if err != nil {
		t.Fatal(err)
	}
	// @keyframes and @media are never marked unused
	if len(used) != 2 {
		t.Errorf("expected 2 used rules (@-rules always used), got %d used, %d unused", len(used), len(unused))
	}
}

func TestFindUnusedRules_NoHTMLFiles(t *testing.T) {
	rules := []Rule{
		{Selector: ".something", Declarations: []Declaration{{Property: "color", Value: "red"}}},
		{Selector: ".other", Declarations: []Declaration{{Property: "margin", Value: "0"}}},
	}

	used, unused, err := FindUnusedRules(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Conservative: no HTML = all rules are considered used
	if len(used) != 2 {
		t.Errorf("expected 2 used rules (no HTML = all used), got %d used, %d unused", len(used), len(unused))
	}
	if len(unused) != 0 {
		t.Errorf("expected 0 unused rules, got %d", len(unused))
	}
}

func TestRemoveUnusedRules(t *testing.T) {
	rules := []Rule{
		{Selector: ".used", Declarations: []Declaration{{Property: "color", Value: "red"}}},
		{Selector: ".unused", Declarations: []Declaration{{Property: "color", Value: "blue"}}},
	}
	htmlFile := writeTestHTML(t, `<div class="used">Content</div>`)
	defer os.Remove(htmlFile)

	filtered, count, err := RemoveUnusedRules(rules, []string{htmlFile})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 removed, got %d", count)
	}
	if len(filtered) != 1 {
		t.Errorf("expected 1 remaining rule, got %d", len(filtered))
	}
	if filtered[0].Selector != ".used" {
		t.Errorf("expected .used rule to remain, got %s", filtered[0].Selector)
	}
}

func TestFindUnusedRules_CompoundSelector(t *testing.T) {
	rules := []Rule{
		{Selector: ".btn.primary", Declarations: []Declaration{{Property: "color", Value: "blue"}}},
	}
	htmlFile := writeTestHTML(t, `<button class="btn">Click</button>`)
	defer os.Remove(htmlFile)

	used, unused, err := FindUnusedRules(rules, []string{htmlFile})
	if err != nil {
		t.Fatal(err)
	}
	// Compound: .btn.primary -> used if any class matches (conservative)
	if len(used) != 1 {
		t.Errorf("expected 1 used rule (compound with matching class), got %d used, %d unused", len(used), len(unused))
	}
}

// writeTestHTML creates a temporary HTML file for testing.
func writeTestHTML(t *testing.T, body string) string {
	t.Helper()
	html := `<!DOCTYPE html><html><head></head><body>` + body + `</body></html>`
	f := filepath.Join(t.TempDir(), "test.html")
	if err := os.WriteFile(f, []byte(html), 0644); err != nil {
		t.Fatal(err)
	}
	return f
}
