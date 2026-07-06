// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractCSSFromJS_StyledComponent(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "styled-component.js"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExtractCSSFromJS(data, "styled-component.js")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) == 0 {
		t.Fatal("expected CSS entries from styled-component.js, got none")
	}
	// Should find styled.button tagged template with "color: red"
	found := false
	for _, e := range result.Entries {
		if strings.Contains(e.CSS, "color: red") && e.Kind == "tagged-template" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tagged-template entry with 'color: red', got entries: %+v", result.Entries)
	}
}

func TestExtractCSSFromJS_CSSTaggedTemplate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "emotion.js"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExtractCSSFromJS(data, "emotion.js")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range result.Entries {
		if strings.Contains(e.CSS, "font-size: 24px") && e.Kind == "tagged-template" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tagged-template entry with 'font-size: 24px', got: %+v", result.Entries)
	}
}

func TestExtractCSSFromJS_KeyframesTemplate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "emotion.js"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExtractCSSFromJS(data, "emotion.js")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range result.Entries {
		if strings.Contains(e.CSS, "opacity: 0") && strings.Contains(e.CSS, "opacity: 1") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected keyframes entry with opacity transitions, got: %+v", result.Entries)
	}
}

func TestExtractCSSFromJS_ObjectStyles(t *testing.T) {
	// Test with inline CSS object style using css() call
	content := []byte(`const box = css({ color: '#333', backgroundColor: 'white', fontSize: '16px' });`)
	result, err := ExtractCSSFromJS(content, "object-styles.js")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range result.Entries {
		if e.Kind == "object-style" &&
			strings.Contains(e.CSS, "background-color: white") &&
			strings.Contains(e.CSS, "color: #333") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected object-style entry with 'background-color: white', got: %+v", result.Entries)
	}
}

func TestExtractCSSFromJS_ObjectStylesFromFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "object-styles.js"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExtractCSSFromJS(data, "object-styles.js")
	if err != nil {
		t.Fatal(err)
	}
	// The css({...}) call should produce an object-style entry with borderRadius/fontSize
	found := false
	for _, e := range result.Entries {
		if e.Kind == "object-style" &&
			strings.Contains(e.CSS, "border-radius: 4px") &&
			strings.Contains(e.CSS, "font-size: 16px") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected object-style entry with 'border-radius: 4px', got: %+v", result.Entries)
	}
}

func TestExtractCSSFromJS_DynamicExpressions(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "styled-component.js"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExtractCSSFromJS(data, "styled-component.js")
	if err != nil {
		t.Fatal(err)
	}
	// The styled.div template has ${spacing} -- should be replaced with var(--dynamic-N)
	found := false
	for _, e := range result.Entries {
		if strings.Contains(e.CSS, "var(--dynamic-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected dynamic expression replaced with var(--dynamic-N), got: %+v", result.Entries)
	}
}

func TestExtractCSSFromJS_NoCSS(t *testing.T) {
	content := []byte(`const x = 1; function foo() { return x + 2; }`)
	result, err := ExtractCSSFromJS(content, "plain.js")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected no entries for plain JS, got %d", len(result.Entries))
	}
}

func TestExtractCSSFromJS_NestedTemplateLiteral(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "nested-template.js"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExtractCSSFromJS(data, "nested-template.js")
	if err != nil {
		t.Fatal(err)
	}
	// Should extract at minimum the outer styled.div template with padding
	found := false
	for _, e := range result.Entries {
		if e.Kind == "tagged-template" && strings.Contains(e.CSS, "padding: 8px") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tagged-template entry with 'padding: 8px' from nested template, got: %+v", result.Entries)
	}
}

func TestExtractCSSFromJS_MultiExpressionTemplate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "multi-expr.js"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := ExtractCSSFromJS(data, "multi-expr.js")
	if err != nil {
		t.Fatal(err)
	}
	// Should extract styled.button with placeholders and static border-radius
	found := false
	for _, e := range result.Entries {
		if e.Kind == "tagged-template" &&
			strings.Contains(e.CSS, "var(--dynamic-1)") &&
			strings.Contains(e.CSS, "var(--dynamic-2)") &&
			strings.Contains(e.CSS, "border-radius: 4px") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tagged-template with dynamic placeholders and 'border-radius: 4px', got: %+v", result.Entries)
	}
}

func TestExtractCSSFromJS_UnparseableJS(t *testing.T) {
	// Malformed JS should return empty result, no error
	content := []byte(`this is not valid javascript {{{{`)
	result, err := ExtractCSSFromJS(content, "bad.js")
	if err != nil {
		t.Fatalf("expected no error for unparseable JS, got: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected no entries for unparseable JS, got %d", len(result.Entries))
	}
}

func TestCamelToKebab(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"backgroundColor", "background-color"},
		{"fontSize", "font-size"},
		{"color", "color"},
		{"borderTopLeftRadius", "border-top-left-radius"},
		{"MozTransform", "-moz-transform"},
		{"WebkitAnimation", "-webkit-animation"},
	}
	for _, tt := range tests {
		got := camelToKebab(tt.in)
		if got != tt.want {
			t.Errorf("camelToKebab(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
