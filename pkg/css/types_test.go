/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"encoding/json"
	"testing"
)

func TestTypesOptionsFields(t *testing.T) {
	opts := Options{
		OutputDir:        "/tmp/out",
		ResolveImports:   true,
		Normalize:        true,
		Deduplicate:      true,
		ResolveVars:      true,
		RemoveUnused:     true,
		IncludeSourceMap: true,
		HTMLFiles:        []string{"a.html"},
		NodeModulesPath:  "/node_modules",
		Verbose:          true,
		NoCache:          true,
	}
	if opts.OutputDir != "/tmp/out" {
		t.Error("OutputDir not set")
	}
	if !opts.ResolveImports {
		t.Error("ResolveImports not set")
	}
	if !opts.Normalize {
		t.Error("Normalize not set")
	}
	if !opts.Deduplicate {
		t.Error("Deduplicate not set")
	}
	if !opts.ResolveVars {
		t.Error("ResolveVars not set")
	}
	if !opts.RemoveUnused {
		t.Error("RemoveUnused not set")
	}
	if !opts.IncludeSourceMap {
		t.Error("IncludeSourceMap not set")
	}
	if len(opts.HTMLFiles) != 1 {
		t.Error("HTMLFiles not set")
	}
	if opts.NodeModulesPath != "/node_modules" {
		t.Error("NodeModulesPath not set")
	}
	if !opts.Verbose {
		t.Error("Verbose not set")
	}
	if !opts.NoCache {
		t.Error("NoCache not set")
	}
}

func TestTypesResultJSONSerialization(t *testing.T) {
	r := Result{
		Stylesheets: []Stylesheet{
			{Path: "test.css", Source: SourceFile, OriginalSize: 100},
		},
		Components:  []Component{{Name: "app", Dir: "/app"}},
		ImportGraph: map[string][]string{"a.css": {"b.css"}},
		Stats:       ExtractionStats{TotalFiles: 1},
		Errors:      []string{"warn"},
		OutputDir:   "/out",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Verify snake_case tags
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal map: %v", err)
	}
	for _, key := range []string{"stylesheets", "components", "import_graph", "stats", "errors", "output_dir"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing JSON key %q", key)
		}
	}
}

func TestTypesStylesheetSourceValues(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{"file", SourceFile, "file"},
		{"html-style", SourceHTMLStyle, "html-style"},
		{"html-inline", SourceHTMLInline, "html-inline"},
		{"css-in-js", SourceCSSInJS, "css-in-js"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.source != tt.want {
				t.Errorf("got %q, want %q", tt.source, tt.want)
			}
		})
	}
}

func TestTypesExtractionStatsZeroValue(t *testing.T) {
	var s ExtractionStats
	if s.TotalFiles != 0 || s.CSSFiles != 0 || s.HTMLFiles != 0 || s.JSFiles != 0 {
		t.Error("zero value should have all zero fields")
	}
	if s.CSSInJSFound != 0 || s.ImportsResolved != 0 || s.RulesRemovedDedup != 0 {
		t.Error("zero value should have all zero fields")
	}
	if s.UnusedRemoved != 0 || s.ComponentCount != 0 {
		t.Error("zero value should have all zero fields")
	}
}
