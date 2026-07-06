package analysis

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestReport_WriteJSON(t *testing.T) {
	report := &Report{
		Root:       "/test/project",
		TotalFiles: 3,
		TotalLOC:   LOCStats{Lines: 100, Code: 70, Comments: 20, Blanks: 10},
		Libraries:  []string{"stl", "boost"},
		Subsystems: []*Subsystem{
			{Name: "HTTP", Files: []*SourceFile{{RelPath: "http.cpp"}}, LOC: LOCStats{Lines: 50}},
		},
	}

	var buf bytes.Buffer
	if err := report.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if parsed["root"] != "/test/project" {
		t.Errorf("root = %v, want /test/project", parsed["root"])
	}

	totalFiles, ok := parsed["total_files"].(float64)
	if !ok || totalFiles != 3 {
		t.Errorf("total_files = %v, want 3", parsed["total_files"])
	}
}

func TestReport_WriteMarkdown(t *testing.T) {
	report := &Report{
		Root:       "/test/project",
		TotalFiles: 5,
		TotalLOC:   LOCStats{Lines: 200, Code: 150, Comments: 30, Blanks: 20},
		Libraries:  []string{"stl", "boost"},
		Subsystems: []*Subsystem{
			{Name: "HTTP", Files: []*SourceFile{{RelPath: "http.cpp"}}, LOC: LOCStats{Lines: 80, Code: 60}},
			{Name: "Uncategorized", Files: []*SourceFile{{RelPath: "main.cpp"}}, LOC: LOCStats{Lines: 20}},
		},
		LargestFiles: []*FileSizeEntry{
			{Path: "http.cpp", LOC: LOCStats{Lines: 80, Code: 60, Comments: 15}},
			{Path: "main.cpp", LOC: LOCStats{Lines: 20, Code: 15, Comments: 3}},
		},
		Symbols: &SymbolTable{
			Classes:    map[string]*ClassInfo{"Foo": {Name: "Foo"}},
			Functions:  map[string]*FunctionInfo{},
			Enums:      map[string]*EnumInfo{},
			Namespaces: map[string]*NamespaceInfo{},
			Typedefs:   map[string]*TypedefInfo{},
		},
	}

	var buf bytes.Buffer
	if err := report.WriteMarkdown(&buf); err != nil {
		t.Fatalf("WriteMarkdown() error = %v", err)
	}

	md := buf.String()

	// Check key sections exist
	checks := []string{
		"# Codebase Analysis Report",
		"## Summary",
		"Total Files | 5",
		"## Detected Libraries",
		"- stl",
		"- boost",
		"## Subsystems",
		"HTTP",
		"## Largest Files",
		"## Symbols",
		"Classes/Structs | 1",
	}

	for _, check := range checks {
		if !strings.Contains(md, check) {
			t.Errorf("markdown missing %q", check)
		}
	}
}

func TestReport_WriteMarkdown_Empty(t *testing.T) {
	report := &Report{
		Root:       "/empty",
		TotalFiles: 0,
		TotalLOC:   LOCStats{},
	}

	var buf bytes.Buffer
	if err := report.WriteMarkdown(&buf); err != nil {
		t.Fatalf("WriteMarkdown() error = %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "Total Files | 0") {
		t.Error("expected Total Files | 0 in output")
	}
}

func TestReport_WriteMarkdown_WithHierarchy(t *testing.T) {
	report := &Report{
		Root:       "/test",
		TotalFiles: 1,
		TotalLOC:   LOCStats{Lines: 10},
		Hierarchy: &ClassHierarchy{
			Roots: []*ClassNode{
				{Name: "Base", File: "base.h", HasPure: true, Methods: []string{"foo"}},
			},
			ByName: map[string]*ClassNode{
				"Base": {Name: "Base", File: "base.h", HasPure: true, Methods: []string{"foo"}},
			},
		},
	}

	var buf bytes.Buffer
	if err := report.WriteMarkdown(&buf); err != nil {
		t.Fatalf("WriteMarkdown() error = %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "## Class Hierarchy") {
		t.Error("missing Class Hierarchy section")
	}

	if !strings.Contains(md, "Interface Candidates") {
		t.Error("missing Interface Candidates section")
	}
}
