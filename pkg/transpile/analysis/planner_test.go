package analysis

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func samplePlan() *Plan {
	return &Plan{
		Project:        "test-project",
		SourceLanguage: "C++",
		TotalFiles:     3,
		TotalCodeLines: 500,
		GoModule:       "github.com/user/test-project",
		GoPackages: []*GoPackage{
			{Name: "stringutil", Path: "pkg/stringutil", Description: "String helper functions"},
			{Name: "types", Path: "pkg/types", Description: "Core type definitions"},
		},
		Phases: []*Phase{
			{
				Name:        "Foundation",
				Description: "Leaf dependencies with no internal imports",
				Order:       1,
				Files: []*FilePlan{
					{
						Source:         "src/utils/string_helpers.cpp",
						Target:         "pkg/stringutil/helpers.go",
						Complexity:     "low",
						CodeLines:      120,
						Strategy:       "Direct translation. No dependencies on other project files.",
						KeyConversions: []string{"std::string → string", "StringHelper class → package-level functions"},
						GoPackage:      "stringutil",
						Dependencies:   nil,
						Risks:          nil,
					},
				},
			},
			{
				Name:        "Core Types",
				Description: "Core type definitions used across the codebase",
				Order:       2,
				Files: []*FilePlan{
					{
						Source:         "src/types/result.h",
						Target:         "pkg/types/result.go",
						Complexity:     "medium",
						CodeLines:      80,
						Strategy:       "Convert template Result<T> to generic Result[T any].",
						KeyConversions: []string{"template<typename T> → [T any]", "std::optional<T> → *T"},
						GoPackage:      "types",
						Dependencies:   []string{"src/utils/string_helpers.cpp"},
						Risks:          []string{"Template specializations may need manual handling"},
					},
				},
			},
			{
				Name:        "Entry Points",
				Description: "Main entry points and CLI",
				Order:       3,
				Files: []*FilePlan{
					{
						Source:     "src/main.cpp",
						Target:     "cmd/main.go",
						Complexity: "low",
						CodeLines:  300,
						Strategy:   "Convert main() to Go main package with cobra CLI.",
						GoPackage:  "main",
					},
				},
			},
		},
		Risks: []*Risk{
			{File: "src/types/result.h", Level: "medium", Reason: "Template specializations may need manual handling"},
		},
		ExternalDeps: []string{"github.com/spf13/cobra"},
	}
}

func TestPlan_WriteJSON(t *testing.T) {
	plan := samplePlan()

	var buf bytes.Buffer
	if err := plan.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}

	// Verify it's valid JSON.
	var parsed Plan
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if parsed.Project != "test-project" {
		t.Errorf("project = %q, want %q", parsed.Project, "test-project")
	}

	if parsed.TotalFiles != 3 {
		t.Errorf("total_files = %d, want 3", parsed.TotalFiles)
	}

	if len(parsed.Phases) != 3 {
		t.Errorf("phases = %d, want 3", len(parsed.Phases))
	}

	if parsed.Phases[0].Files[0].Complexity != "low" {
		t.Errorf("first file complexity = %q, want %q", parsed.Phases[0].Files[0].Complexity, "low")
	}

	if len(parsed.GoPackages) != 2 {
		t.Errorf("go_packages = %d, want 2", len(parsed.GoPackages))
	}

	if len(parsed.Risks) != 1 {
		t.Errorf("risks = %d, want 1", len(parsed.Risks))
	}

	if len(parsed.ExternalDeps) != 1 {
		t.Errorf("external_deps = %d, want 1", len(parsed.ExternalDeps))
	}
}

func TestPlan_WriteMarkdown(t *testing.T) {
	plan := samplePlan()

	var buf bytes.Buffer
	if err := plan.WriteMarkdown(&buf); err != nil {
		t.Fatalf("WriteMarkdown() error = %v", err)
	}

	md := buf.String()

	checks := []string{
		"# Conversion Plan: test-project",
		"## Overview",
		"Source Language | C++",
		"Total Files | 3",
		"Code Lines | 500",
		"Estimated Phases | 3",
		"`github.com/user/test-project`",
		"## Go Module Structure",
		"`stringutil`",
		"`pkg/stringutil`",
		"## Phase 1: Foundation",
		"Leaf dependencies",
		"### File: src/utils/string_helpers.cpp → pkg/stringutil/helpers.go",
		"**Complexity:** low",
		"**Strategy:**",
		"std::string → string",
		"## Phase 2: Core Types",
		"**Dependencies:**",
		"**Risks:**",
		"Template specializations",
		"## Phase 3: Entry Points",
		"## Risk Areas",
		"medium",
		"## External Dependencies",
		"`github.com/spf13/cobra`",
	}

	for _, check := range checks {
		if !strings.Contains(md, check) {
			t.Errorf("markdown missing %q", check)
		}
	}
}

func TestPlanner_BuildPrompts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	planner := NewPlanner(logger)

	report := &Report{
		Root:       "/test/project",
		TotalFiles: 3,
		TotalLOC:   LOCStats{Lines: 500, Code: 400, Comments: 70, Blanks: 30},
		Libraries:  []string{"stl"},
	}

	system, user := planner.BuildPrompts(report)

	if system == "" {
		t.Error("expected non-empty system prompt")
	}

	if user == "" {
		t.Error("expected non-empty user prompt")
	}

	if !strings.Contains(system, "senior software architect") {
		t.Error("system prompt missing expected content")
	}

	if !strings.Contains(user, "/test/project") {
		t.Error("user prompt missing report root")
	}

	if !strings.Contains(user, "stl") {
		t.Error("user prompt missing library name")
	}
}

func TestParsePlanResponse_RawJSON(t *testing.T) {
	input := `{"project":"test","source_language":"C++","total_files":1,"total_code_lines":100,"phases":[]}`

	plan, err := parsePlanResponse(input)
	if err != nil {
		t.Fatalf("parsePlanResponse() error = %v", err)
	}

	if plan.Project != "test" {
		t.Errorf("project = %q, want %q", plan.Project, "test")
	}
}

func TestParsePlanResponse_WithCodeFences(t *testing.T) {
	input := "```json\n{\"project\":\"fenced\",\"source_language\":\"C\",\"total_files\":2,\"total_code_lines\":200,\"phases\":[]}\n```"

	plan, err := parsePlanResponse(input)
	if err != nil {
		t.Fatalf("parsePlanResponse() error = %v", err)
	}

	if plan.Project != "fenced" {
		t.Errorf("project = %q, want %q", plan.Project, "fenced")
	}
}

func TestParsePlanResponse_WithPlainFences(t *testing.T) {
	input := "```\n{\"project\":\"plain\",\"source_language\":\"C++\",\"total_files\":0,\"total_code_lines\":0,\"phases\":[]}\n```"

	plan, err := parsePlanResponse(input)
	if err != nil {
		t.Fatalf("parsePlanResponse() error = %v", err)
	}

	if plan.Project != "plain" {
		t.Errorf("project = %q, want %q", plan.Project, "plain")
	}
}

func TestParsePlanResponse_InvalidJSON(t *testing.T) {
	_, err := parsePlanResponse("this is not json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	if !strings.Contains(err.Error(), "unmarshal plan JSON") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "unmarshal plan JSON")
	}
}

func TestStripCodeFences(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no fences",
			input: `{"key":"value"}`,
			want:  `{"key":"value"}`,
		},
		{
			name:  "json fences",
			input: "```json\n{\"key\":\"value\"}\n```",
			want:  `{"key":"value"}`,
		},
		{
			name:  "plain fences",
			input: "```\n{\"key\":\"value\"}\n```",
			want:  `{"key":"value"}`,
		},
		{
			name:  "with whitespace",
			input: "  \n```json\n{\"key\":\"value\"}\n```\n  ",
			want:  `{"key":"value"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripCodeFences(tt.input)
			if got != tt.want {
				t.Errorf("stripCodeFences() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPlan_WriteMarkdown_Empty(t *testing.T) {
	plan := &Plan{
		Project:        "empty-project",
		SourceLanguage: "C",
		TotalFiles:     0,
		TotalCodeLines: 0,
		Phases:         nil,
	}

	var buf bytes.Buffer
	if err := plan.WriteMarkdown(&buf); err != nil {
		t.Fatalf("WriteMarkdown() error = %v", err)
	}

	md := buf.String()
	if !strings.Contains(md, "# Conversion Plan: empty-project") {
		t.Error("missing plan header")
	}

	if !strings.Contains(md, "Total Files | 0") {
		t.Error("missing total files")
	}
}
