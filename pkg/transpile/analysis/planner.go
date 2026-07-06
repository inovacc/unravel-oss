package analysis

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

// Planner builds prompts for AI-powered implementation plan generation.
type Planner struct {
	logger *slog.Logger
}

// NewPlanner creates a new plan generator.
func NewPlanner(logger *slog.Logger) *Planner {
	return &Planner{logger: logger}
}

// Plan holds the complete conversion implementation plan.
type Plan struct {
	Project        string       `json:"project"`
	SourceLanguage string       `json:"source_language"`
	TotalFiles     int          `json:"total_files"`
	TotalCodeLines int          `json:"total_code_lines"`
	GoModule       string       `json:"go_module,omitempty"`
	GoPackages     []*GoPackage `json:"go_packages,omitempty"`
	Phases         []*Phase     `json:"phases"`
	Risks          []*Risk      `json:"risks,omitempty"`
	ExternalDeps   []string     `json:"external_deps,omitempty"`
}

// GoPackage describes a proposed Go package in the conversion target.
type GoPackage struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Description string `json:"description"`
}

// Phase groups files that should be converted together in dependency order.
type Phase struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Order       int         `json:"order"`
	Files       []*FilePlan `json:"files"`
}

// FilePlan describes the conversion strategy for a single source file.
type FilePlan struct {
	Source         string   `json:"source"`
	Target         string   `json:"target"`
	Complexity     string   `json:"complexity"` // "low", "medium", "high"
	CodeLines      int      `json:"code_lines"`
	Strategy       string   `json:"strategy"`
	KeyConversions []string `json:"key_conversions"`
	GoPackage      string   `json:"go_package"`
	Dependencies   []string `json:"dependencies,omitempty"`
	Risks          []string `json:"risks,omitempty"`
}

// Risk describes a conversion risk area.
type Risk struct {
	File   string `json:"file"`
	Level  string `json:"level"` // "low", "medium", "high"
	Reason string `json:"reason"`
}

// BuildPrompts constructs system and user prompts for AI-powered plan generation.
// The caller should send these to the host LLM and parse the JSON response.
func (p *Planner) BuildPrompts(report *Report) (system, user string) {
	summary := buildAnalysisSummary(report)

	p.logger.Info("built plan generation prompts", "summary_chars", len(summary))

	system = `You are a senior software architect specializing in C/C++ to Go migrations.
You are given a structured analysis of a C/C++ codebase. Your task is to produce a detailed,
actionable implementation plan for converting this codebase to idiomatic Go.

The plan must be structured as a JSON object with this exact schema:

{
  "project": "<project name derived from root directory>",
  "source_language": "C++" or "C" or "C/C++",
  "total_files": <int>,
  "total_code_lines": <int>,
  "go_module": "<proposed go module path>",
  "go_packages": [
    {"name": "<pkg>", "path": "<relative path>", "description": "<what it contains>"}
  ],
  "phases": [
    {
      "name": "<phase name>",
      "description": "<what this phase covers>",
      "order": <int starting from 1>,
      "files": [
        {
          "source": "<original source path>",
          "target": "<proposed Go file path>",
          "complexity": "low" | "medium" | "high",
          "code_lines": <int>,
          "strategy": "<detailed conversion strategy for this file>",
          "key_conversions": ["<C++ pattern> → <Go pattern>", ...],
          "go_package": "<target Go package name>",
          "dependencies": ["<other source files this depends on>"],
          "risks": ["<potential issues>"]
        }
      ]
    }
  ],
  "risks": [
    {"file": "<source path>", "level": "low" | "medium" | "high", "reason": "<why>"}
  ],
  "external_deps": ["<go module paths needed>"]
}

Guidelines:
- Phases should follow dependency order: leaf files first, then core types, then business logic, then entry points.
- Each file's strategy should be specific and actionable, referencing actual types, functions, and patterns.
- Key conversions should map specific C++ constructs found in the file to their Go equivalents.
- Complexity ratings: "low" for straightforward translations, "medium" for files needing pattern changes, "high" for files with complex C++ features (templates, multiple inheritance, heavy pointer arithmetic).
- Risks should call out platform-specific code, unsafe operations, libraries without Go equivalents, and complex template metaprogramming.
- External deps should list Go modules that will be needed (e.g., google.golang.org/grpc, github.com/google/uuid).
- The go_module should be a reasonable module path based on the project name.
- IMPORTANT: Return ONLY the JSON object, no markdown fences, no explanation text.`

	user = summary

	return system, user
}

// parsePlanResponse extracts a Plan from the AI response, handling optional markdown fences.
func parsePlanResponse(response string) (*Plan, error) {
	cleaned := stripCodeFences(response)

	var plan Plan
	if err := json.Unmarshal([]byte(cleaned), &plan); err != nil {
		return nil, fmt.Errorf("unmarshal plan JSON: %w (response length: %d)", err, len(cleaned))
	}

	return &plan, nil
}

// stripCodeFences removes markdown code fences from a response if present.
func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)

	// Remove leading ```json or ```
	if strings.HasPrefix(s, "```") {
		if idx := strings.Index(s, "\n"); idx != -1 {
			s = s[idx+1:]
		}
	}

	// Remove trailing ```
	if strings.HasSuffix(s, "```") {
		s = s[:len(s)-3]
	}

	return strings.TrimSpace(s)
}
