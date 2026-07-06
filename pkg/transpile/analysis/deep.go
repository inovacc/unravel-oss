package analysis

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
)

// DeepAnalyzer builds prompts for AI-powered analysis of a codebase report.
type DeepAnalyzer struct {
	logger *slog.Logger
}

// NewDeepAnalyzer creates a new deep analyzer.
func NewDeepAnalyzer(logger *slog.Logger) *DeepAnalyzer {
	return &DeepAnalyzer{logger: logger}
}

// DeepInsights holds the AI-generated analysis sections.
type DeepInsights struct {
	Architecture       string `json:"architecture"`
	ConversionStrategy string `json:"conversion_strategy"`
	GoPackageMapping   string `json:"go_package_mapping"`
	RiskAssessment     string `json:"risk_assessment"`
	ConversionOrder    string `json:"conversion_order"`
}

// BuildPrompts constructs system and user prompts for AI-powered deep analysis.
// The caller should send these to the host LLM and parse the response.
func (d *DeepAnalyzer) BuildPrompts(report *Report) (system, user string) {
	summary := buildAnalysisSummary(report)

	d.logger.Info("built deep analysis prompts", "summary_chars", len(summary))

	system = `You are a senior software architect specializing in C++ to Go migrations.
You are analyzing a C++ codebase that will be converted to idiomatic Go.

Your task is to provide a comprehensive analysis covering:

1. **Architecture Analysis**: Identify the overall architecture pattern, core abstractions, and dependency flow.
2. **Go Conversion Strategy**: Recommend how to map C++ patterns to Go idioms (interfaces for virtual classes, channels for async, etc.).
3. **Go Package Mapping**: Propose a Go package structure that maps from the C++ subsystems and namespaces.
4. **Risk Assessment**: Identify the hardest parts to convert, platform-specific code, and areas needing manual attention.
5. **Conversion Order**: Recommend the order to convert subsystems (leaves-first dependency order).

Format your response with clear markdown sections for each area. Be specific and reference actual class names, file counts, and subsystem names from the analysis.`

	user = summary

	return system, user
}

// buildAnalysisSummary constructs a compact text summary of the report for the AI.
func buildAnalysisSummary(report *Report) string {
	var buf bytes.Buffer

	p := func(format string, args ...any) {
		_, _ = fmt.Fprintf(&buf, format+"\n", args...)
	}

	p("# C++ Codebase Analysis Summary")
	p("")
	p("Root: %s", report.Root)
	p("Total files: %d | Code: %d | Comments: %d | Blanks: %d | Total lines: %d",
		report.TotalFiles, report.TotalLOC.Code, report.TotalLOC.Comments,
		report.TotalLOC.Blanks, report.TotalLOC.Lines)
	p("")

	// Libraries
	if len(report.Libraries) > 0 {
		p("## Libraries Detected: %s", strings.Join(report.Libraries, ", "))
		p("")
	}

	// Subsystems
	if len(report.Subsystems) > 0 {
		p("## Subsystems")

		for _, sub := range report.Subsystems {
			p("- %s: %d files, %d code lines", sub.Name, len(sub.Files), sub.LOC.Code)
		}

		p("")
	}

	// Largest files
	if len(report.LargestFiles) > 0 {
		p("## Largest Files (top 10)")

		limit := min(len(report.LargestFiles), 10)

		for _, f := range report.LargestFiles[:limit] {
			p("- %s: %d code lines", f.Path, f.LOC.Code)
		}

		p("")
	}

	// Symbols
	if report.Symbols != nil {
		p("## Symbols")
		p("- Classes/Structs: %d", len(report.Symbols.Classes))
		p("- Functions: %d", len(report.Symbols.Functions))
		p("- Enums: %d", len(report.Symbols.Enums))
		p("- Namespaces: %d", len(report.Symbols.Namespaces))
		p("- Typedefs: %d", len(report.Symbols.Typedefs))
		p("")

		// List namespaces
		if len(report.Symbols.Namespaces) > 0 {
			p("### Namespaces")

			for name, ns := range report.Symbols.Namespaces {
				p("- %s (%d files)", name, len(ns.Files))
			}

			p("")
		}
	}

	// Hierarchy
	if report.Hierarchy != nil {
		p("## Class Hierarchy")
		p("- Total classes in hierarchy: %d", len(report.Hierarchy.ByName))
		p("- Root classes: %d", len(report.Hierarchy.Roots))
		p("- Max depth: %d", report.Hierarchy.Depth())

		candidates := report.Hierarchy.InterfaceCandidates()
		if len(candidates) > 0 {
			p("- Interface candidates (pure virtual): %d", len(candidates))
			p("")
			p("### Key Interface Candidates")

			limit := min(len(candidates), 25)

			for _, c := range candidates[:limit] {
				p("- %s (%s): %d pure virtual methods", c.Name, c.File, len(c.Methods))
			}
		}

		p("")

		// Key inheritance trees
		p("### Key Inheritance Trees (classes with children)")

		count := 0

		for _, node := range report.Hierarchy.ByName {
			if len(node.Children) > 2 {
				childNames := make([]string, 0, len(node.ChildNames))

				childNames = append(childNames, node.ChildNames...)
				if len(childNames) > 8 {
					childNames = append(childNames[:8], fmt.Sprintf("... (+%d more)", len(node.ChildNames)-8))
				}

				p("- %s -> [%s]", node.Name, strings.Join(childNames, ", "))

				count++
				if count >= 20 {
					break
				}
			}
		}

		p("")
	}

	// Include graph highlights
	if report.IncludeGraph != nil {
		p("## Include Graph")

		edges := report.IncludeGraph.Edges()
		localEdges := 0
		systemEdges := 0

		for _, e := range edges {
			if e.IsSystem {
				systemEdges++
			} else {
				localEdges++
			}
		}

		p("- Local edges: %d, System edges: %d", localEdges, systemEdges)

		// Most included files
		type inc struct {
			path  string
			count int
		}

		var top []inc

		for path, node := range report.IncludeGraph.Nodes {
			if len(node.IncludedBy) > 10 {
				top = append(top, inc{path, len(node.IncludedBy)})
			}
		}
		// Sort descending
		for i := 1; i < len(top); i++ {
			for j := i; j > 0 && top[j].count > top[j-1].count; j-- {
				top[j], top[j-1] = top[j-1], top[j]
			}
		}

		if len(top) > 0 {
			p("")
			p("### Most Included Headers")

			limit := min(len(top), 15)

			for _, t := range top[:limit] {
				p("- %s: included by %d files", t.path, t.count)
			}
		}
	}

	return buf.String()
}

// parseInsights extracts structured sections from the AI response.
func parseInsights(response string) *DeepInsights {
	insights := &DeepInsights{}

	sections := map[string]*string{
		"architecture":        &insights.Architecture,
		"conversion strategy": &insights.ConversionStrategy,
		"go package":          &insights.GoPackageMapping,
		"risk":                &insights.RiskAssessment,
		"conversion order":    &insights.ConversionOrder,
	}

	// Split by ## headers and assign to matching sections
	lines := strings.Split(response, "\n")

	var (
		currentSection *string
		sectionLines   []string
	)

	flushSection := func() {
		if currentSection != nil && len(sectionLines) > 0 {
			*currentSection = strings.TrimSpace(strings.Join(sectionLines, "\n"))
		}

		sectionLines = nil
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "# ") {
			flushSection()

			header := strings.ToLower(strings.TrimLeft(line, "# "))
			currentSection = nil

			for key, ptr := range sections {
				if strings.Contains(header, key) {
					currentSection = ptr
					break
				}
			}

			continue
		}

		if currentSection != nil {
			sectionLines = append(sectionLines, line)
		}
	}

	flushSection()

	// If no sections were parsed, put everything in Architecture
	if insights.Architecture == "" && insights.ConversionStrategy == "" {
		insights.Architecture = response
	}

	return insights
}

// WriteDeepReport writes the combined deterministic + AI analysis.
func WriteDeepReport(report *Report, insights *DeepInsights, w *bytes.Buffer) {
	p := func(format string, args ...any) {
		_, _ = fmt.Fprintf(w, format+"\n", args...)
	}

	// Write the deterministic report first
	_ = report.WriteMarkdown(w)

	// Append AI insights
	p("---")
	p("")
	p("# AI-Powered Deep Analysis")
	p("")

	if insights.Architecture != "" {
		p("## Architecture Analysis")
		p("")
		p("%s", insights.Architecture)
		p("")
	}

	if insights.ConversionStrategy != "" {
		p("## Go Conversion Strategy")
		p("")
		p("%s", insights.ConversionStrategy)
		p("")
	}

	if insights.GoPackageMapping != "" {
		p("## Go Package Mapping")
		p("")
		p("%s", insights.GoPackageMapping)
		p("")
	}

	if insights.RiskAssessment != "" {
		p("## Risk Assessment")
		p("")
		p("%s", insights.RiskAssessment)
		p("")
	}

	if insights.ConversionOrder != "" {
		p("## Recommended Conversion Order")
		p("")
		p("%s", insights.ConversionOrder)
		p("")
	}
}
