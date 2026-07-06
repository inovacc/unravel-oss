package analysis

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// WriteJSON writes the plan as formatted JSON.
func (pl *Plan) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(pl)
}

// WriteMarkdown writes the plan as a human-readable Markdown document.
func (pl *Plan) WriteMarkdown(w io.Writer) error {
	p := func(format string, args ...any) {
		_, _ = fmt.Fprintf(w, format+"\n", args...)
	}

	p("# Conversion Plan: %s", pl.Project)
	p("")

	// Overview
	p("## Overview")
	p("")
	p("| Detail | Value |")
	p("|--------|-------|")
	p("| Source Language | %s |", pl.SourceLanguage)
	p("| Total Files | %d |", pl.TotalFiles)
	p("| Code Lines | %d |", pl.TotalCodeLines)
	p("| Estimated Phases | %d |", len(pl.Phases))

	if pl.GoModule != "" {
		p("| Go Module | `%s` |", pl.GoModule)
	}

	p("")

	// Go Module Structure
	if len(pl.GoPackages) > 0 {
		p("## Go Module Structure")
		p("")
		p("| Package | Path | Description |")
		p("|---------|------|-------------|")

		for _, pkg := range pl.GoPackages {
			p("| `%s` | `%s` | %s |", pkg.Name, pkg.Path, pkg.Description)
		}

		p("")
	}

	// Phases
	for _, phase := range pl.Phases {
		p("## Phase %d: %s", phase.Order, phase.Name)
		p("")

		if phase.Description != "" {
			p("%s", phase.Description)
			p("")
		}

		for _, f := range phase.Files {
			p("### File: %s → %s", f.Source, f.Target)
			p("")
			p("- **Complexity:** %s", f.Complexity)
			p("- **Code Lines:** %d", f.CodeLines)
			p("- **Go Package:** `%s`", f.GoPackage)
			p("- **Strategy:** %s", f.Strategy)

			if len(f.KeyConversions) > 0 {
				p("- **Key Conversions:**")

				for _, kc := range f.KeyConversions {
					p("  - %s", kc)
				}
			}

			if len(f.Dependencies) > 0 {
				p("- **Dependencies:** %s", joinBacktick(f.Dependencies))
			}

			if len(f.Risks) > 0 {
				p("- **Risks:**")

				for _, r := range f.Risks {
					p("  - %s", r)
				}
			}

			p("")
		}
	}

	// Risk Areas
	if len(pl.Risks) > 0 {
		p("## Risk Areas")
		p("")
		p("| File | Level | Reason |")
		p("|------|-------|--------|")

		for _, r := range pl.Risks {
			p("| `%s` | %s | %s |", r.File, r.Level, r.Reason)
		}

		p("")
	}

	// External Dependencies
	if len(pl.ExternalDeps) > 0 {
		p("## External Dependencies")
		p("")

		for _, dep := range pl.ExternalDeps {
			p("- `%s`", dep)
		}

		p("")
	}

	return nil
}

// joinBacktick joins strings with backtick formatting.
func joinBacktick(items []string) string {
	if len(items) == 0 {
		return ""
	}

	var result strings.Builder
	result.WriteString("`" + items[0] + "`")

	for _, item := range items[1:] {
		result.WriteString(", `" + item + "`")
	}

	return result.String()
}
