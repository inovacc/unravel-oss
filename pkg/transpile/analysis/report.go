package analysis

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/transpile/archive"
)

// Report holds the complete analysis results for a source codebase.
type Report struct {
	Root         string              `json:"root"`
	TotalFiles   int                 `json:"total_files"`
	TotalLOC     LOCStats            `json:"total_loc"`
	SourceFiles  []*SourceFile       `json:"source_files,omitempty"`
	Subsystems   []*Subsystem        `json:"subsystems,omitempty"`
	Libraries    []string            `json:"libraries,omitempty"`
	IncludeGraph *IncludeGraph       `json:"include_graph,omitempty"`
	Symbols      *SymbolTable        `json:"symbols,omitempty"`
	Hierarchy    *ClassHierarchy     `json:"hierarchy,omitempty"`
	FileLOC      map[string]LOCStats `json:"file_loc,omitempty"`
	LargestFiles []*FileSizeEntry    `json:"largest_files,omitempty"`

	// Python-specific analysis
	PyImportGraph *ImportGraph          `json:"py_import_graph,omitempty"`
	PySymbols     *PythonSymbolTable    `json:"py_symbols,omitempty"`
	PyHierarchy   *PythonClassHierarchy `json:"py_hierarchy,omitempty"`
	PyFrameworks  []string              `json:"py_frameworks,omitempty"`

	// Java-specific analysis
	JavaFrameworks []string `json:"java_frameworks,omitempty"`

	// Archive-specific analysis (set when analyzing a JAR/WAR/EAR)
	ArchiveInfo *ArchiveReport `json:"archive_info,omitempty"`
}

// ArchiveReport holds metadata extracted from a Java archive.
type ArchiveReport struct {
	Type         string                 `json:"type"`
	OriginalPath string                 `json:"original_path"`
	Manifest     *archive.ManifestInfo  `json:"manifest,omitempty"`
	WebXML       *archive.WebXMLInfo    `json:"web_xml,omitempty"`
	AppXML       *archive.AppXMLInfo    `json:"app_xml,omitempty"`
	POM          *archive.POMInfo       `json:"pom,omitempty"`
	SpringConfig *archive.SpringConfig  `json:"spring_config,omitempty"`
	Patterns     *archive.PatternReport `json:"patterns,omitempty"`
}

// FileSizeEntry pairs a file path with its LOC stats for ranking.
type FileSizeEntry struct {
	Path string   `json:"path"`
	LOC  LOCStats `json:"loc"`
}

// WriteJSON writes the report as formatted JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(r)
}

// WriteUnitsJSON writes the dependency-ordered conversion units and symbol
// registry as indented JSON. output must not be nil.
func WriteUnitsJSON(w io.Writer, output *UnitsOutput) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

// WriteMarkdown writes the report as a human-readable Markdown document.
func (r *Report) WriteMarkdown(w io.Writer) error {
	p := func(format string, args ...any) {
		_, _ = fmt.Fprintf(w, format+"\n", args...)
	}

	p("# Codebase Analysis Report")
	p("")
	p("**Root:** `%s`", r.Root)
	p("")

	// Summary
	p("## Summary")
	p("")
	p("| Metric | Value |")
	p("|--------|-------|")
	p("| Total Files | %d |", r.TotalFiles)
	p("| Total Lines | %d |", r.TotalLOC.Lines)
	p("| Code Lines | %d |", r.TotalLOC.Code)
	p("| Comment Lines | %d |", r.TotalLOC.Comments)
	p("| Blank Lines | %d |", r.TotalLOC.Blanks)

	if r.TotalLOC.Lines > 0 {
		commentPct := float64(r.TotalLOC.Comments) / float64(r.TotalLOC.Lines) * 100
		p("| Comment Ratio | %.1f%% |", commentPct)
	}

	p("")

	// Archive info
	if r.ArchiveInfo != nil {
		p("## Archive Information")
		p("")
		p("| Property | Value |")
		p("|----------|-------|")
		p("| Type | %s |", r.ArchiveInfo.Type)
		p("| Original Path | `%s` |", r.ArchiveInfo.OriginalPath)

		if r.ArchiveInfo.Manifest != nil {
			if r.ArchiveInfo.Manifest.MainClass != "" {
				p("| Main-Class | `%s` |", r.ArchiveInfo.Manifest.MainClass)
			}

			if r.ArchiveInfo.Manifest.ImplementationTitle != "" {
				p("| Implementation-Title | %s |", r.ArchiveInfo.Manifest.ImplementationTitle)
			}

			if r.ArchiveInfo.Manifest.ImplementationVersion != "" {
				p("| Implementation-Version | %s |", r.ArchiveInfo.Manifest.ImplementationVersion)
			}
		}

		if r.ArchiveInfo.POM != nil {
			p("| Maven Coordinates | `%s:%s:%s` |", r.ArchiveInfo.POM.GroupID, r.ArchiveInfo.POM.ArtifactID, r.ArchiveInfo.POM.Version)

			if len(r.ArchiveInfo.POM.Dependencies) > 0 {
				p("| Maven Dependencies | %d |", len(r.ArchiveInfo.POM.Dependencies))
			}
		}

		p("")

		if r.ArchiveInfo.WebXML != nil {
			p("### web.xml")
			p("")

			if len(r.ArchiveInfo.WebXML.Servlets) > 0 {
				p("**Servlets:**")
				p("")
				p("| Name | Class |")
				p("|------|-------|")

				for _, s := range r.ArchiveInfo.WebXML.Servlets {
					p("| %s | `%s` |", s.Name, s.Class)
				}

				p("")
			}

			if len(r.ArchiveInfo.WebXML.Filters) > 0 {
				p("**Filters:**")
				p("")

				for _, f := range r.ArchiveInfo.WebXML.Filters {
					p("- `%s` (%s)", f.Name, f.Class)
				}

				p("")
			}

			if len(r.ArchiveInfo.WebXML.Listeners) > 0 {
				p("**Listeners:**")
				p("")

				for _, l := range r.ArchiveInfo.WebXML.Listeners {
					p("- `%s`", l.Class)
				}

				p("")
			}
		}

		if r.ArchiveInfo.AppXML != nil && len(r.ArchiveInfo.AppXML.Modules) > 0 {
			p("### application.xml Modules")
			p("")
			p("| Type | URI | Context Root |")
			p("|------|-----|-------------|")

			for _, m := range r.ArchiveInfo.AppXML.Modules {
				p("| %s | %s | %s |", m.Type, m.URI, m.ContextRoot)
			}

			p("")
		}

		if r.ArchiveInfo.Patterns != nil {
			p("### Enterprise Patterns")
			p("")
			p("| Pattern | Detected |")
			p("|---------|----------|")
			p("| Servlets | %v |", r.ArchiveInfo.Patterns.HasServlets)
			p("| EJB | %v |", r.ArchiveInfo.Patterns.HasEJB)
			p("| JNDI | %v |", r.ArchiveInfo.Patterns.HasJNDI)
			p("| ClassLoader | %v |", r.ArchiveInfo.Patterns.HasClassLoading)

			if len(r.ArchiveInfo.Patterns.EJBTypes) > 0 {
				p("| EJB Types | %s |", strings.Join(r.ArchiveInfo.Patterns.EJBTypes, ", "))
			}

			p("")
		}
	}

	// Libraries
	if len(r.Libraries) > 0 {
		p("## Detected Libraries")
		p("")

		for _, lib := range r.Libraries {
			p("- %s", lib)
		}

		p("")
	}

	// Subsystems
	if len(r.Subsystems) > 0 {
		p("## Subsystems")
		p("")
		p("| Subsystem | Files | Code | Comments | Blanks | Total |")
		p("|-----------|-------|------|----------|--------|-------|")

		for _, sub := range r.Subsystems {
			p("| %s | %d | %d | %d | %d | %d |",
				sub.Name, len(sub.Files),
				sub.LOC.Code, sub.LOC.Comments, sub.LOC.Blanks, sub.LOC.Lines)
		}

		p("")
	}

	// Largest files
	if len(r.LargestFiles) > 0 {
		p("## Largest Files (by code lines)")
		p("")
		p("| File | Code | Comments | Total |")
		p("|------|------|----------|-------|")

		limit := min(len(r.LargestFiles), 20)

		for _, f := range r.LargestFiles[:limit] {
			p("| `%s` | %d | %d | %d |", f.Path, f.LOC.Code, f.LOC.Comments, f.LOC.Lines)
		}

		p("")
	}

	// Symbols summary
	if r.Symbols != nil {
		p("## Symbols")
		p("")
		p("| Kind | Count |")
		p("|------|-------|")
		p("| Classes/Structs | %d |", len(r.Symbols.Classes))
		p("| Functions | %d |", len(r.Symbols.Functions))
		p("| Enums | %d |", len(r.Symbols.Enums))
		p("| Namespaces | %d |", len(r.Symbols.Namespaces))
		p("| Typedefs | %d |", len(r.Symbols.Typedefs))
		p("")
	}

	// Hierarchy summary
	if r.Hierarchy != nil && len(r.Hierarchy.ByName) > 0 {
		p("## Class Hierarchy")
		p("")
		p("- Total classes: %d", len(r.Hierarchy.ByName))
		p("- Root classes (no parents): %d", len(r.Hierarchy.Roots))
		p("- Max inheritance depth: %d", r.Hierarchy.Depth())

		candidates := r.Hierarchy.InterfaceCandidates()
		if len(candidates) > 0 {
			p("- Interface candidates (pure virtual): %d", len(candidates))
			p("")
			p("### Interface Candidates")
			p("")

			for _, c := range candidates {
				p("- `%s` (%s) — %d methods", c.Name, c.File, len(c.Methods))
			}
		}

		p("")
	}

	// Include graph summary
	if r.IncludeGraph != nil {
		p("## Include Graph")
		p("")
		p("- Files with includes: %d", len(r.IncludeGraph.Nodes))

		edges := r.IncludeGraph.Edges()
		localEdges := 0
		systemEdges := 0

		for _, e := range edges {
			if e.IsSystem {
				systemEdges++
			} else {
				localEdges++
			}
		}

		p("- Local include edges: %d", localEdges)
		p("- System include edges: %d", systemEdges)

		// Most included files
		type includedCount struct {
			path  string
			count int
		}

		var mostIncluded []includedCount

		for path, node := range r.IncludeGraph.Nodes {
			if len(node.IncludedBy) > 0 {
				mostIncluded = append(mostIncluded, includedCount{path, len(node.IncludedBy)})
			}
		}

		if len(mostIncluded) > 0 {
			// Sort by count descending
			for i := 1; i < len(mostIncluded); i++ {
				for j := i; j > 0 && mostIncluded[j].count > mostIncluded[j-1].count; j-- {
					mostIncluded[j], mostIncluded[j-1] = mostIncluded[j-1], mostIncluded[j]
				}
			}

			p("")
			p("### Most Included Files")
			p("")
			p("| File | Included By |")
			p("|------|-------------|")

			limit := min(len(mostIncluded), 15)

			for _, entry := range mostIncluded[:limit] {
				p("| `%s` | %d files |", entry.path, entry.count)
			}
		}

		p("")
	}

	// Java frameworks
	if len(r.JavaFrameworks) > 0 {
		p("## Detected Java Frameworks")
		p("")

		for _, fw := range r.JavaFrameworks {
			p("- %s", fw)
		}

		p("")
	}

	// Python frameworks
	if len(r.PyFrameworks) > 0 {
		p("## Detected Python Frameworks")
		p("")

		for _, fw := range r.PyFrameworks {
			p("- %s", fw)
		}

		p("")
	}

	// Python import graph summary
	if r.PyImportGraph != nil {
		p("## Python Import Graph")
		p("")
		p("- Files with imports: %d", len(r.PyImportGraph.Nodes))

		localEdges := 0
		stdlibEdges := 0
		thirdPartyEdges := 0

		for _, node := range r.PyImportGraph.Nodes {
			localEdges += len(node.LocalDeps)
			stdlibEdges += len(node.StdlibDeps)
			thirdPartyEdges += len(node.ThirdParty)
		}

		p("- Local import edges: %d", localEdges)
		p("- Stdlib import edges: %d", stdlibEdges)
		p("- Third-party import edges: %d", thirdPartyEdges)

		// Most imported local files
		type importedCount struct {
			path  string
			count int
		}

		var mostImported []importedCount

		for path, node := range r.PyImportGraph.Nodes {
			if len(node.ImportedBy) > 0 {
				mostImported = append(mostImported, importedCount{path, len(node.ImportedBy)})
			}
		}

		if len(mostImported) > 0 {
			for i := 1; i < len(mostImported); i++ {
				for j := i; j > 0 && mostImported[j].count > mostImported[j-1].count; j-- {
					mostImported[j], mostImported[j-1] = mostImported[j-1], mostImported[j]
				}
			}

			p("")
			p("### Most Imported Modules")
			p("")
			p("| File | Imported By |")
			p("|------|-------------|")

			limit := min(len(mostImported), 15)

			for _, entry := range mostImported[:limit] {
				p("| `%s` | %d files |", entry.path, entry.count)
			}
		}

		p("")
	}

	// Python symbols summary
	if r.PySymbols != nil {
		p("## Python Symbols")
		p("")
		p("| Kind | Count |")
		p("|------|-------|")
		p("| Classes | %d |", len(r.PySymbols.Classes))
		p("| Functions | %d |", len(r.PySymbols.Functions))
		p("| Modules | %d |", len(r.PySymbols.Modules))
		p("")
	}

	// Python class hierarchy summary
	if r.PyHierarchy != nil && len(r.PyHierarchy.ByName) > 0 {
		p("## Python Class Hierarchy")
		p("")
		p("- Total classes: %d", len(r.PyHierarchy.ByName))
		p("- Root classes (no parents): %d", len(r.PyHierarchy.Roots))
		p("- Max inheritance depth: %d", r.PyHierarchy.Depth())

		candidates := r.PyHierarchy.InterfaceCandidates()
		if len(candidates) > 0 {
			p("- Interface candidates (ABC/Protocol): %d", len(candidates))
			p("")
			p("### Interface Candidates")
			p("")

			for _, c := range candidates {
				p("- `%s` (%s) — %d methods", c.Name, c.File, len(c.Methods))
			}
		}

		p("")
	}

	return nil
}
