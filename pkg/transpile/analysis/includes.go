package analysis

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/prompt"
)

// IncludeGraph represents the include dependency graph of a C++ codebase.
type IncludeGraph struct {
	Nodes map[string]*IncludeNode `json:"nodes"` // keyed by relative path
}

// IncludeNode represents a file in the include graph.
type IncludeNode struct {
	File       *SourceFile `json:"file"`
	Includes   []string    `json:"includes"`              // raw include paths
	IncludedBy []string    `json:"included_by,omitempty"` // relative paths of files including this one
	Libraries  []string    `json:"libraries,omitempty"`   // detected library names
	LocalDeps  []string    `json:"local_deps,omitempty"`  // resolved local include paths
	SystemDeps []string    `json:"system_deps,omitempty"` // unresolved system includes
}

// IncludeEdge represents a directed edge in the include graph.
type IncludeEdge struct {
	From     string `json:"from"`     // relative path of including file
	To       string `json:"to"`       // include path (raw)
	Resolved string `json:"resolved"` // resolved relative path (empty if system)
	IsSystem bool   `json:"is_system"`
	Library  string `json:"library,omitempty"` // detected library name
}

// BuildIncludeGraph constructs an include dependency graph from source files.
// It resolves local includes relative to the source tree and maps system
// includes to library names using the existing prompt.MapIncludeToRule.
func BuildIncludeGraph(files []*SourceFile, root string) *IncludeGraph {
	graph := &IncludeGraph{
		Nodes: make(map[string]*IncludeNode, len(files)),
	}

	// Build a set of known file paths for local resolution
	knownFiles := make(map[string]*SourceFile, len(files))
	for _, f := range files {
		knownFiles[f.RelPath] = f
		// Also index by basename for #include "header.h" resolution
		base := filepath.Base(f.RelPath)
		if _, exists := knownFiles[base]; !exists {
			knownFiles[base] = f
		}
	}

	// Process each file
	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}

		source := string(data)
		includes := prompt.DetectIncludes(source)

		node := &IncludeNode{
			File:     f,
			Includes: includes,
		}

		libSeen := make(map[string]struct{})

		for _, inc := range includes {
			resolved := resolveInclude(inc, f.RelPath, knownFiles)

			if resolved != "" {
				node.LocalDeps = append(node.LocalDeps, resolved)
			} else {
				node.SystemDeps = append(node.SystemDeps, inc)
			}

			lib := prompt.MapIncludeToRule(inc)
			if lib != "" {
				if _, ok := libSeen[lib]; !ok {
					libSeen[lib] = struct{}{}
					node.Libraries = append(node.Libraries, lib)
				}
			}
		}

		graph.Nodes[f.RelPath] = node
	}

	// Build reverse edges (IncludedBy)
	for relPath, node := range graph.Nodes {
		for _, dep := range node.LocalDeps {
			if target, ok := graph.Nodes[dep]; ok {
				target.IncludedBy = append(target.IncludedBy, relPath)
			}
		}
	}

	return graph
}

// Edges returns all edges in the include graph.
func (g *IncludeGraph) Edges() []IncludeEdge {
	var edges []IncludeEdge

	for relPath, node := range g.Nodes {
		for _, inc := range node.Includes {
			edge := IncludeEdge{
				From: relPath,
				To:   inc,
			}

			resolved := ""

			for _, dep := range node.LocalDeps {
				if strings.HasSuffix(dep, inc) || filepath.Base(dep) == filepath.Base(inc) {
					resolved = dep
					break
				}
			}

			if resolved != "" {
				edge.Resolved = resolved
			} else {
				edge.IsSystem = true
			}

			edge.Library = prompt.MapIncludeToRule(inc)
			edges = append(edges, edge)
		}
	}

	return edges
}

// resolveInclude tries to find a local file matching the include path.
func resolveInclude(includePath, fromRelPath string, knownFiles map[string]*SourceFile) string {
	// Try relative to the including file's directory
	dir := filepath.Dir(fromRelPath)

	candidate := filepath.ToSlash(filepath.Join(dir, includePath))
	if _, ok := knownFiles[candidate]; ok {
		return candidate
	}

	// Try from root
	if _, ok := knownFiles[includePath]; ok {
		return includePath
	}

	// Try basename match
	base := filepath.Base(includePath)
	if f, ok := knownFiles[base]; ok {
		return f.RelPath
	}

	return ""
}
