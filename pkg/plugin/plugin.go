// Package plugin defines the analyzer plugin interface for unravel.
// Plugins implement the Analyzer interface to add support for new file formats
// or analysis capabilities. The interface is designed to be fronted by gRPC
// in a future phase without breaking existing in-process plugins.
package plugin

import (
	"github.com/inovacc/unravel-oss/pkg/detect"
)

// Analyzer is the interface that all analysis plugins must implement.
type Analyzer interface {
	// Name returns the plugin's unique identifier (e.g., "android", "ios", "npm").
	Name() string

	// Version returns the plugin version (semver).
	Version() string

	// Description returns a human-readable description.
	Description() string

	// CanHandle returns true if this plugin can analyze the given file.
	CanHandle(path string, result *detect.DetectResult) bool

	// Analyze runs the analysis and returns a JSON-serializable result.
	Analyze(path string, opts AnalyzeOpts) (any, error)

	// Extract extracts contents to outputDir (optional — return nil if not applicable).
	Extract(path string, outputDir string) error

	// SupportedTypes returns the file types this plugin handles.
	SupportedTypes() []detect.FileType
}

// AnalyzeOpts configures analysis behavior.
type AnalyzeOpts struct {
	Verbose     bool   `json:"verbose"`
	OutputDir   string `json:"output_dir,omitempty"`
	Deobfuscate bool   `json:"deobfuscate"`
	AIAnalysis  bool   `json:"ai_analysis"`
}

// Manifest describes a plugin's metadata for registration and discovery.
type Manifest struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Description    string   `json:"description"`
	Author         string   `json:"author,omitempty"`
	MinUnravelVer  string   `json:"min_unravel_version,omitempty"`
	SupportedTypes []string `json:"supported_types"`
	MCPTools       []string `json:"mcp_tools,omitempty"`
	Commands       []string `json:"commands,omitempty"`
}

// ManifestFrom builds a Manifest from an Analyzer.
func ManifestFrom(a Analyzer) Manifest {
	types := make([]string, len(a.SupportedTypes()))
	for i, t := range a.SupportedTypes() {
		types[i] = string(t)
	}
	return Manifest{
		Name:           a.Name(),
		Version:        a.Version(),
		Description:    a.Description(),
		SupportedTypes: types,
	}
}
