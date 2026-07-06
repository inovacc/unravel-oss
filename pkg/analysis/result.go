/*
Copyright (c) 2026 Security Research
*/

// Package analysis defines the unified Result interface for all format analyzers.
// Each analyzer (Android, Java, npm, etc.) wraps its result type to implement
// this interface, enabling generic handling in dissect, knowledge extraction,
// MCP tools, and output formatting without nil-field checks.
package analysis

import (
	"encoding/json"

	"github.com/inovacc/unravel-oss/pkg/detect"
)

// Result is the common interface implemented by all format analyzer results.
// It provides generic access to analysis findings without requiring consumers
// to know the specific analyzer type.
type Result interface {
	// FormatType returns the detected file type this result corresponds to.
	FormatType() detect.FileType

	// AnalyzerName returns the name of the analyzer that produced this result
	// (e.g., "android", "java", "npm").
	AnalyzerName() string

	// AppName returns the application/package name if detectable.
	AppName() string

	// Version returns the application/package version if detectable.
	Version() string

	// Summary returns a one-line human-readable summary of findings.
	Summary() string

	// RiskScore returns a 0-100 risk score, or -1 if not applicable.
	RiskScore() int

	// JSON returns the full result serialized as JSON bytes.
	JSON() ([]byte, error)

	// Raw returns the underlying typed result for consumers that need
	// format-specific access (e.g., *apk.InfoResult, *npm.AnalysisResult).
	Raw() any
}

// ResultSet holds multiple analysis results from a single dissect run.
// It provides helper methods for querying results by type or name.
type ResultSet struct {
	Results []Result `json:"results"`
}

// Add appends a result to the set.
func (rs *ResultSet) Add(r Result) {
	rs.Results = append(rs.Results, r)
}

// FindByAnalyzer returns the first result from the named analyzer.
func (rs *ResultSet) FindByAnalyzer(name string) Result {
	for _, r := range rs.Results {
		if r.AnalyzerName() == name {
			return r
		}
	}
	return nil
}

// FindByType returns all results for the given file type.
func (rs *ResultSet) FindByType(ft detect.FileType) []Result {
	var out []Result
	for _, r := range rs.Results {
		if r.FormatType() == ft {
			out = append(out, r)
		}
	}
	return out
}

// Count returns the number of results.
func (rs *ResultSet) Count() int {
	return len(rs.Results)
}

// Names returns the analyzer names of all results.
func (rs *ResultSet) Names() []string {
	names := make([]string, len(rs.Results))
	for i, r := range rs.Results {
		names[i] = r.AnalyzerName()
	}
	return names
}

// Wrap creates a simple Result wrapper around any struct with basic metadata.
// Use this for quick adapter creation when a full typed wrapper isn't needed.
func Wrap(analyzerName string, ft detect.FileType, appName, version, summary string, riskScore int, raw any) Result {
	return &wrappedResult{
		analyzerName: analyzerName,
		formatType:   ft,
		appName:      appName,
		version:      version,
		summary:      summary,
		riskScore:    riskScore,
		raw:          raw,
	}
}

type wrappedResult struct {
	analyzerName string
	formatType   detect.FileType
	appName      string
	version      string
	summary      string
	riskScore    int
	raw          any
}

func (w *wrappedResult) FormatType() detect.FileType { return w.formatType }
func (w *wrappedResult) AnalyzerName() string        { return w.analyzerName }
func (w *wrappedResult) AppName() string             { return w.appName }
func (w *wrappedResult) Version() string             { return w.version }
func (w *wrappedResult) Summary() string             { return w.summary }
func (w *wrappedResult) RiskScore() int              { return w.riskScore }
func (w *wrappedResult) Raw() any                    { return w.raw }

func (w *wrappedResult) JSON() ([]byte, error) {
	return json.Marshal(w.raw)
}
