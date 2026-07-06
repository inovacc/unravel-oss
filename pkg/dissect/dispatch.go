/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/detect"
)

// FormatAnalyzer is a function that runs format-specific analysis steps
// on a DissectResult. It receives the file path and options, and populates
// the result struct with findings.
type FormatAnalyzer func(r *DissectResult, path string, opts Options)

// analyzerTable maps file types to their format-specific analyzer functions.
// This replaces the monolithic switch in dispatch() with a lookup table,
// making it easy to add new formats without modifying the dispatch logic.
var analyzerTable = map[detect.FileType]FormatAnalyzer{}

// supplementalTable maps file types to additional analyzers that run after
// the primary analyzer. This allows adding analysis steps (like CSS extraction)
// to existing file types without overwriting the primary analyzer.
var supplementalTable = map[detect.FileType][]FormatAnalyzer{}

// ObfuscationRearmHook is the reverse-registration seam for the AI-assisted
// deobfuscation rearm. pkg/obfuscation/rearm imports pkg/dissect (for
// DissectResult), so dissect cannot import rearm directly without an import
// cycle. Instead rearm.init() installs its orchestrator here, and the
// dissect supplemental analyzer (analyze_obfuscation_rearm.go) builds the
// AI beautifier closure and invokes this hook. nil hook => no-op.
//
// beautify mirrors rearm.Beautifier.Beautify; it stays in dissect so the
// MCP-only ai.NewClient construction lives only in pkg/dissect.
var ObfuscationRearmHook func(ctx context.Context, r *DissectResult, beautify func(ctx context.Context, prompt, input string) (string, error))

// RegisterAnalyzer registers a format analyzer for one or more file types.
// Called from init() functions in per-format analyzer files.
func RegisterAnalyzer(fn FormatAnalyzer, types ...detect.FileType) {
	for _, ft := range types {
		analyzerTable[ft] = fn
	}
}

// RegisterSupplementalAnalyzer registers an additional analyzer that runs
// after the primary analyzer for the given file types. Multiple supplemental
// analyzers can be registered per type.
func RegisterSupplementalAnalyzer(fn FormatAnalyzer, types ...detect.FileType) {
	for _, ft := range types {
		supplementalTable[ft] = append(supplementalTable[ft], fn)
	}
}

// dispatchByTable looks up the analyzer for the given file type and runs it,
// followed by any supplemental analyzers. Returns true if a primary analyzer
// was found and executed.
func dispatchByTable(r *DissectResult, path string, ft detect.FileType, opts Options) bool {
	fn, ok := analyzerTable[ft]
	if !ok {
		return false
	}
	endPrimary := stageTimer("analyzer", string(ft))
	fn(r, path, opts)
	endPrimary("result_count", analysisResultCount(r))

	// Run supplemental analyzers after the primary.
	for _, sfn := range supplementalTable[ft] {
		endSupp := stageTimer("analyzer_supplemental", string(ft))
		sfn(r, path, opts)
		endSupp("result_count", analysisResultCount(r))
	}

	return true
}

// analysisResultCount returns the number of accumulated analysis results in a
// nil-safe way (AnalysisResults is a pointer and may be unset). Used only for
// an observability end field — never affects extraction behavior.
func analysisResultCount(r *DissectResult) int {
	if r == nil || r.AnalysisResults == nil {
		return 0
	}
	return r.AnalysisResults.Count()
}

// AnalyzerCount returns the number of registered format analyzers (for testing).
func AnalyzerCount() int {
	return len(analyzerTable)
}

// HasAnalyzer returns true if a format analyzer is registered for the given type (for testing).
func HasAnalyzer(ft detect.FileType) bool {
	_, ok := analyzerTable[ft]
	return ok
}
