/*
Copyright (c) 2026 Security Research
*/

// Package winui exposes the top-level WinUI 3 analysis orchestrator. It
// composes the cheap-path detectors (deps.json, PE imports), the XAML
// walker, the XBF decoder, the PE-embedded resource scanner, and the
// resources.pri parser into a single Analyze() call.
//
// Architectural note (cycle break):
// Several child packages under pkg/winui (notably pkg/winui/xaml) already
// import pkg/winui for the canonical type set (FrameworkInfo, XAMLIndex,
// XAMLEntry). To keep the public API at the documented location while
// avoiding a circular import, the heavy-lifting orchestrator body lives
// in pkg/winui/internal/orchestrator and registers itself via an init()
// function into the AnalyzeImpl/QuickImpl function variables below. The
// public Analyze and AnalyzeQuick functions are thin wrappers around
// these variables.
package winui

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/dotnet"
)

// Options configures Analyze. Zero values are replaced with documented
// defaults inside the orchestrator implementation.
type Options struct {
	DecodeXBF       bool
	ScanPEEmbedded  bool
	ParsePRI        bool
	WriteXAMLDir    string
	MaxProfilesScan int // unused for winui; reserved for symmetry
	RejectSymlinks  bool
}

// AnalyzeImpl is the function variable populated by the orchestrator
// sub-package's init(). Analyze forwards to it.
//
// Exposed for the cycle-break; not intended for external override.
var AnalyzeImpl func(path string, opts Options) (*Result, error)

// QuickImpl is the function variable populated by the orchestrator
// sub-package's init(). AnalyzeQuick forwards to it.
var QuickImpl func(path string, deps *dotnet.DepsResult, imports []string) *Result

// Analyze is the top-level WinUI 3 orchestrator.
//
// Best-effort: per-step failures are appended to res.Errors and never
// abort the orchestrator. Path-traversal segments are rejected up front.
func Analyze(path string, opts Options) (*Result, error) {
	if AnalyzeImpl == nil {
		return nil, fmt.Errorf("winui: orchestrator not initialised (blank-import pkg/winui/internal/orchestrator to enable)")
	}
	return AnalyzeImpl(path, opts)
}

// AnalyzeQuick is a lightweight variant of Analyze that skips disk walks
// and PE-embedded scans. Used by dissect supplemental analyzers.
func AnalyzeQuick(path string, deps *dotnet.DepsResult, imports []string) *Result {
	if QuickImpl == nil {
		// Quick mode is fully self-contained; provide a fallback that
		// requires no orchestrator state.
		return quickFallback(deps, imports)
	}
	return QuickImpl(path, deps, imports)
}

// MergeFrameworksDedup appends `add` entries to `base` after dropping
// duplicates keyed by (Name, Source). Detection ORDER preserved (D-02).
// Exposed here as the canonical helper consumed by uwp.Analyze and by
// the dissect orchestrator.
func MergeFrameworksDedup(base, add []FrameworkInfo) []FrameworkInfo {
	if len(add) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base)+len(add))
	for _, fi := range base {
		seen[fi.Name+"|"+fi.Source] = struct{}{}
	}
	for _, fi := range add {
		key := fi.Name + "|" + fi.Source
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		base = append(base, fi)
	}
	return base
}
