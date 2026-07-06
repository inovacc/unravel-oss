/*
Copyright (c) 2026 Security Research
*/

// Package uwp exposes the top-level UWP analysis orchestrator. It
// composes manifest extraction + summarisation, the capability-scoring
// rubric, optional XAML analysis (via pkg/winui), and DPAPI-blob
// flagging into a single Analyze() call.
//
// D-18 carry-forward: DPAPI-protected blobs found in UWP user-data are
// flagged with provenance only, never decrypted in-pipeline. This file
// MUST NOT import pkg/dpapi for decryption (DPAPIFlagOnly enforcement).
package uwp

import (
	"fmt"
)

// Options configures Analyze.
type Options struct {
	ExtractIfArchive  bool
	ScoreCapabilities bool
	AnalyzeXAML       bool
	DPAPIFlagOnly     bool
	RubricPath        string
	RejectSymlinks    bool
}

// AnalyzeImpl is the function variable populated by the orchestrator
// sub-package's init(). Analyze forwards to it. Cycle break: see
// pkg/winui/winui.go for the same pattern.
var AnalyzeImpl func(path string, opts Options) (*Result, error)

// Analyze is the top-level UWP orchestrator.
//
// D-18: DPAPI blobs are flagged via provenance, never decrypted.
func Analyze(path string, opts Options) (*Result, error) {
	if AnalyzeImpl == nil {
		return nil, fmt.Errorf("uwp: orchestrator not initialised (blank-import pkg/uwp/internal/orchestrator to enable)")
	}
	return AnalyzeImpl(path, opts)
}

// AnalyzeQuick is a manifest-only variant used by dissect supplemental
// analyzers; it skips XAML walking and capability scoring.
func AnalyzeQuick(path string) (*Result, error) {
	return Analyze(path, Options{ExtractIfArchive: true})
}

// DPAPIBlob records a DPAPI-protected blob discovered during analysis.
// D-18: only the first 8 bytes (magic header) are retained for
// provenance. The full blob is NEVER copied or decrypted.
type DPAPIBlob struct {
	Path  string `json:"path"`
	Bytes []byte `json:"bytes,omitempty"` // first 8 bytes (header only)
	Note  string `json:"note,omitempty"`
}

// DPAPIMagic is the standard CryptProtectData header magic; matches
// any blob whose first 8 bytes equal this sequence (Windows DPAPI v1).
var DPAPIMagic = []byte{0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF}

// Sentinel: ensure pkg/dpapi is NOT importable from this file. The
// following compile-time guard intentionally references no decrypt API.
// If a future change adds an import for pkg/dpapi, the D-18 acceptance
// test will fail.
const _D18Sentinel = "DPAPIFlagOnly: never decrypt in-pipeline"
