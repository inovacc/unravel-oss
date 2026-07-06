/*
Copyright (c) 2026 Security Research
*/

// Package bundle reconstructs JS bundles produced by webpack / Vite /
// esbuild / Rollup back into per-module files when source maps are
// absent. Strategy is the hybrid pattern-first / MCP-fallback /
// brace-balance-validate of D-11.
package bundle

// Kind enumerates supported bundlers.
type Kind string

const (
	KindWebpack Kind = "webpack"
	KindVite    Kind = "vite"
	KindEsbuild Kind = "esbuild"
	KindRollup  Kind = "rollup"
	KindUnknown Kind = "unknown"
)

// ModuleProposal is one candidate per-module split. Start/End are
// inclusive/exclusive byte offsets into the source bundle.
type ModuleProposal struct {
	Start         int    `json:"start"`
	End           int    `json:"end"`
	CandidateName string `json:"candidate_name,omitempty"`
	ModuleID      string `json:"module_id,omitempty"`
	// Source is "pattern" (Pass 1) or "mcp" (Pass 2).
	Source string `json:"source"`
}

// ModuleSet is the result of one recogniser's Match call.
type ModuleSet struct {
	Kind     Kind             `json:"kind"`
	Modules  []ModuleProposal `json:"modules"`
	RunnerUp Kind             `json:"runner_up,omitempty"`
	Evidence []string         `json:"evidence,omitempty"`
}

// Recogniser is the per-bundler pattern interface (Pass 1).
//
// Match returns (set, true) when the recogniser identified its
// fingerprint in src, even when 0 modules were carved (the bundler is
// recognised but the module-extractor failed and Pass 2 should run).
type Recogniser interface {
	Name() Kind
	Match(src []byte) (ModuleSet, bool)
}
