/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
)

// Engine selects the decompilation backend behind the Decompiler.
type Engine int

const (
	// EngineNative is the pure-Go ECMA-335 reader (pkg/dotnet/clr). Default
	// for the capture/KB path: always available, no external tool.
	EngineNative Engine = iota
	// EngineILSpy shells out to ilspycmd, emitting raw .cs under <out>/raw/.
	// Drives the AI-beautify supplemental + orchestrator/provenance.
	EngineILSpy
)

// ErrUnknownEngine is returned by NewWithEngine for an unrecognised Engine.
var ErrUnknownEngine = errors.New("unknown decompiler engine")

// Mode selects the input dispatch mode.
type Mode int

const (
	// ModeAuto stats the input and picks Single (file) or FullApp (dir).
	ModeAuto Mode = iota
	// ModeSingle decompiles a single assembly file.
	ModeSingle
	// ModeFullApp walks deps.json and decompiles every eligible assembly.
	ModeFullApp
)

// Options configures a Decompiler.Run invocation.
type Options struct {
	Input            string        `json:"input"`
	Output           string        `json:"output"`
	IncludeFramework bool          `json:"include_framework"`
	Concurrency      int           `json:"concurrency"`
	Timeout          time.Duration `json:"timeout"`
	Mode             Mode          `json:"mode"`
	// Sink receives native per-type modules in FullApp/capture mode. MANDATORY
	// for ModeFullApp on the native engine; ignored for EngineILSpy.
	Sink Sink `json:"-"`
}

// AssemblyResult records the outcome of decompiling a single assembly.
type AssemblyResult struct {
	Name        string           `json:"name"`
	Path        string           `json:"path"`
	OutDir      string           `json:"out_dir"`
	Decompiled  bool             `json:"decompiled"`
	FileCount   int              `json:"file_count"`
	ModuleCount int              `json:"module_count"` // native: per-type modules
	SHA256      string           `json:"sha256,omitempty"`
	Err         string           `json:"err,omitempty"`
	Modules     []clr.TypeModule `json:"-"` // ModeSingle buffer only (INT-4 cap)
}

// Result is the aggregate decompiler run summary.
type Result struct {
	ILSpyVersion string           `json:"ilspy_version"`
	Engine       Engine           `json:"engine"`
	StartedAt    time.Time        `json:"started_at"`
	EndedAt      time.Time        `json:"ended_at"`
	Assemblies   []AssemblyResult `json:"assemblies"`
	Errors       []string         `json:"errors,omitempty"`
}

// sanitizeOutPath cleans candidate, rejects ".." traversal, makes it absolute,
// and verifies it resolves under root (when root is non-empty).
//
// Per D-04 / D-17 / T-05-01 mitigation. Called at every IO boundary.
func sanitizeOutPath(root, candidate string) (string, error) {
	if candidate == "" {
		return "", fmt.Errorf("sanitize: empty path")
	}

	// Reject traversal markers in the original input early.
	if strings.Contains(candidate, "..") {
		return "", fmt.Errorf("sanitize: path traversal rejected: %q", candidate)
	}

	cleaned := filepath.Clean(candidate)

	// Re-check post-clean (Clean can reduce hidden traversals).
	for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if part == ".." {
			return "", fmt.Errorf("sanitize: path traversal rejected after clean: %q", candidate)
		}
	}

	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("sanitize: abs %q: %w", candidate, err)
	}

	if root != "" {
		rootAbs, err := filepath.Abs(filepath.Clean(root))
		if err != nil {
			return "", fmt.Errorf("sanitize: abs root %q: %w", root, err)
		}

		rel, err := filepath.Rel(rootAbs, abs)
		if err != nil {
			return "", fmt.Errorf("sanitize: rel %q under %q: %w", abs, rootAbs, err)
		}

		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("sanitize: path %q escapes root %q", abs, rootAbs)
		}
	}

	return abs, nil
}
