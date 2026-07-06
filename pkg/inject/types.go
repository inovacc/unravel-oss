/*
Copyright (c) 2026 Security Research
*/
package inject

import (
	"context"
	"time"
)

// Framework identifies the desktop UI framework a seam belongs to.
type Framework string

const (
	FrameworkElectron Framework = "electron"
	FrameworkTauri    Framework = "tauri"
	FrameworkWebView2 Framework = "webview2"
	FrameworkHybrid   Framework = "hybrid"
	FrameworkMacOS    Framework = "macos"
	FrameworkLinux    Framework = "linux"
)

// Confidence is the three-tier scoring band defined in 16-CONTEXT D-03.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// EvidenceType enumerates the artifact classes a scanner may attach to a seam.
type EvidenceType string

const (
	EvidenceFileContent EvidenceType = "file-content"
	EvidencePEImport    EvidenceType = "pe-import"
	EvidenceManifest    EvidenceType = "manifest-field"
	EvidenceConfigKey   EvidenceType = "config-key"
)

// Evidence is a single artifact pointer that supports a Seam.
type Evidence struct {
	Type    EvidenceType `json:"type"`
	Path    string       `json:"path"`
	Snippet string       `json:"snippet,omitempty"`
}

// Seam is one code-injection surface discovered by a scanner.
type Seam struct {
	Kind             string     `json:"kind"`
	Confidence       Confidence `json:"confidence"`
	Framework        Framework  `json:"framework"`
	Evidence         []Evidence `json:"evidence"`
	ReachableRuntime bool       `json:"reachable_runtime"`
	Notes            string     `json:"notes,omitempty"`
	SigningBlocks    []string   `json:"signing_blocks,omitempty"`

	// PtraceEligibleBinary indicates whether this binary's static
	// attributes permit a Frida ptrace attach. nil means "attrs unreadable
	// / not applicable" (e.g., Mach-O / PE seams). Host policy
	// (kernel.yama.ptrace_scope) is a runtime concern and explicitly NOT
	// captured here — see PtraceEligibleBinaryNote and
	// pkg/inject/linux/SCHEMA.md.
	PtraceEligibleBinary *bool `json:"ptrace_eligible_binary,omitempty"`

	// PtraceFlags is an advisory list of binary attrs observed during
	// classification (e.g., "pt_gnu_stack_exec", "non_pie",
	// "static_linkage"). These do NOT gate PtraceEligibleBinary — they
	// are informational only.
	PtraceFlags []string `json:"ptrace_flags,omitempty"`

	// PtraceEligibleBinaryNote carries the fixed Phase 25 D-14 disclaimer
	// text that the host-side ptrace_scope policy is a runtime concern.
	PtraceEligibleBinaryNote string `json:"ptrace_eligible_binary_note,omitempty"`
}

// ArchReport groups seams discovered for a single Mach-O slice. For
// single-arch (thin) binaries Arches contains one entry. For Windows /
// Linux scanners that do not split per-arch, Arches stays nil and
// consumers fall back to the top-level Seams field (D-23, back-compat).
type ArchReport struct {
	Arch  string `json:"arch"`
	Seams []Seam `json:"seams"`
}

// Summary aggregates seam counts by kind and confidence.
type Summary struct {
	TotalSeams   int            `json:"total_seams"`
	ByKind       map[string]int `json:"by_kind"`
	ByConfidence map[string]int `json:"by_confidence"`
}

// ScanResult is the top-level output written to security/injection_seams.json.
type ScanResult struct {
	GeneratedAt string    `json:"generated_at"`
	Framework   Framework `json:"framework"`
	Seams       []Seam    `json:"seams"`
	Summary     Summary   `json:"summary"`
	// Arches is populated by per-arch scanners (currently macOS fat
	// binaries). Empty/omitted for single-arch consumers — they read Seams.
	Arches []ArchReport `json:"arches,omitempty"`
}

// Scanner is the contract per-framework packages implement and register via
// RegisterScanner in their init().
type Scanner interface {
	Framework() Framework
	Detect(appDir string) bool
	Scan(ctx context.Context, appDir string) ([]Seam, error)
}

// ---- Phase 46 active-injection types (Plan 46-02) ---------------------------

// InjectMethod identifies the active-injection backend a caller selects.
// Tauri intentionally has no constant — Inject returns ErrTauriUnsupported
// when a Tauri target is detected.
type InjectMethod string

const (
	// MethodCDP attaches to a running Electron renderer via Chrome DevTools
	// Protocol on a caller-supplied port. Requires the target to have been
	// launched with --remote-debugging-port=N.
	MethodCDP InjectMethod = "cdp"

	// MethodASAR repatches an Electron app's app.asar to include a preload
	// script that injects on next launch. Implemented in Plan 46-01 and
	// wired through the asarRepatcher hook in inject_active.go.
	MethodASAR InjectMethod = "asar"
)

// InjectOpts is the caller-supplied configuration for an Inject call.
//
// Confirmed must be set true by the caller as defense-in-depth — even if a
// CLI/MCP gate is bypassed, the library refuses to do anything destructive
// without an explicit consent boolean.
type InjectOpts struct {
	Method     InjectMethod
	Script     []byte
	ScriptName string
	World      string // "main" (default) or "isolated"
	Persistent bool   // CDP: addScriptToEvaluateOnNewDocument vs Runtime.evaluate
	CDPPort    int    // required when Method == MethodCDP
	ASARPath   string // required when Method == MethodASAR; path to app.asar
	Confirmed  bool   // explicit consent — required, no default-on
}

// InjectResult is the per-call outcome record. ScriptHash is the SHA-256 of
// the script bytes (hex). OutputPath is set only for ASAR mode (the sibling
// .injected.asar that 46-01 produces).
type InjectResult struct {
	Method     InjectMethod
	ScriptHash string
	TargetPath string
	StartedAt  time.Time
	FinishedAt time.Time
	Persistent bool
	OutputPath string
}

// Sentinel errors returned by Inject.
var (
	// ErrConsentRequired is returned when InjectOpts.Confirmed is false.
	ErrConsentRequired = errInject("inject: explicit consent required (set InjectOpts.Confirmed = true)")

	// ErrTauriUnsupported is returned when the target is detected as Tauri.
	// Active injection on Tauri is a known Phase 46 gap — see ROADMAP backlog.
	ErrTauriUnsupported = errInject("inject: Tauri active injection is not supported (Phase 46 known gap)")

	// ErrInjectMethodUnknown is returned when InjectOpts.Method is empty or
	// not one of the registered methods.
	ErrInjectMethodUnknown = errInject("inject: unknown InjectMethod (expected MethodCDP or MethodASAR)")
)

// errInject is a tiny string-error type used for the sentinel values above so
// they remain comparable via errors.Is without pulling in fmt.Errorf wrapping.
type errInject string

func (e errInject) Error() string { return string(e) }
