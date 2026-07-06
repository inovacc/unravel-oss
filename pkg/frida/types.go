/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"bytes"
	"encoding/json"
)

// Target identifies the runtime/binary format the generated Frida scripts
// will attach to. Different targets produce different hook bodies (Java vs
// native module exports).
type Target string

const (
	TargetAndroid   Target = "android" // JVM hooks via Java.perform
	TargetWindowsPE Target = "windows" // PE hooks via Module.findExportByName + Interceptor.attach
	TargetMachO     Target = "macos"   // Mach-O native hooks (subset of PE flavor for now)
	TargetELF       Target = "linux"   // ELF native hooks (subset of PE flavor for now)
)

// ScriptConfig controls which Frida hook scripts to generate.
type ScriptConfig struct {
	Target         Target   // target runtime; empty defaults to TargetAndroid
	PackageName    string   // target app package name (Android) or process name (PE)
	IncludeSSL     bool     // SSL pinning bypass / TLS frame capture
	IncludeRoot    bool     // root detection bypass (Android only)
	IncludeDebug   bool     // anti-debug bypass
	IncludeNetwork bool     // network traffic capture
	IncludeStorage bool     // shared preferences / SQLite monitoring (Android only)
	IncludeCrypto  bool     // crypto API hooking (BCrypt/DPAPI on Windows)
	IncludeIPC     bool     // intent/broadcast monitoring (Android only)
	CustomHooks    []string // additional class.method or module!export patterns
}

// GeneratedScript holds a single Frida JavaScript file.
type GeneratedScript struct {
	Name        string `json:"name"`        // descriptive name
	Description string `json:"description"` // what this script does
	Content     string `json:"content"`     // JavaScript source
	Category    string `json:"category"`    // "bypass", "monitor", "extract"
}

// AnalysisInput holds the relevant dissect analysis data needed
// to auto-detect which Frida hooks to generate. This avoids an
// import cycle between frida and dissect packages.
type AnalysisInput struct {
	PackageName     string          // from manifest
	HasCertPinning  bool            // from network analysis
	NativeFindings  []NativeFinding // from native analysis
	DEXRiskAPIs     []string        // API strings from DEX risk findings
	HasExportedComp bool            // from manifest components
	Domains         []string        // from network analysis endpoints
}

// NativeFinding is a simplified native analysis finding for auto-detection.
type NativeFinding struct {
	Category string // "root-detection", "anti-debug", etc.
}

// CaptureTemplate holds a single traffic capture configuration file.
type CaptureTemplate struct {
	Name        string `json:"name"`
	Tool        string `json:"tool"` // "mitmproxy", "pcapdroid", "burp", "charles"
	Description string `json:"description"`
	Content     string `json:"content"` // config file content
	Format      string `json:"format"`  // "yaml", "json", "xml", "py"
}

// CaptureResult holds all generated capture templates for a target app.
type CaptureResult struct {
	PackageName string            `json:"package_name"`
	Templates   []CaptureTemplate `json:"templates"`
	Domains     []string          `json:"domains,omitempty"` // extracted from network analysis
}

// GenerateResult holds all generated scripts for a target app.
type GenerateResult struct {
	PackageName      string            `json:"package_name"`
	Scripts          []GeneratedScript `json:"scripts"`
	AutoDetected     []string          `json:"auto_detected,omitempty"`     // what was auto-detected from analysis
	CaptureTemplates *CaptureResult    `json:"capture_templates,omitempty"` // traffic capture configs
}

// --- Phase 9 / FRIDA-01 + FRIDA-02 additive types ---

// Criterion is one validation rule emitted alongside an enriched script
// (Phase 9 D-09). The shape is intentionally a tagged-union by `Op`: only
// the fields relevant to the operator carry data; the rest are omitted.
//
// Match operators (D-09): "equals", "present", "in-range", "regex",
// "frequency-count".
//
//	{op: "equals",          target: "args[0]", value: <any>}
//	{op: "present",         target: "args[0]"}
//	{op: "in-range",        target: "args[0]", min: <num>, max: <num>}
//	{op: "regex",           target: "args[0]", pattern: "..."}
//	{op: "frequency-count", target: "<hook-id>", min: <int>, max: <int>}
type Criterion struct {
	// Op is the match operator name. One of:
	// "equals", "present", "in-range", "regex", "frequency-count".
	Op string `json:"op"`
	// Target is a path expression into the captured event record. Examples:
	// "args[0]", "args[1].field", "return", "<hook-id>".
	Target string `json:"target"`
	// Value is the expected literal for op="equals". Type-free at the JSON
	// boundary; consumers compare via reflect.DeepEqual.
	Value any `json:"value,omitempty"`
	// Pattern is the regex source for op="regex". Must compile via Go's
	// regexp package (RE2).
	Pattern string `json:"pattern,omitempty"`
	// Min/Max define the inclusive bounds for op="in-range" (numeric) and
	// op="frequency-count" (integer count of matched events).
	Min *float64 `json:"min,omitempty"`
	Max *float64 `json:"max,omitempty"`
	// Severity, if set, overrides the default severity of a failure for
	// this criterion (BLOCK / FLAG / PASS — Phase 7 D-11 carry-forward).
	Severity string `json:"severity,omitempty"`
	// Description is human-prose context surfaced in the markdown report.
	Description string `json:"description,omitempty"`
	// Phase distinguishes hook entry vs leave events for frequency-count and
	// equals operators. One of "enter", "leave", or "" (default = enter).
	Phase string `json:"phase,omitempty"`
}

// HasMin reports whether Min was supplied in the source JSON. Used by the
// in-range and frequency-count operators to distinguish "no lower bound"
// from "lower bound = 0".
func (c Criterion) HasMin() bool { return c.Min != nil }

// HasMax reports whether Max was supplied in the source JSON.
func (c Criterion) HasMax() bool { return c.Max != nil }

// HookCriteria groups the Criterion set tied to a single instrumentation
// hook. ID matches the script-side `Interceptor.attach` block label.
type HookCriteria struct {
	ID          string      `json:"id"`
	Description string      `json:"description,omitempty"`
	Criteria    []Criterion `json:"criteria"`
}

// CriteriaFile is the on-disk shape of `<script>.criteria.json`. Schema
// stays at SchemaVersion: 1 — additive only.
//
// Tolerant unmarshal accepts both the canonical shape (`schema_version` +
// `hooks` as a slice with explicit `id` fields) and the legacy 09-02 shape
// (`version` + `hooks` as a map keyed by hook ID).
type CriteriaFile struct {
	SchemaVersion int            `json:"schema_version"`
	Script        string         `json:"script"`
	PackageName   string         `json:"package_name,omitempty"`
	Hooks         []HookCriteria `json:"hooks"`
}

// UnmarshalJSON accepts both wire formats for hooks:
//   - canonical: `"hooks": [{"id": "...", ...}]`
//   - legacy: `"hooks": {"hookID": {...}}` (key becomes ID)
//
// And both keys for version: `schema_version` (canonical) or `version` (legacy).
func (c *CriteriaFile) UnmarshalJSON(data []byte) error {
	var raw struct {
		SchemaVersion int             `json:"schema_version"`
		Version       int             `json:"version"`
		Script        string          `json:"script"`
		PackageName   string          `json:"package_name"`
		Hooks         json.RawMessage `json:"hooks"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	c.SchemaVersion = raw.SchemaVersion
	if c.SchemaVersion == 0 && raw.Version != 0 {
		c.SchemaVersion = raw.Version
	}
	c.Script = raw.Script
	c.PackageName = raw.PackageName

	if len(raw.Hooks) == 0 {
		return nil
	}
	// Try slice first.
	if err := json.Unmarshal(raw.Hooks, &c.Hooks); err == nil {
		return nil
	}
	// Fall back to map shape.
	var asMap map[string]HookCriteria
	if err := json.Unmarshal(raw.Hooks, &asMap); err != nil {
		return err
	}
	c.Hooks = make([]HookCriteria, 0, len(asMap))
	for id, hc := range asMap {
		if hc.ID == "" {
			hc.ID = id
		}
		c.Hooks = append(c.Hooks, hc)
	}
	return nil
}

// EventRecord is the per-event shape produced by `pkg/frida/runner.go`
// (Phase 9 RESEARCH event-log v1). Phase 9 mirrors the relevant subset
// here so the validator (09-02) can decode without depending on runner
// internals.
type EventRecord struct {
	V         int            `json:"v,omitempty"`
	TS        string         `json:"ts,omitempty"`
	HookID    string         `json:"hook_id"`
	Phase     string         `json:"phase,omitempty"`
	Timestamp string         `json:"timestamp,omitempty"`
	Args      []any          `json:"args,omitempty"`
	Ret       any            `json:"ret,omitempty"`
	Return    any            `json:"return,omitempty"`
	Frame     string         `json:"frame,omitempty"`
	Extra     map[string]any `json:"extra,omitempty"`
}

// EnrichedScript is the orchestrator output of `pkg/frida/enrich`.
// ScriptPath and CriteriaPath point at the (possibly atomically rewritten)
// sibling files on disk.
type EnrichedScript struct {
	ScriptPath    string         `json:"script_path"`
	CriteriaPath  string         `json:"criteria_path"`
	Hooks         []HookCriteria `json:"hooks"`
	CacheHit      bool           `json:"cache_hit"`
	SchemaVersion int            `json:"schema_version"`
}
