/*
Copyright (c) 2026 Security Research
*/

package winui

// FrameworkInfo is the canonical layered-detection record (D-01, D-02). Each
// detector contributes a FrameworkInfo for every signal it observes; the
// dissect-level Frameworks slice composes contributions from every detector
// without collapsing duplicates that come from distinct sources.
type FrameworkInfo struct {
	// Name is the framework label (e.g. "WinUI 3", "WindowsAppSDK", "UWP",
	// "WebView2", ".NET").
	Name string `json:"name"`
	// Version is the resolved framework version when known.
	Version string `json:"version,omitempty"`
	// Confidence is one of: "low" | "medium" | "high" | "confirmed" (D-05).
	Confidence string `json:"confidence"`
	// Evidence contains greppable, stable strings explaining why this entry
	// was emitted (e.g. "Microsoft.WinUI 1.5.0", "Microsoft.UI.Xaml.dll",
	// "xmlns:uap").
	Evidence []string `json:"evidence"`
	// Source identifies the detector that produced this entry. One of:
	// "dotnet-deps" | "appx-manifest" | "pe-import" | "file-pattern".
	Source string `json:"source"`
}

// Signal is a single low-level observation from a sub-detector (e.g. a PE
// import scan). Multiple signals may roll up into a FrameworkInfo.
type Signal struct {
	// Kind is one of: "pe-import" | "file-pattern" | "appx-manifest".
	Kind string `json:"kind"`
	// Confidence mirrors the FrameworkInfo level vocabulary (D-05).
	Confidence string `json:"confidence"`
	// Detail is a short human-readable context (matched filename, attr, ...).
	Detail string `json:"detail"`
}

// Result aggregates everything known about a WinUI 3 host application.
// XAMLIndex is forward-declared here and populated by plans 03/04/05.
type Result struct {
	IsWinUI    bool            `json:"is_winui"`
	Frameworks []FrameworkInfo `json:"frameworks,omitempty"`
	Signals    []Signal        `json:"signals,omitempty"`
	XAMLIndex  *XAMLIndex      `json:"xaml_index,omitempty"`
	Errors     []string        `json:"errors,omitempty"`
}

// XAMLIndex is a forward-declared index of XAML resources discovered during
// analysis. Plan 01 leaves it empty; plans 03/04/05 populate Entries. The
// Errors slice captures top-level walker audit notices (symlink rejections,
// directory-level errors that aren't bound to a single entry).
type XAMLIndex struct {
	Entries []XAMLEntry `json:"entries"`
	Errors  []string    `json:"errors,omitempty"`
}

// XAMLEntry describes a single discovered XAML resource.
//
// Kind values:
//   - "raw"             — raw .xaml file on disk
//   - "xbf"             — .xbf file on disk (decoded by xbf subpackage)
//   - "pe-embedded"     — XML found in a PE RT_RCDATA resource
//   - "pe-embedded-xbf" — XBF magic found in a PE RT_RCDATA resource
//   - "pri"             — string resource enumerated from resources.pri (plan 05)
type XAMLEntry struct {
	Path         string   `json:"path"`
	Kind         string   `json:"kind"`
	ResourceKeys []string `json:"resource_keys,omitempty"`
	ControlTypes []string `json:"control_types,omitempty"`
	Bindings     []string `json:"bindings,omitempty"`
	SourceBytes  int64    `json:"source_bytes,omitempty"`
	Recovered    string   `json:"-"`
	Errors       []string `json:"errors,omitempty"`
	// RawBytesHex is populated when the decoder produced only a partial result
	// (kind="xbf-raw"); it carries the first 256 bytes of the source as hex
	// so downstream tooling can investigate the format without re-reading the
	// input file.
	RawBytesHex string `json:"raw_bytes_hex,omitempty"`
	// AssembliesSizeHint is the assemblies-table size value the decoder
	// computed before bailing out, populated only when kind="xbf-raw" and the
	// failure path involved the assemblies table.
	AssembliesSizeHint uint64 `json:"assemblies_size_hint,omitempty"`
	// VersionHint records "major.minor" when the decoder detects an XBF
	// version it can't fully parse (e.g. v3.x from Win11 25xxx+ apps).
	// Populated by phase 20 (XBF-V3-01) detect-only path; downstream tooling
	// can route v3 entries to a future decoder when it lands in v2.4.
	VersionHint string `json:"version_hint,omitempty"`
}

// validConfidenceLevels enumerates the locked confidence vocabulary (D-05).
// Kept unexported and read via IsValidConfidence so callers cannot mutate the
// canonical set at runtime.
var validConfidenceLevels = map[string]struct{}{
	"low":       {},
	"medium":    {},
	"high":      {},
	"confirmed": {},
}

// IsValidConfidence reports whether s is one of the four locked confidence
// levels. Intended as an advisory helper for downstream validators; emitters
// are not required to call this at write time.
func IsValidConfidence(s string) bool {
	_, ok := validConfidenceLevels[s]
	return ok
}
