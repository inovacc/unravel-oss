/*
Copyright (c) 2026 Security Research
*/

package webview2

// Result aggregates everything known about a WebView2 host application.
// Per-profile extraction blocks (ProfileData) reference analyze-owned
// types kept separate to avoid an import cycle with the extractor layer
// (pkg/cache, pkg/leveldb, pkg/chromium). The field is declared in
// webview2.go alongside the top-level Analyze entrypoint.
type Result struct {
	IsWebView2 bool          `json:"is_webview2"`
	Signals    []Signal      `json:"signals,omitempty"`
	Runtime    RuntimeInfo   `json:"runtime"`
	UDFs       []UDFInfo     `json:"udfs,omitempty"`
	Profiles   []ProfileInfo `json:"profiles,omitempty"`
	Errors     []string      `json:"errors,omitempty"`
	// ProfileData is populated by webview2.Analyze. Its element type
	// (analyze.ProfileBlock) is declared in the analyze subpackage; we
	// declare the field as []any here so types.go remains dependency-free.
	// Callers should type-assert to []analyze.ProfileBlock.
	ProfileData []any `json:"profile_data,omitempty"`
	// RecoveredJS holds JS *source* recovered from each profile's V8 Code
	// Cache / Service Worker ScriptCache (84-02). Element type is
	// analyze.RecoveredJSEntry, declared as []any so types.go stays
	// dependency-free (mirrors ProfileData). Empty when no cache tree is
	// present (analyzed-empty, never synthesized).
	RecoveredJS []any `json:"recovered_js,omitempty"`
	// RecoveredCSS holds CSS source recovered from the HTTP cache. Element
	// type is analyze.RecoveredCSSEntry, declared as []any so types.go
	// stays dependency-free (mirrors RecoveredJS). Empty when no cache
	// tree is present (analyzed-empty, never synthesized).
	RecoveredCSS []any `json:"recovered_css,omitempty"`
	// Analyzed is the Phase-83 honest-empty sentinel. It is stamped true by
	// every post-Phase-83 webview2.Analyze dispatch (analyze_uwp.go), even
	// when zero EBWebView profiles exist (D-08 honest-empty). The dissect
	// cache-staleness gate keys off this marker — NOT off Profiles or a
	// nil WebView2Info — so a freshly analyzed profile-less MSIX/UWP entry
	// is honored on subsequent runs (one-time re-analysis, not a loop)
	// while a pre-83 / never-analyzed entry (WebView2Info==nil) is still
	// re-dispatched exactly once.
	Analyzed bool `json:"analyzed,omitempty"`
}

// Signal is a single detection observation. Multiple signals may be produced
// for a single target; IsWebView2 becomes true only when at least one positive
// signal is present.
type Signal struct {
	// Kind is one of: "pe-import" | "file-pattern" | "registry" | "legacy-webview".
	Kind string `json:"kind"`
	// Confidence is in the range 0..1.
	Confidence float64 `json:"confidence"`
	// Detail gives a short human-readable context (matched filename, path, etc.).
	Detail string `json:"detail,omitempty"`
}

// RuntimeInfo describes the WebView2 runtime targeted by the host.
type RuntimeInfo struct {
	// Mode is one of: "evergreen" | "fixed" | "unknown".
	Mode       string `json:"mode"`
	Version    string `json:"version,omitempty"`
	InstallDir string `json:"install_dir,omitempty"`
}

// UDFInfo describes a candidate WebView2 User Data Folder.
type UDFInfo struct {
	Path string `json:"path"`
	// Source is one of: "default" | "localappdata" | "registry-policy" | "user-override".
	Source string `json:"source"`
	Exists bool   `json:"exists"`
}

// ProfileInfo names a Chromium profile within a UDF.
type ProfileInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
}
