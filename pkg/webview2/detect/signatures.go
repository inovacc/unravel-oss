/*
Copyright (c) 2026 Security Research
*/

package detect

// Known DLL names, runtime GUID, file-pattern constants for WebView2 detection.
const (
	// DLLWebView2Loader is the definitive WebView2 host marker (PE import).
	DLLWebView2Loader = "WebView2Loader.dll"
	// DLLLegacyEmbeddedWV is the legacy WinRT WebView — NOT WebView2.
	DLLLegacyEmbeddedWV = "EmbeddedBrowserWebView.dll"
	// FixedRuntimeExeName is the fixed-runtime WebView2 executable bundled with apps.
	FixedRuntimeExeName = "msedgewebview2.exe"
	// EvergreenRuntimeGUID is the WebView2 Evergreen runtime registry GUID.
	EvergreenRuntimeGUID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
)

// ProfileDirNames holds recognized Chromium profile directory names.
var ProfileDirNames = []string{"Default", "Guest Profile", "System Profile"}

// ProfileNumberedPrefix is the prefix for enumerated profiles (Profile 1, Profile 2, ...).
const ProfileNumberedPrefix = "Profile "
