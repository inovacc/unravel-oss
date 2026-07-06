/*
Copyright (c) 2026 Security Research
*/

package framework

// ScanResult holds the framework detection results for an APK.
type ScanResult struct {
	Framework   string           `json:"framework"` // "Flutter", "React Native", "Xamarin", ""
	Flutter     *FlutterInfo     `json:"flutter,omitempty"`
	ReactNative *ReactNativeInfo `json:"react_native,omitempty"`
	Xamarin     *XamarinInfo     `json:"xamarin,omitempty"`
}

// FlutterInfo holds Flutter-specific findings.
type FlutterInfo struct {
	EngineVersion    string   `json:"engine_version,omitempty"`
	DartVersion      string   `json:"dart_version,omitempty"`
	IsObfuscated     bool     `json:"is_obfuscated"`
	Plugins          []string `json:"plugins,omitempty"`
	HasAssetManifest bool     `json:"has_asset_manifest"`
	SnapshotFiles    []string `json:"snapshot_files,omitempty"`
	NativeLibs       []string `json:"native_libs,omitempty"`
	ABIs             []string `json:"abis,omitempty"`
}

// ReactNativeInfo holds React Native-specific findings.
type ReactNativeInfo struct {
	JSEngine      string         `json:"js_engine"` // "Hermes", "JSC", "V8", "unknown"
	HermesVersion string         `json:"hermes_version,omitempty"`
	HasJSBundle   bool           `json:"has_js_bundle"`
	JSBundleSize  int64          `json:"js_bundle_size,omitempty"`
	HasSourceMap  bool           `json:"has_source_map"`
	SourceMap     *SourceMapInfo `json:"source_map,omitempty"`
	NativeModules []string       `json:"native_modules,omitempty"`
	NativeLibs    []string       `json:"native_libs,omitempty"`
	ABIs          []string       `json:"abis,omitempty"`
}

// SourceMapInfo holds metadata extracted from JS source map files in the APK.
type SourceMapInfo struct {
	Files       []string `json:"files"`                 // source map file paths in the APK
	Version     int      `json:"version"`               // source map spec version (usually 3)
	SourceCount int      `json:"source_count"`          // number of original source files
	HasSources  bool     `json:"has_sources"`           // sourcesContent array present and non-empty
	TopSources  []string `json:"top_sources,omitempty"` // first 20 source paths (truncated)
}

// XamarinInfo holds Xamarin-specific findings.
type XamarinInfo struct {
	IsXamarinForms bool     `json:"is_xamarin_forms"`
	IsMAUI         bool     `json:"is_maui"`
	HasAOT         bool     `json:"has_aot"`
	Assemblies     []string `json:"assemblies,omitempty"`
	AssemblyCount  int      `json:"assembly_count"`
	NativeLibs     []string `json:"native_libs,omitempty"`
	ABIs           []string `json:"abis,omitempty"`
}
