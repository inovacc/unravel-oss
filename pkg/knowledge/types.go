package knowledge

import (
	"time"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/depth"

	// Phase 84 Task 6: blank import installs dissect.ObfuscationRearmHook
	// via rearm.init() so the dissect supplemental analyzer can invoke the
	// AI-assisted deobfuscation orchestrator without an import cycle.
	_ "github.com/inovacc/unravel-oss/pkg/obfuscation/rearm"
)

type KnowledgeResult struct {
	AppName    string        `json:"app_name"`
	Framework  string        `json:"framework"`
	Version    string        `json:"version,omitempty"`
	AnalyzedAt time.Time     `json:"analyzed_at"`
	Duration   time.Duration `json:"duration"`
	SourcePath string        `json:"source_path"`

	Platform    string `json:"platform"`
	PackageID   string `json:"package_id"`
	DisplayName string `json:"display_name"`
	Publisher   string `json:"publisher,omitempty"`

	Communication *CommunicationKnowledge `json:"communication,omitempty"`
	Auth          *AuthKnowledge          `json:"auth,omitempty"`
	UI            *UIKnowledge            `json:"ui,omitempty"`
	IPC           *IPCKnowledge           `json:"ipc,omitempty"`
	Security      *SecurityKnowledge      `json:"security,omitempty"`
	Stealth       *StealthKnowledge       `json:"stealth,omitempty"`
	Telemetry     *TelemetryKnowledge     `json:"telemetry,omitempty"`
	NPM           *NPMKnowledge           `json:"npm,omitempty"`
	Android       *AndroidKnowledge       `json:"android,omitempty"`
	Binary        *BinaryKnowledge        `json:"binary,omitempty"`
	GoBinary      *GoBinaryKnowledge      `json:"go_binary,omitempty"`
	Packaging     *PackagingKnowledge     `json:"packaging,omitempty"`
	Package       *PackageKnowledge       `json:"package,omitempty"`
	IOS           *IOSKnowledge           `json:"ios,omitempty"`
	CSS           *CSSKnowledge           `json:"css,omitempty"`
	SourceFiles   []SourceFile            `json:"source_files,omitempty"`
	DataDir       *DataDirKnowledge       `json:"data_dir,omitempty"`

	// Phase 84 Task 6: AI-assisted deobfuscation rearm report (additive).
	ObfuscationReport *dissect.ObfuscationReport `json:"obfuscation_report,omitempty"`

	// P38 Plan 38-02: WebView2 host coverage (UDF / profiles / cache /
	// preferences). Populated when DissectResult carries WebView2Info.
	WebView2 *WebView2Knowledge `json:"webview2,omitempty"`

	// P38 Plan 38-03: Electron extractor coverage. Populated when
	// AppAnalysis indicates Electron OR ASAR archive is present.
	// Co-exists with Packaging.UWP for hybrid stacks (Electron-MSIX,
	// e.g. Microsoft Teams) per D-38-HYBRID-DUAL-COVERAGE.
	Electron *ElectronKnowledge `json:"electron,omitempty"`

	// P37 Plan 37-03: per-dimension extractor coverage (D-37). Currently
	// populated only for Android (other platforms land in P38+). Empty
	// when Platform is not "android".
	DepthCovered []depth.Dimension `json:"depth_covered,omitempty"`

	// CLRModules carries native pure-Go CLR decompiler output (one TypeModule
	// per TypeDef) copied verbatim from DissectResult.CLRModules. It is the
	// in-memory feed for KB cil-module ingest (no sidecar file); the capture
	// pipeline passes it into ingest.Options.CLRModules. Empty for non-.NET
	// inputs.
	CLRModules []clr.TypeModule `json:"clr_modules,omitempty"`
}

// UWPKnowledge holds UWP / WinUI extractor coverage data (P38 Plan 38-02).
// All fields additive; empty extractor output stays empty per
// D-35-NO-FALLBACK-INFERENCE.
type UWPKnowledge struct {
	AppxManifest    *UWPManifestSummary `json:"appx_manifest,omitempty"`
	Capabilities    []UWPCapability     `json:"capabilities,omitempty"`
	XAMLResources   []ResourceRef       `json:"xaml_resources,omitempty"`
	PRIResources    []ResourceRef       `json:"pri_resources,omitempty"`
	Dependencies    []string            `json:"dependencies,omitempty"`
	SigningChain    []string            `json:"signing_chain,omitempty"`
	Localization    []string            `json:"localization,omitempty"`
	RiskScore       int                 `json:"risk_score"`
	RiskLevel       string              `json:"risk_level,omitempty"`
	WinUIXAML       []ResourceRef       `json:"winui_xaml,omitempty"`
	WinUIXBF        []ResourceRef       `json:"winui_xbf,omitempty"`
	WinUIPRI        []ResourceRef       `json:"winui_pri,omitempty"`
	WinUIPEEmbedded []string            `json:"winui_pe_embedded,omitempty"`
}

// UWPManifestSummary mirrors the AppxManifest summary the pkg/uwp/manifest
// summarizer emits (Identity, target families, application entry points).
type UWPManifestSummary struct {
	PFN            string   `json:"pfn,omitempty"`
	Name           string   `json:"name,omitempty"`
	Publisher      string   `json:"publisher,omitempty"`
	Version        string   `json:"version,omitempty"`
	ProcessorArch  string   `json:"processor_arch,omitempty"`
	TargetFamilies []string `json:"target_families,omitempty"`
	EntryPoints    []string `json:"entry_points,omitempty"`
}

// UWPCapability is one declared capability (foundation / uap* / rescap /
// device / custom). Type encodes the namespace; Risk carries the bucket-derived
// numeric weight (D-38-CAPABILITY-REUSE-PKG-UWP-RISK).
type UWPCapability struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Risk      int    `json:"risk,omitempty"`
}

// ElectronKnowledge holds Electron extractor coverage (P38 Plan 38-03).
// Populated when DissectResult.AppAnalysis or ASARFiles indicate Electron.
// Coexists with Packaging.UWP on hybrid stacks (Electron-MSIX) without
// collision; dimension prefixes (`uwp.*` vs `electron.*`) keep depth_covered
// disambiguated.
type ElectronKnowledge struct {
	ASARFiles          []SourceFileRef      `json:"asar_files,omitempty"`
	JavaScriptImports  []string             `json:"javascript_imports,omitempty"`
	ElectronMain       string               `json:"electron_main,omitempty"`
	RendererProcesses  []string             `json:"renderer_processes,omitempty"`
	IPCChannels        []ElectronIPCChannel `json:"ipc_channels,omitempty"`
	BundledNodeModules []string             `json:"bundled_node_modules,omitempty"`
	SourceMaps         []SourceFileRef      `json:"source_maps,omitempty"`
}

// SourceFileRef is a path-index reference into an ASAR or other archive.
// Per D-37-SOURCE-FILES-PATH-INDEX, never embeds raw bytes.
type SourceFileRef struct {
	Path string `json:"path"`
	Size int64  `json:"size,omitempty"`
	Tag  string `json:"tag,omitempty"`
}

// ElectronIPCChannel mirrors a discovered Electron IPC channel binding.
type ElectronIPCChannel struct {
	Name      string   `json:"name"`
	Direction string   `json:"direction,omitempty"`
	Risk      string   `json:"risk,omitempty"`
	Targets   []string `json:"targets,omitempty"`
}

// WebView2Knowledge holds WebView2 host extractor coverage (P38 Plan 38-02).
type WebView2Knowledge struct {
	UDFPath          string        `json:"udf_path,omitempty"`
	UDFs             []string      `json:"udfs,omitempty"`
	Profiles         []string      `json:"profiles,omitempty"`
	CacheEntries     []ResourceRef `json:"cache_entries,omitempty"`
	PreferencesFlags []string      `json:"preferences_flags,omitempty"`
	RuntimeMode      string        `json:"runtime_mode,omitempty"`
}

type CommunicationKnowledge struct {
	Endpoints          []Endpoint `json:"endpoints,omitempty"`
	Protocols          []string   `json:"protocols,omitempty"`
	DataFormats        []string   `json:"data_formats,omitempty"`
	CertificatePinning bool       `json:"certificate_pinning"`
	CleartextAllowed   bool       `json:"cleartext_allowed"`
}

type Endpoint struct {
	URL        string   `json:"url"`
	Methods    []string `json:"methods,omitempty"`
	Purpose    string   `json:"purpose"`
	AuthType   string   `json:"auth_type,omitempty"`
	DataFormat string   `json:"data_format,omitempty"`
}

type AuthKnowledge struct {
	Methods      []AuthMethod `json:"methods,omitempty"`
	TokenStorage string       `json:"token_storage,omitempty"`
	MFA          bool         `json:"mfa"`
}

type AuthMethod struct {
	Type           string `json:"type"`
	HeaderName     string `json:"header_name,omitempty"`
	Implementation string `json:"implementation,omitempty"`
}

type UIKnowledge struct {
	Framework    string     `json:"framework"`
	Version      string     `json:"version,omitempty"`
	IsSPA        bool       `json:"is_spa"`
	Routes       []AppRoute `json:"routes,omitempty"`
	Components   []string   `json:"components,omitempty"`
	CSSFramework string     `json:"css_framework,omitempty"`
	BuildTool    string     `json:"build_tool,omitempty"`
}

type AppRoute struct {
	Path      string `json:"path"`
	Component string `json:"component,omitempty"`
}

type IPCKnowledge struct {
	Channels  []IPCChannel `json:"channels,omitempty"`
	Protocols []string     `json:"protocols,omitempty"`
}

type IPCChannel struct {
	Name         string   `json:"name"`
	Direction    string   `json:"direction"`
	MessageTypes []string `json:"message_types,omitempty"`
	Privileged   bool     `json:"privileged"`
	RiskLevel    string   `json:"risk_level,omitempty"`
}

type SecurityKnowledge struct {
	RiskScore       int               `json:"risk_score"`
	RiskLevel       string            `json:"risk_level"`
	Settings        []SecuritySetting `json:"settings,omitempty"`
	Vulnerabilities []string          `json:"vulnerabilities,omitempty"`
}

type SecuritySetting struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Safe    bool   `json:"safe"`
	Comment string `json:"comment,omitempty"`
}

type StealthKnowledge struct {
	ScreenCaptureBlock  bool     `json:"screen_capture_block"`
	ScreenShareHide     bool     `json:"screen_share_hide"`
	ProcessHiding       bool     `json:"process_hiding"`
	AntiDebugging       []string `json:"anti_debugging,omitempty"`
	AntiInstrumentation []string `json:"anti_instrumentation,omitempty"`
	CodeObfuscation     string   `json:"code_obfuscation,omitempty"`
}

type TelemetryKnowledge struct {
	Services []TelemetryService `json:"services,omitempty"`
}

type TelemetryService struct {
	Name      string   `json:"name"`
	Category  string   `json:"category,omitempty"`
	Endpoint  string   `json:"endpoint,omitempty"`
	DataTypes []string `json:"data_types,omitempty"`
}

type NPMKnowledge struct {
	Name                  string            `json:"name"`
	Version               string            `json:"version,omitempty"`
	Description           string            `json:"description,omitempty"`
	Repository            string            `json:"repository,omitempty"`
	Homepage              string            `json:"homepage,omitempty"`
	License               string            `json:"license,omitempty"`
	Tarball               string            `json:"tarball,omitempty"`
	SourceMode            string            `json:"source_mode"`
	Binaries              map[string]string `json:"binaries,omitempty"`
	Scripts               map[string]string `json:"scripts,omitempty"`
	Dependencies          map[string]string `json:"dependencies,omitempty"`
	DevDependencies       map[string]string `json:"dev_dependencies,omitempty"`
	NetworkCalls          []string          `json:"network_calls,omitempty"`
	FSAccess              []string          `json:"fs_access,omitempty"`
	ExecCalls             []string          `json:"exec_calls,omitempty"`
	MCPTools              []string          `json:"mcp_tools,omitempty"`
	MCPTransport          string            `json:"mcp_transport,omitempty"`
	MCPSDKVersion         string            `json:"mcp_sdk_version,omitempty"`
	ObfuscationIndicators []string          `json:"obfuscation_indicators,omitempty"`
	SupplyChainRisks      []string          `json:"supply_chain_risks,omitempty"`
	RiskScore             int               `json:"risk_score"`
	RiskFactors           []string          `json:"risk_factors,omitempty"`
}

type DataDirKnowledge struct {
	Path           string            `json:"path"`
	LocalStorage   *LocalStorageData `json:"local_storage,omitempty"`
	SessionStorage *LocalStorageData `json:"session_storage,omitempty"`
	Cache          *CacheData        `json:"cache,omitempty"`
	Cookies        *CookieData       `json:"cookies,omitempty"`
	IndexedDB      *IndexedDBData    `json:"indexeddb,omitempty"`
	DIPS           *DIPSData         `json:"dips,omitempty"`
	Preferences    map[string]any    `json:"preferences,omitempty"`
	AppState       map[string]any    `json:"app_state,omitempty"`
	SecretFindings []SecretFinding   `json:"secret_findings,omitempty"`
}

type LocalStorageData struct {
	Origins []StorageOrigin `json:"origins"`
	Stats   StorageStats    `json:"stats"`
}

type StorageOrigin struct {
	Origin  string         `json:"origin"`
	Entries []StorageEntry `json:"entries"`
}

type StorageEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type CacheData struct {
	Format     string         `json:"format"`
	Domains    map[string]int `json:"domains"`
	Types      map[string]int `json:"content_types"`
	EntryCount int            `json:"entry_count"`
	TotalSize  int64          `json:"total_size"`
	Entries    []CacheItem    `json:"entries,omitempty"`
}

type CacheItem struct {
	URL         string `json:"url"`
	ContentType string `json:"content_type,omitempty"`
	Status      int    `json:"status,omitempty"`
	Size        int64  `json:"size"`
}

type StorageStats struct {
	TotalEntries int `json:"total_entries"`
	OriginCount  int `json:"origin_count"`
}

// CookieData holds parsed Chromium cookies.
type CookieData struct {
	Cookies []CookieEntry  `json:"cookies"`
	Domains map[string]int `json:"domains"`
	Stats   CookieStats    `json:"stats"`
}

type CookieEntry struct {
	Domain   string `json:"domain"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	Expires  string `json:"expires,omitempty"`
}

type CookieStats struct {
	Total       int `json:"total"`
	Secure      int `json:"secure"`
	HttpOnly    int `json:"http_only"`
	DomainCount int `json:"domain_count"`
}

// IndexedDBData holds parsed IndexedDB databases.
type IndexedDBData struct {
	Databases []IDBDatabase `json:"databases"`
	Stats     IDBStats      `json:"stats"`
}

type IDBDatabase struct {
	Origin     string     `json:"origin"`
	Name       string     `json:"name,omitempty"`
	EntryCount int        `json:"entry_count"`
	Entries    []IDBEntry `json:"entries,omitempty"`
}

type IDBEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type IDBStats struct {
	DatabaseCount int `json:"database_count"`
	TotalEntries  int `json:"total_entries"`
}

// DIPSData holds Chromium DIPS (Detect Incidental Party State) storage access logs.
type DIPSData struct {
	Sites []DIPSSite `json:"sites"`
	Total int        `json:"total"`
}

type DIPSSite struct {
	Site             string `json:"site"`
	FirstSiteStorage string `json:"first_site_storage,omitempty"`
	LastSiteStorage  string `json:"last_site_storage,omitempty"`
	FirstInteraction string `json:"first_interaction,omitempty"`
	LastInteraction  string `json:"last_interaction,omitempty"`
}

// AndroidKnowledge holds Android-specific analysis results.
type AndroidKnowledge struct {
	Package     string              `json:"package"`
	VersionCode string              `json:"version_code,omitempty"`
	VersionName string              `json:"version_name,omitempty"`
	MinSDK      string              `json:"min_sdk,omitempty"`
	TargetSDK   string              `json:"target_sdk,omitempty"`
	Permissions []AndroidPermission `json:"permissions,omitempty"`
	Components  []AndroidComponent  `json:"components,omitempty"`
	DeepLinks   []string            `json:"deep_links,omitempty"`
	Secrets     []SecretFinding     `json:"secrets,omitempty"`
	NativeLibs  []NativeLibInfo     `json:"native_libs,omitempty"`
	Obfuscation *ObfuscationInfo    `json:"obfuscation,omitempty"`
	Framework   *AppFrameworkInfo   `json:"framework,omitempty"`
	DEXStats    *DEXStatsInfo       `json:"dex_stats,omitempty"`
	RiskAPIs    []RiskAPIFinding    `json:"risk_apis,omitempty"`

	// P37 Plan 37-02: additive coverage fields wired from pkg/android/*
	// extractors. Empty fields stay empty (D-35-NO-FALLBACK-INFERENCE);
	// gaps surface via DepthCovered ratio per D-37.
	DexClasses     []DexClassRef            `json:"dex_classes,omitempty"`
	DexMethods     []DexMethodRef           `json:"dex_methods,omitempty"`
	Resources      []ResourceRef            `json:"resources,omitempty"`
	Telemetry      []AndroidTelemetrySDK    `json:"telemetry,omitempty"`
	KotlinFeatures []string                 `json:"kotlin_features,omitempty"`
	Network        []AndroidNetworkEndpoint `json:"network,omitempty"`
}

// DexClassRef is a path-only reference to a DEX class entry per
// D-37-SOURCE-FILES-PATH-INDEX (no decompiled bytes inline).
type DexClassRef struct {
	Name       string `json:"name"`
	Superclass string `json:"superclass,omitempty"`
	SourceFile string `json:"source_file,omitempty"`
}

// DexMethodRef is a path-only reference to a DEX method entry.
type DexMethodRef struct {
	ClassName  string `json:"class_name"`
	Name       string `json:"name"`
	Descriptor string `json:"descriptor,omitempty"`
}

// ResourceRef is a path-only reference to an APK resource asset.
type ResourceRef struct {
	Path     string `json:"path"`
	Category string `json:"category,omitempty"`
	Size     int64  `json:"size,omitempty"`
}

// AndroidTelemetrySDK is a structured record per detected SDK.
type AndroidTelemetrySDK struct {
	Name       string  `json:"name"`
	Category   string  `json:"category,omitempty"`
	Package    string  `json:"package,omitempty"`
	Version    string  `json:"version,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// AndroidNetworkEndpoint mirrors network.EndpointInfo for KnowledgeResult.
type AndroidNetworkEndpoint struct {
	URL    string `json:"url"`
	Scheme string `json:"scheme,omitempty"`
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`
	Source string `json:"source,omitempty"`
}

type AndroidPermission struct {
	Name      string `json:"name"`
	Risk      string `json:"risk,omitempty"`
	Dangerous bool   `json:"dangerous"`
}

type AndroidComponent struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Exported bool   `json:"exported"`
	Risk     string `json:"risk,omitempty"`
}

type SecretFinding struct {
	Type        string `json:"type"`
	File        string `json:"file,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	MaskedValue string `json:"masked_value,omitempty"`
	RawLength   int    `json:"raw_length,omitempty"`
}

type NativeLibInfo struct {
	Name       string   `json:"name"`
	ABI        string   `json:"abi"`
	Size       int64    `json:"size"`
	JNIExports []string `json:"jni_exports,omitempty"`
}

type ObfuscationInfo struct {
	Type       string `json:"type"`
	Confidence int    `json:"confidence"`
	HasMapping bool   `json:"has_mapping"`
	Packer     string `json:"packer,omitempty"`
}

type AppFrameworkInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Engine  string `json:"engine,omitempty"`
}

type DEXStatsInfo struct {
	FileCount    int  `json:"file_count"`
	TotalClasses int  `json:"total_classes"`
	TotalMethods int  `json:"total_methods"`
	MultiDex     bool `json:"multi_dex"`
}

type RiskAPIFinding struct {
	Category string `json:"category"`
	API      string `json:"api"`
	Severity string `json:"severity,omitempty"`
}

// GoBinaryKnowledge holds Go binary analysis results.
type GoBinaryKnowledge struct {
	GoVersion          string            `json:"go_version,omitempty"`
	ModulePath         string            `json:"module_path,omitempty"`
	Arch               string            `json:"arch,omitempty"`
	OS                 string            `json:"os,omitempty"`
	BuildID            string            `json:"build_id,omitempty"`
	BuildSettings      map[string]string `json:"build_settings,omitempty"`
	IsStatic           bool              `json:"is_static"`
	HasSymbolTable     bool              `json:"has_symbol_table"`
	HasDWARF           bool              `json:"has_dwarf"`
	IsGarbled          bool              `json:"is_garbled"`
	GarbleConfidence   float64           `json:"garble_confidence,omitempty"`
	HighEntropyStrings int               `json:"high_entropy_strings,omitempty"`
	StringCategories   map[string]int    `json:"string_categories,omitempty"`
	SymbolCount        int               `json:"symbol_count,omitempty"`
	FunctionCount      int               `json:"function_count,omitempty"`
	ObfuscatedSymbols  int               `json:"obfuscated_symbols,omitempty"`
	ObfuscationRatio   float64           `json:"obfuscation_ratio,omitempty"`
	Packages           []string          `json:"packages,omitempty"`
	// Recovered symbols from the goresym backend (see pkg/garble/goresym).
	// Populated only under the `goresym` build tag with the tool present;
	// empty in the default tool-free build.
	RecoveredFunctions   []string `json:"recovered_functions,omitempty"`
	RecoveredTypes       []string `json:"recovered_types,omitempty"`
	RecoveredSymbolCount int      `json:"recovered_symbol_count,omitempty"`
}

// BinaryKnowledge holds PE/ELF/Mach-O binary analysis results.
type BinaryKnowledge struct {
	Format       string       `json:"format"`
	Arch         string       `json:"arch,omitempty"`
	SizeBytes    int64        `json:"size_bytes"`
	Imports      []string     `json:"imports,omitempty"`
	Libraries    []string     `json:"libraries,omitempty"`
	StringsTotal int          `json:"strings_total,omitempty"`
	URLCount     int          `json:"url_count,omitempty"`
	SampleURLs   []string     `json:"sample_urls,omitempty"`
	Signing      *SigningInfo `json:"signing,omitempty"`
	DotnetInfo   *DotnetInfo  `json:"dotnet,omitempty"`
}

// SigningInfo holds code signing certificate details.
type SigningInfo struct {
	HasSignature bool   `json:"has_signature"`
	Subject      string `json:"subject,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	CommonName   string `json:"common_name,omitempty"`
	Organization string `json:"organization,omitempty"`
	NotBefore    string `json:"not_before,omitempty"`
	NotAfter     string `json:"not_after,omitempty"`
	IsExpired    bool   `json:"is_expired"`
	IsSelfSigned bool   `json:"is_self_signed"`
	Thumbprint   string `json:"thumbprint,omitempty"`
	Verified     bool   `json:"verified"`
	ChainLength  int    `json:"chain_length,omitempty"`
}

// DotnetInfo holds .NET runtime and dependency metadata.
type DotnetInfo struct {
	TargetFramework string   `json:"target_framework,omitempty"`
	Frameworks      []string `json:"frameworks,omitempty"`
	IPCMechanisms   []string `json:"ipc_mechanisms,omitempty"`
	TotalLibraries  int      `json:"total_libraries,omitempty"`
	IsASPNET        bool     `json:"is_aspnet"`
	IsDesktop       bool     `json:"is_desktop"`
}

// PackagingKnowledge holds installer/package metadata.
type PackagingKnowledge struct {
	Format       string            `json:"format"` // "deb", "rpm", "msi", "msix"
	Name         string            `json:"name"`
	Version      string            `json:"version,omitempty"`
	Arch         string            `json:"arch,omitempty"`
	Maintainer   string            `json:"maintainer,omitempty"`
	Description  string            `json:"description,omitempty"`
	Dependencies []string          `json:"dependencies,omitempty"`
	Scripts      []string          `json:"scripts,omitempty"`
	FileCount    int               `json:"file_count"`
	TotalSize    int64             `json:"total_size"`
	HasSignature bool              `json:"has_signature"`
	Properties   map[string]string `json:"properties,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`

	// P38 Plan 38-02: UWP / WinUI extractor coverage. Populated when
	// DissectResult carries MSIXInfo or UWPInfo. Empty for non-Windows
	// packages (deb / rpm).
	UWP *UWPKnowledge `json:"uwp,omitempty"`
}

// PackageKnowledge holds metadata for DEB/RPM/MSI/MSIX packages.
type PackageKnowledge struct {
	Format        string          `json:"format"` // "deb", "rpm", "msi", "msix"
	Name          string          `json:"name"`
	Version       string          `json:"version"`
	Architecture  string          `json:"architecture,omitempty"`
	Maintainer    string          `json:"maintainer,omitempty"`
	Description   string          `json:"description,omitempty"`
	Dependencies  []string        `json:"dependencies,omitempty"`
	Scripts       map[string]bool `json:"scripts,omitempty"`        // preinst, postinst, etc.
	Capabilities  []string        `json:"capabilities,omitempty"`   // MSIX only
	CustomActions []string        `json:"custom_actions,omitempty"` // MSI only
	Files         int             `json:"file_count,omitempty"`
	Signed        bool            `json:"signed"`
}

// IOSKnowledge holds metadata for iOS IPA files.
type IOSKnowledge struct {
	BundleID    string   `json:"bundle_id"`
	BundleName  string   `json:"bundle_name"`
	Version     string   `json:"version"`
	MinimumOS   string   `json:"minimum_os"`
	Platform    string   `json:"platform"`
	Permissions []string `json:"permissions,omitempty"`
	URLSchemes  []string `json:"url_schemes,omitempty"`
	Frameworks  []string `json:"frameworks,omitempty"`
	Signed      bool     `json:"signed"`
}

type SourceFile struct {
	Path     string `json:"path"`
	Original string `json:"original"`
	Size     int64  `json:"size"`
	Purpose  string `json:"purpose"`
	// Signed reports the Authenticode signature presence for PE entries
	// (.exe / .dll). Nil when not scanned (e.g. non-PE entry, ASAR file,
	// or PE scan capped). false = scanned, no signature. true = signed.
	Signed  *bool  `json:"signed,omitempty"`
	Signer  string `json:"signer,omitempty"`
	Content []byte `json:"-"`
	// RawSourcePath is the teardown-relative path to the raw decompiler output.
	RawSourcePath string `json:"raw_source_path,omitempty"`
	// BeautifyProvenance identifies the beautifier pipeline that produced Content.
	// Known values: "phase5-csharp" | "phase6-java" | "phase6-js" | "phase6-bundle" | "phase2-css" | "".
	BeautifyProvenance string `json:"beautify_provenance,omitempty"`
}

// SourceMeta is the sibling _meta.json record emitted alongside every source file
// under <kb>/sources/<component>/<file>.
type SourceMeta struct {
	Component          string  `json:"component"`
	Classifier         string  `json:"classifier"` // "pattern" | "mcp" | "user-override"
	Confidence         float64 `json:"confidence"`
	RawSourcePath      string  `json:"raw_source_path,omitempty"`
	BeautifyProvenance string  `json:"beautify_provenance,omitempty"`
}
