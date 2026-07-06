/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/advinstaller"
	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/android/apk"
	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/framework"
	"github.com/inovacc/unravel-oss/pkg/android/kotlin"
	androidmanifest "github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/android/native"
	"github.com/inovacc/unravel-oss/pkg/android/network"
	"github.com/inovacc/unravel-oss/pkg/android/obfuscation"
	"github.com/inovacc/unravel-oss/pkg/android/protobuf"
	"github.com/inovacc/unravel-oss/pkg/android/resources"
	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/android/telemetry"
	"github.com/inovacc/unravel-oss/pkg/android/tools"
	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/css"
	"github.com/inovacc/unravel-oss/pkg/deb"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/disasm"
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	dotnetdecompile "github.com/inovacc/unravel-oss/pkg/dotnet/decompile"
	"github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	"github.com/inovacc/unravel-oss/pkg/extension"
	"github.com/inovacc/unravel-oss/pkg/frida"
	"github.com/inovacc/unravel-oss/pkg/garble"
	"github.com/inovacc/unravel-oss/pkg/garble/goresym"
	"github.com/inovacc/unravel-oss/pkg/ios"
	"github.com/inovacc/unravel-oss/pkg/jsdeob"
	"github.com/inovacc/unravel-oss/pkg/leveldb"
	"github.com/inovacc/unravel-oss/pkg/msi"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/msm"
	"github.com/inovacc/unravel-oss/pkg/nodeaddon"
	"github.com/inovacc/unravel-oss/pkg/npm"
	"github.com/inovacc/unravel-oss/pkg/nsis"
	"github.com/inovacc/unravel-oss/pkg/rpm"
	"github.com/inovacc/unravel-oss/pkg/sourcemap"
	analysisStore "github.com/inovacc/unravel-oss/pkg/store"
	"github.com/inovacc/unravel-oss/pkg/upx"
	"github.com/inovacc/unravel-oss/pkg/uwp"
	"github.com/inovacc/unravel-oss/pkg/wasm"
	"github.com/inovacc/unravel-oss/pkg/webview2"
	"github.com/inovacc/unravel-oss/pkg/winui"
)

// AnalysisEntry records the execution of a single analysis step.
type AnalysisEntry struct {
	Name      string        `json:"name"`
	Status    string        `json:"status"` // "ok", "error", "skipped"
	Duration  time.Duration `json:"duration"`
	Error     string        `json:"error,omitempty"`
	CacheFile string        `json:"cache_file,omitempty"` // ATS: path to flushed result on disk
}

// Options controls dissect behavior.
type Options struct {
	Verbose         bool
	OutputDir       string
	Deobfuscate     bool            // pass --deobf to jadx
	DecompileNative bool            // decompile .so files with retdec
	DecompileDotnet bool            // decompile .NET DLLs with ilspycmd
	AIAnalysis      bool            // call Claude API for deep AI analysis
	Beautify        bool            // beautify JavaScript files during analysis
	Disassemble     bool            // disassemble binary code sections
	NoCache         bool            // skip cache lookup and storage
	TeardownDir     string          // ATS: flush step results to this dir (empty = in-memory)
	Debug           *debug.Recorder // debug artifact recorder (nil-safe via NopRecorder)
}

// DissectResult holds the aggregated output of all applicable analyses.
type DissectResult struct {
	// Metadata
	Path      string               `json:"path"`
	FileName  string               `json:"file_name"`
	Size      int64                `json:"size"`
	Detection *detect.DetectResult `json:"detection"`
	StartedAt time.Time            `json:"started_at"`
	Duration  time.Duration        `json:"duration"`

	// SourcePath is the absolute input path of the CURRENT invocation. Unlike
	// Path (which may come from a cached prior run), SourcePath is always
	// stamped fresh by Run() and is the only field the report header should
	// trust when re-rendering after a cache hit. BUG-06 / D-06.
	SourcePath string `json:"source_path,omitempty"`

	// OutputDirLabel is the basename of the caller-supplied output directory
	// (filepath.Base(outDir)). It is stamped on the result before report
	// rendering so the report header carries the label that the caller
	// requested, independent of cache key. BUG-06 / D-06.
	OutputDirLabel string `json:"output_dir_label,omitempty"`

	// Per-type results (nil if not applicable)
	GarbleDetect        *garble.DetectionResult           `json:"garble_detect,omitempty"`
	GarbleInfo          *garble.BinaryInfo                `json:"garble_info,omitempty"`
	BinaryInfo          *binary.Info                      `json:"binary_info,omitempty"`
	GarbleStrings       *garble.StringsResult             `json:"garble_strings,omitempty"`
	GarbleSymbols       *garble.SymbolsResult             `json:"garble_symbols,omitempty"`
	GoSymbols           *goresym.Result                   `json:"go_symbols,omitempty"`
	GoSurface           *GoSurface                        `json:"go_surface,omitempty"`
	CertInfo            *cert.CertInfo                    `json:"cert_info,omitempty"`
	APKInfo             *apk.InfoResult                   `json:"apk_info,omitempty"`
	APKVerify           *apk.VerifyResult                 `json:"apk_verify,omitempty"`
	APKCert             *apk.CertResult                   `json:"apk_cert,omitempty"`
	APKExtract          *apk.ExtractReport                `json:"apk_extract,omitempty"`
	ManifestInfo        *androidmanifest.Manifest         `json:"manifest_info,omitempty"`
	ManifestAnalysis    *androidmanifest.Analysis         `json:"manifest_analysis,omitempty"`
	DEXAnalysis         *dex.ParseResult                  `json:"dex_analysis,omitempty"`
	KotlinAnalysis      *kotlin.ScanResult                `json:"kotlin_analysis,omitempty"`
	NativeAnalysis      *native.ScanResult                `json:"native_analysis,omitempty"`
	ObfuscationAnalysis *obfuscation.Result               `json:"obfuscation_analysis,omitempty"`
	NetworkAnalysis     *network.ScanResult               `json:"network_analysis,omitempty"`
	ResourceAnalysis    *resources.ScanResult             `json:"resource_analysis,omitempty"`
	Secrets             *secret.ScanResult                `json:"secrets,omitempty"`
	TelemetryAnalysis   *telemetry.ScanResult             `json:"telemetry_analysis,omitempty"`
	ProtobufAnalysis    *protobuf.ScanResult              `json:"protobuf_analysis,omitempty"`
	FrameworkAnalysis   *framework.ScanResult             `json:"framework_analysis,omitempty"`
	Decompile           *tools.DecompileResult            `json:"decompile,omitempty"`
	ToolsStatus         *tools.ToolsStatus                `json:"tools_status,omitempty"`
	DEBInfo             *deb.InfoResult                   `json:"deb_info,omitempty"`
	DEBVerify           *deb.VerifyResult                 `json:"deb_verify,omitempty"`
	RPMInfo             *rpm.InfoResult                   `json:"rpm_info,omitempty"`
	RPMVerify           *rpm.VerifyResult                 `json:"rpm_verify,omitempty"`
	MSIInfo             *msi.InfoResult                   `json:"msi_info,omitempty"`
	MSIVerify           *msi.VerifyResult                 `json:"msi_verify,omitempty"`
	MSMInfo             *msm.InfoResult                   `json:"msm_info,omitempty"`
	MSIXInfo            *msix.InfoResult                  `json:"msix_info,omitempty"`
	MSIXVerify          *msix.VerifyResult                `json:"msix_verify,omitempty"`
	ASARFiles           []asar.ExtractedFile              `json:"asar_files,omitempty"`
	ASARStats           *ASARSummary                      `json:"asar_stats,omitempty"`
	LevelDB             *leveldb.ParseResult              `json:"leveldb,omitempty"`
	Cache               *cache.ParseResult                `json:"cache,omitempty"`
	JSAnalysis          *JSAnalysisResult                 `json:"js_analysis,omitempty"`
	RecoveredCSS        *RecoveredCSSResult               `json:"recovered_css,omitempty"`
	AppAnalysis         *app.Result                       `json:"app_analysis,omitempty"`
	ExtAnalysis         *extension.ExtensionInfo          `json:"ext_analysis,omitempty"`
	ExtExtract          *extension.ExtensionExtractResult `json:"ext_extract,omitempty"`
	NPMAnalysis         *npm.AnalysisResult               `json:"npm_analysis,omitempty"`
	IPAInfo             *ios.IPAInfo                      `json:"ipa_info,omitempty"`
	SourceMapInfo       *sourcemap.ParseResult            `json:"sourcemap_info,omitempty"`
	SourceMapDeps       *sourcemap.ResolveResult          `json:"sourcemap_deps,omitempty"`
	AdvInstallerInfo    *advinstaller.BootstrapperInfo    `json:"advinstaller_info,omitempty"`

	// Frida script generation
	FridaScripts *frida.GenerateResult `json:"frida_scripts,omitempty"`

	// NSIS installer info
	NSISInfo *nsis.InfoResult `json:"nsis_info,omitempty"`

	// UPX packing info
	UPXInfo *upx.InfoResult `json:"upx_info,omitempty"`

	// .NET metadata (sibling .deps.json / .runtimeconfig.json)
	DotnetDeps    *dotnet.DepsResult          `json:"dotnet_deps,omitempty"`
	DotnetRuntime *dotnet.RuntimeConfigResult `json:"dotnet_runtime,omitempty"`
	DotnetStrings *dotnet.FilteredStrings     `json:"dotnet_strings,omitempty"`

	// .NET decompile results (Phase 5: ilspycmd + AI beautify pipeline).
	// Populated by the supplemental analyzer on TypePE when IsManagedPE
	// returns true. Per D-07 user resolution, the supplemental triggers
	// the FULL pipeline (raw + beautified when AI configured).
	DotNetDecompile *dotnetdecompile.Result         `json:"dotnet_decompile,omitempty"`
	DotNetBeautify  *dotnetdecompile.BeautifyReport `json:"dotnet_beautify,omitempty"`

	// CLRModules carries the native pure-Go CLR decompiler output (one
	// TypeModule per TypeDef) for a managed PE. Populated by the TypePE
	// supplemental analyzer alongside (and independent of) the ilspy
	// beautify track, and threaded into KB ingest as lang='cil' modules.
	// Nil/empty for non-managed inputs or when the native reader errors.
	CLRModules []clr.TypeModule `json:"clr_modules,omitempty"`

	// WebAssembly module info
	WASMInfo *wasm.WASMInfo `json:"wasm_info,omitempty"`

	// Node.js native addon info
	NodeAddonInfo *nodeaddon.Result `json:"nodeaddon_info,omitempty"`

	// WebView2 host analysis (detection signals, UDF discovery, profile data, runtime)
	WebView2Info *webview2.Result `json:"webview2_info,omitempty"`

	// Layered framework detections (FRM-09, D-01/D-02). Each detector
	// contributes a FrameworkInfo for every distinct signal observed; the
	// slice is deduped by {Name, Source} so the same framework reported by
	// two distinct sources retains both entries.
	Frameworks []winui.FrameworkInfo `json:"frameworks,omitempty"`

	// WinUI 3 host analysis (PRIMARY analyzer on TypeWinUIApp; SUPPLEMENTAL
	// on TypePE for hybrid stacks).
	WinUIInfo *winui.Result `json:"winui_info,omitempty"`

	// UWP packaged-app analysis (PRIMARY analyzer on TypeUWPApp; SUPPLEMENTAL
	// on TypeMSIX for cheap manifest peek).
	UWPInfo *uwp.Result `json:"uwp_info,omitempty"`

	// Disassembly results (when --disassemble is used)
	Disassembly *disasm.Result `json:"disassembly,omitempty"`

	// CSS extraction results (Electron/Tauri/ASAR targets)
	CSSExtraction *css.Result `json:"css_extraction,omitempty"`

	// Beautified JavaScript content (when --beautify is used)
	BeautifiedJS string `json:"beautified_js,omitempty"`

	// RecoveredJSSource carries a bounded copy of the attach-time CDP source
	// sidecar combined JS (WebView2-UWP path), set by applyCDPSourceSidecar
	// when present. It is a downstream seam for the obfuscation-rearm
	// collector (which must not import pkg/capture/webview2). json:"-" so the
	// serialized knowledge.json byte-shape is unchanged (golden-safe).
	RecoveredJSSource string `json:"-"`

	// ObfuscationReport is the unified, provenance-tagged record of detected
	// obfuscation mechanisms and AI-reconstructed modules across languages.
	ObfuscationReport *ObfuscationReport `json:"obfuscation_report,omitempty"`

	// AI-generated system prompt for deep analysis
	AIPrompt      string             `json:"ai_prompt,omitempty"`
	AIDataSummary string             `json:"-"`
	AIInsights    *ai.AnalysisResult `json:"ai_insights,omitempty"`

	// Cache
	CacheID string `json:"cache_id,omitempty"`

	// Unified result set (R2 refactor — new analyzers populate this)
	AnalysisResults *analysis.ResultSet `json:"analysis_results,omitempty"`

	// Execution log
	Analyses []AnalysisEntry `json:"analyses"`
	Errors   []string        `json:"errors,omitempty"`

	// internal
	debugRec *debug.Recorder `json:"-"`
	teardown *TeardownWriter `json:"-"` // ATS: flush step results to disk
}

// AddResult appends a unified analysis result to the result set.
func (r *DissectResult) AddResult(result analysis.Result) {
	if r.AnalysisResults == nil {
		r.AnalysisResults = &analysis.ResultSet{}
	}
	r.AnalysisResults.Add(result)
}

// ASARSummary holds summary statistics for an ASAR archive.
type ASARSummary struct {
	HeaderSize int   `json:"header_size"`
	FileCount  int   `json:"file_count"`
	DirCount   int   `json:"dir_count"`
	TotalSize  int64 `json:"total_size"`
}

// RecoveredCSSResult is the clean-room CSS surface recovered from the
// EBWebView HTTP cache. Count + bytes + per-origin paths; analyst-facing.
type RecoveredCSSResult struct {
	Files      int      `json:"files"`
	TotalBytes int      `json:"total_bytes"`
	Origins    []string `json:"origins,omitempty"`
}

// ObfuscationReport is the unified, provenance-tagged record of detected
// obfuscation mechanisms and AI-reconstructed modules across languages. It is
// the single source of truth for what is AI-inferred (no fabrication:
// reconstructed code is never presented as recovered ground truth).
type ObfuscationReport struct {
	Mechanisms []MechanismFinding `json:"mechanisms,omitempty"`
	Modules    []RearmedModule    `json:"modules,omitempty"`
}

// MechanismFinding records a single detected obfuscation mechanism.
type MechanismFinding struct {
	Lang       string `json:"lang"`
	Name       string `json:"name"`
	Confidence int    `json:"confidence"`
	ModuleRef  string `json:"module_ref"`
}

// RearmedModule records the AI-assisted reconstruction outcome for one module.
type RearmedModule struct {
	Lang       string `json:"lang"`
	ModuleRef  string `json:"module_ref"`
	Mechanism  string `json:"mechanism"`
	Confidence int    `json:"confidence"`
	Status     string `json:"status"` // "rearmed" | "not_rearmed_ai_unavailable" | "budget_exhausted" | "error"
	Provenance string `json:"provenance,omitempty"`
	Model      string `json:"model,omitempty"`
}

// JSAnalysisResult holds the results of JavaScript security analysis.
type JSAnalysisResult struct {
	File             string   `json:"file"`
	Size             int      `json:"size_bytes"`
	ObfuscationScore int      `json:"obfuscation_score"`
	Indicators       []string `json:"indicators"`
	DangerousCalls   []string `json:"dangerous_calls"`
	NetworkCalls     []string `json:"network_calls"`
	EncodedData      []string `json:"encoded_data"`
	URLs             []string `json:"urls"`
	StringsCount     int      `json:"strings_count"`
	FunctionsCount   int      `json:"functions_count"`
}

const maxStringsFileSize int64 = 64 * 1024 * 1024 // 64 MB

// cacheEntryStale reports whether a hash-keyed cached DissectResult is too
// incomplete to be served verbatim and must trigger a full re-dispatch.
//
// It is a pure, I/O-free predicate (deterministic, unit-testable) covering
// the identity-completeness gates: an entry cached before a capability
// existed has the identity field but lacks the later-added analysis, so
// serving it would silently suppress required analysis (and skew downstream
// scorers / knowledge extraction). Each arm rejects the "cached before
// capability X existed" shape for its file type.
//
// WR-02 shape assumption: `cached` is always loadCachedResult output
// (JSON-unmarshaled). The Electron/Tauri arm chains
// cached.AppAnalysis.AppInfo.DisplayName and the MSIX arm chains
// cached.MSIXInfo.PackageName; both assume AppInfo / InfoResult are
// value-embedded (not pointer) in their parents — true for the current
// app.Result / msix.InfoResult shapes. If either is ever changed to a
// pointer, add a nil-guard here: a nil-deref in this gate is reachable
// only via a cache load and would not surface in non-cached runs.
func cacheEntryStale(cached *DissectResult) bool {
	if cached.Detection == nil {
		return false
	}
	switch cached.Detection.FileType {
	case detect.TypeAPK, detect.TypeAAB, detect.TypeXAPK, detect.TypeAPKS, detect.TypeAPKM:
		// APK entry from before the ATS-mode identity-preservation fix
		// has no ManifestInfo; extractIdentity would fail.
		return cached.ManifestInfo == nil || cached.ManifestInfo.Package == ""
	case detect.TypeIPA:
		return cached.IPAInfo == nil || cached.IPAInfo.BundleID == ""
	case detect.TypeMSIX, detect.TypeUWPApp:
		// Reject entries cached before the Phase-83 WebView2/UWP on-disk
		// capture existed. Such a pre-83 entry has a valid
		// MSIXInfo.PackageName (packaging always extracted fine) but
		// WebView2Info==nil, so the original PackageName-only gate served
		// it verbatim and the Phase-83 analyzer dispatch never ran —
		// scorer_storage.go then read nil and credited storage=0. Marking
		// it stale forces analyze_uwp to re-dispatch and populate
		// WebView2Info from real on-disk EBWebView evidence.
		//
		// CR-01 one-time semantics: staleness keys off the Phase-83
		// Analyzed sentinel, NOT off WebView2Info==nil or len(Profiles).
		// The post-83 producer (analyze_uwp.go) ALWAYS stamps a non-nil
		// WebView2Info with Analyzed=true — including the D-08 honest-empty
		// case where no EBWebView tree exists (zero profiles). So:
		//   - pre-83 / never-analyzed entry: WebView2Info==nil  -> stale
		//     (re-dispatch exactly once; producer then stamps Analyzed)
		//   - post-83 honest-empty entry: WebView2Info!=nil, Analyzed=true,
		//     zero profiles -> NOT stale (honored; no perpetual thrash for
		//     the large class of non-WebView2 MSIX/UWP apps)
		//   - post-83 populated entry: Analyzed=true, profiles>0 -> NOT stale
		// A non-nil WebView2Info with Analyzed==false can only come from a
		// pre-sentinel build; treat it as pre-83 and re-dispatch once.
		return cached.MSIXInfo == nil ||
			cached.MSIXInfo.PackageName == "" ||
			cached.WebView2Info == nil ||
			!cached.WebView2Info.Analyzed
	case detect.TypeElectronApp, detect.TypeTauriApp:
		// Reject entries cached before pkg/electron/binary extracted PE
		// VS_VERSION_INFO ProductName. Symptom: AppInfo.DisplayName
		// equals the framework literal instead of the real app name,
		// which propagates to kb_apps.display_name / canonical_name.
		return cached.AppAnalysis == nil ||
			cached.AppAnalysis.AppInfo.DisplayName == "" ||
			strings.EqualFold(cached.AppAnalysis.AppInfo.DisplayName, "Electron") ||
			strings.EqualFold(cached.AppAnalysis.AppInfo.DisplayName, "Tauri")
	}
	return false
}

// Run detects the file type at path and runs all applicable non-destructive analyses.
func Run(path string, opts Options) (*DissectResult, error) {
	// Ensure we always have a recorder (NopRecorder if nil)
	if opts.Debug == nil {
		opts.Debug = debug.NopRecorder()
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	// Check cache for a previous result with matching file hash
	if !opts.NoCache {
		endCache := stageTimer("cache_check", absPath)
		if cached, cErr := loadCachedResult(absPath); cErr == nil {
			// Identity-completeness gate: an APK cache entry from before
			// the ATS-mode identity-preservation fix has no ManifestInfo.
			// Reject it so the full pipeline runs and writes a complete
			// entry. Same for IPA / MSIX. Otherwise extractIdentity
			// (knowledge.go) would fail with "no identity derivable".
			if !cacheEntryStale(cached) {
				// BUG-06 / D-06: cache hits must NOT leak the cached source path.
				// Always stamp the current invocation's absolute path so the
				// report renderer reflects this call, not a prior run.
				cached.SourcePath = absPath
				// DSC-06 / 13-06: also stamp Path / FileName / Detection.{Path,Name}
				// so downstream metadata.json + dissect.json rebuilds in
				// WriteWorkspace reflect THIS call's input, not the cached source.
				cached.Path = absPath
				cached.FileName = filepath.Base(absPath)
				if cached.Detection != nil {
					cached.Detection.Path = absPath
					cached.Detection.Name = filepath.Base(absPath)
				}
				endCache("cache_hit", true)
				return cached, nil
			}
		}
		endCache("cache_hit", false)
	}

	start := time.Now()

	endDetect := stageTimer("detect", absPath)
	dr, err := detect.Detect(absPath)
	endDetect()
	if err != nil {
		return nil, fmt.Errorf("detect: %w", err)
	}

	// Record detection result
	_ = opts.Debug.WriteJSON("detection.json", dr)

	result := &DissectResult{
		Path:       absPath,
		SourcePath: absPath,
		FileName:   filepath.Base(absPath),
		Size:       info.Size(),
		Detection:  dr,
		StartedAt:  start,
		Analyses:   []AnalysisEntry{},
		Errors:     []string{},
		debugRec:   opts.Debug,
	}

	// Auto-enable ATS for Android APKs when no explicit teardown dir is set
	switch dr.FileType {
	case detect.TypeAPK, detect.TypeAAB, detect.TypeXAPK, detect.TypeAPKS, detect.TypeAPKM:
		if opts.TeardownDir == "" {
			opts.TeardownDir = TeardownDir()
		}
	}

	// Create TeardownWriter for ATS mode
	if opts.TeardownDir != "" {
		tw, twErr := NewTeardownWriterAt(opts.TeardownDir)
		if twErr == nil {
			result.teardown = tw
		}
	}

	// Auto-detect ./bin directory with RE tools and prepend to PATH
	prependBinToPath()

	dispatch(result, absPath, dr.FileType, opts)

	// Generate Frida scripts for Android targets
	// In ATS mode, most result fields are nilled — Frida generation uses nil-checks
	// so it degrades gracefully with whatever data remains.
	switch dr.FileType {
	case detect.TypeAPK, detect.TypeAAB, detect.TypeXAPK, detect.TypeAPKS, detect.TypeAPKM:
		result.FridaScripts = frida.GenerateFromAnalysis(buildFridaInput(result))
		if result.teardown != nil && result.FridaScripts != nil {
			_ = result.teardown.Flush("frida_scripts", result.FridaScripts, 0, "ok")
			result.FridaScripts = nil
		}
	}

	// Generate AI system prompt for Android targets
	switch dr.FileType {
	case detect.TypeAPK, detect.TypeAAB, detect.TypeXAPK, detect.TypeAPKS, detect.TypeAPKM:
		// In ATS mode the per-step results were flushed to disk and nil'd to
		// bound RAM; reload the summary-level steps the prompt/report read (NOT
		// the heavy dex tables) so the guidance reflects the real analysis
		// instead of falsely reporting "no native libraries / no Kotlin".
		result.reloadSummaryStepsForPrompt()
		result.AIPrompt = GenerateAIPrompt(result)

		// Record AI prompt
		_ = opts.Debug.WriteText("ai_prompt.md", result.AIPrompt)

		// Build AI data summary (used for both API call and prompt file)
		if opts.AIAnalysis {
			result.runStep("ai data prep", func(sr *debug.StepRecorder) error {
				dataJSON, err := ai.MarshalDissectForAI(result)
				if err != nil {
					return fmt.Errorf("marshal data: %w", err)
				}

				result.AIDataSummary = ai.BuildDataSummary(dataJSON)

				sr.RecordOutput(result.AIDataSummary)
				return nil
			})

			// Write combined prompt file for offline use
			if opts.OutputDir != "" && result.AIDataSummary != "" {
				promptPath := filepath.Join(opts.OutputDir, "AI_PROMPT_FULL.md")

				var sb strings.Builder
				sb.WriteString("<!-- SYSTEM PROMPT -->\n\n")
				sb.WriteString(result.AIPrompt)
				sb.WriteString("\n\n---\n\n<!-- USER DATA -->\n\n")
				sb.WriteString(result.AIDataSummary)

				_ = os.WriteFile(promptPath, []byte(sb.String()), 0644)
			}

			// Attempt API call
			sr := result.runStepDebug("ai_analysis")
			entry := AnalysisEntry{Name: "ai analysis"}
			start := time.Now()

			sr.RecordSystemPrompt(result.AIPrompt)
			sr.RecordUserPrompt(result.AIDataSummary)

			err := func() error {
				client, err := ai.NewClient()
				if err != nil {
					return fmt.Errorf("init AI client: %w", err)
				}

				ctx := context.Background()

				insights, err := ai.AnalyzeAndroid(ctx, client, result.AIPrompt, result.AIDataSummary)
				if err != nil {
					return err
				}

				sr.RecordOutput(insights)

				if insights.Usage != nil {
					sr.SetUsage(insights.Usage.InputTokens, insights.Usage.OutputTokens, "")
				}

				result.AIInsights = insights

				return nil
			}()
			if err != nil {
				entry.Status = "error"
				entry.Error = err.Error()
				result.Errors = append(result.Errors, fmt.Sprintf("[ai analysis] %v", err))

				sr.SetStatus("error")
				sr.SetError(err)
			} else {
				entry.Status = "ok"

				sr.SetStatus("ok")
			}

			entry.Duration = time.Since(start)
			result.Analyses = append(result.Analyses, entry)
			_ = sr.Finish()
		}
	}

	result.Duration = time.Since(start)

	// Write teardown manifest (ATS mode)
	if result.teardown != nil {
		// Write metadata (lightweight: path, detection, analyses log, errors — no heavy results)
		meta := &DissectResult{
			Path:      result.Path,
			FileName:  result.FileName,
			Size:      result.Size,
			Detection: result.Detection,
			StartedAt: result.StartedAt,
			Duration:  result.Duration,
			Analyses:  result.Analyses,
			Errors:    result.Errors,
			CacheID:   result.teardown.ID(),
		}

		metaJSON, _ := json.Marshal(meta)
		_ = os.WriteFile(filepath.Join(result.teardown.Dir(), "metadata.json"), metaJSON, 0o644)
		_ = result.teardown.WriteManifest(absPath)

		result.CacheID = result.teardown.ID()
	}

	// Cache the result for later retrieval
	if !opts.NoCache {
		cacheResult(result, absPath)
	}

	return result, nil
}

// cacheResult stores the dissect result in the persistent cache.
// In ATS mode, individual step results are already on disk in the teardown
// directory — we only cache lightweight metadata to avoid the monolithic
// JSON marshal that was causing the second RAM spike.
func cacheResult(result *DissectResult, absPath string) {
	s := analysisStore.New()

	tags := []string{string(result.Detection.FileType)}
	data := map[string][]byte{}

	if result.teardown != nil {
		// ATS mode: store only metadata + pointer to teardown dir.
		// Identity scalars (manifest_info / ipa_info / msix_info / binary_info /
		// app_analysis) are also persisted so cache hits can drive
		// knowledge.extractIdentity (P35-01) without re-running the full
		// pipeline. Heavy slices were already trimmed off these structs by
		// analyze_apk / analyze_packages / analyze_electron before flush.
		meta := map[string]any{
			"path":          result.Path,
			"file_name":     result.FileName,
			"size":          result.Size,
			"detection":     result.Detection,
			"started_at":    result.StartedAt,
			"duration":      result.Duration,
			"analyses":      result.Analyses,
			"errors":        result.Errors,
			"teardown_dir":  result.teardown.Dir(),
			"teardown_id":   result.teardown.ID(),
			"manifest_info": result.ManifestInfo,
			"ipa_info":      result.IPAInfo,
			"msix_info":     result.MSIXInfo,
			// CR-01: persist webview2_info on the ATS path too. Without it,
			// every ATS-written MSIX/UWP entry reloads WebView2Info==nil
			// and the cache-staleness gate (cacheEntryStale) re-flags it
			// stale forever — perpetual full re-dispatch. Mirrors msix_info.
			"webview2_info":  result.WebView2Info,
			"binary_info":    result.BinaryInfo,
			"app_analysis":   result.AppAnalysis,
			"dotnet_deps":    result.DotnetDeps,
			"dotnet_runtime": result.DotnetRuntime,
		}

		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return
		}

		data["result.json"] = metaJSON
	} else {
		// Legacy mode: full monolithic JSON (for non-Android or small files)
		resultJSON, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return
		}

		data["result.json"] = resultJSON
	}

	entry, err := s.Put(absPath, "dissect", tags, data)
	if err != nil {
		return
	}

	result.CacheID = entry.ID
}

// loadCachedResult looks up the store for a previous dissect result whose
// source hash matches the current file on disk. Returns the deserialized
// result or an error if no valid cache entry exists.
func loadCachedResult(absPath string) (*DissectResult, error) {
	s := analysisStore.New()
	entries := s.Find(absPath)
	if len(entries) == 0 {
		return nil, fmt.Errorf("no cache entry")
	}

	// Use the most recent matching entry (last in slice, entries are appended chronologically)
	entry := entries[len(entries)-1]

	data, err := s.ReadFile(entry.ID, "result.json")
	if err != nil {
		return nil, fmt.Errorf("read cached result: %w", err)
	}

	var result DissectResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal cached result: %w", err)
	}

	result.CacheID = entry.ID

	return &result, nil
}

func dispatch(r *DissectResult, path string, ft detect.FileType, opts Options) {
	// Table-based dispatch: each format registers its analyzer via init().
	// See analyze_apk.go, analyze_binary.go, analyze_packages.go,
	//     analyze_electron.go, analyze_java.go, analyze_web.go, analyze_data.go
	dispatchByTable(r, path, ft, opts)
}

func (r *DissectResult) runStep(name string, fn func(sr *debug.StepRecorder) error) {
	sr := r.debugRec.StepRecorder(name)
	sr.Start()

	start := time.Now()
	entry := AnalysisEntry{Name: name}

	if err := fn(sr); err != nil {
		entry.Status = "error"
		entry.Error = err.Error()
		r.Errors = append(r.Errors, fmt.Sprintf("[%s] %v", name, err))

		sr.SetStatus("error")
		sr.SetError(err)
	} else {
		entry.Status = "ok"

		sr.SetStatus("ok")
	}

	entry.Duration = time.Since(start)
	if entry.Duration <= 0 {
		entry.Duration = time.Nanosecond
	}

	r.Analyses = append(r.Analyses, entry)
	_ = sr.Finish()
}

// runStepDebug returns the step recorder for callers that need to record
// additional artifacts (e.g. AI prompts, API requests). The caller must
// call sr.Finish() when done.
func (r *DissectResult) runStepDebug(name string) *debug.StepRecorder {
	sr := r.debugRec.StepRecorder(name)
	sr.Start()

	return sr
}

// runStepATS runs an analysis step and optionally flushes the result to disk.
// When tw is non-nil (ATS mode), the result is serialized to a JSON file and
// the clear function is called to nil the pointer on DissectResult, allowing
// the GC to reclaim the memory. When tw is nil, it behaves like runStep.
func (r *DissectResult) runStepATS(name string, tw *TeardownWriter, fn func(sr *debug.StepRecorder) (any, error), clear func()) {
	sr := r.debugRec.StepRecorder(name)
	sr.Start()

	start := time.Now()
	entry := AnalysisEntry{Name: name}

	result, err := fn(sr)
	entry.Duration = time.Since(start)
	if entry.Duration <= 0 {
		entry.Duration = time.Nanosecond
	}

	if err != nil {
		entry.Status = "error"
		entry.Error = err.Error()
		r.Errors = append(r.Errors, fmt.Sprintf("[%s] %v", name, err))

		sr.SetStatus("error")
		sr.SetError(err)
	} else {
		entry.Status = "ok"
		sr.SetStatus("ok")

		// ATS: flush result to disk and nil the pointer
		if tw != nil && result != nil {
			if flushErr := tw.Flush(name, result, entry.Duration, entry.Status); flushErr == nil {
				entry.CacheFile = tw.StepFile(name)
				if clear != nil {
					clear()
				}
			}
		}
	}

	r.Analyses = append(r.Analyses, entry)
	_ = sr.Finish()
}

// prependBinToPath checks if ./bin exists and contains executables, and if so
// prepends it to PATH. This is the zero-config fix for RE tools installed by
// install-tools.sh.
func prependBinToPath() {
	binDir, err := filepath.Abs("bin")
	if err != nil {
		return
	}

	info, err := os.Stat(binDir)
	if err != nil || !info.IsDir() {
		return
	}

	currentPath := os.Getenv("PATH")
	if strings.Contains(currentPath, binDir) {
		return
	}

	_ = os.Setenv("PATH", binDir+string(os.PathListSeparator)+currentPath)
}

func analyzeJS(path string) (*JSAnalysisResult, error) {
	code, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	codeStr := string(code)
	result := &JSAnalysisResult{
		File:           path,
		Size:           len(code),
		Indicators:     []string{},
		DangerousCalls: []string{},
		NetworkCalls:   []string{},
		EncodedData:    []string{},
	}

	// Check for dangerous function calls
	dangerousPatterns := map[string]*regexp.Regexp{
		"dynamic code execution":  regexp.MustCompile(`\beval\s*\(`),
		"Function constructor":    regexp.MustCompile(`\bFunction\s*\(`),
		"setTimeout with string":  regexp.MustCompile(`setTimeout\s*\(\s*["']`),
		"setInterval with string": regexp.MustCompile(`setInterval\s*\(\s*["']`),
		"DOM write operations":    regexp.MustCompile(`document\.(write|writeln)\s*\(`),
		"innerHTML modification":  regexp.MustCompile(`\.innerHTML\s*=`),
	}

	for name, pattern := range dangerousPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			result.DangerousCalls = append(result.DangerousCalls,
				fmt.Sprintf("%s (%d occurrences)", name, len(matches)))
		}
	}

	// Check for network operations
	networkPatterns := map[string]*regexp.Regexp{
		"fetch()":        regexp.MustCompile(`\bfetch\s*\(`),
		"XMLHttpRequest": regexp.MustCompile(`XMLHttpRequest`),
		"axios":          regexp.MustCompile(`\baxios\b`),
		"WebSocket":      regexp.MustCompile(`\bWebSocket\s*\(`),
		"sendBeacon":     regexp.MustCompile(`navigator\.sendBeacon`),
	}

	for name, pattern := range networkPatterns {
		if pattern.MatchString(codeStr) {
			result.NetworkCalls = append(result.NetworkCalls, name)
		}
	}

	// Check for encoded data
	base64Pattern := regexp.MustCompile(`atob\s*\(\s*["']([A-Za-z0-9+/=]{20,})["']\s*\)`)
	for _, match := range base64Pattern.FindAllStringSubmatch(codeStr, 5) {
		if len(match) > 1 {
			preview := match[1]
			if len(preview) > 30 {
				preview = preview[:30] + "..."
			}

			result.EncodedData = append(result.EncodedData, "base64: "+preview)
		}
	}

	hexPattern := regexp.MustCompile(`"((?:\\x[0-9a-fA-F]{2}){10,})"`)
	if hexPattern.MatchString(codeStr) {
		result.EncodedData = append(result.EncodedData, "hex-encoded strings detected")
	}

	charCodePattern := regexp.MustCompile(`String\.fromCharCode\s*\([\d,\s]{20,}\)`)
	if charCodePattern.MatchString(codeStr) {
		result.EncodedData = append(result.EncodedData, "charcode-encoded strings detected")
	}

	// Calculate obfuscation score
	score := 0

	obfVarPattern := regexp.MustCompile(`_0x[a-f0-9]{4,}`)

	obfVars := len(obfVarPattern.FindAllString(codeStr, -1))
	if obfVars > 10 {
		score += 30

		result.Indicators = append(result.Indicators, fmt.Sprintf("%d obfuscated variable names", obfVars))
	}

	if len(result.EncodedData) > 0 {
		score += 20
	}

	if len(result.DangerousCalls) > 0 {
		score += 15 * len(result.DangerousCalls)
	}

	lines := strings.Split(codeStr, "\n")
	longLines := 0

	for _, line := range lines {
		if len(line) > 500 {
			longLines++
		}
	}

	if longLines > 0 {
		score += 10

		result.Indicators = append(result.Indicators, fmt.Sprintf("%d very long lines (>500 chars)", longLines))
	}

	if len(code) > 1000 && len(lines) < len(code)/500 {
		score += 10

		result.Indicators = append(result.Indicators, "Highly minified/packed code")
	}

	result.ObfuscationScore = score
	result.URLs = jsdeob.ExtractURLs(codeStr)
	result.StringsCount = len(jsdeob.ExtractStrings(codeStr))
	result.FunctionsCount = len(jsdeob.ExtractFunctions(codeStr))

	return result, nil
}

// buildFridaInput extracts relevant analysis data from a DissectResult
// into a frida.AnalysisInput to avoid an import cycle.
func buildFridaInput(r *DissectResult) frida.AnalysisInput {
	input := frida.AnalysisInput{}

	if r.ManifestInfo != nil {
		input.PackageName = r.ManifestInfo.Package

		for _, comp := range r.ManifestInfo.Components {
			if comp.Exported != nil && *comp.Exported {
				input.HasExportedComp = true

				break
			}
		}
	}

	if r.NetworkAnalysis != nil {
		if r.NetworkAnalysis.CertPinning != nil {
			input.HasCertPinning = r.NetworkAnalysis.CertPinning.HasPinning
		}

		for _, ep := range r.NetworkAnalysis.Endpoints {
			if ep.Host != "" {
				input.Domains = append(input.Domains, ep.Host)
			}
		}

		// Deduplicate domains
		if len(input.Domains) > 0 {
			seen := make(map[string]struct{}, len(input.Domains))
			deduped := input.Domains[:0]

			for _, d := range input.Domains {
				if _, ok := seen[d]; !ok {
					seen[d] = struct{}{}
					deduped = append(deduped, d)
				}
			}

			input.Domains = deduped
		}
	}

	if r.NativeAnalysis != nil {
		for _, f := range r.NativeAnalysis.Findings {
			input.NativeFindings = append(input.NativeFindings, frida.NativeFinding{
				Category: f.Category,
			})
		}
	}

	if r.DEXAnalysis != nil {
		for _, rf := range r.DEXAnalysis.RiskFindings {
			input.DEXRiskAPIs = append(input.DEXRiskAPIs, rf.API)
		}
	}

	return input
}
