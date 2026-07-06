package knowledge

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/deb"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/inject/webview2"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/depth"
	"github.com/inovacc/unravel-oss/pkg/leveldb"
	"github.com/inovacc/unravel-oss/pkg/msi"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/npm"
	"github.com/inovacc/unravel-oss/pkg/rpm"

	_ "modernc.org/sqlite"
)

// ExtractV2 is the source-fidelity entry (Plan 07-02). It wraps the legacy
// Extract with the sweep + beautify-track orchestrator and is the function
// the CLI / MCP layer should call once Plan 07-04 wires --with-ai through.
//
// The dispatch is hardcoded (D-15 — no plugin registry):
//
//	if opts.WithAI { runWithAI(...); }
//	if opts.TeardownDir != "" { SweepTeardown(opts.TeardownDir) }
//
// CSS bypasses entirely (D-16) — extract_css.go is invoked via Extract
// below; the orchestrator does not route CSS through the cache or track
// switch. The bundle reconstructor is JS-handler-internal (D-17) — this
// file does not import pkg/jsdeob/bundle.
func ExtractV2(dr *dissect.DissectResult, opts ExtractOptions) *KnowledgeResult {
	return ExtractWithOptions(dr, opts)
}

// Extract transforms a DissectResult into a KnowledgeResult.
func Extract(dr *dissect.DissectResult) *KnowledgeResult {
	platform, packageID, displayName, publisher := extractIdentity(dr)
	kr := &KnowledgeResult{
		AnalyzedAt:  time.Now(),
		SourcePath:  dr.Path,
		Platform:    platform,
		PackageID:   packageID,
		DisplayName: displayName,
		Publisher:   publisher,
		AppName:     extractAppName(dr),
		Framework:   extractFramework(dr, dr.Path),
		Version:     extractVersion(dr),
		Duration:    dr.Duration,
	}

	// FIX #1: thread native CLR modules from dissect → knowledge → ingest.
	// Copied verbatim (no transform); the capture pipeline forwards these to
	// ingest.Options.CLRModules for lang='cil' persistence. Nil for non-.NET.
	kr.CLRModules = dr.CLRModules

	if comm := extractCommunication(dr); comm != nil {
		kr.Communication = comm
	}
	if auth := extractAuth(dr); auth != nil {
		kr.Auth = auth
	}
	if ui := extractUI(dr); ui != nil {
		kr.UI = ui
	}
	if ipcK := extractIPC(dr); ipcK != nil {
		kr.IPC = ipcK
	}
	if sec := extractSecurity(dr); sec != nil {
		kr.Security = sec
	}
	if st := extractStealth(dr); st != nil {
		kr.Stealth = st
	}
	if tel := extractTelemetry(dr); tel != nil {
		kr.Telemetry = tel
	}
	if npmK := extractNPM(dr); npmK != nil {
		kr.NPM = npmK
	}
	kr.SourceFiles = extractSourceFiles(dr)
	if android := extractAndroid(dr); android != nil {
		kr.Android = android
	}
	// P37 Plan 37-02: additive D-37 coverage wire-up. Runs after the
	// legacy extractAndroid populates kr.Android; no-op when Platform
	// is not "android". See pkg/knowledge/extract_android_coverage.go.
	extractAndroidCoverage(dr, kr)

	// P38 Plan 38-02: UWP / WinUI / WebView2 coverage wire-up. No-op when
	// Platform is not "windows". See pkg/knowledge/extract_uwp_coverage.go.
	extractUWPCoverage(dr, kr)

	// P38 Plan 38-03: Electron coverage wire-up. Coexists with UWP path
	// for hybrid stacks (Electron-MSIX) per D-38-HYBRID-DUAL-COVERAGE.
	extractElectronCoverage(dr, kr)

	// Per-dimension coverage scoring (D-37 depth_covered). Each platform
	// branch appends the relevant audits; hybrid Windows binaries (UWP +
	// Electron-MSIX) get BOTH `uwp.*` and `electron.*` dimensions per
	// D-38-HYBRID-DUAL-COVERAGE.
	if kr.Platform == "android" {
		kr.DepthCovered = depth.AuditAndroid(dr, androidCoverageView{kr: kr})
	}
	if strings.HasPrefix(kr.Platform, "windows") {
		if kr.Packaging != nil && kr.Packaging.UWP != nil {
			kr.DepthCovered = append(kr.DepthCovered, depth.AuditUWP(dr, kr)...)
		}
		if kr.Electron != nil {
			kr.DepthCovered = append(kr.DepthCovered, depth.AuditElectron(dr, kr)...)
		}
		if kr.WebView2 != nil {
			kr.DepthCovered = append(kr.DepthCovered, depth.AuditWebView2(dr, kr)...)
		}
	}
	if bin := extractBinaryKnowledge(dr); bin != nil {
		kr.Binary = bin
	}
	if goBin := extractGoBinary(dr); goBin != nil {
		kr.GoBinary = goBin
	}
	if pkg := extractPackaging(dr); pkg != nil {
		// Preserve UWP sub-tree set by extractUWPCoverage (D-38). extractPackaging
		// only knows about the format-level fields (Name, FileCount, Deps, ...);
		// the UWP capability + manifest sub-tree must not be clobbered.
		if kr.Packaging != nil && kr.Packaging.UWP != nil {
			pkg.UWP = kr.Packaging.UWP
		}
		kr.Packaging = pkg
	}

	// DEB package knowledge
	if dr.DEBInfo != nil {
		kr.Package = extractDEBKnowledge(dr)
	}
	// RPM package knowledge
	if dr.RPMInfo != nil {
		kr.Package = extractRPMKnowledge(dr)
	}
	// MSI package knowledge
	if dr.MSIInfo != nil {
		kr.Package = extractMSIKnowledge(dr)
	}
	// MSIX package knowledge
	if dr.MSIXInfo != nil {
		kr.Package = extractMSIXKnowledge(dr)
	}
	// iOS IPA knowledge
	if dr.IPAInfo != nil {
		kr.IOS = extractIOSKnowledge(dr)
	}
	// CSS extraction knowledge
	if cssK := extractCSS(dr); cssK != nil {
		kr.CSS = cssK
	}

	// Extract runtime data from Electron user data directory
	if appName := kr.AppName; appName != "" {
		if dataDir := resolveDataDir(dr.Path, appName); dataDir != "" {
			kr.DataDir = extractDataDir(dataDir)
			if kr.DataDir != nil {
				scanDataDirSecrets(kr.DataDir)
			}
		}
	}

	applyObfuscationReport(kr, dr)

	return kr
}

// applyObfuscationReport maps the dissect AI-deobfuscation rearm report onto
// the knowledge result. Additive and nil-safe.
func applyObfuscationReport(kr *KnowledgeResult, dr *dissect.DissectResult) {
	if dr == nil || dr.ObfuscationReport == nil {
		return
	}
	kr.ObfuscationReport = dr.ObfuscationReport
}

func extractAppName(r *dissect.DissectResult) string {
	if r.NPMAnalysis != nil && r.NPMAnalysis.PackageName != "" {
		return r.NPMAnalysis.PackageName
	}
	if r.AppAnalysis != nil && r.AppAnalysis.AppInfo.Name != "" {
		return r.AppAnalysis.AppInfo.Name
	}
	if r.ManifestInfo != nil && r.ManifestInfo.Package != "" {
		return r.ManifestInfo.Package
	}
	if r.DEBInfo != nil && r.DEBInfo.Control != nil && r.DEBInfo.Control.Package != "" {
		return r.DEBInfo.Control.Package
	}
	if r.RPMInfo != nil && r.RPMInfo.Name != "" {
		return r.RPMInfo.Name
	}
	if r.MSIInfo != nil && r.MSIInfo.ProductName != "" {
		return r.MSIInfo.ProductName
	}
	if r.MSIXInfo != nil && r.MSIXInfo.PackageName != "" {
		return r.MSIXInfo.PackageName
	}
	if r.IPAInfo != nil && r.IPAInfo.BundleName != "" {
		return r.IPAInfo.BundleName
	}
	if r.BinaryInfo != nil && r.BinaryInfo.ProductName != "" {
		return r.BinaryInfo.ProductName
	}
	return r.FileName
}

func extractFramework(r *dissect.DissectResult, appDir string) string {
	if r.NPMAnalysis != nil {
		return "npm"
	}
	if r.AppAnalysis != nil && r.AppAnalysis.AppInfo.Type != "" {
		return r.AppAnalysis.AppInfo.Type
	}
	if r.FrameworkAnalysis != nil && r.FrameworkAnalysis.Framework != "" {
		return r.FrameworkAnalysis.Framework
	}
	if r.GarbleInfo != nil || r.GarbleDetect != nil {
		return "go"
	}
	if r.DotnetDeps != nil || r.DotnetRuntime != nil {
		return "dotnet"
	}
	if r.Detection != nil {
		ft := string(r.Detection.FileType)
		switch {
		case strings.Contains(ft, "apk"), strings.Contains(ft, "android"):
			return "android"
		case strings.Contains(ft, "asar"), strings.Contains(ft, "electron"):
			return "electron"
		case strings.Contains(ft, "pe"):
			return "pe"
		case strings.Contains(ft, "elf"):
			return "elf"
		case strings.Contains(ft, "mach"):
			return "macho"
		case strings.Contains(ft, "npm"), strings.Contains(ft, "node"):
			return "npm"
		}
	}
	// CLSR-03 (P61): UWP installed-dir fallback. When all earlier signals miss
	// but the appDir contains AppxManifest.xml + WebView2Loader.dll evidence,
	// classify as webview2. Empty appDir returns false from Detect — preserves
	// non-regression for callers that don't have a path.
	if appDir != "" && webview2.Detect(appDir) {
		return "webview2"
	}
	return ""
}

func extractVersion(r *dissect.DissectResult) string {
	if r.NPMAnalysis != nil && r.NPMAnalysis.Version != "" {
		return r.NPMAnalysis.Version
	}
	if r.AppAnalysis != nil && r.AppAnalysis.AppInfo.Version != "" {
		return r.AppAnalysis.AppInfo.Version
	}
	if r.ManifestInfo != nil && r.ManifestInfo.VersionName != "" {
		return r.ManifestInfo.VersionName
	}
	if r.DEBInfo != nil && r.DEBInfo.Control != nil && r.DEBInfo.Control.Version != "" {
		return r.DEBInfo.Control.Version
	}
	if r.RPMInfo != nil && r.RPMInfo.Version != "" {
		return r.RPMInfo.Version
	}
	if r.MSIInfo != nil && r.MSIInfo.ProductVersion != "" {
		return r.MSIInfo.ProductVersion
	}
	if r.MSIXInfo != nil && r.MSIXInfo.PackageVersion != "" {
		return r.MSIXInfo.PackageVersion
	}
	if r.IPAInfo != nil && r.IPAInfo.Version != "" {
		return r.IPAInfo.Version
	}
	if r.BinaryInfo != nil && r.BinaryInfo.ProductVersion != "" {
		return r.BinaryInfo.ProductVersion
	}
	return ""
}

func extractCommunication(r *dissect.DissectResult) *CommunicationKnowledge {
	ck := &CommunicationKnowledge{}

	if r.NetworkAnalysis != nil {
		for _, ep := range r.NetworkAnalysis.Endpoints {
			ck.Endpoints = append(ck.Endpoints, Endpoint{
				URL:     ep.URL,
				Purpose: categorizePurpose(ep.URL),
			})
		}
		ck.CertificatePinning = r.NetworkAnalysis.CertPinning != nil
		ck.CleartextAllowed = r.NetworkAnalysis.CleartextAllowed
	}

	if r.AppAnalysis != nil {
		for _, ep := range r.AppAnalysis.Analysis.APIEndpoints {
			ck.Endpoints = append(ck.Endpoints, Endpoint{
				URL:     ep.URL,
				Purpose: ep.Purpose,
			})
		}
	}

	if r.Secrets != nil {
		for _, f := range r.Secrets.Findings {
			t := strings.ToLower(string(f.Type))
			if strings.Contains(t, "url") || strings.Contains(t, "endpoint") {
				ck.Endpoints = append(ck.Endpoints, Endpoint{
					URL:     f.Value,
					Purpose: "discovered",
				})
			}
		}
	}

	if r.NPMAnalysis != nil {
		for _, url := range extractNPMEndpointURLs(r.Path) {
			ck.Endpoints = append(ck.Endpoints, Endpoint{
				URL:     url,
				Methods: []string{"GET", "POST"},
				Purpose: "npm static API call",
			})
		}
	}

	// Go binary surface: backend hosts + gRPC/proto RPC names recovered by
	// streaming the binary (pkg/dissect/analyze_go_surface.go). For stripped
	// standalone Go apps this is usually the only communication signal.
	if r.GoSurface != nil {
		for _, host := range r.GoSurface.Hosts {
			ck.Endpoints = append(ck.Endpoints, Endpoint{
				URL:     host,
				Purpose: categorizePurpose(host),
			})
		}
		for _, svc := range r.GoSurface.RPCServices {
			ck.Endpoints = append(ck.Endpoints, Endpoint{
				URL:        svc,
				Purpose:    "gRPC/proto RPC",
				DataFormat: "grpc",
			})
		}
		if len(r.GoSurface.RPCServices) > 0 {
			ck.DataFormats = append(ck.DataFormats, "grpc")
		}
	}

	protocols := map[string]bool{}
	for _, ep := range ck.Endpoints {
		switch {
		case strings.HasPrefix(ep.URL, "https://"):
			protocols["https"] = true
		case strings.HasPrefix(ep.URL, "http://"):
			protocols["http"] = true
		case strings.HasPrefix(ep.URL, "wss://") || strings.HasPrefix(ep.URL, "ws://"):
			protocols["websocket"] = true
		}
	}
	for p := range protocols {
		ck.Protocols = append(ck.Protocols, p)
	}

	if r.ProtobufAnalysis != nil && r.ProtobufAnalysis.HasProtobuf {
		ck.DataFormats = append(ck.DataFormats, "protobuf")
	}
	if r.ProtobufAnalysis != nil && r.ProtobufAnalysis.HasGRPC {
		ck.DataFormats = append(ck.DataFormats, "grpc")
	}
	if len(ck.Endpoints) > 0 {
		ck.DataFormats = append(ck.DataFormats, "json")
	}

	if len(ck.Endpoints) == 0 && len(ck.Protocols) == 0 && len(ck.DataFormats) == 0 {
		return nil
	}
	return ck
}

var npmEndpointLiteralRE = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)

func extractNPMEndpointURLs(root string) []string {
	seen := map[string]bool{}
	var urls []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "test", "tests":
				return filepath.SkipDir
			}
			return nil
		}
		if !isNPMSourcePath(path) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 512*1024 {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, raw := range npmEndpointLiteralRE.FindAllString(string(body), -1) {
			u := strings.TrimRight(raw, "\"'`).,;}")
			if !seen[u] {
				seen[u] = true
				urls = append(urls, u)
			}
		}
		if len(urls) >= 100 {
			return io.EOF
		}
		return nil
	})
	return urls
}

func extractAuth(r *dissect.DissectResult) *AuthKnowledge {
	ak := &AuthKnowledge{}

	if r.Secrets != nil {
		for _, f := range r.Secrets.Findings {
			t := strings.ToLower(string(f.Type))
			switch {
			case strings.Contains(t, "api_key") || strings.Contains(t, "apikey"):
				ak.Methods = appendAuthMethodIfNew(ak.Methods, AuthMethod{Type: "api_key", Implementation: "custom"})
			case strings.Contains(t, "bearer") || strings.Contains(t, "token"):
				ak.Methods = appendAuthMethodIfNew(ak.Methods, AuthMethod{Type: "bearer", Implementation: "custom"})
			case strings.Contains(t, "oauth"):
				ak.Methods = appendAuthMethodIfNew(ak.Methods, AuthMethod{Type: "oauth2", Implementation: "custom"})
			}
		}
	}

	if len(ak.Methods) == 0 {
		return nil
	}
	return ak
}

func extractUI(r *dissect.DissectResult) *UIKnowledge {
	ui := &UIKnowledge{}

	// Detect frontend framework from JS analysis content indicators
	if r.JSAnalysis != nil {
		for _, indicator := range r.JSAnalysis.Indicators {
			lower := strings.ToLower(indicator)
			switch {
			case strings.Contains(lower, "createelement") || strings.Contains(lower, "usestate") || strings.Contains(lower, "react"):
				if ui.Framework == "" {
					ui.Framework = "react"
				}
			case strings.Contains(lower, "createapp") || strings.Contains(lower, "vue"):
				if ui.Framework == "" {
					ui.Framework = "vue"
				}
			case strings.Contains(lower, "ngmodule") || strings.Contains(lower, "angular"):
				if ui.Framework == "" {
					ui.Framework = "angular"
				}
			}
		}
	}

	// Detect from ASAR files (package.json deps, build tools, etc.)
	for _, f := range r.ASARFiles {
		name := filepath.Base(f.Path)
		lower := strings.ToLower(f.Path)

		// Detect build tool
		switch {
		case name == "webpack.config.js" || name == "webpack.config.ts":
			ui.BuildTool = "webpack"
		case strings.HasPrefix(name, "vite.config"):
			ui.BuildTool = "vite"
		case name == "rollup.config.js" || name == "rollup.config.ts":
			ui.BuildTool = "rollup"
		case name == "esbuild.config.js":
			ui.BuildTool = "esbuild"
		}

		// Detect from node_modules paths
		if strings.Contains(lower, "node_modules/react/") && ui.Framework == "" {
			ui.Framework = "react"
		} else if strings.Contains(lower, "node_modules/vue/") && ui.Framework == "" {
			ui.Framework = "vue"
		} else if strings.Contains(lower, "node_modules/@angular/core/") && ui.Framework == "" {
			ui.Framework = "angular"
		} else if strings.Contains(lower, "node_modules/svelte/") && ui.Framework == "" {
			ui.Framework = "svelte"
		}

		// Detect CSS framework from filenames
		if strings.Contains(lower, "tailwind") {
			ui.CSSFramework = "tailwind"
		} else if strings.Contains(lower, "bootstrap") && ui.CSSFramework == "" {
			ui.CSSFramework = "bootstrap"
		}
	}

	// Detect from mobile framework analysis
	if r.FrameworkAnalysis != nil && r.FrameworkAnalysis.Framework != "" {
		if ui.Framework == "" {
			ui.Framework = r.FrameworkAnalysis.Framework
		}
	}

	// SPA detection: Electron/Tauri apps with a UI framework are SPAs
	if ui.Framework != "" {
		ui.IsSPA = true
	}

	if ui.Framework == "" && ui.BuildTool == "" && ui.CSSFramework == "" {
		return nil
	}
	return ui
}

func extractIPC(r *dissect.DissectResult) *IPCKnowledge {
	ik := &IPCKnowledge{}

	if r.AppAnalysis != nil {
		for _, cmd := range r.AppAnalysis.Analysis.IPCCommands {
			ch := IPCChannel{
				Name:      cmd.Channel,
				Direction: cmd.Direction,
				RiskLevel: cmd.Risk,
			}
			if cmd.Risk == "high" || cmd.Risk == "critical" {
				ch.Privileged = true
			}
			ik.Channels = append(ik.Channels, ch)
		}
		if len(ik.Channels) > 0 {
			ik.Protocols = append(ik.Protocols, "electron-ipc")
		}
	}

	if r.ManifestInfo != nil {
		for _, c := range r.ManifestInfo.Components {
			if c.Exported != nil && *c.Exported {
				ik.Channels = append(ik.Channels, IPCChannel{
					Name:      c.Name,
					Direction: "bidirectional",
				})
			}
		}
		if len(r.ManifestInfo.Components) > 0 {
			ik.Protocols = appendIfNew(ik.Protocols, "android-intent")
		}
	}

	if len(ik.Channels) == 0 {
		return nil
	}
	return ik
}

func extractSecurity(r *dissect.DissectResult) *SecurityKnowledge {
	sk := &SecurityKnowledge{}

	if r.AppAnalysis != nil {
		sk.RiskScore = r.AppAnalysis.Analysis.RiskScore
		sk.RiskLevel = r.AppAnalysis.Analysis.RiskLevel

		for _, s := range r.AppAnalysis.Analysis.SecuritySettings {
			safe := s.Risk == "" || strings.EqualFold(s.Risk, "low")
			sk.Settings = append(sk.Settings, SecuritySetting{
				Name:    s.Name,
				Value:   s.Value,
				Safe:    safe,
				Comment: s.Description,
			})
		}
	}

	if r.ManifestAnalysis != nil {
		if sk.RiskScore == 0 {
			sk.RiskScore = r.ManifestAnalysis.SecurityScore
			sk.RiskLevel = r.ManifestAnalysis.RiskLevel
		}
		for _, issue := range r.ManifestAnalysis.SecurityIssues {
			sk.Vulnerabilities = append(sk.Vulnerabilities, issue.Title)
		}
	}

	if r.ManifestInfo != nil {
		sf := r.ManifestInfo.Security
		if sf.Debuggable {
			sk.Settings = append(sk.Settings, SecuritySetting{Name: "debuggable", Value: "true", Safe: false, Comment: "App is debuggable"})
		}
		if sf.AllowBackup {
			sk.Settings = append(sk.Settings, SecuritySetting{Name: "allowBackup", Value: "true", Safe: false, Comment: "Data backup allowed"})
		}
		if sf.UsesCleartextTraffic {
			sk.Settings = append(sk.Settings, SecuritySetting{Name: "usesCleartextTraffic", Value: "true", Safe: false, Comment: "Cleartext HTTP allowed"})
		}
	}

	// PE/ELF binary certificate security settings
	if r.CertInfo != nil {
		if r.CertInfo.HasSignature {
			sk.Settings = append(sk.Settings, SecuritySetting{Name: "code_signed", Value: "true", Safe: true, Comment: "Binary has code signature"})
			if !r.CertInfo.Verified {
				sk.Settings = append(sk.Settings, SecuritySetting{Name: "signature_verified", Value: "false", Safe: false, Comment: "Signature verification failed: " + r.CertInfo.VerifyError})
			}
			if r.CertInfo.Signer != nil && r.CertInfo.Signer.IsExpired {
				sk.Settings = append(sk.Settings, SecuritySetting{Name: "cert_expired", Value: "true", Safe: false, Comment: "Signing certificate has expired"})
			}
			if r.CertInfo.Signer != nil && r.CertInfo.Signer.IsSelfSigned {
				sk.Settings = append(sk.Settings, SecuritySetting{Name: "self_signed", Value: "true", Safe: false, Comment: "Certificate is self-signed"})
			}
		} else {
			sk.Settings = append(sk.Settings, SecuritySetting{Name: "code_signed", Value: "false", Safe: false, Comment: "Binary is not code signed"})
		}
	}

	if sk.RiskScore == 0 && len(sk.Settings) == 0 {
		return nil
	}

	if sk.RiskLevel == "" {
		switch {
		case sk.RiskScore >= 80:
			sk.RiskLevel = "critical"
		case sk.RiskScore >= 60:
			sk.RiskLevel = "high"
		case sk.RiskScore >= 40:
			sk.RiskLevel = "medium"
		default:
			sk.RiskLevel = "low"
		}
	}

	return sk
}

func extractStealth(r *dissect.DissectResult) *StealthKnowledge {
	sk := &StealthKnowledge{}

	if r.AppAnalysis != nil {
		for _, s := range r.AppAnalysis.Analysis.StealthFeatures {
			lower := strings.ToLower(s.Name)
			switch {
			case strings.Contains(lower, "content protection") || strings.Contains(lower, "screen"):
				sk.ScreenCaptureBlock = true
				sk.ScreenShareHide = true
			case strings.Contains(lower, "debug"):
				sk.AntiDebugging = append(sk.AntiDebugging, s.Name)
			case strings.Contains(lower, "process"):
				sk.ProcessHiding = true
			}
		}
	}

	if r.NativeAnalysis != nil {
		for _, f := range r.NativeAnalysis.Findings {
			switch f.Category {
			case "anti-debug":
				sk.AntiDebugging = append(sk.AntiDebugging, f.Description)
			case "frida-detection":
				sk.AntiInstrumentation = append(sk.AntiInstrumentation, f.Description)
			}
		}
	}

	if r.ObfuscationAnalysis != nil {
		sk.CodeObfuscation = string(r.ObfuscationAnalysis.Type)
	} else if r.GarbleDetect != nil && r.GarbleDetect.IsGarbled {
		sk.CodeObfuscation = "garble"
	}

	// UWP path: graphicsCapture* capabilities mark the app as silent-screen-
	// capture capable (Cluely / Teams pattern). They are not the same as
	// Electron's setContentProtection, but they convey equivalent stealth
	// signal — the app can capture screens without UAC prompt or border.
	if r.UWPInfo != nil && r.UWPInfo.Manifest != nil {
		for _, c := range r.UWPInfo.Manifest.Capabilities {
			lower := strings.ToLower(c.Name)
			if strings.HasPrefix(lower, "graphicscapture") {
				sk.ScreenCaptureBlock = true
				sk.ScreenShareHide = true
				break
			}
		}
	}

	if !sk.ScreenCaptureBlock && !sk.ScreenShareHide && !sk.ProcessHiding &&
		len(sk.AntiDebugging) == 0 && len(sk.AntiInstrumentation) == 0 && sk.CodeObfuscation == "" {
		return nil
	}
	return sk
}

func extractTelemetry(r *dissect.DissectResult) *TelemetryKnowledge {
	tk := &TelemetryKnowledge{}

	if r.TelemetryAnalysis != nil {
		for _, sdk := range r.TelemetryAnalysis.SDKs {
			tk.Services = append(tk.Services, TelemetryService{
				Name:     sdk.Name,
				Category: string(sdk.Category),
			})
		}
	}

	if r.AppAnalysis != nil {
		for _, name := range r.AppAnalysis.AppInfo.Telemetry {
			// Avoid duplicates from TelemetryAnalysis
			found := false
			for _, s := range tk.Services {
				if strings.EqualFold(s.Name, name) {
					found = true
					break
				}
			}
			if !found {
				tk.Services = append(tk.Services, TelemetryService{Name: name})
			}
		}
	}

	if len(tk.Services) == 0 {
		return nil
	}
	return tk
}

func extractNPM(r *dissect.DissectResult) *NPMKnowledge {
	if r.NPMAnalysis == nil {
		return nil
	}
	nk := &NPMKnowledge{
		Name:                  r.NPMAnalysis.PackageName,
		Version:               r.NPMAnalysis.Version,
		SourceMode:            "clean-room-npm-tarball",
		Scripts:               r.NPMAnalysis.Scripts,
		NetworkCalls:          append([]string(nil), r.NPMAnalysis.NetworkCalls...),
		FSAccess:              append([]string(nil), r.NPMAnalysis.FSAccess...),
		ExecCalls:             append([]string(nil), r.NPMAnalysis.ExecCalls...),
		MCPTools:              append([]string(nil), r.NPMAnalysis.MCPTools...),
		MCPTransport:          r.NPMAnalysis.MCPTransport,
		MCPSDKVersion:         r.NPMAnalysis.MCPSDKVersion,
		ObfuscationIndicators: append([]string(nil), r.NPMAnalysis.ObfuscationIndicators...),
		SupplyChainRisks:      append([]string(nil), r.NPMAnalysis.SupplyChainRisks...),
		RiskScore:             r.NPMAnalysis.RiskScore,
		RiskFactors:           append([]string(nil), r.NPMAnalysis.RiskFactors...),
	}

	if pkg, err := npm.ParsePackageJSON(filepath.Join(r.Path, "package.json")); err == nil {
		if nk.Name == "" {
			nk.Name = pkg.Name
		}
		if nk.Version == "" {
			nk.Version = pkg.Version
		}
		nk.Description = pkg.Description
		nk.Repository = normalizeNPMRepository(pkg.Repository)
		nk.Homepage = pkg.Homepage
		nk.License = stringifyPackageField(pkg.License)
		nk.Binaries = pkg.BinEntries()
		nk.Dependencies = pkg.Dependencies
		nk.DevDependencies = pkg.DevDependencies
		if strings.Contains(strings.ToLower(nk.Repository), "github.com/") {
			nk.SourceMode = "github-repository"
		}
	}

	return nk
}

func stringifyPackageField(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		if s, ok := t["type"].(string); ok {
			return s
		}
		if s, ok := t["url"].(string); ok {
			return s
		}
	}
	return ""
}

func normalizeNPMRepository(v any) string {
	switch t := v.(type) {
	case string:
		return normalizeGitURL(t)
	case map[string]any:
		if s, ok := t["url"].(string); ok {
			return normalizeGitURL(s)
		}
	}
	return ""
}

func normalizeGitURL(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "git+")
	s = strings.TrimPrefix(s, "git://")
	s = strings.TrimPrefix(s, "ssh://git@")
	s = strings.TrimPrefix(s, "git@")
	s = strings.TrimSuffix(s, ".git")
	if strings.HasPrefix(s, "github.com:") {
		s = "https://github.com/" + strings.TrimPrefix(s, "github.com:")
	}
	return s
}

func extractSourceFiles(r *dissect.DissectResult) []SourceFile {
	if r.NPMAnalysis != nil {
		return extractNPMSourceFiles(r)
	}
	// UWP / MSIX path: derive source files from MSIXInfo.Files captured
	// during InfoFromDir walk (Plan B2). Only triggers when no ASAR signal
	// is present so Electron-MSIX hybrids stay on the ASAR path.
	if len(r.ASARFiles) == 0 && r.MSIXInfo != nil && len(r.MSIXInfo.Files) > 0 {
		return extractUWPSourceFiles(r.MSIXInfo.Files)
	}
	if len(r.ASARFiles) == 0 {
		return nil
	}

	interesting := map[string]string{
		"main.js":      "main process entry",
		"index.js":     "entry point",
		"package.json": "package metadata",
		"index.html":   "renderer entry",
	}

	var files []SourceFile
	for _, f := range r.ASARFiles {
		if f.IsDir {
			continue
		}
		// Skip node_modules
		if strings.Contains(f.Path, "node_modules/") {
			continue
		}
		name := filepath.Base(f.Path)
		lower := strings.ToLower(name)

		purpose := ""
		if p, ok := interesting[lower]; ok {
			purpose = p
		} else if strings.HasPrefix(lower, "preload") && strings.HasSuffix(lower, ".js") {
			purpose = "preload script"
		} else {
			continue
		}

		files = append(files, SourceFile{
			Path:     f.Path,
			Original: f.Path,
			Size:     f.Size,
			Purpose:  purpose,
		})

		if len(files) >= 20 {
			break
		}
	}
	return files
}

func extractNPMSourceFiles(r *dissect.DissectResult) []SourceFile {
	pkg, _ := npm.ParsePackageJSON(filepath.Join(r.Path, "package.json"))
	wanted := map[string]string{
		"package.json": "package metadata",
		"index.js":     "entry point",
		"index.ts":     "entry point",
		"cli.js":       "cli entry point",
		"cli.ts":       "cli entry point",
	}
	if pkg != nil {
		if pkg.Main != "" {
			wanted[filepath.ToSlash(filepath.Clean(pkg.Main))] = "main entry point"
		}
		for _, bin := range pkg.BinEntries() {
			if bin != "" {
				wanted[filepath.ToSlash(filepath.Clean(bin))] = "cli binary entry point"
			}
		}
		for hook, script := range pkg.Scripts {
			if !strings.Contains(hook, "install") && hook != "prepare" {
				continue
			}
			for _, token := range strings.Fields(script) {
				if isNPMSourcePath(token) {
					wanted[filepath.ToSlash(filepath.Clean(strings.Trim(token, `"'`)))] = hook + " script"
				}
			}
		}
	}

	var files []SourceFile
	seen := map[string]bool{}
	for rel, purpose := range wanted {
		if addNPMSourceFile(r.Path, rel, purpose, seen, &files) && len(files) >= 80 {
			return files
		}
	}

	_ = filepath.WalkDir(r.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == "node_modules" || base == ".git" || base == "test" || base == "tests" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(r.Path, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !isNPMSourcePath(rel) {
			return nil
		}
		if addNPMSourceFile(r.Path, rel, "clean-room source", seen, &files) && len(files) >= 80 {
			return io.EOF
		}
		return nil
	})
	return files
}

func isNPMSourcePath(path string) bool {
	ext := strings.ToLower(filepath.Ext(strings.Trim(path, `"'`)))
	return slices.Contains([]string{".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json"}, ext)
}

func addNPMSourceFile(root, rel, purpose string, seen map[string]bool, files *[]SourceFile) bool {
	rel = filepath.ToSlash(filepath.Clean(strings.Trim(rel, `"'`)))
	if rel == "." || rel == "" || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) || seen[rel] {
		return false
	}
	path := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > 512*1024 {
		return false
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	seen[rel] = true
	*files = append(*files, SourceFile{
		Path:               rel,
		Original:           rel,
		Size:               info.Size(),
		Purpose:            purpose,
		Content:            content,
		RawSourcePath:      rel,
		BeautifyProvenance: "clean-room-npm",
	})
	return true
}

// extractUWPSourceFiles classifies file entries captured by msix.InfoFromDir
// into SourceFile records. Path-based heuristic — see isInterestingForensicFile
// for the upstream filter.
func extractUWPSourceFiles(files []msix.FileEntry) []SourceFile {
	out := make([]SourceFile, 0, len(files))
	for _, f := range files {
		sf := SourceFile{
			Path:     f.Name,
			Original: f.Name,
			Size:     f.Size,
			Purpose:  classifyUWPFilePurpose(f.Name),
		}
		if f.Signed != nil {
			val := *f.Signed
			sf.Signed = &val
			sf.Signer = f.Signer
		}
		out = append(out, sf)
		if len(out) >= 200 {
			break
		}
	}
	return out
}

func classifyUWPFilePurpose(path string) string {
	lower := strings.ToLower(path)
	switch filepath.Ext(lower) {
	case ".exe":
		return "executable"
	case ".dll":
		return "native-module"
	case ".node":
		return "node-native-addon"
	case ".html", ".htm":
		return "web-document"
	case ".js", ".mjs":
		return "web-script"
	case ".css":
		return "web-style"
	case ".wasm":
		return "webassembly"
	case ".json":
		switch {
		case strings.Contains(lower, "deps.json"):
			return "dotnet-deps"
		case strings.Contains(lower, "runtimeconfig.json"):
			return "dotnet-runtime-config"
		case strings.Contains(lower, "package.json"):
			return "package-metadata"
		default:
			return "config"
		}
	case ".xml":
		if strings.Contains(lower, "appxmanifest") {
			return "uwp-manifest"
		}
		return "xml-config"
	case ".manifest":
		return "win-manifest"
	case ".xaml":
		return "xaml-source"
	case ".xbf":
		return "xaml-compiled"
	case ".pri":
		return "uwp-resource-index"
	case ".dat", ".bin":
		return "data-blob"
	}
	return "other"
}

func extractAndroid(r *dissect.DissectResult) *AndroidKnowledge {
	if r.ManifestInfo == nil && r.DEXAnalysis == nil && r.NativeAnalysis == nil {
		return nil
	}

	ak := &AndroidKnowledge{}

	// Manifest data
	if m := r.ManifestInfo; m != nil {
		ak.Package = m.Package
		ak.VersionCode = fmt.Sprintf("%d", m.VersionCode)
		ak.VersionName = m.VersionName
		ak.MinSDK = fmt.Sprintf("%d", m.MinSDK)
		ak.TargetSDK = fmt.Sprintf("%d", m.TargetSDK)

		for _, p := range m.Permissions {
			ak.Permissions = append(ak.Permissions, AndroidPermission{
				Name:      p.Name,
				Risk:      p.RiskLevel,
				Dangerous: p.RiskLevel == "dangerous",
			})
		}

		for _, c := range m.Components {
			exported := c.Exported != nil && *c.Exported
			ak.Components = append(ak.Components, AndroidComponent{
				Name:     c.Name,
				Type:     string(c.Type),
				Exported: exported,
			})
		}
	}

	// Deep links from manifest analysis
	if ma := r.ManifestAnalysis; ma != nil {
		for _, dl := range ma.DeepLinks {
			ak.DeepLinks = append(ak.DeepLinks, dl.URI)
		}
	}

	// Secrets
	if s := r.Secrets; s != nil {
		for _, f := range s.Findings {
			ak.Secrets = append(ak.Secrets, SecretFinding{
				Type:        string(f.Type),
				File:        f.File,
				Confidence:  f.Confidence,
				MaskedValue: f.Value,
				RawLength:   f.RawLength,
			})
		}
	}

	// Native libraries
	if n := r.NativeAnalysis; n != nil {
		for _, lib := range n.Libraries {
			ni := NativeLibInfo{
				Name: lib.Name,
				ABI:  lib.ABI,
				Size: lib.Size,
			}
			for _, jni := range lib.JNIExports {
				ni.JNIExports = append(ni.JNIExports, jni.JavaName)
			}
			ak.NativeLibs = append(ak.NativeLibs, ni)
		}
	}

	// Obfuscation
	if o := r.ObfuscationAnalysis; o != nil && o.Type != "none" {
		ak.Obfuscation = &ObfuscationInfo{
			Type:       string(o.Type),
			Confidence: int(o.Confidence),
			HasMapping: o.HasMapping,
		}
		if o.Packer != nil {
			ak.Obfuscation.Packer = o.Packer.Name
		}
	}

	// Framework
	if f := r.FrameworkAnalysis; f != nil && f.Framework != "" {
		ak.Framework = &AppFrameworkInfo{
			Name: f.Framework,
		}
		switch {
		case f.Flutter != nil:
			ak.Framework.Engine = f.Flutter.EngineVersion
			ak.Framework.Version = f.Flutter.DartVersion
		case f.ReactNative != nil:
			ak.Framework.Engine = f.ReactNative.JSEngine
		}
	}

	// DEX stats
	if d := r.DEXAnalysis; d != nil {
		ak.DEXStats = &DEXStatsInfo{
			FileCount:    len(d.DexFiles),
			TotalClasses: d.TotalClasses,
			TotalMethods: d.TotalMethods,
			MultiDex:     d.MultiDex,
		}
		for _, rf := range d.RiskFindings {
			ak.RiskAPIs = append(ak.RiskAPIs, RiskAPIFinding{
				Category: rf.Category,
				API:      rf.API,
				Severity: rf.Severity,
			})
		}
	}

	return ak
}

func extractBinaryKnowledge(r *dissect.DissectResult) *BinaryKnowledge {
	if r.BinaryInfo == nil && r.CertInfo == nil && r.DotnetDeps == nil && r.DotnetRuntime == nil {
		return nil
	}

	bk := &BinaryKnowledge{}

	if bi := r.BinaryInfo; bi != nil {
		bk.Format = bi.Type
		bk.Arch = bi.Arch
		bk.SizeBytes = bi.SizeBytes
		bk.Imports = bi.Imports
		bk.Libraries = bi.Libraries
		bk.StringsTotal = bi.StringsTotal
		bk.URLCount = bi.URLCount
		if len(bi.SampleURLs) > 0 {
			bk.SampleURLs = bi.SampleURLs
		}
	}

	if ci := r.CertInfo; ci != nil {
		si := &SigningInfo{
			HasSignature: ci.HasSignature,
			Verified:     ci.Verified,
		}
		if ci.Signer != nil {
			si.Subject = ci.Signer.Subject
			si.Issuer = ci.Signer.Issuer
			si.CommonName = ci.Signer.CommonName
			si.Organization = ci.Signer.Organization
			si.NotBefore = ci.Signer.NotBefore.Format(time.RFC3339)
			si.NotAfter = ci.Signer.NotAfter.Format(time.RFC3339)
			si.IsExpired = ci.Signer.IsExpired
			si.IsSelfSigned = ci.Signer.IsSelfSigned
			si.Thumbprint = ci.Signer.Thumbprint
		}
		si.ChainLength = len(ci.Chain)
		bk.Signing = si
	}

	if deps := r.DotnetDeps; deps != nil {
		di := &DotnetInfo{
			TargetFramework: deps.TargetFramework,
			Frameworks:      deps.Frameworks,
			IPCMechanisms:   deps.IPCMechanisms,
			TotalLibraries:  deps.TotalLibraries,
		}
		bk.DotnetInfo = di
	}

	if rt := r.DotnetRuntime; rt != nil {
		if bk.DotnetInfo == nil {
			bk.DotnetInfo = &DotnetInfo{}
		}
		if bk.DotnetInfo.TargetFramework == "" {
			bk.DotnetInfo.TargetFramework = rt.TFM
		}
		bk.DotnetInfo.IsASPNET = rt.IsASPNET
		bk.DotnetInfo.IsDesktop = rt.IsDesktop
		if len(rt.Frameworks) > 0 && len(bk.DotnetInfo.Frameworks) == 0 {
			for _, fw := range rt.Frameworks {
				bk.DotnetInfo.Frameworks = append(bk.DotnetInfo.Frameworks, fw.Name)
			}
		}
	}

	return bk
}

func extractGoBinary(r *dissect.DissectResult) *GoBinaryKnowledge {
	if r.GarbleInfo == nil && r.GarbleDetect == nil {
		return nil
	}

	gb := &GoBinaryKnowledge{}

	if info := r.GarbleInfo; info != nil {
		gb.GoVersion = info.GoVersion
		gb.ModulePath = info.ModulePath
		gb.Arch = info.Arch
		gb.OS = info.OS
		gb.BuildID = info.BuildID
		gb.IsStatic = info.IsStaticLinked
		gb.HasSymbolTable = info.HasSymbolTable
		gb.HasDWARF = info.HasDWARF
		if len(info.BuildSettings) > 0 {
			gb.BuildSettings = info.BuildSettings
		}
	}

	if det := r.GarbleDetect; det != nil {
		gb.IsGarbled = det.IsGarbled
		gb.GarbleConfidence = det.Confidence
	}

	if str := r.GarbleStrings; str != nil {
		gb.HighEntropyStrings = str.HighEntropyCount
		if len(str.ByCategory) > 0 {
			gb.StringCategories = make(map[string]int)
			for cat, count := range str.ByCategory {
				gb.StringCategories[string(cat)] = count
			}
		}
	}

	if sym := r.GarbleSymbols; sym != nil {
		gb.SymbolCount = sym.TotalSymbols
		gb.FunctionCount = sym.FunctionCount
		gb.ObfuscatedSymbols = sym.ObfuscatedCount
		gb.ObfuscationRatio = sym.ObfuscationRatio
		gb.Packages = sym.Packages
	}

	if gs := r.GoSymbols; gs != nil {
		gb.RecoveredSymbolCount = len(gs.Symbols)
		const maxKBSymbols = 500
		for i, s := range gs.Symbols {
			if i >= maxKBSymbols {
				break
			}
			gb.RecoveredFunctions = append(gb.RecoveredFunctions, s.Name)
		}
		gb.RecoveredTypes = gs.Types
	}

	return gb
}

func extractDEBKnowledge(r *dissect.DissectResult) *PackageKnowledge {
	d := r.DEBInfo
	pk := &PackageKnowledge{
		Format: "deb",
		Files:  d.FileCount,
		Signed: d.HasSignature,
	}
	if c := d.Control; c != nil {
		pk.Name = c.Package
		pk.Version = c.Version
		pk.Architecture = c.Architecture
		pk.Maintainer = c.Maintainer
		pk.Description = c.Description
		if c.Depends != "" {
			pk.Dependencies = strings.Split(c.Depends, ", ")
		}
	}
	// Map script names to presence
	if len(d.Scripts) > 0 {
		pk.Scripts = make(map[string]bool, len(d.Scripts))
		for _, s := range d.Scripts {
			pk.Scripts[s] = true
		}
	}
	return pk
}

func extractRPMKnowledge(r *dissect.DissectResult) *PackageKnowledge {
	ri := r.RPMInfo
	pk := &PackageKnowledge{
		Format:       "rpm",
		Name:         ri.Name,
		Version:      ri.Version,
		Architecture: ri.Arch,
		Description:  ri.Description,
		Signed:       ri.HasSignature,
	}
	if ri.Vendor != "" {
		pk.Maintainer = ri.Vendor
	} else {
		pk.Maintainer = ri.Packager
	}
	return pk
}

func extractMSIKnowledge(r *dissect.DissectResult) *PackageKnowledge {
	m := r.MSIInfo
	pk := &PackageKnowledge{
		Format:     "msi",
		Name:       m.ProductName,
		Version:    m.ProductVersion,
		Maintainer: m.Manufacturer,
		Files:      m.FileCount,
		Signed:     m.HasSignature,
	}
	for _, ca := range m.CustomActions {
		pk.CustomActions = append(pk.CustomActions, ca.Action)
	}
	return pk
}

func extractMSIXKnowledge(r *dissect.DissectResult) *PackageKnowledge {
	m := r.MSIXInfo
	pk := &PackageKnowledge{
		Format:       "msix",
		Name:         m.PackageName,
		Version:      m.PackageVersion,
		Architecture: m.ProcessorArchitecture,
		Maintainer:   m.PublisherDisplayName,
		Description:  m.Description,
		Files:        m.FileCount,
		Signed:       m.HasSignature,
		Capabilities: m.Capabilities,
	}
	for _, dep := range m.Dependencies {
		pk.Dependencies = append(pk.Dependencies, dep.Name)
	}
	return pk
}

func extractIOSKnowledge(r *dissect.DissectResult) *IOSKnowledge {
	i := r.IPAInfo
	ik := &IOSKnowledge{
		BundleID:   i.BundleID,
		BundleName: i.BundleName,
		Version:    i.Version,
		MinimumOS:  i.MinimumOS,
		Platform:   i.Platform,
		URLSchemes: i.URLSchemes,
		Frameworks: i.Frameworks,
		Signed:     i.SigningInfo != nil && i.SigningInfo.HasCodeSignature,
	}
	for _, p := range i.Permissions {
		ik.Permissions = append(ik.Permissions, p.Key)
	}
	return ik
}

func extractPackaging(r *dissect.DissectResult) *PackagingKnowledge {
	if r.DEBInfo != nil {
		return extractDEB(r.DEBInfo)
	}
	if r.RPMInfo != nil {
		return extractRPM(r.RPMInfo)
	}
	if r.MSIInfo != nil {
		return extractMSI(r.MSIInfo)
	}
	if r.MSIXInfo != nil {
		return extractMSIX(r.MSIXInfo)
	}
	return nil
}

func extractDEB(d *deb.InfoResult) *PackagingKnowledge {
	pk := &PackagingKnowledge{
		Format:       "deb",
		FileCount:    d.FileCount,
		TotalSize:    d.TotalSize,
		HasSignature: d.HasSignature,
		Scripts:      d.Scripts,
	}
	if c := d.Control; c != nil {
		pk.Name = c.Package
		pk.Version = c.Version
		pk.Arch = c.Architecture
		pk.Maintainer = c.Maintainer
		pk.Description = c.Description
		if c.Depends != "" {
			pk.Dependencies = strings.Split(c.Depends, ", ")
		}
	}
	return pk
}

func extractRPM(r *rpm.InfoResult) *PackagingKnowledge {
	pk := &PackagingKnowledge{
		Format:       "rpm",
		Name:         r.Name,
		Version:      r.Version,
		Arch:         r.Arch,
		Description:  r.Description,
		HasSignature: r.HasSignature,
		TotalSize:    r.InstalledSize,
	}
	if r.Vendor != "" {
		pk.Maintainer = r.Vendor
	} else {
		pk.Maintainer = r.Packager
	}
	return pk
}

func extractMSI(m *msi.InfoResult) *PackagingKnowledge {
	pk := &PackagingKnowledge{
		Format:       "msi",
		Name:         m.ProductName,
		Version:      m.ProductVersion,
		Maintainer:   m.Manufacturer,
		FileCount:    m.FileCount,
		HasSignature: m.HasSignature,
	}
	if len(m.Properties) > 0 {
		pk.Properties = m.Properties
	}
	return pk
}

func extractMSIX(m *msix.InfoResult) *PackagingKnowledge {
	pk := &PackagingKnowledge{
		Format:       "msix",
		Name:         m.PackageName,
		Version:      m.PackageVersion,
		Arch:         m.ProcessorArchitecture,
		Maintainer:   m.PublisherDisplayName,
		Description:  m.Description,
		FileCount:    m.FileCount,
		TotalSize:    m.TotalSize,
		HasSignature: m.HasSignature,
		Capabilities: m.Capabilities,
	}
	for _, dep := range m.Dependencies {
		pk.Dependencies = append(pk.Dependencies, dep.Name)
	}
	return pk
}

func categorizePurpose(url string) string {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "analytics") || strings.Contains(lower, "telemetry") ||
		strings.Contains(lower, "sentry") || strings.Contains(lower, "mixpanel"):
		return "telemetry"
	case strings.Contains(lower, "auth") || strings.Contains(lower, "login") ||
		strings.Contains(lower, "oauth"):
		return "auth"
	case strings.Contains(lower, "cdn") || strings.Contains(lower, "static") ||
		strings.Contains(lower, "assets"):
		return "cdn"
	case strings.Contains(lower, "ws://") || strings.Contains(lower, "wss://"):
		return "websocket"
	default:
		return "api"
	}
}

func appendAuthMethodIfNew(methods []AuthMethod, m AuthMethod) []AuthMethod {
	for _, existing := range methods {
		if existing.Type == m.Type {
			return methods
		}
	}
	return append(methods, m)
}

func appendIfNew(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

// resolveDataDir finds the Electron user data directory for the given app.
func resolveDataDir(appPath, appName string) string {
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("APPDATA")
	case "darwin":
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, "Library", "Application Support")
	default:
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	if base == "" {
		return ""
	}

	candidates := []string{appName, strings.ToLower(appName)}
	// Add title case if different
	if tc := strings.Title(strings.ToLower(appName)); tc != appName && tc != strings.ToLower(appName) { //nolint:staticcheck
		candidates = append(candidates, tc)
	}

	for _, name := range candidates {
		dir := filepath.Join(base, name)
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}
	return ""
}

const maxCacheEntries = 200

// queryDB opens a SQLite database read-only and runs a query.
// Copies to temp dir first to avoid SQLITE_BUSY from locked databases.
// copyFileShared copies a file even if it's locked by another process.
// Uses platform-specific implementation for locked file handling.
func copyFileShared(src, dst string) error {
	in, err := openFileShared(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func queryDB(dbPath string, query string, scanner func(*sql.Rows) error) error {
	tmpDir, err := os.MkdirTemp("", "unravel-db-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpPath := filepath.Join(tmpDir, filepath.Base(dbPath))
	if err := copyFileShared(dbPath, tmpPath); err != nil {
		return fmt.Errorf("copy db: %w", err)
	}

	// Also copy WAL file if it exists (needed for recent data)
	walPath := dbPath + "-wal"
	_ = copyFileShared(walPath, tmpPath+"-wal")

	// Copy journal too if present
	journalPath := dbPath + "-journal"
	_ = copyFileShared(journalPath, tmpPath+"-journal")

	db, err := sql.Open("sqlite", tmpPath+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	return scanner(rows)
}

// chromiumTime converts Chromium microseconds (since 1601-01-01) to RFC3339 string.
func chromiumTime(microseconds int64) string {
	if microseconds <= 0 {
		return ""
	}
	unixSec := (microseconds / 1_000_000) - 11_644_473_600
	if unixSec < 0 {
		return ""
	}
	return time.Unix(unixSec, 0).UTC().Format(time.RFC3339)
}

func extractCookies(dataDir string) *CookieData {
	cookiePath := filepath.Join(dataDir, "Network", "Cookies")
	if _, err := os.Stat(cookiePath); err != nil {
		cookiePath = filepath.Join(dataDir, "Cookies")
		if _, err := os.Stat(cookiePath); err != nil {
			return nil
		}
	}

	cd := &CookieData{
		Domains: make(map[string]int),
	}

	err := queryDB(cookiePath,
		"SELECT host_key, name, path, is_secure, is_httponly, expires_utc FROM cookies",
		func(rows *sql.Rows) error {
			for rows.Next() {
				var (
					hostKey    string
					name       string
					path       string
					isSecure   int
					isHttpOnly int
					expiresUTC int64
				)
				if err := rows.Scan(&hostKey, &name, &path, &isSecure, &isHttpOnly, &expiresUTC); err != nil {
					continue
				}
				entry := CookieEntry{
					Domain:   hostKey,
					Name:     name,
					Path:     path,
					Secure:   isSecure == 1,
					HttpOnly: isHttpOnly == 1,
					Expires:  chromiumTime(expiresUTC),
				}
				cd.Cookies = append(cd.Cookies, entry)
				cd.Domains[hostKey]++
				if entry.Secure {
					cd.Stats.Secure++
				}
				if entry.HttpOnly {
					cd.Stats.HttpOnly++
				}
			}
			return rows.Err()
		},
	)
	if err != nil {
		slog.Info("cookies extraction skipped", "error", err)
		return nil
	}

	cd.Stats.Total = len(cd.Cookies)
	cd.Stats.DomainCount = len(cd.Domains)
	if cd.Stats.Total == 0 {
		return nil
	}
	return cd
}

func extractDIPS(dataDir string) *DIPSData {
	dipsPath := filepath.Join(dataDir, "DIPS")
	if _, err := os.Stat(dipsPath); err != nil {
		return nil
	}

	dips := &DIPSData{}

	err := queryDB(dipsPath,
		"SELECT site, first_site_storage_time, last_site_storage_time, first_user_activation_time, last_user_activation_time FROM bounces",
		func(rows *sql.Rows) error {
			for rows.Next() {
				var (
					site                        string
					firstStorage, lastStorage   sql.NullInt64
					firstInteract, lastInteract sql.NullInt64
				)
				if err := rows.Scan(&site, &firstStorage, &lastStorage, &firstInteract, &lastInteract); err != nil {
					continue
				}
				entry := DIPSSite{Site: site}
				if firstStorage.Valid {
					entry.FirstSiteStorage = chromiumTime(firstStorage.Int64)
				}
				if lastStorage.Valid {
					entry.LastSiteStorage = chromiumTime(lastStorage.Int64)
				}
				if firstInteract.Valid {
					entry.FirstInteraction = chromiumTime(firstInteract.Int64)
				}
				if lastInteract.Valid {
					entry.LastInteraction = chromiumTime(lastInteract.Int64)
				}
				dips.Sites = append(dips.Sites, entry)
			}
			return rows.Err()
		},
	)
	if err != nil {
		slog.Info("DIPS extraction skipped", "error", err)
		return nil
	}

	dips.Total = len(dips.Sites)
	if dips.Total == 0 {
		return nil
	}
	return dips
}

func extractIndexedDB(dataDir string) *IndexedDBData {
	idbDir := filepath.Join(dataDir, "IndexedDB")
	if _, err := os.Stat(idbDir); err != nil {
		return nil
	}

	idb := &IndexedDBData{}

	entries, err := os.ReadDir(idbDir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()
		origin := parseIDBOrigin(dirName)

		dbDir := filepath.Join(idbDir, dirName)
		result, err := leveldb.ParseDirectory(dbDir)
		if err != nil {
			continue
		}

		db := IDBDatabase{
			Origin:     origin,
			EntryCount: result.Stats.ValidEntries,
		}

		for _, e := range result.Entries {
			if e.Type != "value" || e.Value == "" {
				continue
			}
			if !isPrintable(e.Value) || len(e.Value) < 5 {
				continue
			}
			db.Entries = append(db.Entries, IDBEntry{
				Key:   e.Key,
				Value: e.Value,
			})
		}

		if db.EntryCount > 0 || len(db.Entries) > 0 {
			idb.Databases = append(idb.Databases, db)
			idb.Stats.DatabaseCount++
			idb.Stats.TotalEntries += db.EntryCount
		}
	}

	if idb.Stats.DatabaseCount == 0 {
		return nil
	}
	return idb
}

func parseIDBOrigin(dirName string) string {
	name := strings.TrimSuffix(dirName, ".indexeddb.leveldb")
	name = strings.TrimSuffix(name, ".indexeddb.blob")

	idx := strings.Index(name, "_")
	if idx < 0 {
		return dirName
	}
	scheme := name[:idx]
	rest := name[idx+1:]

	// Strip trailing "_<port>" (e.g., "_0", "_3500")
	if lastUnderscore := strings.LastIndex(rest, "_"); lastUnderscore > 0 {
		rest = rest[:lastUnderscore]
	} else if lastUnderscore == 0 {
		// Empty host (e.g., file URLs): rest is "_0", strip entirely
		rest = ""
	}

	return scheme + "://" + rest
}

// extractDataDir extracts runtime data from an Electron user data directory.
func extractDataDir(dataDir string) *DataDirKnowledge {
	dk := &DataDirKnowledge{Path: dataDir}

	// Parse localStorage (LevelDB) — filter garbage entries
	lsDir := filepath.Join(dataDir, "Local Storage", "leveldb")
	if info, err := os.Stat(lsDir); err == nil && info.IsDir() {
		if result, err := leveldb.ParseDirectory(lsDir); err == nil {
			ls := &LocalStorageData{}
			for origin, entries := range result.ByOrigin {
				so := StorageOrigin{Origin: origin}
				for _, e := range entries {
					if !isUsefulStorageEntry(e.Key, e.Value) {
						continue
					}
					so.Entries = append(so.Entries, StorageEntry{
						Key:   e.Key,
						Value: e.Value,
					})
				}
				if len(so.Entries) > 0 {
					ls.Origins = append(ls.Origins, so)
				}
			}
			ls.Stats = StorageStats{
				TotalEntries: result.Stats.TotalEntries,
				OriginCount:  len(result.ByOrigin),
			}
			if len(ls.Origins) > 0 {
				dk.LocalStorage = ls
			}
		} else {
			slog.Debug("failed to parse localStorage", "dir", lsDir, "error", err)
		}
	}

	// Parse Session Storage (LevelDB)
	ssDir := filepath.Join(dataDir, "Session Storage")
	if info, err := os.Stat(ssDir); err == nil && info.IsDir() {
		if result, err := leveldb.ParseDirectory(ssDir); err == nil {
			ss := &LocalStorageData{}
			for origin, entries := range result.ByOrigin {
				so := StorageOrigin{Origin: origin}
				for _, e := range entries {
					if !isUsefulStorageEntry(e.Key, e.Value) {
						continue
					}
					so.Entries = append(so.Entries, StorageEntry{Key: e.Key, Value: e.Value})
				}
				if len(so.Entries) > 0 {
					ss.Origins = append(ss.Origins, so)
				}
			}
			ss.Stats = StorageStats{
				TotalEntries: result.Stats.TotalEntries,
				OriginCount:  len(result.ByOrigin),
			}
			if len(ss.Origins) > 0 {
				dk.SessionStorage = ss
			}
		} else {
			slog.Debug("failed to parse sessionStorage", "dir", ssDir, "error", err)
		}
	}

	// Parse HTTP cache — skip entries with empty URLs
	cacheDir := filepath.Join(dataDir, "Cache", "Cache_Data")
	if info, err := os.Stat(cacheDir); err == nil && info.IsDir() {
		if result, err := cache.Parse(cacheDir, ""); err == nil {
			cd := &CacheData{
				Format:     result.CacheFormat,
				Domains:    result.ByDomain,
				Types:      result.ByType,
				EntryCount: result.Stats.TotalEntries,
				TotalSize:  result.Stats.TotalBodySize,
			}
			added := 0
			for _, e := range result.Entries {
				if added >= maxCacheEntries {
					break
				}
				if e.URL == "" {
					continue
				}
				cd.Entries = append(cd.Entries, CacheItem{
					URL:         e.URL,
					ContentType: e.ContentType,
					Status:      e.HTTPStatus,
					Size:        e.ContentLength,
				})
				added++
			}
			dk.Cache = cd
		} else {
			slog.Debug("failed to parse cache", "dir", cacheDir, "error", err)
		}
	}

	// Read Preferences and Local State (both, not just first found)
	dk.Preferences = make(map[string]any)
	for _, name := range []string{"Preferences", "Local State"} {
		path := filepath.Join(dataDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err == nil {
			dk.Preferences[name] = parsed
		}
	}
	if len(dk.Preferences) == 0 {
		dk.Preferences = nil
	}

	// Parse Cookies (SQLite)
	dk.Cookies = extractCookies(dataDir)

	// Parse IndexedDB (LevelDB per origin)
	dk.IndexedDB = extractIndexedDB(dataDir)

	// Parse DIPS (SQLite)
	dk.DIPS = extractDIPS(dataDir)

	// Scan root-level app state files (JSON, text, config)
	dk.AppState = make(map[string]any)
	dirEntries, _ := os.ReadDir(dataDir)
	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip known Electron internals and binary files
		if isElectronInternal(name) {
			continue
		}
		// Skip already-handled files
		if name == "Preferences" || name == "Local State" {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() == 0 || info.Size() > 1<<20 { // skip empty or >1MB
			continue
		}
		data, err := os.ReadFile(filepath.Join(dataDir, name))
		if err != nil {
			continue
		}
		// Try JSON first
		var parsed any
		if err := json.Unmarshal(data, &parsed); err == nil {
			dk.AppState[name] = parsed
			continue
		}
		// Store as text if it's printable
		text := strings.TrimSpace(string(data))
		if len(text) > 0 && isPrintable(text) {
			dk.AppState[name] = text
		}
	}
	if len(dk.AppState) == 0 {
		dk.AppState = nil
	}

	if dk.LocalStorage == nil && dk.SessionStorage == nil && dk.Cache == nil &&
		dk.Cookies == nil && dk.IndexedDB == nil && dk.DIPS == nil &&
		dk.Preferences == nil && dk.AppState == nil {
		return nil
	}
	return dk
}

// isUsefulStorageEntry filters out LevelDB garbage: binary META entries,
// empty values, garbled/truncated keys, and non-printable content.
func isUsefulStorageEntry(key, value string) bool {
	if key == "" {
		return false
	}
	// Skip META: entries (LevelDB internal bookkeeping with binary values)
	if strings.HasPrefix(key, "META:") {
		return false
	}
	// Skip entries where both key and value look like fragments
	if value == "" && len(key) < 20 {
		return false
	}
	// Skip entries with non-printable characters in the key (garbled data)
	for _, r := range key {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
		// Skip CJK/garbled Unicode that indicates byte-swapped UTF-16
		if r >= 0x2E80 && r <= 0x9FFF {
			return false
		}
	}
	return true
}

// isElectronInternal returns true for known Electron/Chromium internal files
// that contain no app-specific information.
func isElectronInternal(name string) bool {
	lower := strings.ToLower(name)
	internals := []string{
		"lockfile", "lock", "current", "manifest", "log",
		"devtools", "serviceworker", ".db", ".db-journal",
		"-wal", "-shm", "dips",
	}
	for _, s := range internals {
		if lower == s || strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

// isPrintable returns true if the string contains only printable characters.
func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

// scanDataDirSecrets runs the secret pattern engine over parsed data_dir
// storage entries (localStorage / sessionStorage / IndexedDB) and surfaces any
// hardcoded credentials into dd.SecretFindings. Honest-empty (no findings
// leaves the slice nil), non-fatal, nil-safe, never panics.
func scanDataDirSecrets(dd *DataDirKnowledge) {
	if dd == nil {
		return
	}

	seen := make(map[string]bool)

	add := func(label string, entries [][2]string) {
		for _, kv := range entries {
			for _, f := range secret.ScanText(label, kv[0]+" = "+kv[1]) {
				key := string(f.Type) + ":" + f.File + ":" + f.Value
				if seen[key] {
					continue
				}
				seen[key] = true
				dd.SecretFindings = append(dd.SecretFindings, SecretFinding{
					Type:        string(f.Type),
					File:        f.File,
					Confidence:  f.Confidence,
					MaskedValue: f.Value,
					RawLength:   f.RawLength,
				})
			}
		}
	}

	scanLS := func(store string, ls *LocalStorageData) {
		if ls == nil {
			return
		}
		for _, o := range ls.Origins {
			kvs := make([][2]string, 0, len(o.Entries))
			for _, e := range o.Entries {
				kvs = append(kvs, [2]string{e.Key, e.Value})
			}
			add("data_dir:"+store+":"+o.Origin, kvs)
		}
	}

	scanLS("local_storage", dd.LocalStorage)
	scanLS("session_storage", dd.SessionStorage)

	if dd.IndexedDB != nil {
		for _, db := range dd.IndexedDB.Databases {
			kvs := make([][2]string, 0, len(db.Entries))
			for _, e := range db.Entries {
				kvs = append(kvs, [2]string{e.Key, e.Value})
			}
			add("data_dir:indexeddb:"+db.Origin, kvs)
		}
	}
}
