package knowledge

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/framework"
	androidmanifest "github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/android/native"
	"github.com/inovacc/unravel-oss/pkg/android/obfuscation"
	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/deb"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/electron/api"
	"github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/ipc"
	"github.com/inovacc/unravel-oss/pkg/electron/security"
	"github.com/inovacc/unravel-oss/pkg/electron/stealth"
	"github.com/inovacc/unravel-oss/pkg/garble"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/depth"
	"github.com/inovacc/unravel-oss/pkg/msi"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/rpm"
)

func TestExtract_Electron(t *testing.T) {
	dr := &dissect.DissectResult{
		Path:     "/apps/cluely",
		FileName: "cluely",
		AppAnalysis: &app.Result{
			AppInfo: app.AppInfoResult{
				Name:       "cluely",
				Type:       "electron",
				Version:    "1.2.3",
				HasStealth: true,
				Telemetry:  []string{"Sentry", "Mixpanel"},
			},
			Analysis: app.SecurityResult{
				SecuritySettings: []security.Finding{
					{Name: "nodeIntegration", Value: "true", Risk: "high", Description: "Node.js in renderer"},
					{Name: "contextIsolation", Value: "true", Risk: "low", Description: "Context isolation enabled"},
					{Name: "webSecurity", Value: "false", Risk: "critical", Description: "Web security disabled"},
				},
				StealthFeatures: []stealth.Finding{
					{Name: "Content Protection", Description: "screen capture blocked", Risk: "high"},
				},
				IPCCommands: []ipc.Finding{
					{Channel: "get-auth-token", Direction: "renderer-to-main", Risk: "high"},
					{Channel: "update-config", Direction: "main-to-renderer", Risk: "low"},
				},
				APIEndpoints: []api.Finding{
					{URL: "https://api.cluely.com/v1/auth", Purpose: "auth"},
					{URL: "https://api.cluely.com/v1/data", Purpose: "api"},
				},
				RiskScore: 85,
				RiskLevel: "critical",
			},
		},
		ASARFiles: []asar.ExtractedFile{
			{Path: "main.js", Size: 1024},
			{Path: "preload.js", Size: 512},
			{Path: "package.json", Size: 256},
			{Path: "index.html", Size: 128},
			{Path: "node_modules/react/index.js", Size: 64},
			{Path: "assets", IsDir: true},
		},
	}

	kr := Extract(dr)

	// AppName
	if kr.AppName != "cluely" {
		t.Errorf("AppName = %q, want %q", kr.AppName, "cluely")
	}

	// Framework
	if kr.Framework != "electron" {
		t.Errorf("Framework = %q, want %q", kr.Framework, "electron")
	}

	// Version
	if kr.Version != "1.2.3" {
		t.Errorf("Version = %q, want %q", kr.Version, "1.2.3")
	}

	// Communication endpoints
	if kr.Communication == nil {
		t.Fatal("Communication is nil")
	}
	if len(kr.Communication.Endpoints) != 2 {
		t.Errorf("Endpoints count = %d, want 2", len(kr.Communication.Endpoints))
	}

	// IPC channels
	if kr.IPC == nil {
		t.Fatal("IPC is nil")
	}
	if len(kr.IPC.Channels) != 2 {
		t.Errorf("IPC channels = %d, want 2", len(kr.IPC.Channels))
	}
	// High risk channel should be privileged
	if !kr.IPC.Channels[0].Privileged {
		t.Error("expected first IPC channel to be privileged")
	}
	if kr.IPC.Channels[0].RiskLevel != "high" {
		t.Errorf("IPC channel risk = %q, want %q", kr.IPC.Channels[0].RiskLevel, "high")
	}

	// Stealth
	if kr.Stealth == nil {
		t.Fatal("Stealth is nil")
	}
	if !kr.Stealth.ScreenCaptureBlock {
		t.Error("expected ScreenCaptureBlock = true")
	}
	if !kr.Stealth.ScreenShareHide {
		t.Error("expected ScreenShareHide = true")
	}

	// Security
	if kr.Security == nil {
		t.Fatal("Security is nil")
	}
	if kr.Security.RiskScore != 85 {
		t.Errorf("RiskScore = %d, want 85", kr.Security.RiskScore)
	}
	if kr.Security.RiskLevel != "critical" {
		t.Errorf("RiskLevel = %q, want %q", kr.Security.RiskLevel, "critical")
	}
	if len(kr.Security.Settings) != 3 {
		t.Errorf("Settings count = %d, want 3", len(kr.Security.Settings))
	}
	// contextIsolation (risk=low) should be Safe
	if !kr.Security.Settings[1].Safe {
		t.Error("expected contextIsolation to be Safe")
	}
	// nodeIntegration (risk=high) should not be Safe
	if kr.Security.Settings[0].Safe {
		t.Error("expected nodeIntegration to not be Safe")
	}

	// Telemetry
	if kr.Telemetry == nil {
		t.Fatal("Telemetry is nil")
	}
	if len(kr.Telemetry.Services) != 2 {
		t.Errorf("Telemetry services = %d, want 2", len(kr.Telemetry.Services))
	}

	// UI detection (react from ASAR node_modules)
	if kr.UI == nil {
		t.Fatal("UI is nil")
	}
	if kr.UI.Framework != "react" {
		t.Errorf("UI.Framework = %q, want %q", kr.UI.Framework, "react")
	}
	if !kr.UI.IsSPA {
		t.Error("expected UI.IsSPA = true")
	}

	// Source files
	if len(kr.SourceFiles) != 4 {
		t.Errorf("SourceFiles count = %d, want 4", len(kr.SourceFiles))
	}
}

func TestResolveDataDir(t *testing.T) {
	base := t.TempDir()

	// Create a fake app data dir
	appDir := filepath.Join(base, "TestApp")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Override env for Windows test
	origAppData := os.Getenv("APPDATA")
	if runtime.GOOS == "windows" {
		os.Setenv("APPDATA", base)
		defer os.Setenv("APPDATA", origAppData)
	}

	// Test exact match
	if runtime.GOOS == "windows" {
		got := resolveDataDir("/some/path", "TestApp")
		if got != appDir {
			t.Errorf("resolveDataDir exact = %q, want %q", got, appDir)
		}
	}

	// Test lowercase fallback (skip on case-insensitive filesystems like Windows)
	if runtime.GOOS != "windows" {
		lowerDir := filepath.Join(base, "lowercaseapp")
		if err := os.MkdirAll(lowerDir, 0o755); err != nil {
			t.Fatal(err)
		}
		gotLower := resolveDataDir("/some/path", "LowercaseApp")
		if gotLower != lowerDir {
			t.Errorf("resolveDataDir lowercase = %q, want %q", gotLower, lowerDir)
		}
	}

	// Non-existent app returns empty
	got := resolveDataDir("/some/path", "nonexistent-app-xyz-12345")
	if got != "" {
		t.Errorf("resolveDataDir nonexistent = %q, want empty", got)
	}
}

func TestExtractDataDir(t *testing.T) {
	base := t.TempDir()

	// Create Preferences file
	prefsData := `{"profile":{"name":"test"},"browser":{"window_placement":{"x":100}}}`
	if err := os.WriteFile(filepath.Join(base, "Preferences"), []byte(prefsData), 0o644); err != nil {
		t.Fatal(err)
	}

	dk := extractDataDir(base)
	if dk == nil {
		t.Fatal("extractDataDir returned nil, expected preferences")
	}
	if dk.Preferences == nil {
		t.Fatal("Preferences is nil")
	}
	prefsRaw, ok := dk.Preferences["Preferences"].(map[string]any)
	if !ok {
		t.Fatal("Preferences key not a map")
	}
	profile, ok := prefsRaw["profile"].(map[string]any)
	if !ok {
		t.Fatal("profile not a map")
	}
	if profile["name"] != "test" {
		t.Errorf("profile.name = %v, want test", profile["name"])
	}
}

func TestParseIDBOrigin(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https_desktop.cluely.com_0.indexeddb.leveldb", "https://desktop.cluely.com"},
		{"http_localhost_3500.indexeddb.leveldb", "http://localhost"},
		{"file__0.indexeddb.leveldb", "file://"},
		{"plain", "plain"},
	}
	for _, tt := range tests {
		got := parseIDBOrigin(tt.input)
		if got != tt.want {
			t.Errorf("parseIDBOrigin(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestChromiumTime(t *testing.T) {
	// 2026-01-01 00:00:00 UTC = Unix 1767225600
	// Chromium = (1767225600 + 11644473600) * 1000000 = 13411699200000000
	got := chromiumTime(13411699200000000)
	if got != "2026-01-01T00:00:00Z" {
		t.Errorf("chromiumTime = %q, want 2026-01-01T00:00:00Z", got)
	}
	if chromiumTime(0) != "" {
		t.Error("chromiumTime(0) should be empty")
	}
	if chromiumTime(-1) != "" {
		t.Error("chromiumTime(-1) should be empty")
	}
}

func TestExtractDataDir_Empty(t *testing.T) {
	base := t.TempDir()
	dk := extractDataDir(base)
	if dk != nil {
		t.Error("expected nil for empty data dir")
	}
}

func TestExtract_Android(t *testing.T) {
	exported := true
	dr := &dissect.DissectResult{
		FileName: "com.example.app.apk",
		ManifestInfo: &androidmanifest.Manifest{
			Package:     "com.example.app",
			VersionCode: 42,
			VersionName: "2.1.0",
			MinSDK:      21,
			TargetSDK:   34,
			Permissions: []androidmanifest.Permission{
				{Name: "android.permission.INTERNET", RiskLevel: "normal"},
				{Name: "android.permission.CAMERA", RiskLevel: "dangerous"},
			},
			Components: []androidmanifest.Component{
				{Name: ".MainActivity", Type: androidmanifest.ComponentActivity, Exported: &exported},
				{Name: ".SyncService", Type: androidmanifest.ComponentService},
			},
			Security: androidmanifest.SecurityFlags{Debuggable: true},
		},
		ManifestAnalysis: &androidmanifest.Analysis{
			SecurityScore: 72,
			RiskLevel:     "high",
			DeepLinks:     []androidmanifest.DeepLink{{URI: "app://example/open"}},
			SecurityIssues: []androidmanifest.SecurityIssue{
				{Title: "App is debuggable", Severity: "critical"},
			},
		},
		DEXAnalysis: &dex.ParseResult{
			TotalClasses: 500,
			TotalMethods: 3000,
			MultiDex:     true,
			DexFiles:     []dex.DexFile{{Name: "classes.dex"}, {Name: "classes2.dex"}},
			RiskFindings: []dex.RiskFinding{
				{Category: "reflection", API: "Class.forName", Severity: "high"},
			},
		},
		NativeAnalysis: &native.ScanResult{
			Libraries: []native.LibraryInfo{
				{Name: "libnative.so", ABI: "arm64-v8a", Size: 1024000,
					JNIExports: []native.JNIExport{{JavaName: "com.example.Native.init"}}},
			},
			Findings: []native.Finding{
				{Category: "anti-debug", Description: "ptrace detection"},
			},
		},
		ObfuscationAnalysis: &obfuscation.Result{
			Type:       obfuscation.ObfR8,
			Confidence: 85,
			HasMapping: true,
		},
		Secrets: &secret.ScanResult{
			Findings: []secret.Finding{
				{Type: "google_api_key", File: "res/values/strings.xml", Confidence: "high"},
			},
		},
		FrameworkAnalysis: &framework.ScanResult{
			Framework: "Flutter",
			Flutter: &framework.FlutterInfo{
				EngineVersion: "3.16.0",
				DartVersion:   "3.2.0",
			},
		},
	}

	kr := Extract(dr)

	// AppName from manifest
	if kr.AppName != "com.example.app" {
		t.Errorf("AppName = %q, want %q", kr.AppName, "com.example.app")
	}
	if kr.Version != "2.1.0" {
		t.Errorf("Version = %q, want %q", kr.Version, "2.1.0")
	}

	// Android section
	if kr.Android == nil {
		t.Fatal("Android is nil")
	}
	if kr.Android.Package != "com.example.app" {
		t.Errorf("Package = %q", kr.Android.Package)
	}
	if len(kr.Android.Permissions) != 2 {
		t.Errorf("Permissions = %d, want 2", len(kr.Android.Permissions))
	}
	if !kr.Android.Permissions[1].Dangerous {
		t.Error("expected CAMERA to be dangerous")
	}
	if len(kr.Android.Components) != 2 {
		t.Errorf("Components = %d, want 2", len(kr.Android.Components))
	}
	if !kr.Android.Components[0].Exported {
		t.Error("expected MainActivity to be exported")
	}
	if len(kr.Android.DeepLinks) != 1 {
		t.Errorf("DeepLinks = %d, want 1", len(kr.Android.DeepLinks))
	}
	if len(kr.Android.Secrets) != 1 {
		t.Errorf("Secrets = %d, want 1", len(kr.Android.Secrets))
	}
	if len(kr.Android.NativeLibs) != 1 {
		t.Errorf("NativeLibs = %d, want 1", len(kr.Android.NativeLibs))
	}
	if kr.Android.NativeLibs[0].JNIExports[0] != "com.example.Native.init" {
		t.Errorf("JNI export = %q", kr.Android.NativeLibs[0].JNIExports[0])
	}
	if kr.Android.Obfuscation == nil {
		t.Fatal("Obfuscation is nil")
	}
	if kr.Android.Obfuscation.Type != "r8" {
		t.Errorf("Obfuscation.Type = %q, want r8", kr.Android.Obfuscation.Type)
	}
	if kr.Android.DEXStats == nil {
		t.Fatal("DEXStats is nil")
	}
	if kr.Android.DEXStats.TotalClasses != 500 {
		t.Errorf("TotalClasses = %d, want 500", kr.Android.DEXStats.TotalClasses)
	}
	if !kr.Android.DEXStats.MultiDex {
		t.Error("expected MultiDex = true")
	}
	if len(kr.Android.RiskAPIs) != 1 {
		t.Errorf("RiskAPIs = %d, want 1", len(kr.Android.RiskAPIs))
	}
	if kr.Android.Framework == nil || kr.Android.Framework.Name != "Flutter" {
		t.Errorf("Framework = %v", kr.Android.Framework)
	}

	// Security should pull from manifest analysis
	if kr.Security == nil {
		t.Fatal("Security is nil")
	}
	if kr.Security.RiskScore != 72 {
		t.Errorf("RiskScore = %d, want 72", kr.Security.RiskScore)
	}
	if len(kr.Security.Vulnerabilities) != 1 {
		t.Errorf("Vulnerabilities = %d, want 1", len(kr.Security.Vulnerabilities))
	}

	// Stealth should have anti-debug from native
	if kr.Stealth == nil {
		t.Fatal("Stealth is nil")
	}
	if len(kr.Stealth.AntiDebugging) == 0 {
		t.Error("expected anti-debugging findings")
	}
	if kr.Stealth.CodeObfuscation != "r8" {
		t.Errorf("CodeObfuscation = %q, want r8", kr.Stealth.CodeObfuscation)
	}
}

func TestExtract_GoBinary(t *testing.T) {
	dr := &dissect.DissectResult{
		FileName: "myapp.exe",
		GarbleInfo: &garble.BinaryInfo{
			GoVersion:      "go1.22.0",
			ModulePath:     "github.com/example/myapp",
			Arch:           "amd64",
			OS:             "linux",
			BuildID:        "abc123",
			IsStaticLinked: true,
			HasSymbolTable: true,
			HasDWARF:       false,
			BuildSettings:  map[string]string{"CGO_ENABLED": "0", "GOARCH": "amd64"},
		},
		GarbleDetect: &garble.DetectionResult{
			IsGarbled:  true,
			Confidence: 0.92,
		},
		GarbleStrings: &garble.StringsResult{
			HighEntropyCount: 15,
			ByCategory: map[garble.StringCategory]int{
				garble.CatURL:      5,
				garble.CatFilePath: 10,
			},
		},
	}

	kr := Extract(dr)

	if kr.GoBinary == nil {
		t.Fatal("GoBinary is nil")
	}
	g := kr.GoBinary
	if g.GoVersion != "go1.22.0" {
		t.Errorf("GoVersion = %q", g.GoVersion)
	}
	if g.ModulePath != "github.com/example/myapp" {
		t.Errorf("ModulePath = %q", g.ModulePath)
	}
	if g.Arch != "amd64" {
		t.Errorf("Arch = %q", g.Arch)
	}
	if !g.IsStatic {
		t.Error("expected IsStatic = true")
	}
	if !g.HasSymbolTable {
		t.Error("expected HasSymbolTable = true")
	}
	if g.HasDWARF {
		t.Error("expected HasDWARF = false")
	}
	if !g.IsGarbled {
		t.Error("expected IsGarbled = true")
	}
	if g.GarbleConfidence != 0.92 {
		t.Errorf("GarbleConfidence = %f", g.GarbleConfidence)
	}
	if g.HighEntropyStrings != 15 {
		t.Errorf("HighEntropyStrings = %d", g.HighEntropyStrings)
	}
	if len(g.StringCategories) != 2 {
		t.Errorf("StringCategories len = %d", len(g.StringCategories))
	}
	if len(g.BuildSettings) != 2 {
		t.Errorf("BuildSettings len = %d", len(g.BuildSettings))
	}
}

func TestExtract_DEB(t *testing.T) {
	dr := &dissect.DissectResult{
		FileName: "myapp.deb",
		DEBInfo: &deb.InfoResult{
			Control: &deb.Control{
				Package:      "myapp",
				Version:      "1.0.0",
				Architecture: "amd64",
				Maintainer:   "Test Author",
				Description:  "A test app",
				Depends:      "libc6, libssl3",
			},
			FileCount:    42,
			TotalSize:    1024000,
			HasSignature: true,
			Scripts:      []string{"postinst", "prerm"},
		},
	}

	kr := Extract(dr)

	if kr.Packaging == nil {
		t.Fatal("Packaging is nil")
	}
	p := kr.Packaging
	if p.Format != "deb" {
		t.Errorf("Format = %q", p.Format)
	}
	if p.Name != "myapp" {
		t.Errorf("Name = %q", p.Name)
	}
	if p.Version != "1.0.0" {
		t.Errorf("Version = %q", p.Version)
	}
	if p.Arch != "amd64" {
		t.Errorf("Arch = %q", p.Arch)
	}
	if p.Maintainer != "Test Author" {
		t.Errorf("Maintainer = %q", p.Maintainer)
	}
	if len(p.Dependencies) != 2 {
		t.Errorf("Dependencies = %d", len(p.Dependencies))
	}
	if p.FileCount != 42 {
		t.Errorf("FileCount = %d", p.FileCount)
	}
	if !p.HasSignature {
		t.Error("expected HasSignature")
	}
	if len(p.Scripts) != 2 {
		t.Errorf("Scripts = %d", len(p.Scripts))
	}
}

func TestExtract_RPM(t *testing.T) {
	dr := &dissect.DissectResult{
		FileName: "myapp.rpm",
		RPMInfo: &rpm.InfoResult{
			Name:          "myapp",
			Version:       "2.0.0",
			Arch:          "x86_64",
			Description:   "An RPM app",
			Vendor:        "Test Vendor",
			InstalledSize: 2048000,
			HasSignature:  true,
		},
	}

	kr := Extract(dr)

	if kr.Packaging == nil {
		t.Fatal("Packaging is nil")
	}
	p := kr.Packaging
	if p.Format != "rpm" {
		t.Errorf("Format = %q", p.Format)
	}
	if p.Maintainer != "Test Vendor" {
		t.Errorf("Maintainer = %q", p.Maintainer)
	}
	if p.TotalSize != 2048000 {
		t.Errorf("TotalSize = %d", p.TotalSize)
	}
}

func TestExtract_RPM_PackagerFallback(t *testing.T) {
	dr := &dissect.DissectResult{
		FileName: "myapp.rpm",
		RPMInfo: &rpm.InfoResult{
			Name:     "myapp",
			Version:  "1.0.0",
			Packager: "Fallback Packager",
		},
	}

	kr := Extract(dr)
	if kr.Packaging.Maintainer != "Fallback Packager" {
		t.Errorf("Maintainer = %q, want Fallback Packager", kr.Packaging.Maintainer)
	}
}

func TestExtract_MSI(t *testing.T) {
	dr := &dissect.DissectResult{
		FileName: "installer.msi",
		MSIInfo: &msi.InfoResult{
			ProductName:    "My Installer",
			ProductVersion: "3.0.0",
			Manufacturer:   "Test Corp",
			FileCount:      100,
			HasSignature:   false,
			Properties:     map[string]string{"ARPCONTACT": "support@test.com"},
		},
	}

	kr := Extract(dr)

	if kr.Packaging == nil {
		t.Fatal("Packaging is nil")
	}
	p := kr.Packaging
	if p.Format != "msi" {
		t.Errorf("Format = %q", p.Format)
	}
	if p.Name != "My Installer" {
		t.Errorf("Name = %q", p.Name)
	}
	if p.Properties["ARPCONTACT"] != "support@test.com" {
		t.Errorf("Properties = %v", p.Properties)
	}
}

func TestExtract_MSIX(t *testing.T) {
	dr := &dissect.DissectResult{
		FileName: "app.msix",
		MSIXInfo: &msix.InfoResult{
			PackageName:           "TestApp",
			PackageVersion:        "4.0.0",
			ProcessorArchitecture: "x64",
			PublisherDisplayName:  "Test Publisher",
			Description:           "An MSIX app",
			FileCount:             50,
			TotalSize:             500000,
			HasSignature:          true,
			Capabilities:          []string{"internetClient", "webcam"},
			Dependencies:          []msix.Dependency{{Name: "Windows.Desktop"}},
		},
	}

	kr := Extract(dr)

	if kr.Packaging == nil {
		t.Fatal("Packaging is nil")
	}
	p := kr.Packaging
	if p.Format != "msix" {
		t.Errorf("Format = %q", p.Format)
	}
	if p.Name != "TestApp" {
		t.Errorf("Name = %q", p.Name)
	}
	if len(p.Capabilities) != 2 {
		t.Errorf("Capabilities = %d", len(p.Capabilities))
	}
	if len(p.Dependencies) != 1 {
		t.Errorf("Dependencies = %d", len(p.Dependencies))
	}
	if p.Dependencies[0] != "Windows.Desktop" {
		t.Errorf("Dep = %q", p.Dependencies[0])
	}
}

func TestExtract_Nil(t *testing.T) {
	dr := &dissect.DissectResult{
		FileName: "unknown.bin",
	}

	kr := Extract(dr)

	if kr.AppName != "unknown.bin" {
		t.Errorf("AppName = %q, want %q", kr.AppName, "unknown.bin")
	}
	if kr.Communication != nil {
		t.Error("expected Communication to be nil")
	}
	if kr.Auth != nil {
		t.Error("expected Auth to be nil")
	}
	if kr.UI != nil {
		t.Error("expected UI to be nil")
	}
	if kr.IPC != nil {
		t.Error("expected IPC to be nil")
	}
	if kr.Security != nil {
		t.Error("expected Security to be nil")
	}
	if kr.Stealth != nil {
		t.Error("expected Stealth to be nil")
	}
	if kr.Telemetry != nil {
		t.Error("expected Telemetry to be nil")
	}
	if kr.GoBinary != nil {
		t.Error("expected GoBinary to be nil")
	}
	if kr.Packaging != nil {
		t.Error("expected Packaging to be nil")
	}
	if len(kr.SourceFiles) != 0 {
		t.Errorf("SourceFiles count = %d, want 0", len(kr.SourceFiles))
	}
}

// buildAndroidDissectResultWithMultiDimensionFixture builds a multi-dimension
// android DissectResult for P37 Plan 37-03 depth_covered roundtrip tests.
func buildAndroidDissectResultWithMultiDimensionFixture(t *testing.T) *dissect.DissectResult {
	t.Helper()
	return &dissect.DissectResult{
		Path: "/x/test.apk",
		ManifestInfo: &androidmanifest.Manifest{
			Package: "com.example.test",
			Permissions: []androidmanifest.Permission{
				{Name: "android.permission.INTERNET"},
				{Name: "android.permission.CAMERA"},
			},
		},
		DEXAnalysis: &dex.ParseResult{
			TotalClasses: 2,
			TotalMethods: 4,
			DexFiles: []dex.DexFile{
				{
					Name:    "classes.dex",
					Classes: []dex.ClassDef{{ClassName: "A"}, {ClassName: "B"}},
					Methods: []dex.MethodRef{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}},
				},
			},
		},
		NativeAnalysis: &native.ScanResult{
			Libraries: []native.LibraryInfo{{Name: "libfoo.so", ABI: "arm64-v8a"}},
		},
		Secrets: &secret.ScanResult{
			Findings: []secret.Finding{{Type: secret.SecretType("api_key"), File: "x", Confidence: "high"}},
		},
		ObfuscationAnalysis: &obfuscation.Result{
			Type:       obfuscation.ObfProGuard,
			Confidence: 80,
		},
	}
}

func TestExtract_DepthCovered_Android(t *testing.T) {
	dr := buildAndroidDissectResultWithMultiDimensionFixture(t)
	result := Extract(dr)
	if result.Platform != "android" {
		t.Fatalf("expected platform=android, got %q", result.Platform)
	}
	if len(result.DepthCovered) == 0 {
		t.Fatal("DepthCovered empty; AuditAndroid returned nil")
	}
	if len(result.DepthCovered) != 12 {
		t.Errorf("DepthCovered length = %d, want 12", len(result.DepthCovered))
	}
	nonZero := 0
	for _, d := range result.DepthCovered {
		if d.Total > 0 && d.Ratio > 0 {
			nonZero++
		}
		if !depth.RatioOK(d) {
			t.Errorf("dimension %q failed RatioOK (covered=%d, total=%d, ratio=%v)",
				d.Name, d.Covered, d.Total, d.Ratio)
		}
	}
	if nonZero < 1 {
		t.Errorf("expected >= 1 dimension with total>0 and ratio>0, got %d", nonZero)
	}
}

func TestExtract_DepthCovered_NonAndroidPlatform(t *testing.T) {
	// P38 update: MSIX/UWP shape now produces uwp.* dimensions when MSIXInfo
	// triggers Packaging.UWP allocation in extractUWPCoverage. Per
	// D-38-DIMENSIONS-PER-STACK, windows platform gets uwp.* / electron.* /
	// webview2.* dimensions when the corresponding sub-extractor runs.
	dr := &dissect.DissectResult{
		Path: "/x/wa.msix",
		MSIXInfo: &msix.InfoResult{
			PackageName:          "5319275A.WhatsAppDesktop",
			Publisher:            "CN=WhatsApp LLC",
			PublisherDisplayName: "WhatsApp",
		},
	}
	result := Extract(dr)
	// P62 / DEPT-01: granular tag "windows-msix" is load-bearing — see
	// extract_identity_test.go header comment for the registry / allowlist /
	// schema consumers that key off the exact literal.
	if result.Platform != "windows-msix" {
		t.Fatalf("expected platform=windows-msix, got %q", result.Platform)
	}
	// DepthCovered MUST be populated (uwp.* dims) since MSIXInfo allocates
	// Packaging.UWP. Pre-P38 this was nil; P38 wires AuditUWP for windows.
	if len(result.DepthCovered) == 0 {
		t.Fatalf("expected DepthCovered populated for windows MSIX (P38 D-38 wire-up), got empty")
	}
	hasUWP := false
	for _, d := range result.DepthCovered {
		if len(d.Name) >= 4 && d.Name[:4] == "uwp." {
			hasUWP = true
			break
		}
	}
	if !hasUWP {
		t.Errorf("expected uwp.* dimension in DepthCovered (D-38-DIMENSIONS-PER-STACK), got %v",
			result.DepthCovered)
	}
}
