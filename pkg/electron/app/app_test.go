/*
Copyright (c) 2026 Security Research
*/
package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/electron/ipc"
	"github.com/inovacc/unravel-oss/pkg/electron/security"
	"github.com/inovacc/unravel-oss/pkg/electron/stealth"
	"github.com/inovacc/unravel-oss/pkg/manifest"
)

func testManifest() *manifest.Manifest {
	return manifest.Default()
}

func TestReadAppContent_NonExistentPath(t *testing.T) {
	got := ReadAppContent("/no/such/path", false)
	if got != "" {
		t.Fatalf("expected empty string for non-existent path, got %q", got)
	}
}

func TestReadAppContent_SingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.js")
	content := `console.log("hello");`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got := ReadAppContent(path, false)
	if got != content {
		t.Fatalf("expected %q, got %q", content, got)
	}
}

func TestReadAppContent_Directory_JSFiles(t *testing.T) {
	dir := t.TempDir()

	files := map[string]string{
		"main.js":    `const x = 1;`,
		"preload.js": `require("electron");`,
		"style.css":  `body { color: red; }`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got := ReadAppContent(dir, false)
	if got == "" {
		t.Fatal("expected non-empty content from directory with JS files")
	}
}

func TestReadAppContent_Directory_MainPaths(t *testing.T) {
	dir := t.TempDir()

	mainDir := filepath.Join(dir, "resources", "app", "dist", "main")
	if err := os.MkdirAll(mainDir, 0755); err != nil {
		t.Fatal(err)
	}

	mainContent := `const electron = require("electron");`
	if err := os.WriteFile(filepath.Join(mainDir, "index.js"), []byte(mainContent), 0644); err != nil {
		t.Fatal(err)
	}

	got := ReadAppContent(dir, false)
	if got == "" {
		t.Fatal("expected content from resources/app/dist/main/index.js")
	}
}

func TestReadAppContent_Directory_ASAR(t *testing.T) {
	dir := t.TempDir()

	asarDir := filepath.Join(dir, "resources")
	if err := os.MkdirAll(asarDir, 0755); err != nil {
		t.Fatal(err)
	}

	asarContent := `fake-asar-content-for-testing`
	if err := os.WriteFile(filepath.Join(asarDir, "app.asar"), []byte(asarContent), 0644); err != nil {
		t.Fatal(err)
	}

	got := ReadAppContent(dir, false)
	if got == "" {
		t.Fatal("expected content from ASAR file")
	}
}

func TestReadAppContent_Directory_SquirrelASAR(t *testing.T) {
	dir := t.TempDir()

	squirrelDir := filepath.Join(dir, "app-1.2.3", "resources")
	if err := os.MkdirAll(squirrelDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(squirrelDir, "app.asar"), []byte("squirrel-asar"), 0644); err != nil {
		t.Fatal(err)
	}

	got := ReadAppContent(dir, false)
	if got == "" {
		t.Fatal("expected content from squirrel ASAR path")
	}
}

func TestReadAppContent_Verbose(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Should not panic with verbose=true
	got := ReadAppContent(dir, true)
	if got == "" {
		t.Fatal("expected content")
	}
}

func TestReadAppContent_LargeFileTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.js")

	data := make([]byte, 1024)
	for i := range data {
		data[i] = 'a'
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	got := ReadAppContent(path, false)
	if len(got) != 1024 {
		t.Fatalf("expected 1024 bytes, got %d", len(got))
	}
}

func TestCalculateRiskScore_Empty(t *testing.T) {
	m := testManifest()
	result := &Result{}

	calculateRiskScore(m, result)

	if result.Analysis.RiskScore != 0 {
		t.Fatalf("expected score 0, got %d", result.Analysis.RiskScore)
	}
	if result.Analysis.RiskLevel != "LOW" {
		t.Fatalf("expected level LOW, got %s", result.Analysis.RiskLevel)
	}
}

func TestCalculateRiskScore_Levels(t *testing.T) {
	tests := []struct {
		name         string
		secRisks     []security.Finding
		stealthRisks []stealth.Finding
		ipcRisks     []ipc.Finding
		wantLevel    string
		wantMinScore int
	}{
		{
			name:      "LOW with no findings",
			wantLevel: "LOW",
		},
		{
			name: "MEDIUM with medium risks",
			secRisks: []security.Finding{
				{Risk: "MEDIUM"},
				{Risk: "MEDIUM"},
			},
			wantLevel:    "MEDIUM",
			wantMinScore: 20,
		},
		{
			name: "HIGH with high risks",
			secRisks: []security.Finding{
				{Risk: "HIGH"},
				{Risk: "HIGH"},
				{Risk: "HIGH"},
			},
			wantLevel:    "HIGH",
			wantMinScore: 50,
		},
		{
			name: "CRITICAL with critical risks",
			secRisks: []security.Finding{
				{Risk: "CRITICAL"},
				{Risk: "CRITICAL"},
				{Risk: "CRITICAL"},
			},
			wantLevel:    "CRITICAL",
			wantMinScore: 100,
		},
		{
			name: "mixed risks from all categories",
			secRisks: []security.Finding{
				{Risk: "CRITICAL"},
			},
			stealthRisks: []stealth.Finding{
				{Risk: "HIGH"},
			},
			ipcRisks: []ipc.Finding{
				{Risk: "HIGH"},
			},
			wantLevel:    "HIGH",
			wantMinScore: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := testManifest()
			result := &Result{
				Analysis: SecurityResult{
					SecuritySettings: tt.secRisks,
					StealthFeatures:  tt.stealthRisks,
					IPCCommands:      tt.ipcRisks,
				},
			}

			calculateRiskScore(m, result)

			if result.Analysis.RiskLevel != tt.wantLevel {
				t.Errorf("level: got %s, want %s (score=%d)", result.Analysis.RiskLevel, tt.wantLevel, result.Analysis.RiskScore)
			}
			if result.Analysis.RiskScore < tt.wantMinScore {
				t.Errorf("score: got %d, want >= %d", result.Analysis.RiskScore, tt.wantMinScore)
			}
		})
	}
}

func TestRunSecurityAnalysis_NoContent(t *testing.T) {
	m := testManifest()
	result := &Result{Errors: make([]string, 0)}

	runSecurityAnalysis(m, "/nonexistent/path", "electron", result, false)

	if len(result.Errors) == 0 {
		t.Fatal("expected error about no analyzable content")
	}
}

func TestRunSecurityAnalysis_UnknownAppType(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("some content"), 0644); err != nil {
		t.Fatal(err)
	}

	m := testManifest()
	result := &Result{Errors: make([]string, 0)}

	runSecurityAnalysis(m, dir, "nonexistent_type", result, false)

	if len(result.Analysis.SecuritySettings) != 0 {
		t.Fatal("expected no security settings for unknown type")
	}
}

func TestRunSecurityAnalysis_ElectronFindings(t *testing.T) {
	dir := t.TempDir()

	jsContent := `
		const win = new BrowserWindow({
			webPreferences: {
				nodeIntegration: true,
				contextIsolation: false,
				sandbox: false
			}
		});
		ipcMain.handle('get-data', async () => { return data; });
		ipcMain.handle('run-shell', async (e, c) => { return c; });
		win.setContentProtection(true);
		fetch("https://sentry.io/api/report");
		fetch("https://api.example.com/v1/users");
		fetch("https://segment.io/track");
	`
	if err := os.WriteFile(filepath.Join(dir, "main.js"), []byte(jsContent), 0644); err != nil {
		t.Fatal(err)
	}

	m := testManifest()
	result := &Result{Errors: make([]string, 0)}

	runSecurityAnalysis(m, dir, "electron", result, false)

	if len(result.Analysis.SecuritySettings) == 0 {
		t.Fatal("expected security setting findings")
	}

	foundNode := false
	for _, s := range result.Analysis.SecuritySettings {
		if s.Name == "nodeIntegration" && s.Value == "true" {
			foundNode = true
		}
	}
	if !foundNode {
		t.Error("expected to find nodeIntegration: true")
	}

	if len(result.Analysis.IPCCommands) == 0 {
		t.Fatal("expected IPC command findings")
	}

	foundShell := false
	for _, cmd := range result.Analysis.IPCCommands {
		if cmd.Channel == "run-shell" {
			foundShell = true
			if cmd.Risk != "CRITICAL" {
				t.Errorf("run-shell risk: got %s, want CRITICAL", cmd.Risk)
			}
		}
	}
	if !foundShell {
		t.Error("expected to find run-shell IPC channel")
	}

	if len(result.Analysis.StealthFeatures) == 0 {
		t.Fatal("expected stealth feature findings")
	}
	if !result.AppInfo.HasStealth {
		t.Error("expected HasStealth to be true")
	}

	if len(result.AppInfo.Telemetry) == 0 {
		t.Fatal("expected telemetry findings")
	}

	if len(result.Analysis.APIEndpoints) == 0 {
		t.Fatal("expected API endpoint findings")
	}
}

func TestRunSecurityAnalysis_TauriStealth(t *testing.T) {
	m := testManifest()
	m.Analysis["tauri"] = manifest.AnalysisConfig{
		SecuritySettings: []manifest.SecuritySetting{},
	}
	m.Stealth.Tauri = manifest.StealthPatterns{
		Patterns: []manifest.StealthPattern{
			{
				Name:        "Content Protection",
				Description: "Hidden from screen capture",
				Patterns:    []string{"allow-set-content-protected"},
				Risk:        "HIGH",
			},
		},
	}

	dir := t.TempDir()
	jsContent := `allow-set-content-protected`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsContent), 0644); err != nil {
		t.Fatal(err)
	}

	result := &Result{Errors: make([]string, 0)}
	runSecurityAnalysis(m, dir, "tauri", result, false)

	if len(result.Analysis.StealthFeatures) == 0 {
		t.Fatal("expected stealth features for tauri")
	}
}

func TestRunAnalysis_NonExistentPath(t *testing.T) {
	m := testManifest()
	_, err := RunAnalysis("/no/such/path", m, "auto", false)
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestRunAnalysis_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	m := testManifest()

	result, err := RunAnalysis(dir, m, "auto", false)
	if err != nil {
		t.Fatal(err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.AppInfo.Path == "" {
		t.Error("expected non-empty path in AppInfo")
	}
	if result.AppInfo.Name == "" {
		t.Error("expected non-empty name in AppInfo")
	}
	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
	if result.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestRunAnalysis_WithAppTypeOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.js"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	m := testManifest()

	result, err := RunAnalysis(dir, m, "electron", false)
	if err != nil {
		t.Fatal(err)
	}

	if result.AppInfo.Type != "electron" {
		t.Errorf("type: got %s, want electron", result.AppInfo.Type)
	}
	if result.AppInfo.DisplayName != "Electron" {
		t.Errorf("display name: got %s, want Electron", result.AppInfo.DisplayName)
	}
}

func TestRunAnalysis_ElectronApp(t *testing.T) {
	dir := t.TempDir()

	jsContent := `
		nodeIntegration: true
		contextIsolation: false
		ipcMain.handle('run-shell', async (e, cmd) => {});
		setContentProtection(true)
		https://sentry.io/report
		https://api.myapp.com/v1/data
	`
	if err := os.WriteFile(filepath.Join(dir, "main.js"), []byte(jsContent), 0644); err != nil {
		t.Fatal(err)
	}

	m := testManifest()
	result, err := RunAnalysis(dir, m, "electron", false)
	if err != nil {
		t.Fatal(err)
	}

	if result.Analysis.RiskScore == 0 {
		t.Error("expected non-zero risk score for insecure electron app")
	}
	if len(result.Analysis.SecuritySettings) == 0 {
		t.Error("expected security settings")
	}
	if len(result.Analysis.IPCCommands) == 0 {
		t.Error("expected IPC commands")
	}
}

func TestRunAnalysis_VerboseMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	m := testManifest()

	result, err := RunAnalysis(dir, m, "auto", true)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestReadAppContent_MultipleJSExtensions(t *testing.T) {
	dir := t.TempDir()

	files := map[string]string{
		"app.js":     "js content",
		"app.ts":     "ts content",
		"app.mjs":    "mjs content",
		"app.cjs":    "cjs content",
		"readme.txt": "should not appear",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got := ReadAppContent(dir, false)
	if got == "" {
		t.Fatal("expected non-empty content")
	}
}

func TestReadAppContent_SecondaryASARPath(t *testing.T) {
	dir := t.TempDir()

	asarDir := filepath.Join(dir, "app", "resources")
	if err := os.MkdirAll(asarDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(asarDir, "app.asar"), []byte("secondary-asar"), 0644); err != nil {
		t.Fatal(err)
	}

	got := ReadAppContent(dir, false)
	if got == "" {
		t.Fatal("expected content from secondary ASAR path")
	}
}

func TestReadAppContent_SecondaryMainPath(t *testing.T) {
	dir := t.TempDir()

	mainDir := filepath.Join(dir, "resources", "app")
	if err := os.MkdirAll(mainDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mainDir, "main.js"), []byte("main-content"), 0644); err != nil {
		t.Fatal(err)
	}

	got := ReadAppContent(dir, false)
	if got == "" {
		t.Fatal("expected content from resources/app/main.js")
	}
}

func TestRunAnalysis_AutoDetection(t *testing.T) {
	dir := t.TempDir()

	resDir := filepath.Join(dir, "resources")
	if err := os.MkdirAll(resDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resDir, "app.asar"), []byte("electron-asar"), 0644); err != nil {
		t.Fatal(err)
	}

	m := testManifest()
	result, err := RunAnalysis(dir, m, "auto", false)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestReadAppContent_VerboseASAR(t *testing.T) {
	dir := t.TempDir()

	asarDir := filepath.Join(dir, "resources")
	if err := os.MkdirAll(asarDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(asarDir, "app.asar"), []byte("asar-data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Exercise the verbose ASAR print path
	got := ReadAppContent(dir, true)
	if got == "" {
		t.Fatal("expected content")
	}
}

func TestResultTypes(t *testing.T) {
	r := Result{
		AppInfo: AppInfoResult{
			Name:        "TestApp",
			Type:        "electron",
			DisplayName: "Test App",
			Version:     "1.0.0",
			Path:        "/test",
			HasStealth:  true,
			Telemetry:   []string{"Sentry"},
		},
		Analysis: SecurityResult{
			RiskScore: 80,
			RiskLevel: "HIGH",
		},
		Errors: []string{"test error"},
	}

	if r.AppInfo.Name != "TestApp" {
		t.Error("unexpected name")
	}
	if r.Analysis.RiskScore != 80 {
		t.Error("unexpected risk score")
	}
	if len(r.Errors) != 1 {
		t.Error("unexpected errors length")
	}
}
