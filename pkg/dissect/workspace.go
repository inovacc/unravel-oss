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
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/inject"
	_ "github.com/inovacc/unravel-oss/pkg/inject/registry" // blank-import: fire scanner init() registrations
	"github.com/inovacc/unravel-oss/pkg/uwp"
)

// WorkspaceMetadata is persisted as metadata.json in each UUID folder.
type WorkspaceMetadata struct {
	UUID              string `json:"uuid"`
	AppName           string `json:"app_name"`
	AppPath           string `json:"app_path"`
	ASARPath          string `json:"asar_path,omitempty"`
	OS                string `json:"os"`
	Host              string `json:"host"`
	AnalyzedAt        string `json:"analyzed_at"`
	RiskLevel         string `json:"risk_level"`
	RiskScore         int    `json:"risk_score"`
	StealthFeatures   int    `json:"stealth_features"`
	IPCCommands       int    `json:"ipc_commands"`
	APIEndpoints      int    `json:"api_endpoints"`
	SecuritySettings  int    `json:"security_settings"`
	TelemetryServices int    `json:"telemetry_services"`
	Binaries          int    `json:"binaries"`
	Framework         string `json:"framework,omitempty"`
	FrameworkVersion  string `json:"framework_version,omitempty"`
	Duration          string `json:"duration"`
}

// WriteWorkspace writes the full analysis workspace to baseDir/{os}/{uuid}/
// and updates the index.md. Returns the workspace path.
func WriteWorkspace(result *DissectResult, baseDir string) (string, error) {
	osName := detectOSName()
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}

	workDir := filepath.Join(baseDir, osName, id.String())
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return "", fmt.Errorf("create workspace: %w", err)
	}

	// 1. dissect.json
	writeJSON(filepath.Join(workDir, "dissect.json"), result)

	// 1b. UWP scaffolds — BUG-08 / D-08: populate communication/, security/,
	// telemetry/ before report rendering so the report's artifact table can
	// reference them and downstream KB ingest sees them as siblings of
	// DISSECT_REPORT.md. When the primary dispatch picked a non-UWP analyzer
	// (e.g. Electron-app-directory for UWP-packaged WhatsApp/Teams) but an
	// AppxManifest.xml is present, we run a manifest-only UWP analysis here
	// so the scaffold invariant still holds.
	uwpResult := result.UWPInfo
	if uwpResult == nil {
		src := result.SourcePath
		if src == "" {
			src = result.Path
		}
		if src != "" {
			if _, err := os.Stat(filepath.Join(src, "AppxManifest.xml")); err == nil {
				if quick, qerr := uwp.AnalyzeQuick(src); qerr == nil && quick != nil {
					uwpResult = quick
					result.UWPInfo = quick
				}
			}
		}
	}
	if uwpResult != nil {
		_ = writeUWPScaffolds(workDir, uwpResult)
	} else {
		// Always emit empty-but-valid scaffolds so the directory invariant
		// holds. This makes downstream tooling robust against non-UWP runs.
		_ = writeUWPScaffolds(workDir, &uwp.Result{})
	}

	// 1c. Phase 16-05: code-injection seam scan. Runs unconditionally on the
	// dissect source path; per-scanner Detect() gates whether each framework
	// scanner contributes seams. When no scanner detects (Framework == ""),
	// the writer still emits an empty seams[] so downstream tooling can rely
	// on file presence under <ws>/security/injection_seams.json.
	{
		injectSrc := result.SourcePath
		if injectSrc == "" {
			injectSrc = result.Path
		}
		if injectSrc != "" {
			if injResult, ierr := inject.Scan(context.Background(), injectSrc); ierr == nil && injResult != nil {
				_ = inject.WriteSeamsJSON(workDir, injResult)
			}
		}
	}

	// 2. DISSECT_REPORT.md — BUG-06 / D-06: always re-render with current
	// invocation's source path. result.SourcePath is stamped by Run() (both
	// fresh and cache-hit paths), so renderReport will always emit the
	// correct **Source:** header for THIS call, never a stale cached path.
	// OutputDirLabel is the caller-supplied baseDir basename so the header
	// carries the dispatch label the caller requested.
	currentSource := result.SourcePath
	if currentSource == "" {
		currentSource = result.Path
	}
	result.OutputDirLabel = filepath.Base(baseDir)
	_ = renderReport(workDir, currentSource, result)

	// 3. Extract analysis data from result
	meta := buildMetadata(result, id.String(), osName)
	writeJSON(filepath.Join(workDir, "metadata.json"), meta)

	// 4. Electron/Tauri app artifacts
	if result.AppAnalysis != nil {
		writeAppArtifacts(workDir, result)
	}

	// 5. ASAR artifacts
	writeASARArtifacts(workDir, result)

	// 6. SUMMARY.md
	writeSummary(workDir, meta, result)

	// 7. AI artifacts
	if result.AIPrompt != "" {
		_ = os.WriteFile(filepath.Join(workDir, "AI_PROMPT.md"), []byte(result.AIPrompt), 0644)
	}
	if result.AIInsights != nil {
		_ = WriteAIAnalysisReport(result.AIInsights, filepath.Join(workDir, "AI_ANALYSIS.md"))
	}

	// 8. Frida scripts
	if result.FridaScripts != nil && len(result.FridaScripts.Scripts) > 0 {
		fridaDir := filepath.Join(workDir, "frida")
		_ = os.MkdirAll(fridaDir, 0755)

		for _, s := range result.FridaScripts.Scripts {
			_ = os.WriteFile(filepath.Join(fridaDir, s.Name+".js"), []byte(s.Content), 0644)
		}

		writeJSON(filepath.Join(fridaDir, "scripts.json"), result.FridaScripts)
	}

	// 9. Update index
	indexPath := filepath.Join(baseDir, osName, "index.md")
	_ = updateIndex(indexPath, meta)

	// 10. DSC-06 / 13-06: defense-in-depth rewrite — even if any earlier step
	// (cache reconstruction, marshal-from-cached-result) leaked stale
	// input-naming fields into metadata.json or dissect.json, force every
	// input-naming field back to the CURRENT invocation. The result.Path /
	// result.FileName / result.Detection.{Path,Name} fields were already
	// stamped in dissect.Run on cache hit, but this pass is an explicit
	// post-write guarantee so the workspace can never carry a prior run's
	// identity into a different output dir.
	_ = rewriteCachedMetadata(workDir, currentSource)

	return workDir, nil
}

// rewriteCachedMetadata rewrites every input-naming field in metadata.json
// and dissect.json from the current invocation's absolute input path. This
// fires unconditionally on every WriteWorkspace call (fresh and cache-hit
// alike) — for fresh runs it's a no-op rewrite of identical values, for
// cache-hit runs it scrubs any residual stale values. DSC-06 / 13-06.
func rewriteCachedMetadata(wsDir, currentAbsPath string) error {
	if currentAbsPath == "" {
		return nil
	}
	base := filepath.Base(currentAbsPath)
	host, _ := os.Hostname()
	now := time.Now().UTC().Format(time.RFC3339)

	// metadata.json
	mdPath := filepath.Join(wsDir, "metadata.json")
	if data, err := os.ReadFile(mdPath); err == nil {
		var md map[string]any
		if json.Unmarshal(data, &md) == nil {
			md["app_name"] = base
			md["app_path"] = currentAbsPath
			if v, ok := md["asar_path"].(string); ok && v != "" {
				// keep asar_path only if it's still inside the current input dir
				if !strings.HasPrefix(v, currentAbsPath) {
					md["asar_path"] = ""
				}
			}
			md["analyzed_at"] = now
			md["host"] = host
			if out, err := json.MarshalIndent(md, "", "  "); err == nil {
				_ = os.WriteFile(mdPath, out, 0644)
			}
		}
	}

	// dissect.json
	djPath := filepath.Join(wsDir, "dissect.json")
	if data, err := os.ReadFile(djPath); err == nil {
		var dj map[string]any
		if json.Unmarshal(data, &dj) == nil {
			dj["path"] = currentAbsPath
			dj["file_name"] = base
			dj["source_path"] = currentAbsPath
			if det, ok := dj["detection"].(map[string]any); ok {
				det["path"] = currentAbsPath
				det["name"] = base
			}
			if out, err := json.MarshalIndent(dj, "", "  "); err == nil {
				_ = os.WriteFile(djPath, out, 0644)
			}
		}
	}
	return nil
}

func buildMetadata(r *DissectResult, id, osName string) *WorkspaceMetadata {
	m := &WorkspaceMetadata{
		UUID:       id,
		AppName:    inferAppName(r),
		AppPath:    r.Path,
		OS:         osName,
		Host:       hostname(),
		AnalyzedAt: time.Now().Format(time.RFC3339),
		Duration:   r.Duration.String(),
	}

	// Extract from Electron/Tauri app analysis
	if r.AppAnalysis != nil {
		a := r.AppAnalysis
		m.RiskLevel = a.Analysis.RiskLevel
		m.RiskScore = a.Analysis.RiskScore
		m.StealthFeatures = len(nilSlice(a.Analysis.StealthFeatures))
		m.IPCCommands = len(nilSlice(a.Analysis.IPCCommands))
		m.APIEndpoints = len(nilSlice(a.Analysis.APIEndpoints))
		m.SecuritySettings = len(nilSlice(a.Analysis.SecuritySettings))
		m.TelemetryServices = len(a.AppInfo.Telemetry)
		m.Binaries = len(a.Binaries)
		m.Framework = a.AppInfo.Type
		m.FrameworkVersion = a.AppInfo.Version

		// Locate ASAR path from the app directory
		for _, asarName := range []string{"resources/app.asar", "app/resources/app.asar"} {
			candidate := filepath.Join(r.Path, asarName)
			if _, err := os.Stat(candidate); err == nil {
				m.ASARPath = candidate
				break
			}
		}
	}

	// Extract from Android analysis
	if r.ManifestAnalysis != nil {
		m.RiskLevel = r.ManifestAnalysis.RiskLevel
		m.RiskScore = r.ManifestAnalysis.SecurityScore
	}

	return m
}

func writeAppArtifacts(workDir string, r *DissectResult) {
	a := r.AppAnalysis

	// ipc-commands.json
	ipc := nilSlice(a.Analysis.IPCCommands)
	writeJSON(filepath.Join(workDir, "ipc-commands.json"), ipc)

	// security-settings.json
	sec := nilSlice(a.Analysis.SecuritySettings)
	writeJSON(filepath.Join(workDir, "security-settings.json"), sec)

	// stealth-features.json
	stealth := nilSlice(a.Analysis.StealthFeatures)
	writeJSON(filepath.Join(workDir, "stealth-features.json"), stealth)

	// http/ directory
	httpDir := filepath.Join(workDir, "http")
	_ = os.MkdirAll(httpDir, 0755)

	eps := nilSlice(a.Analysis.APIEndpoints)

	// endpoints.txt
	var allURLs, sensitiveURLs, restFile strings.Builder
	sensitiveKeywords := []string{"auth", "login", "token", "key", "secret", "admin", "payment", "password", "session", "oauth", "api/v"}

	for _, ep := range eps {
		url := ep.URL

		allURLs.WriteString(url + "\n")

		lower := strings.ToLower(url)
		for _, kw := range sensitiveKeywords {
			if strings.Contains(lower, kw) {
				sensitiveURLs.WriteString(url + "\n")
				break
			}
		}

		restFile.WriteString(fmt.Sprintf("GET %s\n\n###\n\n", url))
	}

	_ = os.WriteFile(filepath.Join(httpDir, "endpoints.txt"), []byte(allURLs.String()), 0644)
	_ = os.WriteFile(filepath.Join(httpDir, "sensitive-endpoints.txt"), []byte(sensitiveURLs.String()), 0644)
	appName := inferAppName(r)
	_ = os.WriteFile(filepath.Join(httpDir, appName+".http.rest"), []byte(restFile.String()), 0644)

	// js-analysis/ directory (placeholder for pattern searches)
	jsDir := filepath.Join(workDir, "js-analysis")
	_ = os.MkdirAll(jsDir, 0755)

	// leveldb/ and cache/ directories (placeholders for user data)
	_ = os.MkdirAll(filepath.Join(workDir, "leveldb"), 0755)
	_ = os.MkdirAll(filepath.Join(workDir, "cache"), 0755)
}

func writeASARArtifacts(workDir string, r *DissectResult) {
	if r.ASARFiles == nil && r.ASARStats == nil {
		// Try to find ASAR in app analysis path
		if r.AppAnalysis == nil {
			return
		}

		asarPath := ""
		for _, name := range []string{"resources/app.asar", "app/resources/app.asar"} {
			candidate := filepath.Join(r.Path, name)
			if _, err := os.Stat(candidate); err == nil {
				asarPath = candidate
				break
			}
		}

		if asarPath == "" {
			return
		}

		// Parse ASAR for file listing
		f, header, _, _, err := asar.OpenAndParse(asarPath)
		if err != nil {
			return
		}
		defer func() { _ = f.Close() }()

		files := asar.CollectFiles(header.Files, "")

		// asar-filelist.txt
		var listing strings.Builder
		for _, ef := range files {
			if !ef.IsDir {
				listing.WriteString(fmt.Sprintf("%s\t%d\n", ef.Path, ef.Size))
			}
		}
		_ = os.WriteFile(filepath.Join(workDir, "asar-filelist.txt"), []byte(listing.String()), 0644)

		// asar-header.json
		writeJSON(filepath.Join(workDir, "asar-header.json"), header)

		// Search for secrets and URLs in ASAR (recover from panics in large files)
		func() {
			defer func() { _ = recover() }()
			searchASAR(asarPath, workDir)
		}()
		return
	}

	// We already have ASAR data from dissect
	if r.ASARFiles != nil {
		var listing strings.Builder
		for _, ef := range r.ASARFiles {
			if !ef.IsDir {
				listing.WriteString(fmt.Sprintf("%s\t%d\n", ef.Path, ef.Size))
			}
		}
		_ = os.WriteFile(filepath.Join(workDir, "asar-filelist.txt"), []byte(listing.String()), 0644)
	}
}

func searchASAR(asarPath, workDir string) {
	f, header, _, dataOffset, err := asar.OpenAndParse(asarPath)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	// Search for secrets
	secretPatterns := []string{"apiKey", "api_key", "secret", "token", "password", "AWS_", "STRIPE_", "FIREBASE_"}
	var secretResults strings.Builder
	for _, pattern := range secretPatterns {
		result := asar.Search(f, header, dataOffset, pattern)
		for _, m := range result.Matches {
			secretResults.WriteString(fmt.Sprintf("[%s] %s (%d bytes)\n", pattern, m.FilePath, m.FileSize))
		}
	}
	_ = os.WriteFile(filepath.Join(workDir, "asar-secrets-search.txt"), []byte(secretResults.String()), 0644)

	// Search for URLs — reopen since file position moved
	f2, header2, _, dataOffset2, err := asar.OpenAndParse(asarPath)
	if err != nil {
		return
	}
	defer func() { _ = f2.Close() }()

	urlPatterns := []string{"https://", "http://", "wss://", "ws://"}
	var urlResults strings.Builder
	for _, pattern := range urlPatterns {
		result := asar.Search(f2, header2, dataOffset2, pattern)
		for _, m := range result.Matches {
			urlResults.WriteString(fmt.Sprintf("[%s] %s (%d bytes)\n", pattern, m.FilePath, m.FileSize))
		}
	}
	_ = os.WriteFile(filepath.Join(workDir, "asar-urls-search.txt"), []byte(urlResults.String()), 0644)
}

func writeSummary(workDir string, meta *WorkspaceMetadata, r *DissectResult) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# %s Security Analysis\n\n", meta.AppName))
	sb.WriteString(fmt.Sprintf("**Path:** %s\n", meta.AppPath))
	sb.WriteString(fmt.Sprintf("**UUID:** %s\n", meta.UUID))
	sb.WriteString(fmt.Sprintf("**OS:** %s\n", meta.OS))
	sb.WriteString(fmt.Sprintf("**Host:** %s\n", meta.Host))
	sb.WriteString(fmt.Sprintf("**Analyzed:** %s\n", meta.AnalyzedAt))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", meta.Duration))

	sb.WriteString("## Risk\n\n")
	sb.WriteString(fmt.Sprintf("- **Level:** %s\n", meta.RiskLevel))
	sb.WriteString(fmt.Sprintf("- **Score:** %d\n\n", meta.RiskScore))

	if meta.Framework != "" {
		sb.WriteString("## Framework\n\n")
		sb.WriteString(fmt.Sprintf("- **Type:** %s\n", meta.Framework))
		sb.WriteString(fmt.Sprintf("- **Version:** %s\n\n", meta.FrameworkVersion))
	}

	sb.WriteString("## Stats\n\n")
	sb.WriteString(fmt.Sprintf("- **API Endpoints:** %d\n", meta.APIEndpoints))
	sb.WriteString(fmt.Sprintf("- **IPC Commands:** %d\n", meta.IPCCommands))
	sb.WriteString(fmt.Sprintf("- **Security Settings:** %d\n", meta.SecuritySettings))
	sb.WriteString(fmt.Sprintf("- **Stealth Features:** %d\n", meta.StealthFeatures))
	sb.WriteString(fmt.Sprintf("- **Telemetry Services:** %d\n", meta.TelemetryServices))
	sb.WriteString(fmt.Sprintf("- **Binaries:** %d\n\n", meta.Binaries))

	sb.WriteString("## Analyses Performed\n\n")
	sb.WriteString("| Analysis | Status | Duration |\n")
	sb.WriteString("|----------|--------|----------|\n")
	for _, a := range r.Analyses {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", a.Name, a.Status, a.Duration))
	}

	sb.WriteString("\n## Artifacts\n\n")
	sb.WriteString("| Artifact | File |\n")
	sb.WriteString("|----------|------|\n")

	artifacts := []struct{ name, file string }{
		{"Full dissect JSON", "dissect.json"},
		{"Dissect report", "DISSECT_REPORT.md"},
		{"IPC commands", "ipc-commands.json"},
		{"Security settings", "security-settings.json"},
		{"Stealth features", "stealth-features.json"},
		{"ASAR file list", "asar-filelist.txt"},
		{"Secrets search", "asar-secrets-search.txt"},
		{"URL search", "asar-urls-search.txt"},
		{"HTTP endpoints", "http/endpoints.txt"},
		{"Sensitive endpoints", "http/sensitive-endpoints.txt"},
		{"REST file", "http/" + meta.AppName + ".http.rest"},
		{"LevelDB data", "leveldb/"},
		{"Cache data", "cache/"},
		{"JS analysis", "js-analysis/"},
	}

	for _, a := range artifacts {
		p := filepath.Join(workDir, a.file)
		if info, err := os.Stat(p); err == nil && (info.IsDir() || info.Size() > 0) {
			sb.WriteString(fmt.Sprintf("| %s | `%s` |\n", a.name, a.file))
		}
	}

	_ = os.WriteFile(filepath.Join(workDir, "SUMMARY.md"), []byte(sb.String()), 0644)
}

func updateIndex(indexPath string, meta *WorkspaceMetadata) error {
	// Read existing index or create new one
	existing, _ := os.ReadFile(indexPath)
	content := string(existing)

	if content == "" {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("# Unravel Analysis Index (%s)\n\n", meta.OS))
		sb.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Host: %s\n\n", meta.Host))
		sb.WriteString("| App | UUID | Risk | Score | Stealth | IPC | Endpoints | Telemetry | Path |\n")
		sb.WriteString("|-----|------|------|-------|---------|-----|-----------|-----------|------|\n")
		content = sb.String()
	}

	// Append new row
	row := fmt.Sprintf("| %s | `%s` | %s | %d | %d | %d | %d | %d | `%s` |\n",
		meta.AppName, meta.UUID, meta.RiskLevel, meta.RiskScore,
		meta.StealthFeatures, meta.IPCCommands, meta.APIEndpoints,
		meta.TelemetryServices, meta.AppPath)

	content += row

	return os.WriteFile(indexPath, []byte(content), 0644)
}

// --- helpers ---

func detectOSName() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "macos"
	default:
		return runtime.GOOS
	}
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func inferAppName(r *DissectResult) string {
	if r.AppAnalysis != nil && r.AppAnalysis.AppInfo.Name != "" {
		return strings.ToLower(r.AppAnalysis.AppInfo.Name)
	}
	name := r.FileName
	// Strip common extensions
	for _, ext := range []string{".asar", ".apk", ".exe", ".deb", ".rpm", ".msi"} {
		name = strings.TrimSuffix(name, ext)
	}
	return strings.ToLower(name)
}

func writeJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0644)
}

// nilSlice returns an empty slice if the input is nil, for safe len() calls.
// Uses generics to work with any slice type.
func nilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
