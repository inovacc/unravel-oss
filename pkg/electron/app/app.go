/*
Copyright (c) 2026 Security Research
*/
package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/electron/api"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	"github.com/inovacc/unravel-oss/pkg/electron/ipc"
	"github.com/inovacc/unravel-oss/pkg/electron/risk"
	"github.com/inovacc/unravel-oss/pkg/electron/security"
	"github.com/inovacc/unravel-oss/pkg/electron/stealth"
	"github.com/inovacc/unravel-oss/pkg/electron/telemetry"
	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// Result holds the complete analysis output.
type Result struct {
	AppInfo   AppInfoResult  `json:"app_info"`
	Analysis  SecurityResult `json:"analysis"`
	Binaries  []binary.Info  `json:"binaries,omitempty"`
	Errors    []string       `json:"errors,omitempty"`
	Duration  time.Duration  `json:"duration"`
	Timestamp time.Time      `json:"timestamp"`
}

// AppInfoResult describes the analyzed application.
type AppInfoResult struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	DisplayName string   `json:"display_name"`
	Version     string   `json:"version"`
	Path        string   `json:"path"`
	HasStealth  bool     `json:"has_stealth"`
	Telemetry   []string `json:"telemetry"`
}

// SecurityResult holds all security findings.
type SecurityResult struct {
	SecuritySettings []security.Finding `json:"security_settings"`
	StealthFeatures  []stealth.Finding  `json:"stealth_features"`
	IPCCommands      []ipc.Finding      `json:"ipc_commands"`
	APIEndpoints     []api.Finding      `json:"api_endpoints"`
	RiskScore        int                `json:"risk_score"`
	RiskLevel        string             `json:"risk_level"`
}

// RunAnalysis performs a full security analysis on the given application path.
func RunAnalysis(appPath string, m *manifest.Manifest, appType string, verbose bool) (*Result, error) {
	if _, err := os.Stat(appPath); err != nil {
		return nil, fmt.Errorf("path does not exist: %s", appPath)
	}

	absAppPath, _ := filepath.Abs(appPath)

	start := time.Now()
	result := &Result{
		Timestamp: time.Now(),
		Errors:    make([]string, 0),
	}

	// Stage 1: Detect
	detector := manifest.NewDetector(m, verbose)

	detection, err := detector.Detect(absAppPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("[detect] %v", err))
	}

	if appType != "" && appType != "auto" {
		detection.Type = appType
		for _, rule := range m.Detection {
			if rule.Name == appType {
				detection.DisplayName = rule.DisplayName
				break
			}
		}
	}

	result.AppInfo = AppInfoResult{
		Name:        filepath.Base(absAppPath),
		Type:        detection.Type,
		DisplayName: detection.DisplayName,
		Version:     detection.Version,
		Path:        absAppPath,
	}

	// Stage 2: Analyze
	runSecurityAnalysis(m, absAppPath, detection.Type, result, verbose)
	calculateRiskScore(m, result)

	// Stage 2b: Binary analysis (always for Unknown apps)
	result.Binaries = binary.Analyze(absAppPath, verbose)

	// Stage 2c: enrich AppInfo.DisplayName from the main binary's PE
	// VS_VERSION_INFO ProductName when present. detection.DisplayName is
	// the framework label ("Electron"/"Tauri") — useful for taxonomy but
	// not for downstream identity (kb_apps.display_name, canonical_name).
	// Prefer the binary whose stem matches the directory basename
	// (case-insensitive) to avoid picking a helper exe like elevate.exe;
	// fall back to the first non-empty ProductName.
	if len(result.Binaries) > 0 {
		dirBase := strings.ToLower(filepath.Base(absAppPath))
		var matched, fallback string
		for _, b := range result.Binaries {
			if b.ProductName == "" {
				continue
			}
			stem := strings.ToLower(strings.TrimSuffix(filepath.Base(b.Path), filepath.Ext(b.Path)))
			if matched == "" && stem == dirBase {
				matched = b.ProductName
			}
			if fallback == "" {
				fallback = b.ProductName
			}
		}
		if matched != "" {
			result.AppInfo.DisplayName = matched
		} else if fallback != "" && (result.AppInfo.DisplayName == "" || strings.EqualFold(result.AppInfo.DisplayName, "Electron") || strings.EqualFold(result.AppInfo.DisplayName, "Tauri")) {
			result.AppInfo.DisplayName = fallback
		}
	}

	result.Duration = time.Since(start)

	return result, nil
}

func runSecurityAnalysis(m *manifest.Manifest, appPath, appType string, result *Result, verbose bool) {
	content := ReadAppContent(appPath, verbose)
	if content == "" {
		result.Errors = append(result.Errors, "[analyze] no analyzable content found")
		return
	}

	analysisConfig, ok := m.Analysis[appType]
	if !ok {
		return
	}

	for _, setting := range analysisConfig.SecuritySettings {
		finding := security.Check(content, setting)
		if finding != nil {
			result.Analysis.SecuritySettings = append(result.Analysis.SecuritySettings, *finding)
		}
	}

	for _, ipcPattern := range analysisConfig.IPCPatterns {
		findings := ipc.Find(content, ipcPattern, analysisConfig.DangerousIPCKeywords)
		result.Analysis.IPCCommands = append(result.Analysis.IPCCommands, findings...)
	}

	var stealthConfig manifest.StealthPatterns

	switch appType {
	case "electron":
		stealthConfig = m.Stealth.Electron
	case "tauri":
		stealthConfig = m.Stealth.Tauri
	}

	for _, pattern := range stealthConfig.Patterns {
		finding := stealth.Detect(content, pattern)
		if finding != nil {
			result.Analysis.StealthFeatures = append(result.Analysis.StealthFeatures, *finding)
			result.AppInfo.HasStealth = true
		}
	}

	for _, service := range m.Telemetry.Services {
		if telemetry.HasService(content, service) {
			result.AppInfo.Telemetry = append(result.AppInfo.Telemetry, service.Name)
		}
	}

	for _, urlPattern := range m.API.URLPatterns {
		findings := api.Find(content, urlPattern, m.API.Classifications)
		result.Analysis.APIEndpoints = append(result.Analysis.APIEndpoints, findings...)
	}
}

// ReadAppContent reads all analyzable content from the given path.
func ReadAppContent(appPath string, verbose bool) string {
	var content strings.Builder

	maxSize := 100 * 1024 * 1024

	info, err := os.Stat(appPath)
	if err != nil {
		return ""
	}

	if !info.IsDir() {
		if data, err := os.ReadFile(appPath); err == nil {
			if len(data) > maxSize {
				data = data[:maxSize]
			}

			content.Write(data)
		}

		return content.String()
	}

	asarPaths := []string{
		filepath.Join(appPath, "resources", "app.asar"),
		filepath.Join(appPath, "app", "resources", "app.asar"),
	}

	squirrelDirs, _ := filepath.Glob(filepath.Join(appPath, "app-*", "resources", "app.asar"))
	if len(squirrelDirs) > 0 {
		asarPaths = append(asarPaths, squirrelDirs[len(squirrelDirs)-1])
	}

	for _, asarPath := range asarPaths {
		if data, err := os.ReadFile(asarPath); err == nil {
			content.Write(data)

			if verbose {
				fmt.Printf("  [CONTENT] Read ASAR: %s (%d bytes)\n", asarPath, len(data))
			}

			break
		}
	}

	mainPaths := []string{
		filepath.Join(appPath, "resources", "app", "dist", "main", "index.js"),
		filepath.Join(appPath, "resources", "app", "main.js"),
		filepath.Join(appPath, "app", "resources", "app", "main.js"),
	}
	for _, p := range mainPaths {
		if data, err := os.ReadFile(p); err == nil {
			content.Write(data)
		}
	}

	jsExtensions := map[string]bool{".js": true, ".ts": true, ".mjs": true, ".cjs": true}
	jsCount := 0
	_ = filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if content.Len() > maxSize {
			return filepath.SkipAll
		}

		ext := strings.ToLower(filepath.Ext(path))
		if jsExtensions[ext] {
			if data, err := os.ReadFile(path); err == nil {
				content.Write(data)
				content.WriteString("\n")

				jsCount++
			}
		}

		return nil
	})

	if verbose && jsCount > 0 {
		fmt.Printf("  [CONTENT] Read %d source files\n", jsCount)
	}

	binExtensions := map[string]bool{".exe": true, "": true}
	_ = filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if content.Len() > maxSize {
			return filepath.SkipAll
		}

		ext := strings.ToLower(filepath.Ext(path))
		if binExtensions[ext] && info.Size() > 1024*1024 && info.Size() < 500*1024*1024 {
			if ext == "" {
				f, err := os.Open(path)
				if err != nil {
					return nil
				}

				header := make([]byte, 4)
				n, _ := f.Read(header)
				_ = f.Close()

				if n < 2 {
					return nil
				}

				isPE := header[0] == 'M' && header[1] == 'Z'
				isELF := header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F'

				isMachO := (header[0] == 0xfe && header[1] == 0xed) || (header[0] == 0xcf && header[1] == 0xfa)
				if !isPE && !isELF && !isMachO {
					return nil
				}
			}

			if data, err := os.ReadFile(path); err == nil {
				content.Write(data)

				if verbose {
					fmt.Printf("  [CONTENT] Read binary: %s (%d MB)\n", filepath.Base(path), len(data)/1024/1024)
				}
			}
		}

		return nil
	})

	return content.String()
}

func calculateRiskScore(m *manifest.Manifest, result *Result) {
	var secRisks, stealthRisks, ipcRisks []string

	for _, s := range result.Analysis.SecuritySettings {
		secRisks = append(secRisks, s.Risk)
	}

	for _, s := range result.Analysis.StealthFeatures {
		stealthRisks = append(stealthRisks, s.Risk)
	}

	for _, c := range result.Analysis.IPCCommands {
		ipcRisks = append(ipcRisks, c.Risk)
	}

	score := risk.CalculateFromManifest(m, secRisks, stealthRisks, ipcRisks)
	result.Analysis.RiskScore = score.Value
	result.Analysis.RiskLevel = score.Level
}
