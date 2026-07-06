/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	"github.com/inovacc/unravel-oss/pkg/electron/gather"
	"github.com/inovacc/unravel-oss/pkg/manifest"

	"github.com/spf13/cobra"
)

var (
	manifestPath string
	appType      string
	gatherApps   bool
)

var analyzeCmd = &cobra.Command{
	Use:   "scan <app_path>",
	Short: "Full security analysis with manifest-based detection",
	Long: `Analyze an Electron or Tauri application for security issues.

Uses a YAML manifest file to define detection rules and analysis patterns.
Detects framework type, security configuration, stealth features,
telemetry services, IPC commands, and API endpoints.`,
	Args: cobra.ArbitraryArgs,
	Run:  runAnalyze,
}

func init() {
	appCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().StringVarP(&manifestPath, "manifest", "m", "", "Path to manifest file")
	analyzeCmd.Flags().StringVarP(&appType, "type", "t", "auto", "Force app type: electron, tauri, auto")
	analyzeCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
	analyzeCmd.Flags().BoolVar(&gatherApps, "gather", false, "Scan system for installed Electron/Tauri apps")
}

func loadManifest() *manifest.Manifest {
	var (
		m   *manifest.Manifest
		err error
	)

	if manifestPath != "" {
		m, err = manifest.Load(manifestPath)
		if err != nil {
			fmt.Printf("Error loading manifest: %v\n", err)
			os.Exit(1)
		}
	} else {
		m, err = manifest.LoadDefault()
		if err != nil {
			m = manifest.Default()
		}
	}

	return m
}

func runGather(m *manifest.Manifest) {
	fmt.Println("Scanning for installed Electron/Tauri applications...")
	fmt.Println()

	entries := gather.Gather(m, verbose)
	if len(entries) == 0 {
		fmt.Println("No Electron/Tauri applications found.")
		return
	}

	fmt.Printf("Found %d application(s):\n\n", len(entries))

	for i, e := range entries {
		ver := ""
		if e.Version != "" {
			ver = " v" + e.Version
		}

		fmt.Printf("  [%d] %s (%s%s, score=%d)\n", i+1, e.Path, e.DisplayName, ver, e.Score)
	}

	fmt.Println()
	fmt.Print("Enter number to analyze (or 'all', 'q' to quit): ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return
	}

	input := strings.TrimSpace(scanner.Text())

	switch strings.ToLower(input) {
	case "q", "quit", "":
		return
	case "all":
		for _, e := range entries {
			fmt.Printf("\n--- Analyzing: %s ---\n\n", e.Path)
			analyzeApp(e.Path, m)
		}
	default:
		n, err := strconv.Atoi(input)
		if err != nil || n < 1 || n > len(entries) {
			fmt.Printf("Invalid selection: %s\n", input)
			return
		}

		analyzeApp(entries[n-1].Path, m)
	}
}

func runAnalyze(_ *cobra.Command, args []string) {
	m := loadManifest()

	if gatherApps {
		runGather(m)
		return
	}

	if len(args) == 0 {
		fmt.Println("Error: requires an app path argument or --gather flag")
		os.Exit(1)
	}

	appPath := args[0]
	analyzeApp(appPath, m)
}

func analyzeApp(appPath string, m *manifest.Manifest) {
	absAppPath, _ := filepath.Abs(appPath)
	fmt.Printf("Analyzing: %s\n", absAppPath)
	fmt.Printf("Manifest: %s\n\n", m.Name)

	fmt.Println("Stage 1: DETECT")

	result, err := app.RunAnalysis(appPath, m, appType, verbose)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  Detected: %s (%s) v%s\n", result.AppInfo.Name, result.AppInfo.DisplayName, result.AppInfo.Version)

	fmt.Println("\nStage 2: ANALYZE")

	if verbose {
		for _, s := range result.Analysis.SecuritySettings {
			fmt.Printf("  [SECURITY] %s = %s (%s)\n", s.Name, s.Value, s.Risk)
		}

		if len(result.Analysis.IPCCommands) > 0 {
			fmt.Printf("  [IPC] Found %d commands\n", len(result.Analysis.IPCCommands))
		}

		for _, s := range result.Analysis.StealthFeatures {
			fmt.Printf("  [STEALTH] %s detected\n", s.Name)
		}

		for _, t := range result.AppInfo.Telemetry {
			fmt.Printf("  [TELEMETRY] %s detected\n", t)
		}

		if len(result.Analysis.APIEndpoints) > 0 {
			fmt.Printf("  [API] Found %d endpoints\n", len(result.Analysis.APIEndpoints))
		}
	}

	// Stage 3: Report
	fmt.Println("\nStage 3: REPORT")

	outDir := output
	if outDir == "" {
		outDir = "unravel_" + filepath.Base(appPath)
	}

	_ = os.MkdirAll(outDir, 0755)

	if jsonFormat {
		jsonPath := filepath.Join(outDir, "data.json")
		writeAnalysisJSON(result, jsonPath)
		fmt.Printf("  JSON: %s\n", jsonPath)
	} else {
		mdPath := filepath.Join(outDir, "UNRAVEL_REPORT.md")
		writeAnalysisMarkdown(result, mdPath)
		fmt.Printf("  Report: %s\n", mdPath)

		jsonPath := filepath.Join(outDir, "data.json")
		writeAnalysisJSON(result, jsonPath)
		fmt.Printf("  Data: %s\n", jsonPath)
	}

	printAnalysisSummary(result)
	fmt.Println("\nAnalysis complete!")
}

func writeAnalysisJSON(result *app.Result, path string) {
	data, _ := json.MarshalIndent(result, "", "  ")
	_ = os.WriteFile(path, data, 0644)
}

func writeAnalysisMarkdown(result *app.Result, path string) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# App Unravel Report: %s\n\n", result.AppInfo.Name))
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Framework:** %s %s\n", result.AppInfo.DisplayName, result.AppInfo.Version))

	stealth := "NO"
	if result.AppInfo.HasStealth {
		stealth = "YES"
	}

	sb.WriteString(fmt.Sprintf("**Stealth Features:** %s\n", stealth))
	sb.WriteString(fmt.Sprintf("**Risk Level:** %s (Score: %d)\n\n---\n\n", result.Analysis.RiskLevel, result.Analysis.RiskScore))

	if len(result.Analysis.SecuritySettings) > 0 {
		sb.WriteString("## Security Configuration\n\n| Setting | Value | Risk | Description |\n|---------|-------|------|-------------|\n")

		for _, s := range result.Analysis.SecuritySettings {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", s.Name, s.Value, s.Risk, s.Description))
		}

		sb.WriteString("\n")
	}

	if len(result.Analysis.StealthFeatures) > 0 {
		sb.WriteString("## Stealth Features\n\n")

		for _, s := range result.Analysis.StealthFeatures {
			sb.WriteString(fmt.Sprintf("### %s\n\n**Description:** %s\n\n**Risk:** %s\n\n**Evidence:**\n```\n%s\n```\n\n", s.Name, s.Description, s.Risk, s.Evidence))
		}
	}

	if len(result.AppInfo.Telemetry) > 0 {
		sb.WriteString("## Telemetry Services\n\n")

		for _, t := range result.AppInfo.Telemetry {
			sb.WriteString(fmt.Sprintf("- %s\n", t))
		}

		sb.WriteString("\n")
	}

	if len(result.Analysis.IPCCommands) > 0 {
		sb.WriteString("## IPC Commands\n\n| Channel | Direction | Risk |\n|---------|-----------|------|\n")

		for _, c := range result.Analysis.IPCCommands {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", c.Channel, c.Direction, c.Risk))
		}

		sb.WriteString("\n")
	}

	if len(result.Analysis.APIEndpoints) > 0 {
		sb.WriteString("## API Endpoints\n\n| URL | Purpose |\n|-----|--------|\n")

		for _, a := range result.Analysis.APIEndpoints {
			sb.WriteString(fmt.Sprintf("| %s | %s |\n", a.URL, a.Purpose))
		}

		sb.WriteString("\n")
	}

	if len(result.Binaries) > 0 {
		sb.WriteString("## Binary Analysis\n\n")
		for _, b := range result.Binaries {
			sb.WriteString(fmt.Sprintf("### %s\n\n", b.Name))
			sb.WriteString(fmt.Sprintf("Path: %s\n\n", b.Path))
			sb.WriteString(fmt.Sprintf("Type: %s\n\n", b.Type))
			if b.Arch != "" {
				sb.WriteString(fmt.Sprintf("Arch: %s\n\n", b.Arch))
			}
			sb.WriteString(fmt.Sprintf("Size: %.1f MB\n\n", b.SizeMB))
			if len(b.Imports) > 0 {
				sb.WriteString(fmt.Sprintf("Imports: %d\n\n", len(b.Imports)))
			}
			if len(b.Libraries) > 0 {
				sb.WriteString(fmt.Sprintf("Libraries: %d\n\n", len(b.Libraries)))
			}
			if b.CertSubject != "" {
				sb.WriteString(fmt.Sprintf("Certificate Subject: %s\n\n", b.CertSubject))
			}
			if b.CertIssuer != "" {
				sb.WriteString(fmt.Sprintf("Certificate Issuer: %s\n\n", b.CertIssuer))
			}
			if len(b.SampleURLs) > 0 {
				sb.WriteString("Sample URLs:\n```\n")
				for _, u := range b.SampleURLs {
					sb.WriteString(u + "\n")
				}
				sb.WriteString("```\n\n")
			}
			if len(b.SampleStrings) > 0 {
				sb.WriteString("Sample Strings:\n```\n")
				for _, s := range b.SampleStrings {
					sb.WriteString(s + "\n")
				}
				sb.WriteString("```\n\n")
			}
			if len(b.ToolResults) > 0 {
				sb.WriteString("Tool Outputs:\n")
				for _, tr := range b.ToolResults {
					sb.WriteString(fmt.Sprintf("- %s: %s\n", tr.Name, tr.Status))
					sb.WriteString(fmt.Sprintf("  Command: %s\n", tr.Command))
					if tr.Output != "" {
						sb.WriteString("  Output:\n```\n")
						sb.WriteString(tr.Output + "\n")
						sb.WriteString("```\n")
					}
				}
				sb.WriteString("\n")
			}
			// Strategy section
			sb.WriteString("Strategy:\n```\n")
			sb.WriteString(strategySummary(b) + "\n")
			sb.WriteString("```\n\n")
		}
	}

	sb.WriteString(fmt.Sprintf("---\n\n*Analysis completed in %s*\n", result.Duration))
	_ = os.WriteFile(path, []byte(sb.String()), 0644)
}

func printAnalysisSummary(result *app.Result) {
	fmt.Println()
	fmt.Println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557")
	fmt.Println("\u2551                    UNRAVEL RESULTS                          \u2551")
	fmt.Println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563")
	fmt.Printf("\u2551 App: %-55s \u2551\n", result.AppInfo.Name)
	fmt.Printf("\u2551 Type: %-54s \u2551\n", result.AppInfo.DisplayName)
	fmt.Printf("\u2551 Version: %-51s \u2551\n", result.AppInfo.Version)

	stealth := "NO"
	if result.AppInfo.HasStealth {
		stealth = "YES"
	}

	fmt.Printf("\u2551 Stealth Features: %-42s \u2551\n", stealth)
	fmt.Println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563")
	fmt.Printf("\u2551 Risk Level: %-48s \u2551\n", result.Analysis.RiskLevel)
	fmt.Printf("\u2551 Risk Score: %-48d \u2551\n", result.Analysis.RiskScore)
	fmt.Printf("\u2551 Security Settings: %-41d \u2551\n", len(result.Analysis.SecuritySettings))
	fmt.Printf("\u2551 IPC Commands: %-46d \u2551\n", len(result.Analysis.IPCCommands))
	fmt.Printf("\u2551 API Endpoints: %-45d \u2551\n", len(result.Analysis.APIEndpoints))
	fmt.Printf("\u2551 Binaries: %-50d \u2551\n", len(result.Binaries))
	fmt.Printf("\u2551 Telemetry Services: %-40d \u2551\n", len(result.AppInfo.Telemetry))
	fmt.Println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563")
	fmt.Printf("\u2551 Duration: %-50s \u2551\n", result.Duration.String())
	fmt.Println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d")
}

func strategySummary(b binary.Info) string {
	status := func(name string) string {
		for _, tr := range b.ToolResults {
			if tr.Name == name {
				return tr.Status
			}
		}
		return "missing"
	}

	lines := []string{}

	if status("strings") == "ok" {
		lines = append(lines, "Strings extraction: OK")
	} else {
		lines = append(lines, "Strings extraction: unavailable")
	}

	switch b.Type {
	case "PE":
		if status("objdump") == "ok" {
			lines = append(lines, "Static headers/imports: objdump OK")
		} else {
			lines = append(lines, "Static headers/imports: objdump unavailable")
		}
		if status("nm") == "ok" {
			lines = append(lines, "Symbols: nm OK")
		} else {
			lines = append(lines, "Symbols: nm unavailable")
		}
	case "ELF":
		if status("readelf") == "ok" {
			lines = append(lines, "ELF headers/sections: readelf OK")
		} else {
			lines = append(lines, "ELF headers/sections: readelf unavailable")
		}
		if status("ldd") == "ok" {
			lines = append(lines, "Dynamic deps: ldd OK")
		} else {
			lines = append(lines, "Dynamic deps: ldd unavailable")
		}
		if status("nm") == "ok" {
			lines = append(lines, "Symbols: nm OK")
		} else {
			lines = append(lines, "Symbols: nm unavailable")
		}
	default:
		if status("objdump") == "ok" {
			lines = append(lines, "Static headers/imports: objdump OK")
		} else {
			lines = append(lines, "Static headers/imports: objdump unavailable")
		}
	}

	if status("binwalk") == "ok" {
		lines = append(lines, "Embedded content scan: binwalk OK")
	} else {
		lines = append(lines, "Embedded content scan: binwalk unavailable")
	}

	if status("ndisasm") == "ok" {
		lines = append(lines, "Raw disassembly: ndisasm OK")
	} else {
		lines = append(lines, "Raw disassembly: ndisasm unavailable")
	}

	if b.CertSubject != "" {
		lines = append(lines, "Code signing: certificate present")
	} else {
		lines = append(lines, "Code signing: not detected")
	}

	// Decompiler hints (command-only)
	r2 := status("radare2")
	if r2 == "skipped" {
		lines = append(lines, "Decompiler: radare2 available (manual)")
	} else if r2 == "missing" {
		lines = append(lines, "Decompiler: radare2 missing")
	}
	gh := status("ghidra")
	if gh == "skipped" {
		lines = append(lines, "Decompiler: Ghidra available (manual)")
	} else if gh == "missing" {
		lines = append(lines, "Decompiler: Ghidra missing")
	}

	return strings.Join(lines, "\n")
}
