/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/inovacc/unravel-oss/pkg/forensic"

	"github.com/spf13/cobra"
)

var (
	forensicAI      bool
	forensicHTML    bool
	forensicDiffOld string
	forensicDiffNew string
	forensicRubric  string
)

var forensicCmd = &cobra.Command{
	Use:   "forensic <teardown-dir>",
	Short: "Generate forensic report with API replay scripts from teardown data",
	Long: `Generate a comprehensive forensic report from previously dissected APK teardown data.
Includes network endpoint analysis, secret detection summary, SDK/telemetry inventory,
and curl scripts for replaying discovered API communication.

Single app mode:
  unravel forensic D:\unravel_teardowns\apks\com.example.app -o ./report

Batch mode (all apps in a directory):
  unravel forensic D:\unravel_teardowns\apks -o ./reports --json

The output includes:
  - FORENSIC_REPORT.md — Full markdown report per app
  - curl/ — Executable curl scripts by category (auth, api, analytics, etc.)
  - forensic.json — Machine-readable report
  - FORENSIC_SUMMARY.md — Batch summary with risk rankings
  - DOMAIN_INDEX.md — Domain-to-app cross-reference
  - SDK_INDEX.md — SDK/tracker-to-app cross-reference`,
	Args: cobra.ExactArgs(1),
	RunE: runForensic,
}

func init() {
	appCmd.AddCommand(forensicCmd)
	forensicCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output JSON to stdout")
	forensicCmd.Flags().BoolVar(&forensicAI, "ai", false, "Use Claude Code MCP for AI-enriched findings")
	forensicCmd.Flags().BoolVar(&forensicHTML, "html", false, "Emit polished single-file HTML report (Phase 10 / RPT-01)")
	forensicCmd.Flags().StringVar(&forensicDiffOld, "diff-old", "", "Old KB directory for regression analysis (Phase 10 / D-19)")
	forensicCmd.Flags().StringVar(&forensicDiffNew, "diff-new", "", "New KB directory for regression analysis (Phase 10 / D-19)")
	forensicCmd.Flags().StringVar(&forensicRubric, "rubric", "", "kb-regressions.yaml override (Phase 7 D-10 carry-forward)")
}

func runForensic(_ *cobra.Command, args []string) error {
	path := args[0]
	start := time.Now()

	// D-28: --ai implies --html (executive summary is an HTML-only artifact at first ship).
	if forensicAI {
		forensicHTML = true
	}
	// D-19: --diff-old and --diff-new are paired — error if only one is set.
	if (forensicDiffOld == "") != (forensicDiffNew == "") {
		return fmt.Errorf("--diff-old and --diff-new must be specified together")
	}

	// MCP client seam (B2 closure): production client when --ai, NilMCPClient otherwise.
	// Mirrors pkg/frida/enrich/enrich.go:64 New() pattern (Orchestrator{MCP: nilClient{}}).
	// Phase 9 currently ships with the nil client wired by default; the seam is preserved
	// here so a real backend can be plugged in without touching dispatch code.
	var mcpClient forensic.MCPClient = forensic.NilMCPClient()
	if forensicAI {
		mcpClient = forensic.NilMCPClient() // executor: replace with production client when wired
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}

	// Detect mode: single app (has UUID subdir with manifest.json) or batch
	isBatch := isBatchDir(path)

	if isBatch {
		fmt.Fprintf(os.Stderr, "Batch forensic analysis: %s\n", path)

		opts := forensic.Options{
			TeardownDir: path,
			OutputDir:   output,
			Verbose:     verbose,
			AIEnrich:    forensicAI,
		}

		batch, err := forensic.RunBatch(path, opts)
		if err != nil {
			return err
		}

		if jsonFormat {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(batch)
		}

		// Write reports to disk
		outDir := output
		if outDir == "" {
			outDir = "./forensic-report"
		}

		if err := forensic.WriteBatchReport(batch, outDir); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "\nForensic batch complete: %d apps in %s\n", batch.TotalApps, time.Since(start).Truncate(time.Millisecond))
		fmt.Fprintf(os.Stderr, "Reports: %s\n", outDir)

		// Print top risks
		fmt.Println()
		fmt.Printf("%-45s %5s %7s %7s %5s\n", "APP", "RISK", "LEVEL", "SECRETS", "SDKS")
		fmt.Println(repeat("─", 80))

		for _, app := range batch.TopRisks {
			secrets := 0
			if app.Secrets != nil {
				secrets = app.Secrets.HighConfidence
			}
			sdks := 0
			if app.Telemetry != nil {
				sdks = app.Telemetry.SDKCount
			}
			fmt.Printf("%-45s %5d %7s %7d %5d\n", truncID(app.AppID, 45), app.RiskScore, app.RiskLevel, secrets, sdks)
		}

		return nil
	}

	// Single app mode
	report, err := forensic.RunSingle(path)
	if err != nil {
		return err
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	outDir := output
	if outDir == "" {
		outDir = fmt.Sprintf("./forensic-%s", report.AppID)
	}

	if err := forensic.WriteReport(report, outDir); err != nil {
		return err
	}

	// Phase 10 D-28 dispatch: --html emits report.html alongside the existing
	// Markdown output. Default no-flag behavior is preserved (D-25 backward-compat).
	if forensicHTML {
		htmlOpts := forensic.HTMLRenderOptions{
			KBDir:         path,
			IncludeImages: true,
			AI:            forensicAI,
			MCPClient:     mcpClient,
			DiffOld:       forensicDiffOld,
			DiffNew:       forensicDiffNew,
			Rubric:        forensicRubric,
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := forensic.WriteHTMLReportFull(ctx, report, htmlOpts, outDir); err != nil {
			slog.Warn("html report failed", "err", err)
		}
	}

	fmt.Printf("Forensic report: %s\n", outDir)
	fmt.Printf("  Risk: %d/100 (%s)\n", report.RiskScore, report.RiskLevel)
	fmt.Printf("  Findings: %d\n", len(report.Findings))
	fmt.Printf("  Curl scripts: %d\n", len(report.CurlScripts))
	fmt.Printf("  Duration: %s\n", time.Since(start).Truncate(time.Millisecond))

	return nil
}

// isBatchDir returns true if the directory contains app subdirectories (batch mode).
func isBatchDir(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	// If any direct child has a UUID subdir with manifest.json, it's a batch dir.
	// If we directly find a manifest.json in a UUID subdir, it's a single app.
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		// Check if this entry IS a UUID dir (single app mode)
		candidate := fmt.Sprintf("%s/%s/manifest.json", dir, e.Name())
		if _, err := os.Stat(candidate); err == nil {
			return false // Single app — the dir itself contains the teardown
		}

		// Check if this entry has a UUID subdir (batch mode)
		subEntries, err := os.ReadDir(fmt.Sprintf("%s/%s", dir, e.Name()))
		if err != nil {
			continue
		}
		for _, sub := range subEntries {
			if sub.IsDir() {
				manifest := fmt.Sprintf("%s/%s/%s/manifest.json", dir, e.Name(), sub.Name())
				if _, err := os.Stat(manifest); err == nil {
					return true
				}
			}
		}
	}

	return false
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func truncID(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
