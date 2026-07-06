/*
Copyright © 2026 Security Research
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

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/extension"
	"github.com/inovacc/unravel-oss/pkg/extension/gather"
	"github.com/inovacc/unravel-oss/pkg/extension/snapshot"
	"github.com/inovacc/unravel-oss/pkg/manifest"

	"github.com/spf13/cobra"
)

var (
	extJSONFormat  bool
	extBrowser     string
	extPath        string
	extExtractOut  string
	snapshotCSV    string
	snapshotTarget string
	snapshotID     string
)

var extensionCmd = &cobra.Command{
	Use:   "extension",
	Short: "Browser extension forensics",
	Long: `Discover, analyze, and search browser extensions across all
Chromium-based browsers (Chrome, Edge, Brave, Opera, Vivaldi, Chromium).

Subcommands:
  scan     - Full discovery and analysis of all extensions
  analyze  - Deep analysis of a single extension
  extract  - Extract extension files + analysis artifacts
  search   - Search pattern across all extension source code
  list     - Quick tabular listing of all extensions`,
}

var extScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan all browser extensions",
	Long: `Discover and analyze all extensions across all Chromium-based browsers.
Parses manifests, analyzes permissions, scans source code for suspicious patterns,
and detects stealth/cheating tools.`,
	Run: runExtScan,
}

var extAnalyzeCmd = &cobra.Command{
	Use:   "analyze <extension_id_or_path>",
	Short: "Deep analysis of a single extension",
	Long: `Analyze a single extension by its ID or directory path.
Performs full permission analysis, source code scanning, stealth detection,
and cheating detection.`,
	Args: cobra.ExactArgs(1),
	Run:  runExtAnalyze,
}

var extSearchCmd = &cobra.Command{
	Use:   "search <pattern>",
	Short: "Search pattern across extension source code",
	Long:  `Search for a string pattern across all extension source files.`,
	Args:  cobra.ExactArgs(1),
	Run:   runExtSearch,
}

var extListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all browser extensions",
	Long:  `Quick tabular listing of all discovered extensions with basic info.`,
	Run:   runExtList,
}

var extExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all extensions with reports and beautified JS",
	Long: `Export all browser extensions to a directory. Each extension is copied
to its own subdirectory with beautified JavaScript files and a detailed
REPORT.md. A global SUMMARY.md is generated at the output root.`,
	Run: runExtExport,
}

var extExtractCmd = &cobra.Command{
	Use:   "extract <extension_id_or_path_or_package>",
	Short: "Extract extension files and forensic metadata",
	Long: `Extract a browser extension from:
  - installed extension ID
  - unpacked extension directory
  - package file (.crx, .zip, .xpi)

Writes extracted files plus analysis artifacts (analysis.json + REPORT.md).`,
	Args: cobra.ExactArgs(1),
	Run:  runExtExtract,
}

var extGatherCmd = &cobra.Command{
	Use:   "gather",
	Short: "Discover all installed extensions with risk scores",
	Long: `Scan all Chromium-based browsers for installed extensions.
Lists every extension with risk score, permissions count, and manifest version.
Select an extension by number for deep analysis.`,
	Run: runExtGather,
}

var extSnapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Download, crawl, and analyze extensions from CSV",
	Long: `Run the full extension snapshot pipeline:
1. Download CRX from Chrome Web Store
2. Extract URLs from source code
3. Launch browser and visit stores (HAR + DOM + storage + screenshots)
4. Analyze: map source URLs to live network traffic

Use --id to run for a single extension, or let it process the full CSV.`,
	Run: runExtSnapshot,
}

var extExportOutput string

func init() {
	rootCmd.AddCommand(extensionCmd)
	extensionCmd.AddCommand(extScanCmd)
	extensionCmd.AddCommand(extAnalyzeCmd)
	extensionCmd.AddCommand(extSearchCmd)
	extensionCmd.AddCommand(extListCmd)
	extensionCmd.AddCommand(extExportCmd)
	extensionCmd.AddCommand(extExtractCmd)
	extensionCmd.AddCommand(extGatherCmd)
	extensionCmd.AddCommand(extSnapshotCmd)

	extSnapshotCmd.Flags().StringVar(&snapshotCSV, "csv", "chrome_discount_extensions.csv", "CSV file with extension names + Chrome Web Store URLs")
	extSnapshotCmd.Flags().StringVar(&snapshotTarget, "target", "target", "Output directory for snapshot data")
	extSnapshotCmd.Flags().StringVar(&snapshotID, "id", "", "Run for a single extension ID instead of full CSV")

	extExportCmd.Flags().StringVarP(&extExportOutput, "output", "o", "", "Output directory (required)")
	_ = extExportCmd.MarkFlagRequired("output")

	extExtractCmd.Flags().StringVarP(&extExtractOut, "output", "o", "", "Output directory (optional, defaults to ./extension_extract_<name>)")

	extensionCmd.PersistentFlags().BoolVar(&extJSONFormat, "json", false, "Output as JSON")
	extensionCmd.PersistentFlags().StringVar(&extBrowser, "browser", "", "Filter by browser (chrome, edge, brave, opera, vivaldi, chromium)")
	extensionCmd.PersistentFlags().StringVar(&extPath, "path", "", "Custom extension directory path")
}

func loadExtManifest() *manifest.Manifest {
	var (
		m   *manifest.Manifest
		err error
	)

	if manifestPath != "" {
		m, err = manifest.Load(manifestPath)
	} else {
		m, err = manifest.LoadDefault()
	}

	if err != nil {
		m = manifest.Default()
	}

	return m
}

func runExtScan(_ *cobra.Command, _ []string) {
	m := loadExtManifest()

	fmt.Println("Scanning browser extensions...")

	if extBrowser != "" {
		fmt.Printf("Filter: %s\n", extBrowser)
	}

	fmt.Println()

	result := extension.ScanAllExtensions(m, extBrowser, verbose)

	if extJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	// Print browser summary
	fmt.Println("Browsers Discovered")
	fmt.Println(strings.Repeat("-", 70))

	for _, bp := range result.Browsers {
		fmt.Printf("  %-10s %-15s %d extensions\n", bp.Browser, bp.Profile, bp.ExtCount)
	}

	fmt.Println()

	if len(result.Extensions) == 0 {
		fmt.Println("No extensions found.")
		return
	}

	// Print extensions grouped by risk
	for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		var exts []extension.ExtensionInfo

		for _, ext := range result.Extensions {
			if ext.RiskLevel == level {
				exts = append(exts, ext)
			}
		}

		if len(exts) == 0 {
			continue
		}

		fmt.Printf("[%s] %d extensions\n", level, len(exts))
		fmt.Println(strings.Repeat("-", 70))

		for _, ext := range exts {
			fmt.Printf("  %-40s %-12s Score: %d\n", out.Truncate(ext.Name, 40), ext.Browser, ext.RiskScore)
			fmt.Printf("    ID: %s  V%d  Perms: %d\n", ext.ID, ext.ManifestVer, len(ext.Permissions.All))

			if len(ext.StealthFlags) > 0 {
				fmt.Printf("    Stealth: %d indicators\n", len(ext.StealthFlags))
			}

			if len(ext.CheatingFlags) > 0 {
				fmt.Printf("    Cheating: %d indicators\n", len(ext.CheatingFlags))
			}
		}

		fmt.Println()
	}

	// Summary
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total: %d extensions across %d browser profiles\n", result.TotalExts, len(result.Browsers))
	fmt.Printf("Risk: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d\n",
		result.RiskSummary["CRITICAL"], result.RiskSummary["HIGH"],
		result.RiskSummary["MEDIUM"], result.RiskSummary["LOW"])
}

func runExtAnalyze(_ *cobra.Command, args []string) {
	m := loadExtManifest()
	target := args[0]

	fmt.Printf("Analyzing extension: %s\n\n", target)

	info, err := extension.AnalyzeSingleExtension(m, target, extBrowser, verbose)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if extJSONFormat {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintExtensionDetail(info)
}

func runExtSearch(_ *cobra.Command, args []string) {
	pattern := args[0]

	fmt.Printf("Searching extensions for: %q\n", pattern)

	if extBrowser != "" {
		fmt.Printf("Filter: %s\n", extBrowser)
	}

	fmt.Println()

	result := extension.SearchExtensions(pattern, extBrowser)

	if extJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	if result.Total == 0 {
		fmt.Println("No matches found.")
		return
	}

	currentExt := ""

	for _, match := range result.Matches {
		label := fmt.Sprintf("%s (%s/%s)", match.Extension, match.Browser, match.Profile)
		if label != currentExt {
			currentExt = label
			fmt.Printf("\n[%s]\n", label)
		}

		fmt.Printf("  %s:%d  %s\n", match.File, match.Line, match.Context)
	}

	fmt.Printf("\n%s\n", strings.Repeat("-", 70))
	fmt.Printf("Total: %d matches for %q\n", result.Total, pattern)
}

func runExtList(_ *cobra.Command, _ []string) {
	profiles := extension.DiscoverBrowsers(extBrowser)

	if extJSONFormat {
		var allExts []extension.ExtensionInfo

		for _, bp := range profiles {
			entries, err := os.ReadDir(bp.ExtDir)
			if err != nil {
				continue
			}

			for _, e := range entries {
				if !e.IsDir() || e.Name() == "Temp" {
					continue
				}

				extPath := fmt.Sprintf("%s%c%s", bp.ExtDir, os.PathSeparator, e.Name())

				info, err := extension.ParseExtension(extPath, e.Name(), bp.Browser, bp.Profile)
				if err != nil {
					continue
				}

				allExts = append(allExts, *info)
			}
		}

		data, _ := json.MarshalIndent(allExts, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("%-10s %-15s %-35s %-40s %-8s %s\n",
		"BROWSER", "PROFILE", "ID", "NAME", "VERSION", "PERMS")
	fmt.Println(strings.Repeat("-", 120))

	total := 0

	for _, bp := range profiles {
		entries, err := os.ReadDir(bp.ExtDir)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if !e.IsDir() || e.Name() == "Temp" {
				continue
			}

			ePath := fmt.Sprintf("%s%c%s", bp.ExtDir, os.PathSeparator, e.Name())

			info, err := extension.ParseExtension(ePath, e.Name(), bp.Browser, bp.Profile)
			if err != nil {
				continue
			}

			total++

			fmt.Printf("%-10s %-15s %-35s %-40s %-8s %d\n",
				info.Browser,
				info.Profile,
				out.Truncate(info.ID, 35),
				out.Truncate(info.Name, 40),
				info.Version,
				len(info.Permissions.All),
			)
		}
	}

	fmt.Println(strings.Repeat("-", 120))
	fmt.Printf("Total: %d extensions\n", total)
}

func runExtExport(_ *cobra.Command, _ []string) {
	m := loadExtManifest()

	_, err := extension.ExportAllExtensions(m, extBrowser, extExportOutput, verbose)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func runExtGather(_ *cobra.Command, _ []string) {
	m := loadExtManifest()

	entries := gather.Gather(m, extBrowser, verbose)
	if len(entries) == 0 {
		fmt.Println("No browser extensions found.")
		return
	}

	if extJSONFormat {
		data, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Found %d extension(s):\n\n", len(entries))
	fmt.Printf("  %-4s %-35s %-10s %-12s %-8s %-8s %s\n",
		"#", "NAME", "BROWSER", "PROFILE", "VERSION", "RISK", "PERMS")
	fmt.Println(strings.Repeat("-", 95))

	for i, e := range entries {
		dupeTag := ""
		if e.Duplicate {
			dupeTag = " [dupe:" + e.DupeOf + "]"
		}

		fmt.Printf("  [%d] %-35s %-10s %-12s %-8s %-8s %d%s\n",
			i+1,
			out.Truncate(e.Name, 35),
			e.Browser,
			out.Truncate(e.Profile, 12),
			e.Version,
			fmt.Sprintf("%s(%d)", e.RiskLevel, e.RiskScore),
			e.Permissions,
			dupeTag,
		)
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
			fmt.Printf("\n--- Analyzing: %s (%s/%s) ---\n\n", e.Name, e.Browser, e.Profile)

			info, err := extension.AnalyzeSingleExtension(m, e.Path, "", verbose)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}

			if extJSONFormat {
				data, _ := json.MarshalIndent(info, "", "  ")
				fmt.Println(string(data))
			} else {
				out.PrintExtensionDetail(info)
			}
		}
	default:
		n, err := strconv.Atoi(input)
		if err != nil || n < 1 || n > len(entries) {
			fmt.Printf("Invalid selection: %s\n", input)
			return
		}

		e := entries[n-1]

		info, analyzeErr := extension.AnalyzeSingleExtension(m, e.Path, "", verbose)
		if analyzeErr != nil {
			fmt.Printf("Error: %v\n", analyzeErr)
			return
		}

		out.PrintExtensionDetail(info)
	}
}

func runExtExtract(_ *cobra.Command, args []string) {
	m := loadExtManifest()
	target := args[0]

	outDir := extExtractOut
	if outDir == "" {
		outDir = output
	}

	if outDir == "" {
		base := filepath.Base(target)

		base = strings.TrimSuffix(base, filepath.Ext(base))
		if base == "" {
			base = "extension"
		}

		outDir = fmt.Sprintf("./extension_extract_%s", base)
	}

	result, err := extension.ExtractExtensionData(m, target, extBrowser, outDir, verbose)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if extJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Println("Extension extraction complete")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Target:      %s\n", result.Target)
	fmt.Printf("Source type: %s\n", result.SourceType)
	fmt.Printf("Output dir:  %s\n", result.OutputDir)
	fmt.Printf("Files dir:   %s\n", result.FilesDir)
	fmt.Printf("File count:  %d\n", result.FileCount)
	fmt.Printf("Analysis:    %s\n", result.AnalysisPath)
	fmt.Printf("Report:      %s\n", result.ReportPath)

	if result.Analysis != nil {
		fmt.Printf("Risk:        %s (score %d)\n", result.Analysis.RiskLevel, result.Analysis.RiskScore)
		fmt.Printf("Extension:   %s (%s)\n", result.Analysis.Name, result.Analysis.Version)
	}
}

func runExtSnapshot(_ *cobra.Command, _ []string) {
	m := loadExtManifest()

	var exts []snapshot.Extension

	if snapshotID != "" {
		exts = []snapshot.Extension{{Name: snapshotID, ID: snapshotID}}
	} else {
		var err error
		exts, err = snapshot.LoadCSV(snapshotCSV)
		if err != nil {
			fmt.Printf("Error loading CSV: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Loaded %d extension(s)\n", len(exts))

	// Step 1: Download
	fmt.Println("=== Step 1/4: Downloading extensions ===")
	if err := snapshot.DownloadExtensions(exts, snapshotTarget); err != nil {
		fmt.Printf("Download error: %v\n", err)
		os.Exit(1)
	}

	// Step 2: Extract URLs
	fmt.Println("=== Step 2/4: Extracting URLs from source code ===")
	for i, ext := range exts {
		fmt.Printf("[%d/%d] Extracting %s\n", i+1, len(exts), ext.Name)

		extSrcDir := filepath.Join(snapshotTarget, ext.ID, "ext")
		extracted, err := snapshot.ExtractURLsFromExtension(ext.ID, extSrcDir)
		if err != nil {
			fmt.Printf("[%s] ERROR extracting: %v\n", ext.Name, err)
			continue
		}
		if len(extracted.URLs) == 0 {
			fmt.Printf("[%s] No URLs found\n", ext.Name)
			continue
		}

		dbPath := filepath.Join(snapshotTarget, ext.ID, "db", ext.ID+".db")
		db, err := snapshot.OpenDB(dbPath)
		if err != nil {
			fmt.Printf("[%s] ERROR opening db: %v\n", ext.Name, err)
			continue
		}
		if err := db.SaveSourceURLs(extracted.URLs); err != nil {
			fmt.Printf("[%s] ERROR saving URLs: %v\n", ext.Name, err)
		} else {
			fmt.Printf("[%s] Saved %d URLs\n", ext.Name, len(extracted.URLs))
		}
		_ = db.Close()
	}

	// Step 3: Scan stores
	fmt.Println("=== Step 3/4: Scanning stores with extensions ===")
	for i, ext := range exts {
		fmt.Printf("[%d/%d] Scanning %s\n", i+1, len(exts), ext.Name)
		if err := snapshot.CrawlExtension(ext, snapshotTarget, snapshot.DefaultStores); err != nil {
			fmt.Printf("[%s] ERROR: %v\n", ext.Name, err)
		}
	}

	// Step 4: Analyze
	fmt.Println("=== Step 4/4: Analyzing extensions ===")
	for i, ext := range exts {
		fmt.Printf("[%d/%d] Analyzing %s\n", i+1, len(exts), ext.Name)

		dbPath := filepath.Join(snapshotTarget, ext.ID, "db", ext.ID+".db")
		db, err := snapshot.OpenDB(dbPath)
		if err != nil {
			fmt.Printf("[%s] ERROR opening db: %v\n", ext.Name, err)
			continue
		}
		sourceURLs, err := db.GetSourceURLs(ext.ID)
		if err != nil {
			fmt.Printf("[%s] ERROR loading source URLs: %v\n", ext.Name, err)
			_ = db.Close()
			continue
		}
		_ = db.Close()

		if len(sourceURLs) == 0 {
			fmt.Printf("[%s] No source URLs, skipping analysis\n", ext.Name)
			continue
		}

		extracted := &snapshot.ExtractedURLs{
			ExtensionID: ext.ID,
			URLs:        sourceURLs,
		}
		if err := snapshot.AnalyzeExtension(ext, snapshotTarget, extracted); err != nil {
			fmt.Printf("[%s] ERROR: %v\n", ext.Name, err)
		}
	}

	// Step 5: Run unravel analysis
	fmt.Println("=== Running unravel analysis ===")
	for i, ext := range exts {
		fmt.Printf("[%d/%d] Unravel analysis: %s\n", i+1, len(exts), ext.Name)

		extDir := filepath.Join(snapshotTarget, ext.ID, "ext")
		outDir := filepath.Join(snapshotTarget, ext.ID)

		result, err := extension.ExtractExtensionData(m, extDir, extBrowser, outDir, verbose)
		if err != nil {
			fmt.Printf("[%s] Unravel error: %v\n", ext.Name, err)
			continue
		}

		if extJSONFormat {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("[%s] Risk: %s (score %d)\n", ext.Name, result.Analysis.RiskLevel, result.Analysis.RiskScore)
		}
	}

	fmt.Println("=== Pipeline complete ===")
}
