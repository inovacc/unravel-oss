/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/winui"
	_ "github.com/inovacc/unravel-oss/pkg/winui/runtime" // wire AnalyzeImpl

	"github.com/spf13/cobra"
)

var (
	winuiJSON      bool
	winuiOutputDir string
)

var winuiCmd = &cobra.Command{
	Use:   "winui",
	Short: "WinUI 3 application analysis",
	Long: `Analyze WinUI 3 desktop applications: detection (deps.json + PE imports +
Microsoft.UI.Xaml.dll), XAML extraction (raw .xaml + .xbf decode + PE-embedded),
and resources.pri parsing.

Subcommands:
  detect       - Fast detection (deps.json + PE imports)
  analyze      - Full pipeline (detect + XAML walk + XBF + PRI)
  xaml         - XAML extraction only
  capabilities - Framework dependency surface (use 'uwp capabilities' for capability scoring)`,
}

var winuiDetectCmd = &cobra.Command{
	Use:   "detect <path>",
	Short: "Fast WinUI 3 detection (deps.json + PE imports)",
	Args:  cobra.ExactArgs(1),
	Run:   runWinUIDetect,
}

var winuiAnalyzeCmd = &cobra.Command{
	Use:   "analyze <path>",
	Short: "Full WinUI 3 analysis (detect + XAML + XBF + PRI + PE-embedded)",
	Args:  cobra.ExactArgs(1),
	Run:   runWinUIAnalyze,
}

var winuiXAMLCmd = &cobra.Command{
	Use:   "xaml <path>",
	Short: "XAML extraction only (raw + XBF + PE-embedded)",
	Args:  cobra.ExactArgs(1),
	Run:   runWinUIXAML,
}

var winuiCapabilitiesCmd = &cobra.Command{
	Use:   "capabilities <path>",
	Short: "Framework dependency surface (deps-derived)",
	Args:  cobra.ExactArgs(1),
	Run:   runWinUICapabilities,
}

func init() {
	winuiCmd.AddCommand(winuiDetectCmd)
	winuiCmd.AddCommand(winuiAnalyzeCmd)
	winuiCmd.AddCommand(winuiXAMLCmd)
	winuiCmd.AddCommand(winuiCapabilitiesCmd)

	winuiCmd.PersistentFlags().BoolVar(&winuiJSON, "json", false, "Output as JSON")
	winuiAnalyzeCmd.Flags().StringVar(&winuiOutputDir, "output", "", "Optional directory for decoded XAML output (sanitized against path traversal)")
	winuiXAMLCmd.Flags().StringVar(&winuiOutputDir, "output", "", "Optional directory for decoded XAML output (sanitized against path traversal)")
}

// sanitizeFrameworkPath cleans + rejects path-traversal segments at every CLI/MCP
// boundary (T-04-01).
func sanitizeFrameworkPath(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	cleaned := filepath.Clean(p)
	for _, seg := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path contains '..' segment: %q", p)
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	return abs, nil
}

// sanitizeOutputDir is identical to sanitizeFrameworkPath but tolerates a
// non-existent target (the directory is created lazily by the orchestrator).
func sanitizeOutputDir(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	return sanitizeFrameworkPath(p)
}

func emitJSONOrExit(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func runWinUIDetect(_ *cobra.Command, args []string) {
	abs, err := sanitizeFrameworkPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	res, err := winui.Analyze(abs, winui.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if winuiJSON {
		emitJSONOrExit(res)
		return
	}
	out.DisplayWinUIDetectResult(res)
}

func runWinUIAnalyze(_ *cobra.Command, args []string) {
	abs, err := sanitizeFrameworkPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	outDir, err := sanitizeOutputDir(winuiOutputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	opts := winui.Options{
		DecodeXBF:      true,
		ScanPEEmbedded: true,
		ParsePRI:       true,
		WriteXAMLDir:   outDir,
		RejectSymlinks: true,
	}

	res, err := winui.Analyze(abs, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if winuiJSON {
		emitJSONOrExit(res)
		return
	}
	out.DisplayWinUIAnalyzeResult(res)
}

func runWinUIXAML(_ *cobra.Command, args []string) {
	abs, err := sanitizeFrameworkPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	outDir, err := sanitizeOutputDir(winuiOutputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	opts := winui.Options{
		DecodeXBF:      true,
		ScanPEEmbedded: true,
		ParsePRI:       false,
		WriteXAMLDir:   outDir,
		RejectSymlinks: true,
	}

	res, err := winui.Analyze(abs, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if winuiJSON {
		emitJSONOrExit(res.XAMLIndex)
		return
	}
	out.DisplayWinUIXAMLIndex(res.XAMLIndex)
}

func runWinUICapabilities(_ *cobra.Command, args []string) {
	abs, err := sanitizeFrameworkPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	res, err := winui.Analyze(abs, winui.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if winuiJSON {
		emitJSONOrExit(res.Frameworks)
		return
	}
	fmt.Printf("Frameworks (%d):\n", len(res.Frameworks))
	for _, fi := range res.Frameworks {
		ver := fi.Version
		if ver == "" {
			ver = "-"
		}
		fmt.Printf("  %-20s ver=%-12s conf=%-9s src=%s\n",
			fi.Name, ver, fi.Confidence, fi.Source)
	}
}
