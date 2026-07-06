/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"fmt"
	"os"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/uwp"
	_ "github.com/inovacc/unravel-oss/pkg/uwp/runtime" // wire AnalyzeImpl

	"github.com/spf13/cobra"
)

var (
	uwpJSON       bool
	uwpRubricPath string
)

var uwpCmd = &cobra.Command{
	Use:   "uwp",
	Short: "UWP (MSIX/AppX) application analysis",
	Long: `Analyze UWP packaged applications: AppxManifest.xml extraction, capability
enumeration with security scoring, optional XAML extraction, and DPAPI blob
provenance flagging (D-18: never decrypted in-pipeline).

Subcommands:
  detect       - Fast UWP detection (manifest namespace peek)
  analyze      - Full pipeline (manifest + capabilities + score + XAML)
  xaml         - XAML extraction only
  capabilities - Capability enumeration + categorical+numeric scoring`,
}

var uwpDetectCmd = &cobra.Command{
	Use:   "detect <path>",
	Short: "Fast UWP detection (AppxManifest.xml peek)",
	Args:  cobra.ExactArgs(1),
	Run:   runUWPDetect,
}

var uwpAnalyzeCmd = &cobra.Command{
	Use:   "analyze <path>",
	Short: "Full UWP analysis (manifest + capabilities + score + XAML)",
	Args:  cobra.ExactArgs(1),
	Run:   runUWPAnalyze,
}

var uwpXAMLCmd = &cobra.Command{
	Use:   "xaml <path>",
	Short: "XAML extraction only (raw + XBF + PE-embedded)",
	Args:  cobra.ExactArgs(1),
	Run:   runUWPXAML,
}

var uwpCapabilitiesCmd = &cobra.Command{
	Use:   "capabilities <path>",
	Short: "Capability enumeration + scoring (rubric-driven)",
	Args:  cobra.ExactArgs(1),
	Run:   runUWPCapabilities,
}

func init() {
	uwpCmd.AddCommand(uwpDetectCmd)
	uwpCmd.AddCommand(uwpAnalyzeCmd)
	uwpCmd.AddCommand(uwpXAMLCmd)
	uwpCmd.AddCommand(uwpCapabilitiesCmd)

	uwpCmd.PersistentFlags().BoolVar(&uwpJSON, "json", false, "Output as JSON")
	uwpAnalyzeCmd.Flags().StringVar(&uwpRubricPath, "rubric", "", "Override capabilities rubric YAML path (sanitized)")
	uwpCapabilitiesCmd.Flags().StringVar(&uwpRubricPath, "rubric", "", "Override capabilities rubric YAML path (sanitized)")
}

func runUWPDetect(_ *cobra.Command, args []string) {
	abs, err := sanitizeFrameworkPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	res, err := uwp.Analyze(abs, uwp.Options{ExtractIfArchive: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if uwpJSON {
		emitJSONOrExit(res)
		return
	}
	out.DisplayUWPDetectResult(res)
}

func runUWPAnalyze(_ *cobra.Command, args []string) {
	abs, err := sanitizeFrameworkPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	rubric, err := sanitizeFrameworkPath(uwpRubricPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	opts := uwp.Options{
		ExtractIfArchive:  true,
		ScoreCapabilities: true,
		AnalyzeXAML:       true,
		DPAPIFlagOnly:     true,
		RubricPath:        rubric,
		RejectSymlinks:    true,
	}

	res, err := uwp.Analyze(abs, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if uwpJSON {
		emitJSONOrExit(res)
		return
	}
	out.DisplayUWPAnalyzeResult(res)
}

func runUWPXAML(_ *cobra.Command, args []string) {
	abs, err := sanitizeFrameworkPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	opts := uwp.Options{
		ExtractIfArchive: true,
		AnalyzeXAML:      true,
		RejectSymlinks:   true,
	}

	res, err := uwp.Analyze(abs, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if uwpJSON {
		emitJSONOrExit(res.XAMLIndex)
		return
	}
	if res.XAMLIndex == nil {
		fmt.Println("XAML Index: (empty)")
		return
	}
	fmt.Printf("XAML Index (%d entries):\n", len(res.XAMLIndex.Entries))
	for _, e := range res.XAMLIndex.Entries {
		fmt.Printf("  [%-16s] %s\n", e.Kind, e.Path)
	}
}

func runUWPCapabilities(_ *cobra.Command, args []string) {
	abs, err := sanitizeFrameworkPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	rubric, err := sanitizeFrameworkPath(uwpRubricPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	opts := uwp.Options{
		ExtractIfArchive:  true,
		ScoreCapabilities: true,
		RubricPath:        rubric,
		RejectSymlinks:    true,
	}

	res, err := uwp.Analyze(abs, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if uwpJSON {
		payload := struct {
			Capabilities any `json:"capabilities"`
			Score        any `json:"score"`
		}{nil, res.Score}
		if res.Manifest != nil {
			payload.Capabilities = res.Manifest.Capabilities
		}
		emitJSONOrExit(payload)
		return
	}
	out.DisplayUWPCapabilities(res)
	out.DisplayUWPScore(res.Score)
}
