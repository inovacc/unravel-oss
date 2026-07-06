/*
Copyright © 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/garble"

	"github.com/spf13/cobra"
)

var (
	garbleJSONFormat bool
	garbleMinLen     int
	garbleOutputDir  string
)

var garbleCmd = &cobra.Command{
	Use:   "garble",
	Short: "Go binary obfuscation analysis (garble detection)",
	Long: `Detect and analyze garble obfuscation in Go binaries.

Analyzes Go binaries for signs of mvdan.cc/garble obfuscation using
weighted heuristics including build info, DWARF, symbol hashing, and more.

Subcommands:
  detect    - Detect garble obfuscation with confidence scoring
  info      - Extract Go binary metadata (version, build info, linkage)
  strings   - Extract and categorize strings with entropy analysis
  symbols   - Analyze symbol table for obfuscated names
  scan      - Batch scan directory for garbled Go binaries`,
}

var garbleDetectCmd = &cobra.Command{
	Use:   "detect <binary>",
	Short: "Detect garble obfuscation with confidence scoring",
	Long:  `Run weighted heuristics to detect if a Go binary was built with garble.`,
	Args:  cobra.ExactArgs(1),
	Run:   runGarbleDetect,
}

var garbleInfoCmd = &cobra.Command{
	Use:   "info <binary>",
	Short: "Extract Go binary metadata",
	Long:  `Extract Go version, build settings, linkage, and section information from a binary.`,
	Args:  cobra.ExactArgs(1),
	Run:   runGarbleInfo,
}

var garbleStringsCmd = &cobra.Command{
	Use:   "strings <binary>",
	Short: "Extract and categorize strings with entropy analysis",
	Long:  `Scan a binary for printable strings, compute Shannon entropy, and categorize them.`,
	Args:  cobra.ExactArgs(1),
	Run:   runGarbleStrings,
}

var garbleSymbolsCmd = &cobra.Command{
	Use:   "symbols <binary>",
	Short: "Analyze symbol table for obfuscated names",
	Long:  `Parse the symbol table and detect obfuscated (garble-hashed) symbol names.`,
	Args:  cobra.ExactArgs(1),
	Run:   runGarbleSymbols,
}

var garbleScanCmd = &cobra.Command{
	Use:   "scan <directory>",
	Short: "Batch scan directory for garbled Go binaries",
	Long: `Recursively scan a directory for Go binaries and run garble detection
on each one. Reports a summary table of results.`,
	Args: cobra.ExactArgs(1),
	Run:  runGarbleScan,
}

func init() {
	rootCmd.AddCommand(garbleCmd)
	garbleCmd.AddCommand(garbleDetectCmd)
	garbleCmd.AddCommand(garbleInfoCmd)
	garbleCmd.AddCommand(garbleStringsCmd)
	garbleCmd.AddCommand(garbleSymbolsCmd)
	garbleCmd.AddCommand(garbleScanCmd)

	garbleCmd.PersistentFlags().BoolVar(&garbleJSONFormat, "json", false, "Output as JSON")

	garbleStringsCmd.Flags().IntVar(&garbleMinLen, "min-len", 4, "Minimum string length to extract")

	garbleScanCmd.Flags().StringVarP(&garbleOutputDir, "output", "o", "", "Output report path (optional)")
	garbleDetectCmd.Flags().StringVarP(&garbleOutputDir, "output", "o", "", "Output report path (optional)")
}

func runGarbleDetect(_ *cobra.Command, args []string) {
	result, err := garble.Detect(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if garbleJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		out.PrintGarbleDetect(result)
	}

	// Generate report if output specified
	if garbleOutputDir != "" {
		reportPath := garbleOutputDir
		if !strings.HasSuffix(reportPath, ".md") {
			reportPath = reportPath + "/GARBLE_DETECT.md"
		}

		if err := garble.GenerateDetectReport(result, reportPath); err != nil {
			fmt.Printf("Error writing report: %v\n", err)
		} else {
			fmt.Printf("\nReport written to %s\n", reportPath)
		}
	}
}

func runGarbleInfo(_ *cobra.Command, args []string) {
	info, err := garble.ExtractInfo(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if garbleJSONFormat {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintGarbleInfo(info, verbose)
}

func runGarbleStrings(_ *cobra.Command, args []string) {
	result, err := garble.ExtractStrings(args[0], garbleMinLen)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if garbleJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintGarbleStrings(result, verbose)
}

func runGarbleSymbols(_ *cobra.Command, args []string) {
	result, err := garble.AnalyzeSymbols(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if garbleJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintGarbleSymbols(result, verbose)
}

func runGarbleScan(_ *cobra.Command, args []string) {
	fmt.Printf("Scanning directory: %s\n\n", args[0])

	result, err := garble.ScanDirectory(args[0], verbose)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if garbleJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	if len(result.Results) == 0 {
		fmt.Println("No Go binaries found.")
		return
	}

	// Summary
	fmt.Printf("Found %d Go binaries out of %d files — %d garbled\n\n",
		result.GoBinaryCount, result.TotalFiles, result.GarbledCount)

	// Table
	fmt.Printf("%-35s %-8s %-10s %-12s %-10s\n", "BINARY", "FORMAT", "GARBLED", "CONFIDENCE", "LABEL")
	fmt.Println(strings.Repeat("-", 77))

	for _, r := range result.Results {
		name := r.FileName
		if len(name) > 35 {
			name = name[:32] + "..."
		}

		garbled := "No"
		if r.IsGarbled {
			garbled = "YES"
		}

		fmt.Printf("%-35s %-8s %-10s %-12s %-10s\n",
			name, r.Format, garbled,
			fmt.Sprintf("%.1f%%", r.Confidence*100),
			r.ConfidenceLabel)
	}

	// Generate report if output specified
	if garbleOutputDir != "" {
		reportPath := garbleOutputDir
		if !strings.HasSuffix(reportPath, ".md") {
			reportPath = reportPath + "/GARBLE_SCAN.md"
		}

		if err := garble.GenerateScanReport(result, reportPath); err != nil {
			fmt.Printf("\nError writing report: %v\n", err)
		} else {
			fmt.Printf("\nReport written to %s\n", reportPath)
		}
	}
}
