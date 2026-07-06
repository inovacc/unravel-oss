/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/nodeaddon"

	"github.com/spf13/cobra"
)

var (
	nodeaddonJSONFormat bool
	nodeaddonMinLen     int
)

var nodeaddonCmd = &cobra.Command{
	Use:   "nodeaddon",
	Short: "Node.js native addon (.node) reverse engineering",
	Long: `Analyze Node.js native addon (.node) files for security research.

Native addons are PE/ELF/Mach-O shared libraries that export N-API functions.
This command extracts metadata, symbols, imports, and risk indicators.

Subcommands:
  info      - Full analysis with N-API detection and risk scoring
  symbols   - Export symbol table with N-API annotation
  strings   - Extract strings with entropy analysis
  imports   - Import analysis with risk classification`,
}

var nodeaddonInfoCmd = &cobra.Command{
	Use:   "info <file>",
	Short: "Analyze Node.js native addon metadata",
	Long:  `Full analysis: format, architecture, N-API detection, exports, imports, risk scoring, binding context.`,
	Args:  cobra.ExactArgs(1),
	Run:   runNodeaddonInfo,
}

var nodeaddonSymbolsCmd = &cobra.Command{
	Use:   "symbols <file>",
	Short: "Extract exported symbols with N-API annotation",
	Long:  `Parse the symbol table and annotate N-API registration functions.`,
	Args:  cobra.ExactArgs(1),
	Run:   runNodeaddonSymbols,
}

var nodeaddonStringsCmd = &cobra.Command{
	Use:   "strings <file>",
	Short: "Extract strings with entropy analysis",
	Long:  `Scan the binary for printable strings, compute Shannon entropy, and categorize them.`,
	Args:  cobra.ExactArgs(1),
	Run:   runNodeaddonStrings,
}

var nodeaddonImportsCmd = &cobra.Command{
	Use:   "imports <file>",
	Short: "Analyze imported libraries with risk classification",
	Long:  `Extract dynamically linked libraries and classify them by function (crypto, network, process, etc).`,
	Args:  cobra.ExactArgs(1),
	Run:   runNodeaddonImports,
}

func init() {
	rootCmd.AddCommand(nodeaddonCmd)
	nodeaddonCmd.AddCommand(nodeaddonInfoCmd)
	nodeaddonCmd.AddCommand(nodeaddonSymbolsCmd)
	nodeaddonCmd.AddCommand(nodeaddonStringsCmd)
	nodeaddonCmd.AddCommand(nodeaddonImportsCmd)

	nodeaddonCmd.PersistentFlags().BoolVar(&nodeaddonJSONFormat, "json", false, "Output as JSON")
	nodeaddonStringsCmd.Flags().IntVar(&nodeaddonMinLen, "min-len", 6, "Minimum string length")
}

func runNodeaddonInfo(_ *cobra.Command, args []string) {
	result, err := nodeaddon.Analyze(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if nodeaddonJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	out.PrintNodeAddonInfo(result)
}

func runNodeaddonSymbols(_ *cobra.Command, args []string) {
	result, err := nodeaddon.Symbols(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if nodeaddonJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	out.PrintNodeAddonSymbols(result)
}

func runNodeaddonStrings(_ *cobra.Command, args []string) {
	result, err := nodeaddon.Strings(args[0], nodeaddonMinLen)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if nodeaddonJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	out.PrintNodeAddonStrings(result)
}

func runNodeaddonImports(_ *cobra.Command, args []string) {
	result, err := nodeaddon.Imports(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if nodeaddonJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Node Addon Imports: %s\n", args[0])
	fmt.Printf("  Libraries:    %d\n", len(result.Imports))
	fmt.Printf("  Risk Score:   %d/100\n", result.RiskScore)
	fmt.Println()

	for _, imp := range result.Imports {
		fmt.Printf("  %-30s  [%s]\n", imp.Library, imp.Category)
		for _, fn := range imp.Functions {
			fmt.Printf("    %s\n", fn)
		}
	}

	if len(result.RiskFactors) > 0 {
		fmt.Println("\nRisk Factors:")
		for _, rf := range result.RiskFactors {
			fmt.Printf("  [%-8s] %-30s %s\n", rf.Severity, rf.Name, rf.Description)
		}
	}
}
