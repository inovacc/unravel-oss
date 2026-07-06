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
	"github.com/inovacc/unravel-oss/pkg/asar"

	"github.com/spf13/cobra"
)

var asarCmd = &cobra.Command{
	Use:   "asar",
	Short: "ASAR archive operations",
	Long:  `Extract, list, search, and analyze Electron ASAR archives.`,
}

var asarExtractCmd = &cobra.Command{
	Use:   "extract <file.asar>",
	Short: "Extract ASAR archive",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		asarFile := args[0]
		file, header, _, dataOffset, err := asar.OpenAndParse(asarFile)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = file.Close() }()

		outDir := output
		if outDir == "" {
			base := filepath.Base(asarFile)
			outDir = strings.TrimSuffix(base, filepath.Ext(base)) + "_extracted"
		}

		report := asar.Extract(file, header, dataOffset, outDir, asarFile, verbose)
		if jsonFormat {
			jsonBytes, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(jsonBytes))
		} else {
			out.PrintASARSummary(report)
		}
	},
}

var asarListCmd = &cobra.Command{
	Use:   "list <file.asar>",
	Short: "List ASAR contents",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		asarFile := args[0]
		file, header, headerSize, _, err := asar.OpenAndParse(asarFile)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = file.Close() }()

		out.PrintASARList(header, headerSize)
	},
}

var asarSearchCmd = &cobra.Command{
	Use:   "search <file.asar> <pattern>",
	Short: "Search for pattern in ASAR",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		asarFile := args[0]
		pattern := args[1]
		file, header, _, dataOffset, err := asar.OpenAndParse(asarFile)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = file.Close() }()

		result := asar.Search(file, header, dataOffset, pattern)
		fmt.Printf("Searching for: %q\n", pattern)
		fmt.Println(strings.Repeat("-", 70))
		for _, m := range result.Matches {
			fmt.Printf("\n[MATCH] %s (%s)\n", m.FilePath, asar.FormatBytes(m.FileSize))
			for _, c := range m.Contexts {
				fmt.Printf("  Line %d: ...%s...\n", c.Line, c.Snippet)
			}
		}
		fmt.Println(strings.Repeat("-", 70))
		fmt.Printf("Found %d files containing %q\n", result.Total, pattern)
	},
}

var asarDumpCmd = &cobra.Command{
	Use:   "dump <file.asar>",
	Short: "Dump ASAR header as JSON",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		asarFile := args[0]
		file, header, _, _, err := asar.OpenAndParse(asarFile)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = file.Close() }()

		jsonBytes, _ := json.MarshalIndent(header, "", "  ")
		fmt.Println(string(jsonBytes))
	},
}

func init() {
	rootCmd.AddCommand(asarCmd)
	asarCmd.AddCommand(asarExtractCmd)
	asarCmd.AddCommand(asarListCmd)
	asarCmd.AddCommand(asarSearchCmd)
	asarCmd.AddCommand(asarDumpCmd)

	asarExtractCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}
