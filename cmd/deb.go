/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/deb"

	"github.com/spf13/cobra"
)

var debJSONFormat bool

var debCmd = &cobra.Command{
	Use:   "deb",
	Short: "Debian package analysis and extraction",
	Long: `Parse, extract, and analyze Debian .deb packages.

DEB files are ar(1) archives containing:
  debian-binary     - format version (2.0)
  control.tar.*     - package metadata and scripts
  data.tar.*        - installable files

Subcommands:
  info      - Display package metadata and structure
  extract   - Extract package contents to disk
  verify    - Check for package signatures`,
}

var debInfoCmd = &cobra.Command{
	Use:   "info <file>",
	Short: "Display package metadata and structure",
	Args:  cobra.ExactArgs(1),
	Run:   runDebInfo,
}

var debExtractCmd = &cobra.Command{
	Use:   "extract <file>",
	Short: "Extract package contents to disk",
	Args:  cobra.ExactArgs(1),
	Run:   runDebExtract,
}

var debVerifyCmd = &cobra.Command{
	Use:   "verify <file>",
	Short: "Check for package signatures",
	Args:  cobra.ExactArgs(1),
	Run:   runDebVerify,
}

func init() {
	rootCmd.AddCommand(debCmd)
	debCmd.AddCommand(debInfoCmd)
	debCmd.AddCommand(debExtractCmd)
	debCmd.AddCommand(debVerifyCmd)

	debCmd.PersistentFlags().BoolVar(&debJSONFormat, "json", false, "Output as JSON")
}

func runDebInfo(_ *cobra.Command, args []string) {
	info, err := deb.Info(args[0], verbose)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if debJSONFormat {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintDebInfo(info)
}

func runDebExtract(_ *cobra.Command, args []string) {
	report, err := deb.Extract(args[0], output)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if debJSONFormat {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintDebExtract(report)
}

func runDebVerify(_ *cobra.Command, args []string) {
	result, err := deb.Verify(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if debJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintDebVerify(result)
}
