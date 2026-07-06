/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/msm"

	"github.com/spf13/cobra"
)

var msmJSONFormat bool

var msmCmd = &cobra.Command{
	Use:   "msm",
	Short: "Merge Module (.msm) analysis",
	Long: `Parse and analyze Windows Installer Merge Modules (.msm).

A merge module is an OLE Compound Document (CFBF) container holding an MSI
relational database — the same format as an .msi — identified by a
ModuleSignature table. Merge modules are merged into a parent .msi at build
time and frequently bundle kernel drivers (OpenVPN DCO, WireGuard, etc.).

Subcommands:
  info    - Display module metadata, components, files, and driver payloads`,
}

var msmInfoCmd = &cobra.Command{
	Use:   "info <file>",
	Short: "Display Merge Module metadata, components, and driver files",
	Args:  cobra.ExactArgs(1),
	Run:   runMsmInfo,
}

func init() {
	rootCmd.AddCommand(msmCmd)
	msmCmd.AddCommand(msmInfoCmd)

	msmCmd.PersistentFlags().BoolVar(&msmJSONFormat, "json", false, "Output as JSON")
}

func runMsmInfo(_ *cobra.Command, args []string) {
	info, err := msm.Info(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if msmJSONFormat {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintMsmInfo(info)
}
