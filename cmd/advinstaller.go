/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/inovacc/unravel-oss/pkg/advinstaller"

	"github.com/spf13/cobra"
)

var advinstallerJSONFormat bool

var advinstallerCmd = &cobra.Command{
	Use:   "advinstaller",
	Short: "Advanced Installer bootstrapper analysis and extraction",
	Long: `Analyze and extract Advanced Installer bootstrapper executables.

Advanced Installer bootstrappers are PE executables that wrap an embedded
MSI or CAB payload. This command detects bootstrapper markers and extracts
the embedded installer for further analysis.

Subcommands:
  info    - Analyze bootstrapper: detect markers, locate embedded MSI
  extract - Extract embedded MSI/CAB payload to disk`,
}

var advinstallerInfoCmd = &cobra.Command{
	Use:   "info <file>",
	Short: "Analyze Advanced Installer bootstrapper",
	Args:  cobra.ExactArgs(1),
	Run:   runAdvinstallerInfo,
}

var advinstallerExtractCmd = &cobra.Command{
	Use:   "extract <file>",
	Short: "Extract embedded MSI/CAB payload",
	Args:  cobra.ExactArgs(1),
	Run:   runAdvinstallerExtract,
}

func init() {
	rootCmd.AddCommand(advinstallerCmd)
	advinstallerCmd.AddCommand(advinstallerInfoCmd)
	advinstallerCmd.AddCommand(advinstallerExtractCmd)

	advinstallerCmd.PersistentFlags().BoolVar(&advinstallerJSONFormat, "json", false, "Output as JSON")
}

func runAdvinstallerInfo(_ *cobra.Command, args []string) {
	info, err := advinstaller.Info(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if advinstallerJSONFormat {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("File: %s\n", info.Path)
	fmt.Printf("Size: %d bytes\n", info.Size)
	fmt.Printf("Advanced Installer: %v\n", info.IsAdvInstaller)

	if len(info.Markers) > 0 {
		fmt.Println("\nMarkers found:")
		for _, m := range info.Markers {
			fmt.Printf("  - %s\n", m)
		}
	}

	fmt.Printf("\nEmbedded MSI: %v\n", info.HasEmbeddedMSI)
	if info.HasEmbeddedMSI {
		fmt.Printf("  Offset: 0x%X (%d)\n", info.MSIOffset, info.MSIOffset)
		fmt.Printf("  Size:   %d bytes\n", info.MSISize)
	}
}

func runAdvinstallerExtract(_ *cobra.Command, args []string) {
	outDir := output
	if outDir == "" {
		outDir = "advinstaller_extracted"
	}

	result, err := advinstaller.ExtractMSI(args[0], outDir)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if advinstallerJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Source:  %s\n", result.BootstrapperPath)
	if result.MSIPath != "" {
		fmt.Printf("Output:  %s\n", result.MSIPath)
		fmt.Printf("Size:    %d bytes\n", result.MSISize)
		fmt.Printf("Method:  %s\n", result.Method)
	}
	if result.Error != "" {
		fmt.Printf("Error:   %s\n", result.Error)
	}
}
