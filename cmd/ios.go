/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/inovacc/unravel-oss/pkg/ios"

	"github.com/spf13/cobra"
)

var iosJSONFormat bool

var iosCmd = &cobra.Command{
	Use:   "ios",
	Short: "iOS IPA package analysis and extraction",
	Long: `Parse, extract, and analyze iOS application archives (.ipa).

IPA files are ZIP archives containing a Payload directory with a .app bundle.
This command extracts metadata from Info.plist including bundle ID, version,
permissions, frameworks, URL schemes, and signing information.

Subcommands:
  info      - Display app metadata, permissions, frameworks, and signing info
  extract   - Extract IPA contents to disk`,
}

var iosInfoCmd = &cobra.Command{
	Use:   "info <file>",
	Short: "Display iOS app metadata",
	Args:  cobra.ExactArgs(1),
	Run:   runIOSInfo,
}

var iosExtractCmd = &cobra.Command{
	Use:   "extract <file>",
	Short: "Extract IPA contents to disk",
	Args:  cobra.ExactArgs(1),
	Run:   runIOSExtract,
}

func init() {
	rootCmd.AddCommand(iosCmd)
	iosCmd.AddCommand(iosInfoCmd)
	iosCmd.AddCommand(iosExtractCmd)

	iosCmd.PersistentFlags().BoolVar(&iosJSONFormat, "json", false, "Output as JSON")
}

func runIOSInfo(_ *cobra.Command, args []string) {
	info, err := ios.Info(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if iosJSONFormat {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("iOS Application: %s\n", info.Path)
	fmt.Printf("  Bundle ID:     %s\n", info.BundleID)
	fmt.Printf("  Bundle Name:   %s\n", info.BundleName)
	fmt.Printf("  Version:       %s (build %s)\n", info.Version, info.BuildVersion)
	fmt.Printf("  Minimum OS:    %s\n", info.MinimumOS)
	fmt.Printf("  Platform:      %s\n", info.Platform)
	fmt.Printf("  Executable:    %s\n", info.Executable)
	fmt.Printf("  Files:         %d\n", info.FileCount)
	fmt.Printf("  Total Size:    %d bytes\n", info.TotalSize)

	if len(info.DeviceFamily) > 0 {
		fmt.Printf("  Device Family: %v\n", info.DeviceFamily)
	}

	if len(info.Frameworks) > 0 {
		fmt.Printf("  Frameworks (%d):\n", len(info.Frameworks))
		for _, fw := range info.Frameworks {
			fmt.Printf("    - %s\n", fw)
		}
	}

	if len(info.URLSchemes) > 0 {
		fmt.Printf("  URL Schemes:\n")
		for _, s := range info.URLSchemes {
			fmt.Printf("    - %s\n", s)
		}
	}

	if len(info.Permissions) > 0 {
		fmt.Printf("  Permissions (%d):\n", len(info.Permissions))
		for _, p := range info.Permissions {
			fmt.Printf("    - %s: %s\n", p.Key, p.Description)
			if p.Usage != "" {
				fmt.Printf("      Usage: %s\n", p.Usage)
			}
		}
	}

	if info.SigningInfo != nil {
		fmt.Printf("  Code Signature: %v\n", info.SigningInfo.HasCodeSignature)
		if info.SigningInfo.TeamID != "" {
			fmt.Printf("  Team ID:        %s\n", info.SigningInfo.TeamID)
		}
	}

	fmt.Printf("  Provisioning:  %v\n", info.HasProvisioning)
}

func runIOSExtract(_ *cobra.Command, args []string) {
	outDir := output
	if outDir == "" {
		outDir = "ipa_extracted"
	}

	result, err := ios.Extract(args[0], outDir)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if iosJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("Extraction Complete\n")
	fmt.Printf("  Output:     %s\n", result.OutputDir)
	fmt.Printf("  Files:      %d\n", result.Files)
	fmt.Printf("  Total Size: %d bytes\n", result.TotalSize)
	fmt.Printf("  App Bundle: %s\n", result.AppBundle)

	if result.Executable != "" {
		fmt.Printf("  Executable: %s\n", result.Executable)
	}
}
