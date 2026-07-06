/*
Copyright © 2026 Security Research
*/
package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/tpm"

	"github.com/spf13/cobra"
)

var tpmCmd = &cobra.Command{
	Use:   "tpm",
	Short: "TPM key extraction",
	Long: `Extract keys from Trusted Platform Module (TPM).

Uses sealbox for TPM operations. Supports scan, unseal, and seal commands.`,
}

var tpmInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show TPM availability and system info",
	Run: func(cmd *cobra.Command, args []string) {
		info := tpm.CheckTPM()

		if jsonFormat {
			data, _ := json.MarshalIndent(info, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("Platform: %s\n", info.Platform)
		fmt.Printf("TPM Available: %v\n", info.Available)
		if info.Error != "" {
			fmt.Printf("Error: %s\n", info.Error)
		}
	},
}

var tpmExtractCmd = &cobra.Command{
	Use:   "extract <search_path>",
	Short: "Scan for sealed blobs and extract keys",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		searchPath := args[0]
		outDir := output
		if outDir == "" {
			outDir = "tpm_results"
		}

		fmt.Printf("Scanning: %s\n", searchPath)
		fmt.Printf("Output: %s\n\n", outDir)

		result, err := tpm.ScanAndExtract(searchPath, outDir)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if jsonFormat {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("TPM Available: %v\n", result.TPMInfo.Available)
		fmt.Printf("Sealed blobs found: %d\n", len(result.SealedKeys))
		fmt.Printf("Keys extracted: %d\n", result.ExtractedKeys)

		if outDir != "" {
			resultPath := filepath.Join(outDir, "extraction_results.json")
			fmt.Printf("\nReport: %s\n", resultPath)
		}
	},
}

var tpmUnsealCmd = &cobra.Command{
	Use:   "unseal <blob_path>",
	Short: "Unseal a specific sealed blob",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		blobPath := args[0]

		fmt.Printf("Unsealing: %s\n\n", blobPath)

		key, err := tpm.UnsealKey(blobPath)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully unsealed %d-byte key\n", len(key))
		fmt.Printf("Key (hex): %s\n", hex.EncodeToString(key))
	},
}

var tpmSealCmd = &cobra.Command{
	Use:   "seal <output_path>",
	Short: "Create and seal a new key (for testing)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		outputPath := args[0]

		fmt.Printf("Sealing new key to: %s\n\n", outputPath)

		key, err := tpm.SealKey(outputPath)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Sealed key saved to: %s\n", outputPath)
		fmt.Printf("Key length: %d bytes\n", len(key))
		fmt.Printf("Key (hex): %s\n", hex.EncodeToString(key))
	},
}

func init() {
	rootCmd.AddCommand(tpmCmd)
	tpmCmd.AddCommand(tpmInfoCmd)
	tpmCmd.AddCommand(tpmExtractCmd)
	tpmCmd.AddCommand(tpmUnsealCmd)
	tpmCmd.AddCommand(tpmSealCmd)

	tpmInfoCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
	tpmExtractCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}
