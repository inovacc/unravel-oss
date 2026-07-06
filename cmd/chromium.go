/*
Copyright © 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/chromium"

	"github.com/spf13/cobra"
)

var chromiumCmd = &cobra.Command{
	Use:   "chromium",
	Short: "Extract Chromium profile data",
	Long: `Extract data from Chromium-based browser profiles.

Extracts cookies, localStorage, history, and other profile data
from Electron apps that use Chromium storage.`,
}

var chromiumExtractCmd = &cobra.Command{
	Use:   "extract <profile_path>",
	Short: "Extract all Chromium data",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		profilePath := args[0]
		outDir := output
		if outDir == "" {
			outDir = "chromium_extracted"
		}

		appName := filepath.Base(profilePath)

		fmt.Printf("Extracting Chromium data from: %s\n", profilePath)
		fmt.Printf("Output: %s\n\n", outDir)

		result, err := chromium.Extract(chromium.ExtractorConfig{
			SourcePath: profilePath,
			OutputPath: outDir,
			AppName:    appName,
		})
		if err != nil {
			return fmt.Errorf("extraction failed: %w", err)
		}

		fmt.Printf("Extracted %d files (%d bytes)\n", result.FileCount, result.TotalSize)
		fmt.Printf("Databases found: %d\n", len(result.Databases))
		fmt.Printf("Cookies found: %d\n", len(result.Cookies))

		if jsonFormat {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal result: %w", err)
			}
			_, _ = fmt.Fprintln(os.Stdout, string(data))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(chromiumCmd)
	chromiumCmd.AddCommand(chromiumExtractCmd)
}
