/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/cache"

	"github.com/spf13/cobra"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Parse HTTP cache",
	Long: `Parse Chromium HTTP cache.

Extracts cached HTTP responses from Electron apps.
Supports Simple Cache and Block File Cache formats.`,
}

var cacheParseCmd = &cobra.Command{
	Use:   "parse <cache_path>",
	Short: "Parse HTTP cache entries",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cachePath := args[0]

		fmt.Printf("Parsing cache: %s\n\n", cachePath)

		outDir := output
		result, err := cache.Parse(cachePath, outDir)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Detected format: %s\n\n", result.CacheFormat)

		if jsonFormat {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Print(cache.FormatSummary(result))

		if outDir != "" {
			resultPath := filepath.Join(outDir, "cache_results.json")
			data, _ := json.MarshalIndent(result, "", "  ")
			_ = os.WriteFile(resultPath, data, 0644)
			fmt.Printf("\nOutput: %s\n", resultPath)
		}

		fmt.Printf("\nTotal: %d entries (%d valid, %d bodies extracted, %s)\n",
			result.Stats.TotalEntries, result.Stats.ValidEntries,
			result.Stats.ExtractedBodies, cache.FormatBytes(result.Stats.TotalBodySize))
	},
}

func init() {
	rootCmd.AddCommand(cacheCmd)
	cacheCmd.AddCommand(cacheParseCmd)
	cacheParseCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}
