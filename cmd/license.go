/*
Copyright © 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/inovacc/unravel-oss/pkg/license"

	"github.com/spf13/cobra"
)

var (
	licenseKey     string
	licenseURL     string
	licenseTimeout time.Duration
	licenseAnalyze bool
)

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "License validation testing",
	Long: `Test and analyze license validation mechanisms.

Discovers how applications validate licenses and tests for bypasses.
FOR AUTHORIZED SECURITY TESTING ONLY.`,
}

var licenseTestCmd = &cobra.Command{
	Use:   "test <endpoint_url>",
	Short: "Test license validation endpoint",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetURL := args[0]

		fmt.Printf("Testing license validation: %s\n\n", targetURL)

		config := license.Config{
			TargetURL:   targetURL,
			Timeout:     licenseTimeout,
			Verbose:     verbose,
			LicenseKey:  licenseKey,
			AnalyzeOnly: licenseAnalyze,
		}

		report := license.RunTests(config)

		if jsonFormat {
			data, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(data))
			return
		}

		if output != "" {
			_ = os.MkdirAll(output, 0755)
			reportPath := filepath.Join(output, "license_test_report.json")
			data, _ := json.MarshalIndent(report, "", "  ")
			_ = os.WriteFile(reportPath, data, 0644)
			fmt.Printf("\nReport: %s\n", reportPath)
		}

		fmt.Printf("\nSummary: %d tests, %d successful, %d interesting, %d potential bypasses\n",
			report.Summary.TotalTests, report.Summary.SuccessResponses,
			report.Summary.InterestingFinds, report.Summary.BypassAttempts)
	},
}

var licenseMachineIDCmd = &cobra.Command{
	Use:   "machine-ids",
	Short: "Generate and analyze test machine IDs",
	Run: func(cmd *cobra.Command, args []string) {
		ids := license.AnalyzeMachineIDs()

		if jsonFormat {
			data, _ := json.MarshalIndent(ids, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("Generated %d test machine IDs:\n", len(ids))
		for i, id := range ids {
			display := id
			if len(display) > 60 {
				display = display[:60] + "..."
			}
			fmt.Printf("  %2d. %s\n", i+1, display)
		}
	},
}

func init() {
	rootCmd.AddCommand(licenseCmd)
	licenseCmd.AddCommand(licenseTestCmd)
	licenseCmd.AddCommand(licenseMachineIDCmd)

	licenseTestCmd.Flags().StringVar(&licenseKey, "license", "", "Valid license key for testing")
	licenseTestCmd.Flags().DurationVar(&licenseTimeout, "timeout", 10*time.Second, "Request timeout")
	licenseTestCmd.Flags().BoolVar(&licenseAnalyze, "analyze", false, "Analysis mode only (no requests)")
	licenseTestCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")

	licenseMachineIDCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}
