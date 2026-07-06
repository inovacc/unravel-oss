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

	"github.com/inovacc/unravel-oss/pkg/ipc"

	"github.com/spf13/cobra"
)

var (
	ipcTargetURL  string
	ipcIterations int
	ipcTimeout    time.Duration
	ipcDiscover   bool
)

var ipcCmd = &cobra.Command{
	Use:   "ipc",
	Short: "IPC channel fuzzing",
	Long: `Fuzz Electron/Tauri IPC channels.

Discovers and tests IPC handlers for vulnerabilities.
FOR AUTHORIZED SECURITY TESTING ONLY.`,
}

var ipcFuzzCmd = &cobra.Command{
	Use:   "fuzz <app_path>",
	Short: "Fuzz IPC channels",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appPath := args[0]

		fmt.Printf("IPC Fuzzing: %s\n\n", appPath)

		commands, err := ipc.DiscoverCommands(appPath)
		if err != nil {
			fmt.Printf("Error discovering commands: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Discovered %d potential IPC commands\n", len(commands))
		for _, c := range commands {
			fmt.Printf("  - %s (from %s)\n", c.Name, c.Source)
		}

		config := ipc.FuzzerConfig{
			TargetURL:    ipcTargetURL,
			BinaryPath:   appPath,
			Iterations:   ipcIterations,
			Timeout:      ipcTimeout,
			Verbose:      verbose,
			DiscoverOnly: ipcDiscover,
		}

		report := ipc.FuzzCommands(config, commands)

		if jsonFormat {
			data, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(data))
			return
		}

		if output != "" {
			_ = os.MkdirAll(output, 0755)
			reportPath := filepath.Join(output, "fuzz_report.json")
			data, _ := json.MarshalIndent(report, "", "  ")
			_ = os.WriteFile(reportPath, data, 0644)
			fmt.Printf("\nReport: %s\n", reportPath)
		}

		fmt.Printf("\nSummary: %d requests, %d successful, %d interesting finds\n",
			report.Summary.TotalRequests, report.Summary.SuccessfulCalls, report.Summary.InterestingFinds)
	},
}

var ipcListCmd = &cobra.Command{
	Use:   "list <app_path>",
	Short: "List discovered IPC channels",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		appPath := args[0]

		fmt.Printf("Discovering IPC channels in: %s\n\n", appPath)

		commands, err := ipc.DiscoverCommands(appPath)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if jsonFormat {
			data, _ := json.MarshalIndent(commands, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("Found %d IPC commands:\n", len(commands))
		for _, c := range commands {
			fmt.Printf("  %-40s [%s]\n", c.Name, c.Source)
		}
	},
}

func init() {
	rootCmd.AddCommand(ipcCmd)
	ipcCmd.AddCommand(ipcFuzzCmd)
	ipcCmd.AddCommand(ipcListCmd)

	ipcFuzzCmd.Flags().StringVar(&ipcTargetURL, "url", "", "Target IPC endpoint URL")
	ipcFuzzCmd.Flags().IntVar(&ipcIterations, "iterations", 100, "Fuzz iterations per command")
	ipcFuzzCmd.Flags().DurationVar(&ipcTimeout, "timeout", 5*time.Second, "Request timeout")
	ipcFuzzCmd.Flags().BoolVar(&ipcDiscover, "discover", false, "Only discover commands")
	ipcFuzzCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")

	ipcListCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}
