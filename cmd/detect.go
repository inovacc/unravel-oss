/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/detect"

	"github.com/spf13/cobra"
)

var detectCmd = &cobra.Command{
	Use:   "detect <path>",
	Short: "Detect file type and show applicable unravel commands",
	Long: `Identify files by content (magic bytes, headers, structure) and show
which unravel commands apply.

For files: reads magic bytes and applies heuristics to identify the format.
For directories: checks for recognizable app structures (Electron, Tauri,
LevelDB, Chromium cache) or recursively scans all files.

Examples:
  unravel detect ./binary.exe
  unravel detect ./app.asar
  unravel detect ./MyApp/                  # scan directory
  unravel detect ./binary --json
  unravel detect ./directory -v`,
	Args: cobra.ExactArgs(1),
	Run:  runDetect,
}

func init() {
	appCmd.AddCommand(detectCmd)
	detectCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}

func runDetect(_ *cobra.Command, args []string) {
	path := args[0]

	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if info.IsDir() {
		runDetectScan(path)
	} else {
		runDetectFile(path)
	}
}

func runDetectFile(path string) {
	result, err := detect.Detect(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintFileDetect(result, verbose)
}

func runDetectScan(path string) {
	result, err := detect.Scan(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintScanResult(result, verbose)
}
