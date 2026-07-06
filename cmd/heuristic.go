/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/heuristic"

	"github.com/spf13/cobra"
)

var heuristicCmd = &cobra.Command{
	Use:   "heuristic <path>",
	Short: "Heuristic malicious code analysis",
	Long: `Scan source code files or directories for malicious patterns using
heuristic detection. Identifies:

  - External connections (C2, exfiltration, reverse shells)
  - Code obfuscation (eval, packing, encoding, JSFuck)
  - Execution patterns (child_process, shell commands, PowerShell)
  - Data access (keyloggers, clipboard, credential theft)
  - Persistence mechanisms (registry, cron, startup)
  - Evasion techniques (anti-debug, VM detection, sandbox detection)
  - Crypto threats (miners, wallet theft)
  - Supply chain indicators (install hooks, typosquatting)
  - CVE exploitation patterns (prototype pollution, deserialization)

Examples:
  unravel heuristic ./src/
  unravel heuristic ./suspicious.js
  unravel heuristic ./node_modules/some-package/ --json
  unravel heuristic ./app.js -v`,
	Args: cobra.ExactArgs(1),
	Run:  runHeuristic,
}

func init() {
	appCmd.AddCommand(heuristicCmd)
	heuristicCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}

func runHeuristic(_ *cobra.Command, args []string) {
	path := args[0]

	scanner := heuristic.NewDefaultScanner(verbose)

	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	var result *heuristic.Result
	if info.IsDir() {
		result, err = scanner.ScanDirectory(path)
		if err != nil {
			fmt.Printf("Error scanning directory: %v\n", err)
			os.Exit(1)
		}
	} else {
		findings, ferr := scanner.ScanFile(path)
		if ferr != nil {
			fmt.Printf("Error scanning file: %v\n", ferr)
			os.Exit(1)
		}
		// Build result from single file
		result = heuristic.BuildResult([]string{path}, findings)
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}

	out.PrintHeuristicResult(result, verbose)
}
