/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	mcpclient "github.com/inovacc/unravel-oss/pkg/mcp/client"

	"github.com/spf13/cobra"
)

var probeTimeout int

var probeCmd = &cobra.Command{
	Use:   "probe <command> [args...]",
	Short: "Probe an MCP server to enumerate tools, resources, and prompts",
	Long: `Launch an MCP server via stdio transport and enumerate its capabilities
using the MCP protocol (JSON-RPC). Discovers tools, resources, and prompts.

Examples:
  unravel probe node server.js
  unravel probe npx -y @anthropic/mcp-server-time
  unravel probe go run . mcp serve
  unravel probe ./my-mcp-server --json`,
	Args: cobra.MinimumNArgs(1),
	Run:  runProbe,
}

func init() {
	rootCmd.AddCommand(probeCmd)
	probeCmd.Flags().IntVar(&probeTimeout, "timeout", 10, "Timeout in seconds for server enumeration")
}

func runProbe(_ *cobra.Command, args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(probeTimeout)*time.Second)
	defer cancel()

	result, err := mcpclient.Probe(ctx, args[0], args[1:]...)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	printProbeResult(result)
}

func printProbeResult(result *mcpclient.ProbeResult) {
	if result.Error != "" {
		fmt.Printf("Error:         %s\n", result.Error)

		return
	}

	fmt.Printf("Server:        %s", result.ServerName)
	if result.ServerVersion != "" {
		fmt.Printf(" v%s", result.ServerVersion)
	}

	fmt.Println()

	if result.ProtocolVer != "" {
		fmt.Printf("Protocol:      %s\n", result.ProtocolVer)
	}

	fmt.Printf("Duration:      %s\n", result.Duration.Round(time.Millisecond))

	if len(result.Tools) > 0 {
		fmt.Printf("\nTools (%d):\n", len(result.Tools))
		for _, t := range result.Tools {
			if t.Description != "" {
				fmt.Printf("  %-40s %s\n", t.Name, t.Description)
			} else {
				fmt.Printf("  %s\n", t.Name)
			}
		}
	}

	if len(result.Resources) > 0 {
		fmt.Printf("\nResources (%d):\n", len(result.Resources))
		for _, r := range result.Resources {
			if r.Description != "" {
				fmt.Printf("  %-40s %s\n", r.URI, r.Description)
			} else {
				fmt.Printf("  %s\n", r.URI)
			}
		}
	}

	if len(result.Prompts) > 0 {
		fmt.Printf("\nPrompts (%d):\n", len(result.Prompts))
		for _, p := range result.Prompts {
			if p.Description != "" {
				fmt.Printf("  %-40s %s\n", p.Name, p.Description)
			} else {
				fmt.Printf("  %s\n", p.Name)
			}
		}
	}

	total := len(result.Tools) + len(result.Resources) + len(result.Prompts)
	if total == 0 {
		fmt.Println("\nNo tools, resources, or prompts discovered.")
	}
}
