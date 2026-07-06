/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"os"

	"github.com/inovacc/unravel-oss/pkg/heuristic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type heuristicScanInput struct {
	Path    string `json:"path" jsonschema:"Path to file or directory to scan for malicious patterns"`
	Verbose bool   `json:"verbose,omitempty" jsonschema:"Include evidence details in output"`
}

func registerHeuristicTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_heuristic",
		Description: "Heuristic malicious code analysis: detect external connections, obfuscation, backdoors, C2, keyloggers, crypto miners, supply chain attacks, CVE patterns, and more",
	}, handleHeuristicScan)
}

func handleHeuristicScan(_ context.Context, _ *mcp.CallToolRequest, input heuristicScanInput) (*mcp.CallToolResult, any, error) {
	scanner := heuristic.NewDefaultScanner(input.Verbose)

	info, err := os.Stat(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	var result *heuristic.Result
	if info.IsDir() {
		result, err = scanner.ScanDirectory(input.Path)
		if err != nil {
			return errorResult(err), nil, nil
		}
	} else {
		findings, ferr := scanner.ScanFile(input.Path)
		if ferr != nil {
			return errorResult(ferr), nil, nil
		}
		result = heuristic.BuildResult([]string{input.Path}, findings)
	}

	return jsonResult(result), nil, nil
}
