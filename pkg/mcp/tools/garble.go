/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/garble"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type garbleDetectInput struct {
	BinaryPath string `json:"binary_path" jsonschema:"Path to Go binary to analyze"`
}

type garbleInfoInput struct {
	BinaryPath string `json:"binary_path" jsonschema:"Path to Go binary"`
}

type garbleStringsInput struct {
	BinaryPath string `json:"binary_path" jsonschema:"Path to Go binary"`
	MinLen     int    `json:"min_len,omitempty" jsonschema:"Minimum string length (default 6)"`
}

type garbleSymbolsInput struct {
	BinaryPath string `json:"binary_path" jsonschema:"Path to Go binary"`
}

type garbleScanInput struct {
	DirectoryPath string `json:"directory_path" jsonschema:"Directory to scan for Go binaries"`
	Verbose       bool   `json:"verbose,omitempty" jsonschema:"Show verbose output"`
}

func registerGarbleTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_garble_detect",
		Description: "Detect garble obfuscation in a Go binary with weighted heuristic confidence scoring",
	}, handleGarbleDetect)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_garble_info",
		Description: "Extract metadata from a Go binary (Go version, build settings, architecture, OS)",
	}, handleGarbleInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_garble_strings",
		Description: "Extract and categorize strings from a Go binary with Shannon entropy analysis",
	}, handleGarbleStrings)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_garble_symbols",
		Description: "Analyze symbol table of a Go binary for obfuscation indicators",
	}, handleGarbleSymbols)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_garble_scan",
		Description: "Batch scan a directory for garble-obfuscated Go binaries",
	}, handleGarbleScan)
}

func handleGarbleDetect(_ context.Context, _ *mcp.CallToolRequest, input garbleDetectInput) (*mcp.CallToolResult, any, error) {
	result, err := garble.Detect(input.BinaryPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleGarbleInfo(_ context.Context, _ *mcp.CallToolRequest, input garbleInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := garble.ExtractInfo(input.BinaryPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleGarbleStrings(_ context.Context, _ *mcp.CallToolRequest, input garbleStringsInput) (*mcp.CallToolResult, any, error) {
	minLen := input.MinLen
	if minLen <= 0 {
		minLen = 6
	}

	result, err := garble.ExtractStrings(input.BinaryPath, minLen)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleGarbleSymbols(_ context.Context, _ *mcp.CallToolRequest, input garbleSymbolsInput) (*mcp.CallToolResult, any, error) {
	result, err := garble.AnalyzeSymbols(input.BinaryPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleGarbleScan(_ context.Context, _ *mcp.CallToolRequest, input garbleScanInput) (*mcp.CallToolResult, any, error) {
	result, err := garble.ScanDirectory(input.DirectoryPath, input.Verbose)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

// jsonResult marshals any value to a JSON text result.
func jsonResult(v any) *mcp.CallToolResult {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorResult(err)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}
}

// errorResult returns an MCP error result.
func errorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)},
		},
		IsError: true,
	}
}
