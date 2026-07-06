/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/extension"
	"github.com/inovacc/unravel-oss/pkg/extension/gather"
	"github.com/inovacc/unravel-oss/pkg/manifest"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type extensionScanInput struct {
	Browser string `json:"browser,omitempty" jsonschema:"Filter by browser (chrome, edge, brave, etc.)"`
}

type extensionAnalyzeInput struct {
	Target  string `json:"target" jsonschema:"Extension ID or path to analyze"`
	Browser string `json:"browser,omitempty" jsonschema:"Filter by browser"`
}

type extensionSearchInput struct {
	Pattern string `json:"pattern" jsonschema:"Pattern to search for in extension code"`
	Browser string `json:"browser,omitempty" jsonschema:"Filter by browser"`
}

type extensionListInput struct {
	Browser string `json:"browser,omitempty" jsonschema:"Filter by browser"`
}

type extensionGatherInput struct {
	Browser string `json:"browser,omitempty" jsonschema:"Filter by browser (chrome, edge, brave, etc.)"`
}

func registerExtensionTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_extension_scan",
		Description: "Scan all browser extensions for security risks, permissions, and stealth features",
	}, handleExtensionScan)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_extension_analyze",
		Description: "Deep security analysis of a single browser extension by ID or path",
	}, handleExtensionAnalyze)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_extension_search",
		Description: "Search across all browser extensions for a code pattern",
	}, handleExtensionSearch)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_extension_list",
		Description: "List all discovered Chromium-based browser profiles with extensions",
	}, handleExtensionList)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_extension_gather",
		Description: "Discover all installed browser extensions with risk scores, sorted by risk",
	}, handleExtensionGather)
}

func loadManifest() *manifest.Manifest {
	m, err := manifest.LoadDefault()
	if err != nil {
		m = manifest.Default()
	}

	return m
}

func handleExtensionScan(_ context.Context, _ *mcp.CallToolRequest, input extensionScanInput) (*mcp.CallToolResult, any, error) {
	m := loadManifest()
	result := extension.ScanAllExtensions(m, input.Browser, false)

	return jsonResult(result), nil, nil
}

func handleExtensionAnalyze(_ context.Context, _ *mcp.CallToolRequest, input extensionAnalyzeInput) (*mcp.CallToolResult, any, error) {
	m := loadManifest()

	result, err := extension.AnalyzeSingleExtension(m, input.Target, input.Browser, false)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleExtensionSearch(_ context.Context, _ *mcp.CallToolRequest, input extensionSearchInput) (*mcp.CallToolResult, any, error) {
	result := extension.SearchExtensions(input.Pattern, input.Browser)
	return jsonResult(result), nil, nil
}

func handleExtensionList(_ context.Context, _ *mcp.CallToolRequest, input extensionListInput) (*mcp.CallToolResult, any, error) {
	profiles := extension.DiscoverBrowsers(input.Browser)
	return jsonResult(profiles), nil, nil
}

func handleExtensionGather(_ context.Context, _ *mcp.CallToolRequest, input extensionGatherInput) (*mcp.CallToolResult, any, error) {
	m := loadManifest()
	entries := gather.Gather(m, input.Browser, false)

	return jsonResult(entries), nil, nil
}
