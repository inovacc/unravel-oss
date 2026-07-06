/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/winui"
	_ "github.com/inovacc/unravel-oss/pkg/winui/runtime" // wire AnalyzeImpl

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type winuiDetectInput struct {
	Path string `json:"path" jsonschema:"Path to executable or app directory to inspect"`
}

type winuiAnalyzeInput struct {
	Path           string `json:"path" jsonschema:"Path to executable or app directory to inspect"`
	WriteXAMLDir   string `json:"write_xaml_dir,omitempty" jsonschema:"Optional directory to write decoded XAML files (sanitized against path traversal)"`
	DecodeXBF      bool   `json:"decode_xbf,omitempty" jsonschema:"Decode .xbf files to readable XAML (default true when omitted)"`
	ScanPEEmbedded bool   `json:"scan_pe_embedded,omitempty" jsonschema:"Scan PE RT_RCDATA for embedded XAML/XBF (default true when omitted)"`
	ParsePRI       bool   `json:"parse_pri,omitempty" jsonschema:"Parse resources.pri (default true when omitted)"`
}

type winuiXAMLInput struct {
	Path         string `json:"path" jsonschema:"Path to executable or app directory to inspect"`
	WriteXAMLDir string `json:"write_xaml_dir,omitempty" jsonschema:"Optional directory to write decoded XAML files"`
}

type winuiCapabilitiesInput struct {
	Path string `json:"path" jsonschema:"Path to executable or app directory to inspect"`
}

func registerWinUITools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_winui_detect",
		Description: "Fast WinUI 3 detection: deps.json (Microsoft.WinUI / Microsoft.WindowsAppSDK) + PE imports (Microsoft.UI.Xaml.dll)",
	}, handleWinUIDetect)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_winui_analyze",
		Description: "Full WinUI 3 analysis: detection + XAML walk + XBF decode + PRI parse + PE-embedded scan",
	}, handleWinUIAnalyze)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_winui_xaml",
		Description: "WinUI 3 XAML extraction: raw + XBF + PE-embedded; returns the XAMLIndex without detection summary",
	}, handleWinUIXAML)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_winui_capabilities",
		Description: "WinUI 3 framework dependency surface (deps-derived). For UWP capability scoring use unravel_uwp_capabilities.",
	}, handleWinUICapabilities)
}

// sanitizeMCPPath cleans + rejects '..' segments at the MCP boundary (T-04-01).
func sanitizeMCPPath(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	cleaned := filepath.Clean(p)
	for _, seg := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path contains '..' segment: %q", p)
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	return abs, nil
}

// jsonResultCapped wraps jsonResult and caps body at 1 MiB (T-04-15). On
// overflow it returns a truncated JSON document with a marker.
func jsonResultCapped(v any) *mcp.CallToolResult {
	const maxBytes = 1 << 20 // 1 MiB
	res := jsonResult(v)
	for i, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok && len(tc.Text) > maxBytes {
			tc.Text = tc.Text[:maxBytes-32] + `..."truncated":true}`
			res.Content[i] = tc
		}
	}
	return res
}

func handleWinUIDetect(_ context.Context, _ *mcp.CallToolRequest, input winuiDetectInput) (*mcp.CallToolResult, any, error) {
	abs, err := sanitizeMCPPath(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	res, err := winui.Analyze(abs, winui.Options{})
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResultCapped(res), nil, nil
}

func handleWinUIAnalyze(_ context.Context, _ *mcp.CallToolRequest, input winuiAnalyzeInput) (*mcp.CallToolResult, any, error) {
	abs, err := sanitizeMCPPath(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	outDir, err := sanitizeMCPPath(input.WriteXAMLDir)
	if err != nil {
		return errorResult(err), nil, nil
	}
	opts := winui.Options{
		DecodeXBF:      true,
		ScanPEEmbedded: true,
		ParsePRI:       true,
		WriteXAMLDir:   outDir,
		RejectSymlinks: true,
	}
	// Allow callers to explicitly disable any branch.
	if input.DecodeXBF || input.ScanPEEmbedded || input.ParsePRI {
		opts.DecodeXBF = input.DecodeXBF
		opts.ScanPEEmbedded = input.ScanPEEmbedded
		opts.ParsePRI = input.ParsePRI
	}
	res, err := winui.Analyze(abs, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResultCapped(res), nil, nil
}

func handleWinUIXAML(_ context.Context, _ *mcp.CallToolRequest, input winuiXAMLInput) (*mcp.CallToolResult, any, error) {
	abs, err := sanitizeMCPPath(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	outDir, err := sanitizeMCPPath(input.WriteXAMLDir)
	if err != nil {
		return errorResult(err), nil, nil
	}
	opts := winui.Options{
		DecodeXBF:      true,
		ScanPEEmbedded: true,
		WriteXAMLDir:   outDir,
		RejectSymlinks: true,
	}
	res, err := winui.Analyze(abs, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResultCapped(res.XAMLIndex), nil, nil
}

func handleWinUICapabilities(_ context.Context, _ *mcp.CallToolRequest, input winuiCapabilitiesInput) (*mcp.CallToolResult, any, error) {
	abs, err := sanitizeMCPPath(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	res, err := winui.Analyze(abs, winui.Options{})
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResultCapped(res.Frameworks), nil, nil
}
