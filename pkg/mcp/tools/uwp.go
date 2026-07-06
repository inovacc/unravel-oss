/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/uwp"
	_ "github.com/inovacc/unravel-oss/pkg/uwp/runtime" // wire AnalyzeImpl

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type uwpDetectInput struct {
	Path string `json:"path" jsonschema:"Path to MSIX archive or already-extracted UWP app directory"`
}

type uwpAnalyzeInput struct {
	Path       string `json:"path" jsonschema:"Path to MSIX archive or already-extracted UWP app directory"`
	RubricPath string `json:"rubric_path,omitempty" jsonschema:"Optional capabilities rubric YAML path (sanitized)"`
	ExtractTo  string `json:"extract_to,omitempty" jsonschema:"Optional extraction directory for archive inputs (sanitized)"`
}

type uwpXAMLInput struct {
	Path string `json:"path" jsonschema:"Path to MSIX archive or already-extracted UWP app directory"`
}

type uwpCapabilitiesInput struct {
	Path       string `json:"path" jsonschema:"Path to MSIX archive or already-extracted UWP app directory"`
	RubricPath string `json:"rubric_path,omitempty" jsonschema:"Optional capabilities rubric YAML path (sanitized)"`
}

func registerUWPTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_uwp_detect",
		Description: "Fast UWP detection: AppxManifest.xml namespace peek (uap*/rescap)",
	}, handleUWPDetect)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_uwp_analyze",
		Description: "Full UWP analysis: manifest extraction + capability enumeration + categorical+numeric scoring + XAML walk + DPAPI provenance flagging (D-18: never decrypted)",
	}, handleUWPAnalyze)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_uwp_xaml",
		Description: "UWP XAML extraction (delegates to the WinUI XAML pipeline since formats are shared)",
	}, handleUWPXAML)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_uwp_capabilities",
		Description: "UWP capability enumeration + categorical+numeric scoring (rubric-driven; rescap auto-critical, unknown-min-high, signature multiplier)",
	}, handleUWPCapabilities)
}

func handleUWPDetect(_ context.Context, _ *mcp.CallToolRequest, input uwpDetectInput) (*mcp.CallToolResult, any, error) {
	abs, err := sanitizeMCPPath(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	res, err := uwp.Analyze(abs, uwp.Options{ExtractIfArchive: true})
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResultCapped(res), nil, nil
}

func handleUWPAnalyze(_ context.Context, _ *mcp.CallToolRequest, input uwpAnalyzeInput) (*mcp.CallToolResult, any, error) {
	abs, err := sanitizeMCPPath(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	rubric, err := sanitizeMCPPath(input.RubricPath)
	if err != nil {
		return errorResult(err), nil, nil
	}
	if _, err := sanitizeMCPPath(input.ExtractTo); err != nil {
		return errorResult(err), nil, nil
	}
	opts := uwp.Options{
		ExtractIfArchive:  true,
		ScoreCapabilities: true,
		AnalyzeXAML:       true,
		DPAPIFlagOnly:     true,
		RubricPath:        rubric,
		RejectSymlinks:    true,
	}
	res, err := uwp.Analyze(abs, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResultCapped(res), nil, nil
}

func handleUWPXAML(_ context.Context, _ *mcp.CallToolRequest, input uwpXAMLInput) (*mcp.CallToolResult, any, error) {
	abs, err := sanitizeMCPPath(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	opts := uwp.Options{
		ExtractIfArchive: true,
		AnalyzeXAML:      true,
		RejectSymlinks:   true,
	}
	res, err := uwp.Analyze(abs, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResultCapped(res.XAMLIndex), nil, nil
}

func handleUWPCapabilities(_ context.Context, _ *mcp.CallToolRequest, input uwpCapabilitiesInput) (*mcp.CallToolResult, any, error) {
	abs, err := sanitizeMCPPath(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	rubric, err := sanitizeMCPPath(input.RubricPath)
	if err != nil {
		return errorResult(err), nil, nil
	}
	opts := uwp.Options{
		ExtractIfArchive:  true,
		ScoreCapabilities: true,
		RubricPath:        rubric,
		RejectSymlinks:    true,
	}
	res, err := uwp.Analyze(abs, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}
	payload := struct {
		Capabilities any        `json:"capabilities"`
		Score        *uwp.Score `json:"score"`
	}{nil, res.Score}
	if res.Manifest != nil {
		payload.Capabilities = res.Manifest.Capabilities
	}
	return jsonResultCapped(payload), nil, nil
}
