/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/msix"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type msixExtractInput struct {
	MsixPath  string `json:"msix_path" jsonschema:"Path to .msix/.appx package file"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory (default: <name>_extracted)"`
}

type msixInfoInput struct {
	MsixPath string `json:"msix_path" jsonschema:"Path to .msix/.appx package file"`
}

type msixVerifyInput struct {
	MsixPath string `json:"msix_path" jsonschema:"Path to .msix/.appx package file"`
}

func registerMsixTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_msix_extract",
		Description: "Extract an MSIX/APPX package to a directory",
	}, handleMsixExtract)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_msix_info",
		Description: "Display MSIX/APPX package metadata: identity, capabilities, applications, dependencies",
	}, handleMsixInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_msix_verify",
		Description: "Check an MSIX/APPX package for AppxSignature.p7x digital signatures",
	}, handleMsixVerify)
}

func handleMsixExtract(_ context.Context, _ *mcp.CallToolRequest, input msixExtractInput) (*mcp.CallToolResult, any, error) {
	report, err := msix.Extract(input.MsixPath, input.OutputDir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(report), nil, nil
}

func handleMsixInfo(_ context.Context, _ *mcp.CallToolRequest, input msixInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := msix.Info(input.MsixPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleMsixVerify(_ context.Context, _ *mcp.CallToolRequest, input msixVerifyInput) (*mcp.CallToolResult, any, error) {
	result, err := msix.Verify(input.MsixPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
