/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/msi"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type msiExtractInput struct {
	MsiPath   string `json:"msi_path" jsonschema:"Path to .msi package file"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory (default: <name>_extracted)"`
}

type msiInfoInput struct {
	MsiPath string `json:"msi_path" jsonschema:"Path to .msi package file"`
}

type msiVerifyInput struct {
	MsiPath string `json:"msi_path" jsonschema:"Path to .msi package file"`
}

func registerMsiTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_msi_extract",
		Description: "Extract an MSI package OLE streams to a directory",
	}, handleMsiExtract)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_msi_info",
		Description: "Display MSI package metadata: product info, tables, files, custom actions, registry entries",
	}, handleMsiInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_msi_verify",
		Description: "Check an MSI package for Authenticode digital signatures",
	}, handleMsiVerify)
}

func handleMsiExtract(_ context.Context, _ *mcp.CallToolRequest, input msiExtractInput) (*mcp.CallToolResult, any, error) {
	report, err := msi.Extract(input.MsiPath, input.OutputDir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(report), nil, nil
}

func handleMsiInfo(_ context.Context, _ *mcp.CallToolRequest, input msiInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := msi.Info(input.MsiPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleMsiVerify(_ context.Context, _ *mcp.CallToolRequest, input msiVerifyInput) (*mcp.CallToolResult, any, error) {
	result, err := msi.Verify(input.MsiPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
