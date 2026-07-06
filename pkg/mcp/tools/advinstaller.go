/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/advinstaller"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type advinstallerInfoInput struct {
	Path string `json:"path" jsonschema:"Path to potential Advanced Installer bootstrapper executable"`
}

type advinstallerExtractInput struct {
	Path      string `json:"path" jsonschema:"Path to Advanced Installer bootstrapper executable"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory for extracted MSI (default: advinstaller_extracted)"`
}

func registerAdvinstallerTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_advinstaller_info",
		Description: "Analyze a PE executable for Advanced Installer bootstrapper markers and embedded MSI/CAB payload location",
	}, handleAdvinstallerInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_advinstaller_extract",
		Description: "Extract the embedded MSI or CAB payload from an Advanced Installer bootstrapper to disk",
	}, handleAdvinstallerExtract)
}

func handleAdvinstallerInfo(_ context.Context, _ *mcp.CallToolRequest, input advinstallerInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := advinstaller.Info(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleAdvinstallerExtract(_ context.Context, _ *mcp.CallToolRequest, input advinstallerExtractInput) (*mcp.CallToolResult, any, error) {
	outDir := input.OutputDir
	if outDir == "" {
		outDir = "advinstaller_extracted"
	}

	result, err := advinstaller.ExtractMSI(input.Path, outDir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
