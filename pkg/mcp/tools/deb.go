/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/deb"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type debExtractInput struct {
	DebPath   string `json:"deb_path" jsonschema:"Path to .deb package file"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory (default: <name>_extracted)"`
}

type debInfoInput struct {
	DebPath string `json:"deb_path" jsonschema:"Path to .deb package file"`
}

type debVerifyInput struct {
	DebPath string `json:"deb_path" jsonschema:"Path to .deb package file"`
}

func registerDebTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_deb_extract",
		Description: "Extract a Debian .deb package to a directory",
	}, handleDebExtract)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_deb_info",
		Description: "Display Debian package metadata: control fields, dependencies, scripts, file listing",
	}, handleDebInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_deb_verify",
		Description: "Check a Debian package for dpkg-sig/debsigs signatures",
	}, handleDebVerify)
}

func handleDebExtract(_ context.Context, _ *mcp.CallToolRequest, input debExtractInput) (*mcp.CallToolResult, any, error) {
	report, err := deb.Extract(input.DebPath, input.OutputDir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(report), nil, nil
}

func handleDebInfo(_ context.Context, _ *mcp.CallToolRequest, input debInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := deb.Info(input.DebPath, true)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleDebVerify(_ context.Context, _ *mcp.CallToolRequest, input debVerifyInput) (*mcp.CallToolResult, any, error) {
	result, err := deb.Verify(input.DebPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
