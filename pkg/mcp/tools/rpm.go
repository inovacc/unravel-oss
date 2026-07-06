/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/rpm"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type rpmExtractInput struct {
	RPMPath   string `json:"rpm_path" jsonschema:"Path to .rpm package file"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory (default: <name>_extracted)"`
}

type rpmInfoInput struct {
	RPMPath string `json:"rpm_path" jsonschema:"Path to .rpm package file"`
}

type rpmVerifyInput struct {
	RPMPath string `json:"rpm_path" jsonschema:"Path to .rpm package file"`
}

func registerRpmTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_rpm_extract",
		Description: "Extract an RPM package payload (CPIO archive) to a directory",
	}, handleRpmExtract)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_rpm_info",
		Description: "Display RPM package metadata: name, version, arch, deps, build info, signatures",
	}, handleRpmInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_rpm_verify",
		Description: "Check RPM signature and hash information (MD5, SHA1, SHA256, PGP/GPG)",
	}, handleRpmVerify)
}

func handleRpmExtract(_ context.Context, _ *mcp.CallToolRequest, input rpmExtractInput) (*mcp.CallToolResult, any, error) {
	report, err := rpm.Extract(input.RPMPath, input.OutputDir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(report), nil, nil
}

func handleRpmInfo(_ context.Context, _ *mcp.CallToolRequest, input rpmInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := rpm.Info(input.RPMPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleRpmVerify(_ context.Context, _ *mcp.CallToolRequest, input rpmVerifyInput) (*mcp.CallToolResult, any, error) {
	result, err := rpm.Verify(input.RPMPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
