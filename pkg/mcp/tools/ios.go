/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/ios"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type iosInfoInput struct {
	Path string `json:"path" jsonschema:"Path to .ipa file"`
}

type iosExtractInput struct {
	Path      string `json:"path" jsonschema:"Path to .ipa file"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory for extracted contents"`
}

func registerIOSTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_ios_info",
		Description: "Display iOS IPA metadata: bundle ID, version, permissions, frameworks, signing info",
	}, handleIOSInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_ios_extract",
		Description: "Extract an iOS IPA archive to a directory",
	}, handleIOSExtract)
}

func handleIOSInfo(_ context.Context, _ *mcp.CallToolRequest, input iosInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := ios.Info(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleIOSExtract(_ context.Context, _ *mcp.CallToolRequest, input iosExtractInput) (*mcp.CallToolResult, any, error) {
	outDir := input.OutputDir
	if outDir == "" {
		outDir = "ipa_extracted"
	}

	result, err := ios.Extract(input.Path, outDir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
