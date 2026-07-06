/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/asar"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type asarExtractInput struct {
	FilePath  string `json:"file_path" jsonschema:"Path to .asar archive file"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory (default: <name>_extracted)"`
}

type asarDumpInput struct {
	FilePath string `json:"file_path" jsonschema:"Path to .asar archive file"`
}

type asarSearchInput struct {
	FilePath string `json:"file_path" jsonschema:"Path to .asar archive file"`
	Pattern  string `json:"pattern" jsonschema:"Text pattern to search for"`
}

func registerAsarTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_asar_extract",
		Description: "Extract an Electron ASAR archive to a directory",
	}, handleAsarExtract)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_asar_dump",
		Description: "Dump the ASAR archive header as JSON (file listing without extraction)",
	}, handleAsarDump)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_asar_search",
		Description: "Search for a text pattern inside all files in an ASAR archive",
	}, handleAsarSearch)
}

func handleAsarExtract(_ context.Context, _ *mcp.CallToolRequest, input asarExtractInput) (*mcp.CallToolResult, any, error) {
	file, header, _, dataOffset, err := asar.OpenAndParse(input.FilePath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	defer func() { _ = file.Close() }()

	outDir := input.OutputDir
	if outDir == "" {
		outDir = input.FilePath + "_extracted"
	}

	report := asar.Extract(file, header, dataOffset, outDir, input.FilePath, false)

	return jsonResult(report), nil, nil
}

func handleAsarDump(_ context.Context, _ *mcp.CallToolRequest, input asarDumpInput) (*mcp.CallToolResult, any, error) {
	file, header, _, _, err := asar.OpenAndParse(input.FilePath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	defer func() { _ = file.Close() }()

	return jsonResult(header), nil, nil
}

func handleAsarSearch(_ context.Context, _ *mcp.CallToolRequest, input asarSearchInput) (*mcp.CallToolResult, any, error) {
	file, header, _, dataOffset, err := asar.OpenAndParse(input.FilePath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	defer func() { _ = file.Close() }()

	result := asar.Search(file, header, dataOffset, input.Pattern)

	return jsonResult(result), nil, nil
}
