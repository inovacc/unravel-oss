/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/sourcemap"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type sourcemapParseInput struct {
	Path string `json:"path" jsonschema:"Path to .map source map file"`
}

type sourcemapExtractInput struct {
	Path      string `json:"path" jsonschema:"Path to .map source map file"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory (default: sourcemap_extracted)"`
}

type sourcemapScanInput struct {
	Directory string `json:"directory" jsonschema:"Directory to scan for .map files"`
}

type sourcemapResolveInput struct {
	Path string `json:"path" jsonschema:"Path to .map source map file or bundled .js file"`
}

func registerSourcemapTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_sourcemap_parse",
		Description: "Parse a JavaScript source map (.map) file and return metadata: version, sources, names, bundler detection",
	}, handleSourcemapParse)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_sourcemap_extract",
		Description: "Extract original source files from a source map's inline sourcesContent to disk",
	}, handleSourcemapExtract)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_sourcemap_scan",
		Description: "Scan a directory tree for .map files and report source counts and detected bundlers",
	}, handleSourcemapScan)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_sourcemap_resolve",
		Description: "Resolve npm package dependencies from a source map or bundled JS file",
	}, handleSourcemapResolve)
}

func handleSourcemapParse(_ context.Context, _ *mcp.CallToolRequest, input sourcemapParseInput) (*mcp.CallToolResult, any, error) {
	result, err := sourcemap.Parse(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleSourcemapExtract(_ context.Context, _ *mcp.CallToolRequest, input sourcemapExtractInput) (*mcp.CallToolResult, any, error) {
	outDir := input.OutputDir
	if outDir == "" {
		outDir = "sourcemap_extracted"
	}

	result, err := sourcemap.ExtractSources(input.Path, outDir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleSourcemapScan(_ context.Context, _ *mcp.CallToolRequest, input sourcemapScanInput) (*mcp.CallToolResult, any, error) {
	result, err := sourcemap.ScanDir(input.Directory)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleSourcemapResolve(_ context.Context, _ *mcp.CallToolRequest, input sourcemapResolveInput) (*mcp.CallToolResult, any, error) {
	var result *sourcemap.ResolveResult
	var err error

	if strings.HasSuffix(strings.ToLower(input.Path), ".map") {
		result, err = sourcemap.ResolveDependencies(input.Path)
	} else {
		result, err = sourcemap.ResolveBundleJS(input.Path)
	}

	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
