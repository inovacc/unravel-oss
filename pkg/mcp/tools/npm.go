/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/npm"
	"github.com/inovacc/unravel-oss/pkg/npm/mcpprobe"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type npmInfoInput struct {
	Package string `json:"package" jsonschema:"npm package name (e.g. express, lodash)"`
}

type npmDownloadInput struct {
	Package   string `json:"package" jsonschema:"npm package name to download"`
	OutputDir string `json:"output_dir" jsonschema:"Directory to save the downloaded package"`
}

type npmAnalyzeInput struct {
	Dir string `json:"dir" jsonschema:"Directory containing extracted npm package to analyze"`
}

type npmDepsInput struct {
	Dir string `json:"dir" jsonschema:"Directory containing package.json to parse dependencies from"`
}

type npmProbeInput struct {
	Dir     string `json:"dir" jsonschema:"Directory containing an extracted npm MCP server package"`
	Timeout int    `json:"timeout,omitempty" jsonschema:"Probe timeout in seconds (default 10)"`
}

func registerNpmTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_npm_info",
		Description: "Fetch npm registry metadata for a package: versions, maintainers, dependencies",
	}, handleNpmInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_npm_download",
		Description: "Download an npm package tarball and extract it to a directory",
	}, handleNpmDownload)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_npm_analyze",
		Description: "Analyze an extracted npm package directory for security patterns and suspicious code",
	}, handleNpmAnalyze)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_npm_deps",
		Description: "Parse package.json to extract dependency tree and metadata",
	}, handleNpmDeps)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_npm_probe",
		Description: "Probe an npm MCP server package directory to enumerate tools, resources, and prompts via stdio",
	}, handleNpmProbe)
}

func handleNpmInfo(_ context.Context, _ *mcp.CallToolRequest, input npmInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := npm.FetchInfo(input.Package)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleNpmDownload(_ context.Context, _ *mcp.CallToolRequest, input npmDownloadInput) (*mcp.CallToolResult, any, error) {
	name, version := splitPkgSpec(input.Package)
	result, err := npm.Download(name, version, input.OutputDir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleNpmAnalyze(_ context.Context, _ *mcp.CallToolRequest, input npmAnalyzeInput) (*mcp.CallToolResult, any, error) {
	result, err := npm.Analyze(input.Dir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleNpmDeps(_ context.Context, _ *mcp.CallToolRequest, input npmDepsInput) (*mcp.CallToolResult, any, error) {
	result, err := npm.ParsePackageJSON(filepath.Join(input.Dir, "package.json"))
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleNpmProbe(ctx context.Context, _ *mcp.CallToolRequest, input npmProbeInput) (*mcp.CallToolResult, any, error) {
	if input.Dir == "" {
		return errorResult(fmt.Errorf("dir is required")), nil, nil
	}

	timeout := 10 * time.Second
	if input.Timeout > 0 {
		timeout = time.Duration(input.Timeout) * time.Second
	}

	result, err := mcpprobe.Probe(ctx, input.Dir, timeout)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

// splitPkgSpec splits "name@version" into name and version.
// Handles scoped packages like "@scope/pkg@1.0.0".
func splitPkgSpec(spec string) (string, string) {
	// Handle scoped packages: @scope/pkg@version
	if strings.HasPrefix(spec, "@") {
		if idx := strings.LastIndex(spec[1:], "@"); idx > 0 {
			return spec[:idx+1], spec[idx+2:]
		}

		return spec, ""
	}

	if idx := strings.LastIndex(spec, "@"); idx > 0 {
		return spec[:idx], spec[idx+1:]
	}

	return spec, ""
}
