/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/css"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type cssExtractInput struct {
	Path           string `json:"path" jsonschema:"Path to Electron/Tauri app, ASAR archive, or directory"`
	OutputDir      string `json:"output_dir,omitempty" jsonschema:"Output directory for extracted CSS"`
	Normalize      *bool  `json:"normalize,omitempty" jsonschema:"Normalize and deduplicate CSS (default true)"`
	ResolveImports *bool  `json:"resolve_imports,omitempty" jsonschema:"Resolve @import chains (default true)"`
	Verbose        bool   `json:"verbose,omitempty" jsonschema:"Include detailed per-file output"`
}

func registerCSSTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_css_extract",
		Description: "Extract and organize CSS from Electron/Tauri applications, ASAR archives, or directories",
	}, handleCSSExtract)
}

func handleCSSExtract(_ context.Context, _ *mcp.CallToolRequest, input cssExtractInput) (*mcp.CallToolResult, any, error) {
	normalize := true
	if input.Normalize != nil {
		normalize = *input.Normalize
	}
	resolveImports := true
	if input.ResolveImports != nil {
		resolveImports = *input.ResolveImports
	}

	opts := css.Options{
		OutputDir:      input.OutputDir,
		Normalize:      normalize,
		Deduplicate:    normalize, // deduplicate when normalizing
		ResolveImports: resolveImports,
		Verbose:        input.Verbose,
	}

	result, err := css.Extract(input.Path, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}

	// Write manifest if output dir specified.
	if opts.OutputDir != "" {
		_ = css.WriteManifest(result, opts.OutputDir)
	}

	return jsonResult(result), nil, nil
}
