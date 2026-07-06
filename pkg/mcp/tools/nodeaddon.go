/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/nodeaddon"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type nodeaddonPathInput struct {
	Path string `json:"path" jsonschema:"Path to a .node native addon file"`
}

type nodeaddonStringsInput struct {
	Path   string `json:"path" jsonschema:"Path to a .node native addon file"`
	MinLen int    `json:"min_len,omitempty" jsonschema:"Minimum string length (default 6)"`
}

func registerNodeaddonTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_nodeaddon_info",
		Description: "Analyze a Node.js native addon (.node): format, architecture, N-API detection, exports, imports, risk scoring, binding context",
	}, handleNodeaddonInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_nodeaddon_symbols",
		Description: "Extract exported symbols from a .node addon with N-API annotation",
	}, handleNodeaddonSymbols)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_nodeaddon_strings",
		Description: "Extract printable strings from a .node addon with Shannon entropy analysis and categorization",
	}, handleNodeaddonStrings)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_nodeaddon_imports",
		Description: "Analyze imported libraries from a .node addon with risk classification (crypto, network, process, registry)",
	}, handleNodeaddonImports)
}

func handleNodeaddonInfo(_ context.Context, _ *mcp.CallToolRequest, input nodeaddonPathInput) (*mcp.CallToolResult, any, error) {
	result, err := nodeaddon.Analyze(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(result), nil, nil
}

func handleNodeaddonSymbols(_ context.Context, _ *mcp.CallToolRequest, input nodeaddonPathInput) (*mcp.CallToolResult, any, error) {
	result, err := nodeaddon.Symbols(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(result), nil, nil
}

func handleNodeaddonStrings(_ context.Context, _ *mcp.CallToolRequest, input nodeaddonStringsInput) (*mcp.CallToolResult, any, error) {
	minLen := input.MinLen
	if minLen <= 0 {
		minLen = 6
	}
	result, err := nodeaddon.Strings(input.Path, minLen)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(result), nil, nil
}

func handleNodeaddonImports(_ context.Context, _ *mcp.CallToolRequest, input nodeaddonPathInput) (*mcp.CallToolResult, any, error) {
	result, err := nodeaddon.Imports(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(result), nil, nil
}
