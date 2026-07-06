/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/wasm"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type wasmInfoInput struct {
	Path string `json:"path" jsonschema:"Path to WebAssembly (.wasm) binary file"`
}

func registerWasmTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_wasm_info",
		Description: "Parse a WebAssembly (.wasm) binary module and return metadata: version, sections, imports, exports, function counts",
	}, handleWasmInfo)
}

func handleWasmInfo(_ context.Context, _ *mcp.CallToolRequest, input wasmInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := wasm.Parse(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
