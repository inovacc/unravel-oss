/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/disasm"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type disasmInput struct {
	Path            string   `json:"path" jsonschema:"Path to binary file to disassemble"`
	MaxInstructions int      `json:"max_instructions,omitempty" jsonschema:"Maximum instructions to decode (default 1000)"`
	Sections        []string `json:"sections,omitempty" jsonschema:"Sections to disassemble (default .text)"`
	ExternalOnly    bool     `json:"external_only,omitempty" jsonschema:"Only use external tools (objdump/radare2), skip native fallback"`
}

func registerDisasmTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_disasm",
		Description: "Disassemble a binary file using objdump/radare2 (preferred) or native Go x86 decoder",
	}, handleDisasm)
}

func handleDisasm(_ context.Context, _ *mcp.CallToolRequest, input disasmInput) (*mcp.CallToolResult, any, error) {
	opts := disasm.Options{
		MaxInstructions: input.MaxInstructions,
		SectionsFilter:  input.Sections,
		ExternalOnly:    input.ExternalOnly,
	}

	result, err := disasm.Disassemble(input.Path, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
