/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"
	"time"

	mcpclient "github.com/inovacc/unravel-oss/pkg/mcp/client"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type probeInput struct {
	Command string   `json:"command" jsonschema:"Executable to launch the MCP server (e.g. node, npx, python)"`
	Args    []string `json:"args" jsonschema:"Arguments for the command (e.g. [server.js] or [-y, @anthropic/mcp-server-time])"`
}

func registerProbeTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_mcp_probe",
		Description: "Launch an MCP server via stdio and enumerate its tools, resources, and prompts",
	}, handleMCPProbe)
}

func handleMCPProbe(ctx context.Context, _ *mcp.CallToolRequest, input probeInput) (*mcp.CallToolResult, any, error) {
	if input.Command == "" {
		return errorResult(fmt.Errorf("command is required")), nil, nil
	}

	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	result, err := mcpclient.Probe(probeCtx, input.Command, input.Args...)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
