/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"time"

	"github.com/inovacc/unravel-oss/pkg/ipc"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ipcDiscoverInput struct {
	BinaryPath string `json:"binary_path" jsonschema:"Path to Electron/Tauri binary to analyze for IPC commands"`
}

type ipcFuzzInput struct {
	URL        string `json:"url" jsonschema:"URL of IPC endpoint to fuzz"`
	Iterations int    `json:"iterations,omitempty" jsonschema:"Number of fuzz iterations per command (default 10)"`
	Timeout    int    `json:"timeout,omitempty" jsonschema:"Request timeout in seconds (default 10)"`
}

func registerIPCTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_ipc_discover",
		Description: "Discover IPC commands from an Electron/Tauri binary using static analysis",
	}, handleIPCDiscover)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_ipc_fuzz",
		Description: "Fuzz IPC endpoints with generated payloads to test for security issues",
	}, handleIPCFuzz)
}

func handleIPCDiscover(_ context.Context, _ *mcp.CallToolRequest, input ipcDiscoverInput) (*mcp.CallToolResult, any, error) {
	commands, err := ipc.DiscoverCommands(input.BinaryPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(commands), nil, nil
}

func handleIPCFuzz(_ context.Context, _ *mcp.CallToolRequest, input ipcFuzzInput) (*mcp.CallToolResult, any, error) {
	iterations := input.Iterations
	if iterations <= 0 {
		iterations = 10
	}

	timeout := input.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	cfg := ipc.FuzzerConfig{
		TargetURL:  input.URL,
		Iterations: iterations,
		Timeout:    time.Duration(timeout) * time.Second,
	}

	report := ipc.FuzzCommands(cfg, nil)

	return jsonResult(report), nil, nil
}
