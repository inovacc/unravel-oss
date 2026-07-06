//go:build example

/*
Copyright (c) 2026 Security Research

mcp-sample-cli is a minimal MCP server that demonstrates the pkg/mcp
sampling library. It registers one tool — echo_uppercase — that uses
pkg/mcp.Sample to ask the connected MCP host (e.g. Claude Code) to
convert text to uppercase. This proves the library is importable and
callable from an external consumer.

Build:

	go build -tags=example ./examples/mcp-sample-cli/

Run (wired via .mcp.json, see README):

	./mcp-sample-cli
*/
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	pkgmcp "github.com/inovacc/unravel-oss/pkg/mcp"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoInput struct {
	Text string `json:"text" jsonschema:"the text to convert to uppercase"`
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	srv := gomcp.NewServer(&gomcp.Implementation{
		Name:    "mcp-sample-cli",
		Version: "0.0.1",
	}, nil)

	gomcp.AddTool(srv, &gomcp.Tool{
		Name:        "echo_uppercase",
		Description: "Converts text to uppercase using MCP sampling (pkg/mcp.Sample).",
	}, func(ctx context.Context, _ *gomcp.CallToolRequest, input echoInput) (*gomcp.CallToolResult, echoInput, error) {
		prompt := "Convert the following text to uppercase and return ONLY the result, no explanation:\n" + input.Text
		body, err := pkgmcp.Sample(ctx, prompt)
		if err != nil {
			return &gomcp.CallToolResult{IsError: true, Content: []gomcp.Content{
				&gomcp.TextContent{Text: fmt.Sprintf("sampling error: %v", err)},
			}}, echoInput{}, nil
		}
		return &gomcp.CallToolResult{Content: []gomcp.Content{
			&gomcp.TextContent{Text: string(body)},
		}}, echoInput{}, nil
	})

	// Connect via stdio then wire the sampling session.
	ss, err := srv.Connect(context.Background(), &gomcp.StdioTransport{}, nil)
	if err != nil {
		logger.Error("connect failed", "err", err)
		os.Exit(1)
	}
	pkgmcp.SetSession(ss, logger)
	logger.Info("pkg/mcp session wired", "tool", "echo_uppercase")

	if err := ss.Wait(); err != nil {
		logger.Error("server exited", "err", err)
		os.Exit(1)
	}
}
