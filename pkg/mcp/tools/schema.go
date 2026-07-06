/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/schema"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type schemaInput struct {
	Path          string `json:"path" jsonschema:"Path to file or directory to extract schema from"`
	AIAnalysisMCP bool   `json:"ai_analysis_mcp,omitempty" jsonschema:"Return AI prompt for Claude Code to enrich the schema directly"`
}

func registerSchemaTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_schema",
		Description: "Extract a taxonomic application schema describing communication, auth, storage, IPC, stealth, and telemetry — machine-readable for cross-framework replication",
	}, handleSchema)
}

func handleSchema(_ context.Context, _ *mcp.CallToolRequest, input schemaInput) (*mcp.CallToolResult, any, error) {
	result, err := dissect.Run(input.Path, dissect.Options{})
	if err != nil {
		return errorResult(err), nil, nil
	}

	opts := schema.Options{
		AIAnalysisMCP: input.AIAnalysisMCP,
	}

	appSchema, err := schema.Extract(result, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}

	if input.AIAnalysisMCP && appSchema.AIPrompt != "" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: appSchema.AIPrompt},
				&mcp.TextContent{Text: "Schema data follows as JSON:"},
			},
		}, nil, nil
	}

	return jsonResult(appSchema), nil, nil
}
