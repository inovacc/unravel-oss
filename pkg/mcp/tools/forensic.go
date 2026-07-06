/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"path/filepath"

	mcpinternal "github.com/inovacc/unravel-oss/internal/mcp"
	"github.com/inovacc/unravel-oss/pkg/forensic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type forensicInput struct {
	TeardownDir string `json:"teardown_dir" jsonschema:"Path to teardown directory (single app or batch base dir)"`
	OutputDir   string `json:"output_dir,omitempty" jsonschema:"Output directory for reports (optional)"`
	JSON        bool   `json:"json,omitempty" jsonschema:"Return JSON instead of writing files"`
	Verbose     bool   `json:"verbose,omitempty" jsonschema:"Verbose output"`
	AI          bool   `json:"ai,omitempty" jsonschema:"Render HTML report with AI executive summary via MCP sampling"`
}

type forensicAppInput struct {
	AppDir string `json:"app_dir" jsonschema:"Path to single app teardown directory"`
	AI     bool   `json:"ai,omitempty" jsonschema:"Render HTML report with AI executive summary via MCP sampling"`
}

func registerForensicTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_forensic",
		Description: "Generate forensic report with API replay curl scripts from teardown data. Supports single app or batch mode (all apps in directory). Returns risk scores, network endpoints, secrets, SDK inventory, and curl commands for replaying discovered API communication.",
	}, handleForensic)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_forensic_app",
		Description: "Generate forensic report for a single app from its teardown directory. Returns risk score, findings, API endpoints, and curl replay scripts.",
	}, handleForensicApp)
}

func handleForensic(ctx context.Context, _ *mcp.CallToolRequest, input forensicInput) (*mcp.CallToolResult, any, error) {
	opts := forensic.Options{
		TeardownDir: input.TeardownDir,
		OutputDir:   input.OutputDir,
		Verbose:     input.Verbose,
		AIEnrich:    input.AI,
	}

	batch, err := forensic.RunBatch(input.TeardownDir, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}

	if input.OutputDir != "" {
		if err := forensic.WriteBatchReport(batch, input.OutputDir); err != nil {
			return errorResult(err), nil, nil
		}

		// 11-03 D-13: when --ai requested, render the HTML executive summary
		// per-app using the production sampling client (lazy resolver — falls
		// back to NilMCPClient if no daemon session is active, preserving D-06
		// graceful degrade).
		if input.AI {
			for i := range batch.Apps {
				app := &batch.Apps[i]
				appKBDir := filepath.Join(input.TeardownDir, app.AppID)
				appOut := filepath.Join(input.OutputDir, app.AppID)
				htmlOpts := forensic.HTMLRenderOptions{
					KBDir:         appKBDir,
					IncludeImages: true,
					AI:            true,
					MCPClient:     mcpinternal.ForensicClient(),
				}
				_ = forensic.WriteHTMLReportFull(ctx, app, htmlOpts, appOut)
			}
		}
	}

	return jsonResult(batch), nil, nil
}

func handleForensicApp(ctx context.Context, _ *mcp.CallToolRequest, input forensicAppInput) (*mcp.CallToolResult, any, error) {
	report, err := forensic.RunSingle(input.AppDir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	// 11-03 D-13: when --ai requested, render the HTML executive summary
	// using the production sampling client (lazy resolver).
	if input.AI {
		htmlOpts := forensic.HTMLRenderOptions{
			KBDir:         input.AppDir,
			IncludeImages: true,
			AI:            true,
			MCPClient:     mcpinternal.ForensicClient(),
		}
		_ = forensic.WriteHTMLReportFull(ctx, report, htmlOpts, input.AppDir)
	}

	return jsonResult(report), nil, nil
}
