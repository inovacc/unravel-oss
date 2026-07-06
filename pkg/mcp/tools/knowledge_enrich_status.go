/*
Copyright (c) 2026 Security Research
*/
// unravel_kb_enrich_status — list recent enrich_runs, sweep stale
// in_progress rows to 'interrupted', and (when RunID is set) return the
// failed-module detail block for that run. Designed for cross-session
// visibility into mid-flight enrichment.
//
// Thin delegate: all SQL + sweep logic lives in
// pkg/knowledge/kbenrich/status.go so the supervisor dispatcher (enrich.status)
// and this MCP tool share one code path.
package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/supervisor"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EnrichStatusInput is the typed input for unravel_kb_enrich_status.
type EnrichStatusInput struct {
	DB    string `json:"db,omitempty" jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	App   string `json:"app,omitempty" jsonschema:"filter runs by app"`
	Limit int    `json:"limit,omitempty" jsonschema:"max runs to return (default 20, hard cap 200)"`
	RunID string `json:"run_id,omitempty" jsonschema:"when set, return failed-module detail for this run"`
}

func registerKnowledgeEnrichStatusTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_enrich_status",
		Description: "Cross-session visibility into KB enrich runs. " +
			"Side-effect: sweeps in_progress runs whose last_heartbeat_at is older " +
			"than 10 minutes to 'interrupted'. Returns recent runs (with started_ago_sec / " +
			"last_heartbeat_ago_sec / in_flight), coverage.by_app, and — when run_id is set — " +
			"the failed-module detail list. Pair with unravel_kb_enrich_retry to " +
			"re-run only the failures.",
	}, handleKnowledgeEnrichStatus)
}

func handleKnowledgeEnrichStatus(ctx context.Context, _ *mcp.CallToolRequest, in EnrichStatusInput) (*mcp.CallToolResult, any, error) {
	cli, err := getEnrichClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("enrich client: %w", err)), nil, nil
	}
	payload, err := cli.Status(ctx, supervisor.EnrichStatusParams{
		App:   in.App,
		RunID: in.RunID,
		Limit: in.Limit,
	})
	if err != nil {
		return errorResult(fmt.Errorf("status: %w", err)), nil, nil
	}
	return jsonResult(payload), payload, nil
}
