/*
Copyright (c) 2026 Security Research
*/
// unravel_kb_drift_history — list recent drift_alerts rows for app.
package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DriftHistoryInput is the typed input for unravel_kb_drift_history.
type DriftHistoryInput struct {
	DB    string `json:"db,omitempty"    jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	App   string `json:"app"             jsonschema:"app to query"`
	Limit int    `json:"limit,omitempty" jsonschema:"max rows (default 20, max 500)"`
}

// DriftHistoryRow is one row of the drift_alerts history output.
type DriftHistoryRow struct {
	ID                int64   `json:"id"`
	RunID             string  `json:"run_id"`
	BaselineRunID     string  `json:"baseline_run_id"`
	Metric            string  `json:"metric"`
	BaselineValue     float64 `json:"baseline_value"`
	RecentValue       float64 `json:"recent_value"`
	RelativeDelta     float64 `json:"relative_delta"`
	ThresholdRelative float64 `json:"threshold_relative"`
	CreatedAt         string  `json:"created_at"`
}

func registerKbDriftHistoryTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_drift_history",
		Description: "Return recent drift_alerts rows for app (newest first). " +
			"Default limit 20, hard cap 500.",
	}, handleKbDriftHistory)
}

func handleKbDriftHistory(ctx context.Context, _ *mcp.CallToolRequest, in DriftHistoryInput) (*mcp.CallToolResult, any, error) {
	if in.Limit <= 0 {
		in.Limit = 20
	}
	if in.Limit > 500 {
		in.Limit = 500
	}
	cli, err := getDriftClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("drift client: %w", err)), nil, nil
	}
	res, err := cli.History(ctx, in.App, in.Limit)
	if err != nil {
		return errorResult(fmt.Errorf("drift history: %w", err)), nil, nil
	}
	return jsonResult(res), res, nil
}
