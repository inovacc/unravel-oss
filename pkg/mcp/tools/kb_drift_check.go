/*
Copyright (c) 2026 Security Research
*/
// unravel_kb_drift_check — Phase G drift detection. Compares an enrich
// run against the per-app baseline and returns a verdict. Skipped if no
// baseline set or run too small. Drift errors are never fatal to the
// surrounding enrich pipeline (see drift.Check docstring).
package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/inovacc/unravel-oss/internal/supervisor"
)

// DriftCheckInput is the typed input for unravel_kb_drift_check.
type DriftCheckInput struct {
	DB                string  `json:"db,omitempty"                 jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	App               string  `json:"app"                          jsonschema:"app to check"`
	RunID             string  `json:"run_id,omitempty"             jsonschema:"specific enrich_runs.run_id (uuid) to check (default: most-recent for app)"`
	ThresholdRelative float64 `json:"threshold_relative,omitempty" jsonschema:"override relative-delta threshold (default 0.20)"`
	MinRunSize        int     `json:"min_run_size,omitempty"       jsonschema:"override min modules processed (default 25)"`
}

func registerKbDriftCheckTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_drift_check",
		Description: "Phase G drift detection: compares the named enrich run " +
			"against the app's baseline and returns a verdict with per-metric " +
			"relative deltas. Skipped if no baseline set or run too small.",
	}, handleKbDriftCheck)
}

func handleKbDriftCheck(ctx context.Context, _ *mcp.CallToolRequest, in DriftCheckInput) (*mcp.CallToolResult, any, error) {
	cli, err := getDriftClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("drift client: %w", err)), nil, nil
	}
	v, err := cli.Check(ctx, supervisor.DriftCheckParams{
		App:               in.App,
		RunID:             in.RunID,
		ThresholdRelative: in.ThresholdRelative,
		MinRunSize:        in.MinRunSize,
	})
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(v), v, nil
}
