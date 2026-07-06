/*
Copyright (c) 2026 Security Research
*/
// unravel_kb_drift_baseline — set / clear / show the per-app drift baseline.
package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DriftBaselineInput is the typed input for unravel_kb_drift_baseline.
type DriftBaselineInput struct {
	DB     string `json:"db,omitempty"     jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	Action string `json:"action"           jsonschema:"set | clear | show"`
	App    string `json:"app"              jsonschema:"app to manage"`
	RunID  string `json:"run_id,omitempty" jsonschema:"required for action=set; enrich_runs.run_id (uuid)"`
	Force  bool   `json:"force,omitempty"  jsonschema:"set: allow baseline below min-run-size"`
}

// DriftBaselineOutput is the typed output for unravel_kb_drift_baseline.
type DriftBaselineOutput struct {
	BaselineRunID string `json:"baseline_run_id,omitempty"`
	Cleared       bool   `json:"cleared,omitempty"`
	Note          string `json:"note,omitempty"`
}

func registerKbDriftBaselineTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_drift_baseline",
		Description: "Set / clear / show the per-app drift baseline. " +
			"action=set requires run_id; refuses runs below min-run-size " +
			"unless force=true.",
	}, handleKbDriftBaseline)
}

func handleKbDriftBaseline(ctx context.Context, _ *mcp.CallToolRequest, in DriftBaselineInput) (*mcp.CallToolResult, any, error) {
	action := in.Action
	if action == "" {
		action = "show"
	}
	if action != "set" && action != "clear" && action != "show" {
		return errorResult(fmt.Errorf("unknown action %q (want set|clear|show)", action)), nil, nil
	}
	if action == "set" && in.RunID == "" {
		return errorResult(fmt.Errorf("action=set requires run_id")), nil, nil
	}
	cli, err := getDriftClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("drift client: %w", err)), nil, nil
	}
	res, err := cli.Baseline(ctx, action, in.App, in.RunID, in.Force)
	if err != nil {
		return errorResult(err), nil, nil
	}
	out := DriftBaselineOutput{
		BaselineRunID: res.BaselineRunID,
		Cleared:       res.Cleared,
		Note:          res.Note,
	}
	return jsonResult(out), out, nil
}
