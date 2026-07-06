/*
Copyright (c) 2026 Security Research
*/

// Package mcptools / kb_cost_report.go registers unravel_kb_enrich_cost_report — the
// read+record surface for KB enrichment cost accounting (Phase 1). Thin
// client: dials the host-singleton supervisor and calls enrich.cost_report
// (mode=report) or enrich.record_cost (mode=record). All SQL lives in
// pkg/knowledge/kbenrich; the supervisor owns the DB pool.
package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/supervisor"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// KBCostReportInput is the typed input for unravel_kb_enrich_cost_report.
type KBCostReportInput struct {
	Mode        string  `json:"mode,omitempty" jsonschema:"'report' (default) reads totals; 'record' prices a batch's subagent_tokens"`
	App         string  `json:"app,omitempty" jsonschema:"app filter (report) / app the batch belongs to (record)"`
	RunID       string  `json:"run_id,omitempty" jsonschema:"run_id to scope a report to one run, or the run the batch belongs to (record)"`
	Model       string  `json:"model,omitempty" jsonschema:"pricing model alias for record mode: haiku | sonnet | opus (default haiku)"`
	TotalTokens int64   `json:"total_tokens,omitempty" jsonschema:"record mode: the batch's observed subagent_tokens total"`
	ModuleIDs   []int64 `json:"module_ids,omitempty" jsonschema:"record mode: module ids the batch covered (cost split evenly across them)"`
}

func registerKBCostReportTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_enrich_cost_report",
		Description: "KB enrichment cost accounting (Phase 1). mode='report' (default) " +
			"returns per-run/per-app/global token + notional-USD totals from kb_cost_rollup " +
			"and enrich_runs. mode='record' prices a batch's subagent_tokens (90/10 in/out " +
			"split), writes per-module attempt token+cost, and bumps the run + rollup totals " +
			"(idempotent on replay). Notional USD is a budgeting figure, not a bill — the " +
			"subscription path makes no API charge.",
	}, handleKBCostReport)
}

func handleKBCostReport(ctx context.Context, _ *mcp.CallToolRequest, in KBCostReportInput) (*mcp.CallToolResult, any, error) {
	mode := in.Mode
	if mode == "" {
		mode = "report"
	}
	cli, err := getEnrichClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("enrich client: %w", err)), nil, nil
	}

	switch mode {
	case "record":
		if in.RunID == "" {
			return errorResult(fmt.Errorf("run_id is required for mode=record")), nil, nil
		}
		if len(in.ModuleIDs) == 0 {
			return errorResult(fmt.Errorf("module_ids is required for mode=record")), nil, nil
		}
		model := in.Model
		if model == "" {
			model = "haiku"
		}
		res, err := cli.RecordCost(ctx, supervisor.EnrichRecordCostParams{
			RunID:       in.RunID,
			App:         in.App,
			Model:       model,
			TotalTokens: in.TotalTokens,
			ModuleIDs:   in.ModuleIDs,
		})
		if err != nil {
			return errorResult(fmt.Errorf("record cost: %w", err)), nil, nil
		}
		out := map[string]any{
			"mode":                 "record",
			"run_id":               res.RunID,
			"app":                  res.App,
			"model":                res.Model,
			"total_tokens":         res.TotalTokens,
			"total_cost_micro_usd": res.TotalCostMicroUSD,
			"modules_priced":       res.ModulesPriced,
		}
		return jsonResult(out), out, nil

	case "report":
		res, err := cli.CostReport(ctx, supervisor.EnrichCostReportParams{
			App:   in.App,
			RunID: in.RunID,
		})
		if err != nil {
			return errorResult(fmt.Errorf("cost report: %w", err)), nil, nil
		}
		out := map[string]any{
			"mode":   "report",
			"global": res.Global,
			"app":    res.App,
			"apps":   res.Apps,
			"runs":   res.Runs,
		}
		return jsonResult(out), out, nil

	default:
		return errorResult(fmt.Errorf("mode must be 'report' or 'record', got %q", mode)), nil, nil
	}
}
