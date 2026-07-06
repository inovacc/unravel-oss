/*
Copyright (c) 2026 Security Research
*/

// Package mcptools / kb_enrich_run_record.go registers unravel_kb_enrich_record
// — a single combined MCP tool used by the /unravel-enrich plugin skill to
// (a) start a run audit row in enrich_runs and (b) record per-module
// attempt outcomes in enrich_attempts. Pairs with unravel_kb_enrich_pending
// + unravel_kb_enrich_write_enrichment to provide the run_id audit chain that
// existed for the legacy EnrichCore path but was lost when the plugin
// pivot moved orchestration into the Claude Code session.
//
// Thin delegate: all SQL lives in pkg/knowledge/kbenrich/record.go so the
// supervisor dispatcher (enrich.record) and this MCP tool share one
// implementation. The extraction also fixed the column-name mismatch
// between the legacy SQL here and the real migration-000013 schema —
// see kbenrich/record.go comment for detail.
package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/supervisor"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// KBEnrichRecordInput is the typed input. Two modes:
//   - action="start" — insert a new enrich_runs row, return run_id
//   - action="attempt" — insert an enrich_attempts row keyed by (run_id, module_id, attempt_no)
type KBEnrichRecordInput struct {
	Action      string `json:"action" jsonschema:"'start' to open a new run, 'attempt' to record one module's outcome"`
	DB          string `json:"db,omitempty" jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	App         string `json:"app,omitempty" jsonschema:"app the run targets (start mode)"`
	TotalTarget int    `json:"total_target,omitempty" jsonschema:"limit value for this run (start mode)"`
	Model       string `json:"model,omitempty" jsonschema:"model label (start mode; default 'claude-code-subagent')"`
	RunID       string `json:"run_id,omitempty" jsonschema:"existing run_id (attempt mode)"`
	ModuleID    int64  `json:"module_id,omitempty" jsonschema:"module id (attempt mode)"`
	AttemptNo   int    `json:"attempt_no,omitempty" jsonschema:"attempt number (attempt mode; default 1)"`
	Status      string `json:"status,omitempty" jsonschema:"'success' | 'failure' | 'timeout' | 'interrupted' (attempt mode)"`
	ErrorClass  string `json:"error_class,omitempty" jsonschema:"short classification (attempt mode; e.g. 'parse', 'schema')"`
	ErrorMsg    string `json:"error_message,omitempty" jsonschema:"redacted error message (attempt mode)"`
}

func registerKBEnrichRecordTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_enrich_record",
		Description: "Run-audit recorder for the /unravel-enrich plugin path. " +
			"action='start' opens a new enrich_runs row and returns its run_id; " +
			"action='attempt' inserts one enrich_attempts row keyed by " +
			"(run_id, module_id, attempt_no). Pair with unravel_kb_enrich_status " +
			"for cross-session visibility of plugin-driven runs.",
	}, handleKBEnrichRecord)
}

func handleKBEnrichRecord(ctx context.Context, _ *mcp.CallToolRequest, in KBEnrichRecordInput) (*mcp.CallToolResult, any, error) {
	if in.Action != "start" && in.Action != "attempt" {
		return errorResult(fmt.Errorf("action must be 'start' or 'attempt', got %q", in.Action)), nil, nil
	}
	cli, err := getEnrichClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("enrich client: %w", err)), nil, nil
	}
	payload, err := cli.Record(ctx, supervisor.EnrichRecordParams{
		Action:      in.Action,
		App:         in.App,
		TotalTarget: in.TotalTarget,
		Model:       in.Model,
		RunID:       in.RunID,
		ModuleID:    in.ModuleID,
		AttemptNo:   in.AttemptNo,
		Status:      in.Status,
		ErrorClass:  in.ErrorClass,
		ErrorMsg:    in.ErrorMsg,
	})
	if err != nil {
		return errorResult(fmt.Errorf("enrich.record: %w", err)), nil, nil
	}
	return jsonResult(payload), payload, nil
}
