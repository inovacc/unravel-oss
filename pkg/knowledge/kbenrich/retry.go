/*
Copyright (c) 2026 Security Research
*/

// Package kbenrich / retry.go: free-function Retry() extracted from
// pkg/mcp/tools/knowledge_enrich_retry.go. Re-runs failed / timed-out
// modules from a prior enrich run under a new enrich_runs row whose
// parent_run_id points back at the source.
//
// The LLM call seam is the kbenrich.CallFn parameter so the dispatcher
// (supervisor.enrich.retry) injects kbllm.Call and the MCP-tool test path
// can inject a stub.
package kbenrich

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrRetryRunNotFound is returned when Retry can't locate the parent run.
// Wrappers (supervisor dispatch + client) translate this to CodeNotFound /
// ErrEnrichRunNotFound respectively.
var ErrRetryRunNotFound = errors.New("kbenrich: parent run not found")

// RetryHardMaxConcurrent caps the per-call internal worker fanout regardless
// of what the caller asks for. Mirrors the cap used by the legacy MCP-tool
// path so dispatcher behaviour is unchanged.
const RetryHardMaxConcurrent = 16

// RetryOptions controls Retry().
//
//   - RunID      : required; source run whose failed attempts will be re-run
//   - ErrorClass : optional filter — only re-run attempts with this error_class
//   - Concurrent : worker fanout (default 8, hard cap RetryHardMaxConcurrent)
//   - Model      : "sonnet" (default) or "haiku"
//   - TimeoutSec : per-module LLM timeout passed through to EnrichCore (default 90)
type RetryOptions struct {
	RunID      string
	ErrorClass string
	Concurrent int
	Model      string
	TimeoutSec int
}

// RetryPayload is the response body for Retry().
type RetryPayload struct {
	ParentRunID string  `json:"parent_run_id"`
	Summary     Summary `json:"summary"`
	Note        string  `json:"note,omitempty"`
}

// Retry re-runs failed / timed-out attempts from parent opts.RunID under
// a NEW enrich_runs row. callFn is the LLM seam — the dispatcher injects
// kbllm.Call; tests inject a stub.
//
// Returns ErrRetryRunNotFound (wrapped) when the parent run row does not
// exist.
func Retry(ctx context.Context, db *sql.DB, opts RetryOptions, callFn CallFn) (*RetryPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("Retry: nil db")
	}
	if opts.RunID == "" {
		return nil, fmt.Errorf("Retry: run_id is required")
	}
	if opts.Model == "" {
		opts.Model = "sonnet"
	}
	if opts.Model != "sonnet" && opts.Model != "haiku" {
		return nil, fmt.Errorf("Retry: invalid model %q: must be 'sonnet' or 'haiku'", opts.Model)
	}
	if opts.Concurrent < 1 {
		opts.Concurrent = 8
	}
	if opts.Concurrent > RetryHardMaxConcurrent {
		opts.Concurrent = RetryHardMaxConcurrent
	}
	if opts.TimeoutSec < 1 {
		opts.TimeoutSec = 90
	}

	moduleIDs, app, err := SelectRetryModuleIDs(ctx, db, opts.RunID, opts.ErrorClass)
	if err != nil {
		return nil, err
	}
	if len(moduleIDs) == 0 {
		return &RetryPayload{
			ParentRunID: opts.RunID,
			Summary:     Summary{ModelUsed: opts.Model},
			Note:        "no failed/timeout/interrupted modules found for filter",
		}, nil
	}

	summary, err := EnrichCore(ctx, db, Opts{
		App:          app,
		Limit:        len(moduleIDs),
		Concurrent:   opts.Concurrent,
		Model:        opts.Model,
		BoundedInput: true,
		PromptBatch:  1,
		TimeoutSec:   opts.TimeoutSec,
		ModuleIDs:    moduleIDs,
		ParentRunID:  opts.RunID,
		ForceNewRun:  true,
	}, callFn)
	if err != nil {
		return nil, fmt.Errorf("enrich: %w", err)
	}

	return &RetryPayload{ParentRunID: opts.RunID, Summary: summary}, nil
}

// SelectRetryModuleIDs returns the distinct module_ids that should be
// re-run for parent run_id, optionally narrowed by error_class. Also
// returns the app of the parent run so the new run is tagged correctly.
//
// Returns ErrRetryRunNotFound (wrapped) when the parent run row does not exist.
func SelectRetryModuleIDs(ctx context.Context, db *sql.DB, parentRunID, errorClass string) ([]int64, string, error) {
	var app string
	err := db.QueryRowContext(ctx, `SELECT app FROM enrich_runs WHERE run_id=$1::uuid`, parentRunID).Scan(&app)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", fmt.Errorf("%w: %s", ErrRetryRunNotFound, parentRunID)
	}
	if err != nil {
		return nil, "", fmt.Errorf("parent run lookup: %w", err)
	}

	q := `SELECT DISTINCT module_id FROM enrich_attempts
	       WHERE run_id = $1::uuid
	         AND status IN ('failure','timeout')`
	args := []any{parentRunID}
	if errorClass != "" {
		q += " AND error_class = $2"
		args = append(args, errorClass)
	}
	q += " ORDER BY module_id"

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, "", err
		}
		ids = append(ids, id)
	}
	return ids, app, rows.Err()
}
