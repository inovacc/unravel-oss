/*
Copyright (c) 2026 Security Research
*/

// Package kbenrich / recordcost.go: plugin-path cost accounting. RecordCost
// takes a batch's observed subagent_tokens total, splits it input/output via
// a fixed 90/10 ratio (P1; refined to a calibrated estimator in P2), prices it
// via CostMicroUSD, writes per-module enrich_attempts token+cost columns,
// bumps the parent enrich_runs totals, and UPSERTs kb_cost_rollup for the app
// and global scopes. Idempotent on replay: an attempt row already priced
// (input_tokens IS NOT NULL) is skipped, so a re-sent batch never double-counts
// even when the per-module cost legitimately rounds to zero (unknown model or
// tiny token counts).
package kbenrich

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// inputTokenRatioP1 is the fixed fraction of a batch total attributed to input
// tokens on the subscription/plugin path. Output is small for enrichment
// (compact JSON), so 90/10 in/out is the P1 default. P2 replaces this with a
// self-calibrating estimator fitted against observed actuals.
const inputTokenRatioP1 = 0.9

// SplitTokens90_10 splits a batch token total into (input, output) using the
// fixed P1 ratio. Output is total-input so the two always sum to total
// (no token lost to rounding). Negative totals clamp to (0,0).
func SplitTokens90_10(total int64) (input, output int64) {
	if total <= 0 {
		return 0, 0
	}
	input = int64(float64(total) * inputTokenRatioP1)
	output = total - input
	return input, output
}

// RecordCostOptions controls RecordCost().
type RecordCostOptions struct {
	RunID       string
	App         string
	Model       string // pricing-table alias: haiku | sonnet | opus
	TotalTokens int64  // batch subagent_tokens observed by the orchestrator
	ModuleIDs   []int64
}

// RecordCostPayload is the response body for RecordCost(). It reports the
// delta actually applied (zero on a full replay where every module was
// already priced).
type RecordCostPayload struct {
	RunID             string `json:"run_id"`
	App               string `json:"app"`
	Model             string `json:"model"`
	TotalTokens       int64  `json:"total_tokens"`
	TotalCostMicroUSD int64  `json:"total_cost_micro_usd"`
	ModulesPriced     int    `json:"modules_priced"`
}

// RecordCost prices a batch's subagent_tokens and writes it through the
// per-module attempt rows, the run totals, and the cost rollup. Idempotent on
// replay: a module whose latest attempt is already priced (input_tokens IS NOT
// NULL) is skipped, so re-sending an identical batch never double-counts — even
// when the per-module cost rounds to zero (unknown model or tiny token counts).
// All writes run in one transaction.
func RecordCost(ctx context.Context, db *sql.DB, opts RecordCostOptions) (*RecordCostPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("RecordCost: nil db")
	}
	if opts.RunID == "" {
		return nil, fmt.Errorf("RecordCost: run_id required")
	}
	if len(opts.ModuleIDs) == 0 {
		return nil, fmt.Errorf("RecordCost: module_ids required")
	}
	model := opts.Model
	if model == "" {
		model = "claude-code-subagent"
	}

	inBatch, outBatch := SplitTokens90_10(opts.TotalTokens)
	n := int64(len(opts.ModuleIDs))
	inEach, inRem := inBatch/n, inBatch%n
	outEach, outRem := outBatch/n, outBatch%n

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("RecordCost: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	var appliedTok, appliedCost int64
	var priced int

	for i, mid := range opts.ModuleIDs {
		modIn, modOut := inEach, outEach
		if int64(i) == n-1 { // last module absorbs the remainder
			modIn += inRem
			modOut += outRem
		}
		modCost := CostMicroUSD(model, modIn, modOut)

		// Price the latest attempt row only when it is still unpriced. The
		// "unpriced" sentinel is input_tokens IS NULL (migration 000018 leaves
		// it NULL until priced); keying on cost_micro_usd=0 would re-match — and
		// double-count — a row whose real cost legitimately rounds to zero.
		res, uerr := tx.ExecContext(ctx, `
			UPDATE enrich_attempts
			   SET input_tokens=$2, output_tokens=$3, cost_micro_usd=$4
			 WHERE attempt_id = (
			       SELECT attempt_id FROM enrich_attempts
			        WHERE run_id=$1::uuid AND module_id=$5
			        ORDER BY attempt_id DESC LIMIT 1)
			   AND input_tokens IS NULL`,
			opts.RunID, modIn, modOut, modCost, mid)
		if uerr != nil {
			return nil, fmt.Errorf("RecordCost: price attempt module=%d: %w", mid, uerr)
		}
		affected, _ := res.RowsAffected()
		if affected == 0 {
			// affected==0 means the latest attempt is already priced
			// (input_tokens IS NOT NULL) OR no attempt row exists at all. Insert
			// a synthetic attempt only in the latter case, so replays of an
			// already-priced module are no-ops.
			var hasAttempt bool
			if qerr := tx.QueryRowContext(ctx, `
				SELECT EXISTS(SELECT 1 FROM enrich_attempts
				   WHERE run_id=$1::uuid AND module_id=$2)`,
				opts.RunID, mid).Scan(&hasAttempt); qerr != nil {
				return nil, fmt.Errorf("RecordCost: probe attempt module=%d: %w", mid, qerr)
			}
			if hasAttempt {
				continue // already priced — skip (idempotent)
			}
			if _, ierr := tx.ExecContext(ctx, `
				INSERT INTO enrich_attempts
				    (run_id, module_id, attempt_no, started_at, ended_at,
				     status, model_used, input_tokens, output_tokens, cost_micro_usd)
				VALUES ($1::uuid, $2, 1, NOW(), NOW(),
				        'success', $3, $4, $5, $6)`,
				opts.RunID, mid, model, modIn, modOut, modCost); ierr != nil {
				if isForeignKeyViolation(ierr) {
					return nil, fmt.Errorf("%w: %s", ErrRecordRunNotFound, opts.RunID)
				}
				return nil, fmt.Errorf("RecordCost: insert attempt module=%d: %w", mid, ierr)
			}
		}
		appliedTok += modIn + modOut
		appliedCost += modCost
		priced++
	}

	if priced > 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE enrich_runs
			   SET total_tokens = total_tokens + $2,
			       total_cost_micro_usd = total_cost_micro_usd + $3,
			       last_heartbeat_at = NOW()
			 WHERE run_id = $1::uuid`,
			opts.RunID, appliedTok, appliedCost); err != nil {
			return nil, fmt.Errorf("RecordCost: bump run: %w", err)
		}
		for _, sk := range [][2]string{{"app", opts.App}, {"global", "all"}} {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO kb_cost_rollup
				    (scope, key, total_tokens, total_cost_micro_usd, attempts, updated_at)
				VALUES ($1, $2, $3, $4, $5, NOW())
				ON CONFLICT (scope, key) DO UPDATE SET
				    total_tokens = kb_cost_rollup.total_tokens + EXCLUDED.total_tokens,
				    total_cost_micro_usd = kb_cost_rollup.total_cost_micro_usd + EXCLUDED.total_cost_micro_usd,
				    attempts = kb_cost_rollup.attempts + EXCLUDED.attempts,
				    updated_at = NOW()`,
				sk[0], sk[1], appliedTok, appliedCost, int64(priced)); err != nil {
				return nil, fmt.Errorf("RecordCost: upsert rollup %s/%s: %w", sk[0], sk[1], err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("RecordCost: commit: %w", err)
	}
	return &RecordCostPayload{
		RunID:             opts.RunID,
		App:               opts.App,
		Model:             model,
		TotalTokens:       appliedTok,
		TotalCostMicroUSD: appliedCost,
		ModulesPriced:     priced,
	}, nil
}

// CostReportOptions controls CostReport(). Empty App + empty RunID returns the
// global total plus all per-app rollup rows.
type CostReportOptions struct {
	App   string
	RunID string
}

// CostBucket is a single (tokens, cost, attempts) total with a label.
type CostBucket struct {
	Scope             string `json:"scope"`
	Key               string `json:"key"`
	TotalTokens       int64  `json:"total_tokens"`
	TotalCostMicroUSD int64  `json:"total_cost_micro_usd"`
	Attempts          int64  `json:"attempts"`
}

// CostRunBucket is per-run totals read from enrich_runs.
type CostRunBucket struct {
	RunID             string `json:"run_id"`
	App               string `json:"app"`
	TotalTokens       int64  `json:"total_tokens"`
	TotalCostMicroUSD int64  `json:"total_cost_micro_usd"`
}

// CostReportPayload is the response body for CostReport().
type CostReportPayload struct {
	Global *CostBucket     `json:"global"`
	App    *CostBucket     `json:"app,omitempty"`
	Apps   []CostBucket    `json:"apps,omitempty"`
	Runs   []CostRunBucket `json:"runs,omitempty"`
}

// CostReport reads per-run/per-app/global totals from kb_cost_rollup +
// enrich_runs. Global is always populated (zero bucket if no rollup yet).
func CostReport(ctx context.Context, db *sql.DB, opts CostReportOptions) (*CostReportPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("CostReport: nil db")
	}
	out := &CostReportPayload{}

	// Global bucket (zero if absent).
	g := CostBucket{Scope: "global", Key: "all"}
	if err := db.QueryRowContext(ctx, `
		SELECT COALESCE(total_tokens,0), COALESCE(total_cost_micro_usd,0), COALESCE(attempts,0)
		  FROM kb_cost_rollup WHERE scope='global' AND key='all'`).
		Scan(&g.TotalTokens, &g.TotalCostMicroUSD, &g.Attempts); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("CostReport: global: %w", err)
	}
	out.Global = &g

	if opts.App != "" {
		a := CostBucket{Scope: "app", Key: opts.App}
		err := db.QueryRowContext(ctx, `
			SELECT COALESCE(total_tokens,0), COALESCE(total_cost_micro_usd,0), COALESCE(attempts,0)
			  FROM kb_cost_rollup WHERE scope='app' AND key=$1`, opts.App).
			Scan(&a.TotalTokens, &a.TotalCostMicroUSD, &a.Attempts)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("CostReport: app: %w", err)
		}
		out.App = &a
	} else {
		rows, err := db.QueryContext(ctx, `
			SELECT key, total_tokens, total_cost_micro_usd, attempts
			  FROM kb_cost_rollup WHERE scope='app' ORDER BY total_cost_micro_usd DESC`)
		if err != nil {
			return nil, fmt.Errorf("CostReport: apps: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			b := CostBucket{Scope: "app"}
			if err := rows.Scan(&b.Key, &b.TotalTokens, &b.TotalCostMicroUSD, &b.Attempts); err != nil {
				return nil, fmt.Errorf("CostReport: scan app: %w", err)
			}
			out.Apps = append(out.Apps, b)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("CostReport: apps rows: %w", err)
		}
	}

	if opts.RunID != "" {
		r := CostRunBucket{RunID: opts.RunID}
		err := db.QueryRowContext(ctx, `
			SELECT app, total_tokens, total_cost_micro_usd
			  FROM enrich_runs WHERE run_id=$1::uuid`, opts.RunID).
			Scan(&r.App, &r.TotalTokens, &r.TotalCostMicroUSD)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w: %s", ErrRecordRunNotFound, opts.RunID)
			}
			return nil, fmt.Errorf("CostReport: run: %w", err)
		}
		out.Runs = append(out.Runs, r)
	} else if opts.App != "" {
		rows, err := db.QueryContext(ctx, `
			SELECT run_id::text, app, total_tokens, total_cost_micro_usd
			  FROM enrich_runs WHERE app=$1 ORDER BY started_at DESC LIMIT 50`, opts.App)
		if err != nil {
			return nil, fmt.Errorf("CostReport: app runs: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r CostRunBucket
			if err := rows.Scan(&r.RunID, &r.App, &r.TotalTokens, &r.TotalCostMicroUSD); err != nil {
				return nil, fmt.Errorf("CostReport: scan run: %w", err)
			}
			out.Runs = append(out.Runs, r)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("CostReport: app runs rows: %w", err)
		}
	}

	return out, nil
}
