/*
Copyright (c) 2026 Security Research
*/
package drift

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrRunNotFound indicates the enrich_runs row for the requested id doesn't exist.
var ErrRunNotFound = errors.New("enrich_runs row not found")

// ComputeMetrics aggregates a single enrich run's outcomes into RunMetrics.
// Reads enrich_runs + enrich_attempts + modules (joined on app). Idempotent.
func ComputeMetrics(ctx context.Context, db *sql.DB, runID string) (RunMetrics, error) {
	const q = `
WITH run AS (
    SELECT run_id, app, completed
      FROM enrich_runs
     WHERE run_id = $1::uuid
),
mods AS (
    SELECT
        COUNT(*) FILTER (WHERE m.summary IS NOT NULL
                          AND m.needs_human_verification = false) AS n_success,
        COUNT(*) FILTER (WHERE m.escalated_to = 'opus')          AS n_escalated,
        COUNT(*) FILTER (WHERE m.needs_human_verification)        AS n_human_review
      FROM modules m, run
     WHERE m.app = run.app
),
cost AS (
    SELECT COALESCE(SUM(ea.cost_micro_usd), 0)::float8 AS sum_cost
      FROM enrich_attempts ea, run
     WHERE ea.run_id = run.run_id
)
SELECT
    run.run_id::text,
    run.app,
    run.completed,
    CASE WHEN run.completed > 0
         THEN mods.n_success::float8 / run.completed
         ELSE 0 END                                          AS success_rate,
    CASE WHEN run.completed > 0
         THEN mods.n_escalated::float8 / run.completed
         ELSE 0 END                                          AS escalation_rate,
    CASE WHEN run.completed > 0
         THEN mods.n_human_review::float8 / run.completed
         ELSE 0 END                                          AS human_review_rate,
    CASE WHEN run.completed > 0
         THEN cost.sum_cost / run.completed
         ELSE 0 END                                          AS mean_cost_micro_usd
FROM run, mods, cost;`

	var m RunMetrics
	err := db.QueryRowContext(ctx, q, runID).Scan(
		&m.RunID, &m.App, &m.ModulesProcessed,
		&m.SuccessRate, &m.EscalationRate, &m.HumanReviewRate, &m.MeanCostMicroUSD,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return RunMetrics{}, fmt.Errorf("%w: id=%s", ErrRunNotFound, runID)
	}
	if err != nil {
		return RunMetrics{}, fmt.Errorf("compute metrics: %w", err)
	}
	return m, nil
}
