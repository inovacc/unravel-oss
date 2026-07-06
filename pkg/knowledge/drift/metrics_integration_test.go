//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package drift_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/drift"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// seedFixture creates an enrich_runs row with N modules, of which `success`
// have summary set (and !needs_human_verification), `escalated` have
// escalated_to='opus', `humanReview` have needs_human_verification=true,
// and SUM(enrich_attempts.cost_micro_usd) = total*meanCost.
//
// Counts are disjoint: rows 1..success are clean successes,
// rows success+1..success+escalated are opus successes (summary set, escalated_to='opus'),
// rows success+escalated+1..success+escalated+humanReview are flagged (no summary).
// Remaining rows have NULL summary (unprocessed).
//
// modules.id is GENERATED ALWAYS AS IDENTITY so we use OVERRIDING SYSTEM VALUE
// to supply stable ids for cross-table foreign-key references.
func seedFixture(t *testing.T, ctx context.Context, db *sql.DB, app string,
	total, success, escalated, humanReview int, meanCostPerModule int64,
) string {
	t.Helper()

	var runID string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO enrich_runs (app, model, concurrency, prompt_batch, status, started_at,
		                          total_target, completed, failed, last_heartbeat_at, host, pid)
		 VALUES ($1, 'test', 1, 1, 'completed', now(), $2, $2, 0, now(), 'test', 0)
		 RETURNING run_id::text`, app, total).Scan(&runID); err != nil {
		t.Fatalf("seed enrich_runs: %v", err)
	}

	// Use a stable per-run bigint namespace derived from the run's hash to avoid
	// id collisions across multiple seedFixture calls within the same test DB.
	var baseID int64
	if err := db.QueryRowContext(ctx,
		`SELECT ('x'||substr(md5($1),1,15))::bit(60)::bigint * 10000`, runID).Scan(&baseID); err != nil {
		t.Fatalf("derive base id: %v", err)
	}
	if baseID < 0 {
		baseID = -baseID
	}
	if baseID == 0 {
		baseID = 1
	}

	for i := 1; i <= total; i++ {
		modID := baseID + int64(i)
		var summary sql.NullString
		var escalatedTo sql.NullString
		needsHR := false

		switch {
		case i <= success:
			summary = sql.NullString{String: "ok", Valid: true}
		case i <= success+escalated:
			summary = sql.NullString{String: "ok via opus", Valid: true}
			escalatedTo = sql.NullString{String: "opus", Valid: true}
		case i <= success+escalated+humanReview:
			needsHR = true
		}

		// body_sha256 must be NOT NULL and unique per (app, body_sha256).
		sha := fmt.Sprintf("sha-%s-%d", app, modID)

		if _, err := db.ExecContext(ctx,
			`INSERT INTO modules (id, app, name, body_sha256, summary, escalated_to, needs_human_verification)
			 OVERRIDING SYSTEM VALUE
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			modID, app, fmt.Sprintf("mod-%s-%d", app, i), sha, summary, escalatedTo, needsHR,
		); err != nil {
			t.Fatalf("seed module %d: %v", i, err)
		}

		// One attempt per module with cost = meanCostPerModule.
		if _, err := db.ExecContext(ctx,
			`INSERT INTO enrich_attempts (run_id, module_id, attempt_no, status, model_used, cost_micro_usd)
			 VALUES ($1::uuid, $2, 1, 'success', 'test', $3)`, runID, modID, meanCostPerModule); err != nil {
			t.Fatalf("seed attempt for module %d: %v", i, err)
		}
	}
	return runID
}

func TestComputeMetrics_GoldenRun(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)

	// 10 modules: 7 clean successes, 1 opus success, 1 human-review flag,
	// 1 unprocessed (no summary, no escalation). Mean cost = 5000 micro-USD.
	runID := seedFixture(t, ctx, db, "canary", 10, 7, 1, 1, 5000)

	got, err := drift.ComputeMetrics(ctx, db, runID)
	if err != nil {
		t.Fatalf("ComputeMetrics: %v", err)
	}

	// n_success = modules with summary AND !needs_human_verification:
	// 7 clean + 1 opus (opus row has summary set and needs_HR=false) = 8
	// success_rate = 8/10 = 0.8
	wantSuccess := 0.8
	if got.SuccessRate != wantSuccess {
		t.Errorf("SuccessRate = %v, want %v", got.SuccessRate, wantSuccess)
	}

	wantEsc := 0.1 // 1/10
	if got.EscalationRate != wantEsc {
		t.Errorf("EscalationRate = %v, want %v", got.EscalationRate, wantEsc)
	}

	wantHR := 0.1 // 1/10
	if got.HumanReviewRate != wantHR {
		t.Errorf("HumanReviewRate = %v, want %v", got.HumanReviewRate, wantHR)
	}

	wantCost := 5000.0 // 10 attempts × 5000 / 10 modules = 5000
	if got.MeanCostMicroUSD != wantCost {
		t.Errorf("MeanCostMicroUSD = %v, want %v", got.MeanCostMicroUSD, wantCost)
	}

	if got.ModulesProcessed != 10 {
		t.Errorf("ModulesProcessed = %d, want 10", got.ModulesProcessed)
	}
	if got.App != "canary" {
		t.Errorf("App = %q, want %q", got.App, "canary")
	}
	if got.RunID != runID {
		t.Errorf("RunID = %q, want %q", got.RunID, runID)
	}
}

func TestComputeMetrics_RunNotFound(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)

	_, err := drift.ComputeMetrics(ctx, db, "00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatalf("ComputeMetrics with bogus id: got nil err, want ErrRunNotFound")
	}
}
