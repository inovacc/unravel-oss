//go:build integration

/*
Copyright (c) 2026 Security Research
*/

package kbenrich_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

// seedCounter makes each seeded module's name + body_sha256 unique within a run.
var seedCounter int64

// seedModule inserts a minimal modules row and returns its id. body_sha256 is
// NOT NULL in the modules schema, so each row gets a distinct synthetic 64-hex
// digest (and a unique name) to avoid collisions across multiple seeds.
func seedModule(t *testing.T, db *sql.DB, app string) int64 {
	t.Helper()
	n := atomic.AddInt64(&seedCounter, 1)
	var id int64
	if err := db.QueryRow(
		`INSERT INTO modules (app, name, body_sha256) VALUES ($1, $2, $3) RETURNING id`,
		app, fmt.Sprintf("mod-%s-%d", app, n), fmt.Sprintf("%064x", n)).Scan(&id); err != nil {
		t.Fatalf("seed module: %v", err)
	}
	return id
}

func TestRecordCost_WritesAttemptsBumpsRunAndRollup(t *testing.T) {
	conn, _ := dbtest.StartPostgresOrSkip(t)
	ctx := context.Background()

	app := "whatsapp"
	run, err := kbenrich.StartRun(ctx, conn, kbenrich.StartRunOptions{
		App: app, TotalTarget: 2, Model: "haiku",
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	m1 := seedModule(t, conn, app)
	m2 := seedModule(t, conn, app)
	// One pre-existing attempt per module (status success, cost 0).
	for _, m := range []int64{m1, m2} {
		if _, err := kbenrich.RecordAttempt(ctx, conn, kbenrich.RecordAttemptOptions{
			RunID: run.RunID, ModuleID: m, Status: "success", ModelUsed: "haiku",
		}); err != nil {
			t.Fatalf("RecordAttempt m=%d: %v", m, err)
		}
	}

	out, err := kbenrich.RecordCost(ctx, conn, kbenrich.RecordCostOptions{
		RunID:       run.RunID,
		App:         app,
		Model:       "haiku",
		TotalTokens: 2000,
		ModuleIDs:   []int64{m1, m2},
	})
	if err != nil {
		t.Fatalf("RecordCost: %v", err)
	}
	if out.TotalTokens != 2000 {
		t.Errorf("recorded total_tokens = %d, want 2000", out.TotalTokens)
	}
	// 2000 total => 1800 in / 200 out @ haiku (800000/4000000 per M):
	// (1800*800000 + 200*4000000)/1e6 = 1440 + 800 = 2240 micro-USD.
	if out.TotalCostMicroUSD != 2240 {
		t.Errorf("recorded cost = %d, want 2240", out.TotalCostMicroUSD)
	}

	// enrich_runs bumped.
	var runTok, runCost int64
	if err := conn.QueryRow(
		`SELECT total_tokens, total_cost_micro_usd FROM enrich_runs WHERE run_id=$1::uuid`,
		run.RunID).Scan(&runTok, &runCost); err != nil {
		t.Fatalf("scan run totals: %v", err)
	}
	if runTok != 2000 || runCost != 2240 {
		t.Errorf("run totals = (%d,%d), want (2000,2240)", runTok, runCost)
	}

	// Per-module attempt rows priced (1000 tokens each).
	var mtok int64
	if err := conn.QueryRow(`
		SELECT COALESCE(input_tokens,0)+COALESCE(output_tokens,0)
		  FROM enrich_attempts WHERE module_id=$1 ORDER BY attempt_id DESC LIMIT 1`,
		m1).Scan(&mtok); err != nil {
		t.Fatalf("scan m1 tokens: %v", err)
	}
	if mtok != 1000 {
		t.Errorf("m1 attempt tokens = %d, want 1000", mtok)
	}

	// Rollup: app + global both bumped.
	for _, sk := range [][2]string{{"app", app}, {"global", "all"}} {
		var tok, cost, att int64
		if err := conn.QueryRow(`
			SELECT total_tokens, total_cost_micro_usd, attempts
			  FROM kb_cost_rollup WHERE scope=$1 AND key=$2`,
			sk[0], sk[1]).Scan(&tok, &cost, &att); err != nil {
			t.Fatalf("scan rollup %v: %v", sk, err)
		}
		if tok != 2000 || cost != 2240 || att != 2 {
			t.Errorf("rollup %v = (%d,%d,%d), want (2000,2240,2)", sk, tok, cost, att)
		}
	}
}

func TestRecordCost_IdempotentOnReplay(t *testing.T) {
	conn, _ := dbtest.StartPostgresOrSkip(t)
	ctx := context.Background()
	app := "teams"
	run, err := kbenrich.StartRun(ctx, conn, kbenrich.StartRunOptions{
		App: app, TotalTarget: 1, Model: "haiku",
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	m := seedModule(t, conn, app)
	if _, err := kbenrich.RecordAttempt(ctx, conn, kbenrich.RecordAttemptOptions{
		RunID: run.RunID, ModuleID: m, Status: "success", ModelUsed: "haiku",
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	opts := kbenrich.RecordCostOptions{
		RunID: run.RunID, App: app, Model: "haiku",
		TotalTokens: 1000, ModuleIDs: []int64{m},
	}
	if _, err := kbenrich.RecordCost(ctx, conn, opts); err != nil {
		t.Fatalf("RecordCost first: %v", err)
	}
	// Replay the identical batch — must NOT double count.
	if _, err := kbenrich.RecordCost(ctx, conn, opts); err != nil {
		t.Fatalf("RecordCost replay: %v", err)
	}
	var runTok int64
	if err := conn.QueryRow(
		`SELECT total_tokens FROM enrich_runs WHERE run_id=$1::uuid`,
		run.RunID).Scan(&runTok); err != nil {
		t.Fatalf("scan run: %v", err)
	}
	if runTok != 1000 {
		t.Errorf("run total_tokens after replay = %d, want 1000 (no double-count)", runTok)
	}
	var glTok int64
	if err := conn.QueryRow(
		`SELECT total_tokens FROM kb_cost_rollup WHERE scope='global' AND key='all'`).
		Scan(&glTok); err != nil {
		t.Fatalf("scan global rollup: %v", err)
	}
	if glTok != 1000 {
		t.Errorf("global rollup after replay = %d, want 1000", glTok)
	}
}

// TestRecordCost_IdempotentOnReplay_ZeroCost guards the idempotency fix: an
// unknown model prices every module to cost 0, so keying the replay guard on
// cost_micro_usd=0 (rather than input_tokens IS NULL) would re-match the row
// and double-count tokens + rollup attempts on a re-sent batch.
func TestRecordCost_IdempotentOnReplay_ZeroCost(t *testing.T) {
	conn, _ := dbtest.StartPostgresOrSkip(t)
	ctx := context.Background()
	app := "teams"
	run, err := kbenrich.StartRun(ctx, conn, kbenrich.StartRunOptions{
		App: app, TotalTarget: 1, Model: "haiku",
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	m := seedModule(t, conn, app)
	if _, err := kbenrich.RecordAttempt(ctx, conn, kbenrich.RecordAttemptOptions{
		RunID: run.RunID, ModuleID: m, Status: "success", ModelUsed: "haiku",
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	opts := kbenrich.RecordCostOptions{
		RunID: run.RunID, App: app, Model: "unknown-model-alias",
		TotalTokens: 1000, ModuleIDs: []int64{m},
	}
	if _, err := kbenrich.RecordCost(ctx, conn, opts); err != nil {
		t.Fatalf("RecordCost first: %v", err)
	}
	// Replay the identical zero-cost batch — must NOT double count.
	if _, err := kbenrich.RecordCost(ctx, conn, opts); err != nil {
		t.Fatalf("RecordCost replay: %v", err)
	}
	var runTok, runCost int64
	if err := conn.QueryRow(
		`SELECT total_tokens, total_cost_micro_usd FROM enrich_runs WHERE run_id=$1::uuid`,
		run.RunID).Scan(&runTok, &runCost); err != nil {
		t.Fatalf("scan run: %v", err)
	}
	if runTok != 1000 {
		t.Errorf("run total_tokens after zero-cost replay = %d, want 1000 (no double-count)", runTok)
	}
	if runCost != 0 {
		t.Errorf("run total_cost_micro_usd = %d, want 0 (unknown model is unpriced)", runCost)
	}
	var glTok, glAtt int64
	if err := conn.QueryRow(
		`SELECT total_tokens, attempts FROM kb_cost_rollup WHERE scope='global' AND key='all'`).
		Scan(&glTok, &glAtt); err != nil {
		t.Fatalf("scan global rollup: %v", err)
	}
	if glTok != 1000 {
		t.Errorf("global rollup tokens after zero-cost replay = %d, want 1000", glTok)
	}
	if glAtt != 1 {
		t.Errorf("global rollup attempts after zero-cost replay = %d, want 1 (no double-count)", glAtt)
	}
}

func TestCostReport_SumsPerRunAppGlobal(t *testing.T) {
	conn, _ := dbtest.StartPostgresOrSkip(t)
	ctx := context.Background()
	app := "slack"
	run, err := kbenrich.StartRun(ctx, conn, kbenrich.StartRunOptions{
		App: app, TotalTarget: 1, Model: "haiku",
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	m := seedModule(t, conn, app)
	if _, err := kbenrich.RecordAttempt(ctx, conn, kbenrich.RecordAttemptOptions{
		RunID: run.RunID, ModuleID: m, Status: "success", ModelUsed: "haiku",
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	if _, err := kbenrich.RecordCost(ctx, conn, kbenrich.RecordCostOptions{
		RunID: run.RunID, App: app, Model: "haiku",
		TotalTokens: 1000, ModuleIDs: []int64{m},
	}); err != nil {
		t.Fatalf("RecordCost: %v", err)
	}

	rep, err := kbenrich.CostReport(ctx, conn, kbenrich.CostReportOptions{App: app})
	if err != nil {
		t.Fatalf("CostReport: %v", err)
	}
	if rep.Global.TotalTokens < 1000 {
		t.Errorf("global tokens = %d, want >= 1000", rep.Global.TotalTokens)
	}
	if rep.App == nil || rep.App.TotalTokens != 1000 {
		t.Errorf("app rollup = %+v, want tokens 1000", rep.App)
	}

	repRun, err := kbenrich.CostReport(ctx, conn, kbenrich.CostReportOptions{RunID: run.RunID})
	if err != nil {
		t.Fatalf("CostReport run: %v", err)
	}
	if len(repRun.Runs) != 1 || repRun.Runs[0].TotalTokens != 1000 {
		t.Errorf("run report = %+v, want 1 run with 1000 tokens", repRun.Runs)
	}
}
