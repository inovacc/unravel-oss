//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package kbenrich_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

// TestCrashMidRunResumes implements spec §8 scenario end-to-end:
//  1. seed 30 fake modules.
//  2. start EnrichCore with HeartbeatInterval=200ms, StaleAfter=600ms, and a
//     fake CallFn that panics on the 11th call.
//  3. recover the panic in test scaffolding.
//  4. wait > StaleAfter so the row goes stale.
//  5. call SweepInterrupted → assert run flipped to 'interrupted'.
//  6. select all module_ids without summary AND start a fresh EnrichCore with
//     ModuleIDs allow-list (mirrors what the retry MCP tool does).
//  7. assert final summarised count = 30.
func TestCrashMidRunResumes(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)

	// Seed 30 modules.
	for i := range 30 {
		if _, err := db.Exec(`
			INSERT INTO modules (app, name, body_excerpt, body_sha256)
			VALUES ('crashapp', $1, $2, $3)`,
			fmt.Sprintf("crashMod%02d", i),
			fmt.Sprintf("function m%d(){}", i),
			fmt.Sprintf("sha-crash-%02d", i),
		); err != nil {
			t.Fatalf("seed module %d: %v", i, err)
		}
	}

	// Panicking call fn: bombs out on the 11th invocation.
	var calls atomic.Int64
	panicCallFn := kbenrich.CallFn(func(_ context.Context, _ string, _ string, _ time.Duration) (string, error) {
		n := calls.Add(1)
		if n == 11 {
			panic("simulated mid-run crash")
		}
		return `{"summary":"ok","long_summary":"ok","role":"util","inputs":[],"outputs":[],"side_effects":[],"deps":[],"tags":[]}`, nil
	})

	// Run + recover the panic.
	parentRunID := ""
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("recovered expected panic: %v", r)
			}
		}()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		opts := kbenrich.Opts{
			App:               "crashapp",
			Limit:             30,
			Concurrent:        1,
			Model:             "haiku",
			BoundedInput:      true,
			PromptBatch:       1,
			TimeoutSec:        5,
			HeartbeatInterval: 200 * time.Millisecond,
			StaleAfter:        600 * time.Millisecond,
		}
		_, _ = kbenrich.EnrichCore(ctx, db, opts, panicCallFn)
	}()

	// Grab the in_progress run that the panic left behind.
	if err := db.QueryRow(`
		SELECT run_id::text FROM enrich_runs
		 WHERE app='crashapp'
		 ORDER BY started_at DESC LIMIT 1`).Scan(&parentRunID); err != nil {
		t.Fatalf("read parent run: %v", err)
	}

	// Wait long enough for the row to go stale.
	time.Sleep(1500 * time.Millisecond)

	// Sweep — should flip to interrupted.
	n, err := kbenrich.SweepInterrupted(db, 600*time.Millisecond)
	if err != nil {
		t.Fatalf("SweepInterrupted: %v", err)
	}
	t.Logf("swept %d rows", n)

	var status string
	if err := db.QueryRow(`SELECT status FROM enrich_runs WHERE run_id=$1::uuid`, parentRunID).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status == "in_progress" {
		t.Errorf("expected parent run to be swept, still in_progress")
	}

	// Resume: pick all modules still lacking a summary.
	rows, err := db.Query(`SELECT id FROM modules WHERE app='crashapp' AND (summary IS NULL OR summary='')`)
	if err != nil {
		t.Fatalf("select pending: %v", err)
	}
	var pending []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			t.Fatalf("scan id: %v", err)
		}
		pending = append(pending, id)
	}
	_ = rows.Close()
	if len(pending) == 0 {
		t.Fatal("no pending modules after panic — test pre-condition failed")
	}
	t.Logf("pending after panic: %d", len(pending))

	// Retry with a non-panicking fake.
	goodCallFn := kbenrich.CallFn(func(_ context.Context, _ string, _ string, _ time.Duration) (string, error) {
		return `{"summary":"ok","long_summary":"ok","role":"util","inputs":[],"outputs":[],"side_effects":[],"deps":[],"tags":[]}`, nil
	})
	retryOpts := kbenrich.Opts{
		App:               "crashapp",
		Limit:             len(pending),
		Concurrent:        2,
		Model:             "haiku",
		BoundedInput:      true,
		PromptBatch:       1,
		TimeoutSec:        5,
		HeartbeatInterval: 200 * time.Millisecond,
		StaleAfter:        10 * time.Second,
		ModuleIDs:         pending,
		ParentRunID:       parentRunID,
		ForceNewRun:       true,
	}
	sum, err := kbenrich.EnrichCore(context.Background(), db, retryOpts, goodCallFn)
	if err != nil {
		t.Fatalf("retry EnrichCore: %v", err)
	}
	if sum.Enriched != len(pending) {
		t.Errorf("retry enriched: want %d, got %d (failed=%d)", len(pending), sum.Enriched, sum.Failed)
	}

	// Final count.
	var summarised int
	if err := db.QueryRow(`SELECT COUNT(*) FROM modules WHERE app='crashapp' AND summary IS NOT NULL AND summary <> ''`).Scan(&summarised); err != nil {
		t.Fatalf("final count: %v", err)
	}
	if summarised != 30 {
		t.Errorf("final summarised: want 30, got %d", summarised)
	}
}
