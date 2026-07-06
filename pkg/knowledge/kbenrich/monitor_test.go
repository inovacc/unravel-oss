//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package kbenrich_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

// TestHeartbeatTickWritesRow verifies that a Monitor.Start row is inserted
// and that the heartbeat goroutine updates last_heartbeat_at + counters
// at the configured cadence.
func TestHeartbeatTickWritesRow(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := kbenrich.Opts{
		App:               "testapp",
		Model:             "haiku",
		Concurrent:        1,
		PromptBatch:       1,
		HeartbeatInterval: 100 * time.Millisecond,
		StaleAfter:        10 * time.Second,
	}
	m, err := kbenrich.StartMonitor(ctx, db, opts, 5)
	if err != nil {
		t.Fatalf("StartMonitor: %v", err)
	}
	runID := m.RunID()
	if runID == "" {
		t.Fatal("RunID empty")
	}

	// Read initial heartbeat.
	var first time.Time
	if err := db.QueryRow(`SELECT last_heartbeat_at FROM enrich_runs WHERE run_id=$1`, runID).Scan(&first); err != nil {
		t.Fatalf("read heartbeat: %v", err)
	}

	// Wait 3 ticks, bump counters.
	time.Sleep(400 * time.Millisecond)
	m.IncCompleted()
	m.IncCompleted()
	m.IncFailed()
	time.Sleep(300 * time.Millisecond)

	var later time.Time
	var completed, failed int
	if err := db.QueryRow(`SELECT last_heartbeat_at, completed, failed FROM enrich_runs WHERE run_id=$1`, runID).
		Scan(&later, &completed, &failed); err != nil {
		t.Fatalf("read updated row: %v", err)
	}
	if !later.After(first) {
		t.Errorf("heartbeat did not advance: first=%v later=%v", first, later)
	}
	if completed != 2 {
		t.Errorf("completed: want 2, got %d", completed)
	}
	if failed != 1 {
		t.Errorf("failed: want 1, got %d", failed)
	}

	m.Finalise("completed")
	var status string
	var ended sql.NullTime
	if err := db.QueryRow(`SELECT status, ended_at FROM enrich_runs WHERE run_id=$1`, runID).Scan(&status, &ended); err != nil {
		t.Fatalf("finalise read: %v", err)
	}
	if status != "completed" {
		t.Errorf("status: want completed, got %s", status)
	}
	if !ended.Valid {
		t.Error("ended_at not set on finalise")
	}

	// Idempotent finalise — second call must not error.
	m.Finalise("completed")
}

// TestRecordAttemptInsertsRow verifies enrich_attempts row insertion and that
// error_message is redacted on the way in.
func TestRecordAttemptInsertsRow(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Seed one module so module_id FK is satisfied.
	var modID int64
	if err := db.QueryRow(
		`INSERT INTO modules (app, name, body_excerpt, body_sha256)
		 VALUES ('testapp','m1','x','sha1') RETURNING id`).Scan(&modID); err != nil {
		t.Fatalf("seed module: %v", err)
	}

	opts := kbenrich.Opts{
		App:               "testapp",
		Model:             "haiku",
		Concurrent:        1,
		PromptBatch:       1,
		HeartbeatInterval: time.Second,
		StaleAfter:        10 * time.Second,
	}
	m, err := kbenrich.StartMonitor(ctx, db, opts, 1)
	if err != nil {
		t.Fatalf("StartMonitor: %v", err)
	}
	defer m.Finalise("completed")

	m.RecordAttempt(modID, "failure", "json_parse",
		`open C:\Users\bob\file.txt: api_key=ABC`,
		"haiku", 1)

	var status, errClass, errMsg string
	if err := db.QueryRow(
		`SELECT status, error_class, error_message_redacted FROM enrich_attempts WHERE run_id=$1 AND module_id=$2`,
		m.RunID(), modID).Scan(&status, &errClass, &errMsg); err != nil {
		t.Fatalf("read attempt: %v", err)
	}
	if status != "failure" {
		t.Errorf("status: want failure, got %s", status)
	}
	if errClass != "json_parse" {
		t.Errorf("error_class: want json_parse, got %s", errClass)
	}
	if !contains(errMsg, "<path>") || !contains(errMsg, "<redacted>") {
		t.Errorf("redaction not applied: %q", errMsg)
	}
}

// TestSweeperFlipsStaleRun inserts an artificially-old in_progress row and
// calls SweepInterrupted; the row must flip to 'interrupted' with ended_at set.
func TestSweeperFlipsStaleRun(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)

	var runID string
	if err := db.QueryRow(`
		INSERT INTO enrich_runs
		  (app, model, concurrency, prompt_batch, status, total_target,
		   started_at, last_heartbeat_at, host, pid)
		VALUES ('testapp','haiku',1,1,'in_progress',5,
		        now() - interval '20 min', now() - interval '11 min',
		        'fakehost', 9999)
		RETURNING run_id::text`).Scan(&runID); err != nil {
		t.Fatalf("seed stale row: %v", err)
	}

	n, err := kbenrich.SweepInterrupted(db, 10*time.Minute)
	if err != nil {
		t.Fatalf("SweepInterrupted: %v", err)
	}
	if n < 1 {
		t.Errorf("expected >=1 row swept, got %d", n)
	}

	var status string
	var ended sql.NullTime
	if err := db.QueryRow(`SELECT status, ended_at FROM enrich_runs WHERE run_id=$1::uuid`, runID).Scan(&status, &ended); err != nil {
		t.Fatalf("read swept row: %v", err)
	}
	if status != "interrupted" {
		t.Errorf("status: want interrupted, got %s", status)
	}
	if !ended.Valid {
		t.Error("ended_at not set after sweep")
	}
}

// TestResumePicksMatchingInProgressRun seeds a fresh in_progress row for
// (app, host) and asserts StartMonitor reuses it. A second scenario marks
// the row stale and asserts StartMonitor creates a NEW row.
func TestResumePicksMatchingInProgressRun(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	host, _ := os.Hostname()
	if len(host) > 255 {
		host = host[:255]
	}

	// Fresh in_progress row (heartbeat = now()).
	var seededID string
	if err := db.QueryRow(`
		INSERT INTO enrich_runs
		  (app, model, concurrency, prompt_batch, status, total_target,
		   started_at, last_heartbeat_at, host, pid)
		VALUES ('resumeapp','haiku',1,1,'in_progress',5,
		        now(), now(), $1, 9999)
		RETURNING run_id::text`, host).Scan(&seededID); err != nil {
		t.Fatalf("seed fresh row: %v", err)
	}

	opts := kbenrich.Opts{
		App:               "resumeapp",
		Model:             "haiku",
		Concurrent:        1,
		PromptBatch:       1,
		HeartbeatInterval: 5 * time.Second,
		StaleAfter:        10 * time.Minute,
	}
	m, err := kbenrich.StartMonitor(ctx, db, opts, 5)
	if err != nil {
		t.Fatalf("StartMonitor (fresh): %v", err)
	}
	if m.RunID() != seededID {
		t.Errorf("expected reuse %s, got %s", seededID, m.RunID())
	}
	if !m.Resumed() {
		t.Error("expected Resumed=true")
	}
	m.Finalise("completed")

	// Now seed a STALE in_progress row and assert StartMonitor inserts a NEW one.
	var staleID string
	if err := db.QueryRow(`
		INSERT INTO enrich_runs
		  (app, model, concurrency, prompt_batch, status, total_target,
		   started_at, last_heartbeat_at, host, pid)
		VALUES ('resumeapp2','haiku',1,1,'in_progress',5,
		        now() - interval '20 min', now() - interval '11 min', $1, 9999)
		RETURNING run_id::text`, host).Scan(&staleID); err != nil {
		t.Fatalf("seed stale row: %v", err)
	}
	opts2 := opts
	opts2.App = "resumeapp2"
	m2, err := kbenrich.StartMonitor(ctx, db, opts2, 5)
	if err != nil {
		t.Fatalf("StartMonitor (stale): %v", err)
	}
	if m2.RunID() == staleID {
		t.Errorf("expected NEW run_id, got reused stale %s", staleID)
	}
	if m2.Resumed() {
		t.Error("expected Resumed=false on stale path")
	}
	m2.Finalise("completed")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
