//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// handleKnowledgeEnrichRetryWithCallFn is the integration-test seam that
// bypasses the supervisor IPC and calls kbenrich.Retry directly with an
// injectable CallFn. Production callers route through getEnrichClient (see
// knowledge_enrich_retry.go). Moved here in v2.17 thin-client B7-P4 so the
// production file is supervisor-only and the B7 invariant (no openKB / no
// kbenrich import outside test files) holds.
func handleKnowledgeEnrichRetryWithCallFn(ctx context.Context, _ *mcp.CallToolRequest, in EnrichRetryInput, callFn kbenrich.CallFn) (*mcp.CallToolResult, any, error) {
	if in.RunID == "" {
		return errorResult(fmt.Errorf("run_id is required")), nil, nil
	}
	select {
	case enrichGlobalSem <- struct{}{}:
		defer func() { <-enrichGlobalSem }()
	case <-ctx.Done():
		return errorResult(fmt.Errorf("enrich-retry cancelled before acquire: %w", ctx.Err())), nil, nil
	}
	db, err := openKB(ctx, in.DB)
	if err != nil {
		return errorResult(fmt.Errorf("open KB: %w", err)), nil, nil
	}
	defer func() { _ = db.Close() }()
	payload, err := kbenrich.Retry(ctx, db, kbenrich.RetryOptions{
		RunID:      in.RunID,
		ErrorClass: in.ErrorClass,
		Concurrent: in.Concurrent,
		Model:      in.Model,
	}, callFn)
	if err != nil {
		return errorResult(fmt.Errorf("enrich: %w", err)), nil, nil
	}
	return jsonResult(payload), payload, nil
}

// TestEnrichRetry_NarrowsToFailures seeds a parent run with 3 modules:
//  1. success
//  2. failure(json_parse)
//  3. timeout
//
// Calling the retry handler with a CallFn that always succeeds must:
//   - retry only modules #2 and #3 (skipping the success),
//   - create a new enrich_runs row with parent_run_id == parent,
//   - narrow to module #2 only when error_class='json_parse'.
func TestEnrichRetry_NarrowsToFailures(t *testing.T) {
	db, dsn := dbtest.StartPostgresOrSkip(t)

	// Seed parent run.
	var parentID string
	if err := db.QueryRow(`
		INSERT INTO enrich_runs (app, model, concurrency, prompt_batch, status, total_target,
		   completed, failed, started_at, ended_at, last_heartbeat_at, host, pid)
		VALUES ('retryapp','haiku',1,1,'completed',3,1,2,
		        now() - interval '10 min', now() - interval '9 min',
		        now() - interval '9 min', 'fake', 1)
		RETURNING run_id::text`).Scan(&parentID); err != nil {
		t.Fatalf("seed parent: %v", err)
	}

	// Seed 3 modules.
	var modIDs [3]int64
	for i := range 3 {
		if err := db.QueryRow(`
			INSERT INTO modules (app, name, body_excerpt, body_sha256)
			VALUES ('retryapp', $1, $2, $3) RETURNING id`,
			"mod"+string(rune('A'+i)),
			"function "+string(rune('A'+i))+"(){}",
			"sha-retry-"+string(rune('A'+i))).Scan(&modIDs[i]); err != nil {
			t.Fatalf("seed module %d: %v", i, err)
		}
	}
	// First module is "success" (give it a summary).
	if _, err := db.Exec(`UPDATE modules SET summary='ok' WHERE id=$1`, modIDs[0]); err != nil {
		t.Fatalf("mark mod0 summarised: %v", err)
	}

	// Seed attempt rows.
	seedAttempt := func(modID int64, status, errClass string) {
		if _, err := db.Exec(`
			INSERT INTO enrich_attempts (run_id, module_id, ended_at, status, error_class,
			   error_message_redacted, model_used, attempt_no)
			VALUES ($1::uuid, $2, now(), $3, NULLIF($4,''), NULL, 'haiku', 1)`,
			parentID, modID, status, errClass); err != nil {
			t.Fatalf("seed attempt: %v", err)
		}
	}
	seedAttempt(modIDs[0], "success", "")
	seedAttempt(modIDs[1], "failure", "json_parse")
	seedAttempt(modIDs[2], "timeout", "timeout")

	fakeCall := kbenrich.CallFn(func(_ context.Context, _ string, _ string, _ time.Duration) (string, error) {
		return `{"summary":"ok","long_summary":"ok","role":"util","inputs":[],"outputs":[],"side_effects":[],"deps":[],"tags":[]}`, nil
	})

	// Case 1: full retry — should enrich exactly 2 modules.
	in := EnrichRetryInput{DB: dsn, RunID: parentID, Model: "haiku", Concurrent: 1}
	res, payload, err := handleKnowledgeEnrichRetryWithCallFn(context.Background(), nil, in, fakeCall)
	if err != nil {
		t.Fatalf("retry handler: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("retry handler error result: %+v", res)
	}
	m := payload.(map[string]any)
	summary := m["summary"].(kbenrich.Summary)
	if summary.Enriched != 2 {
		t.Errorf("Case1 enriched: want 2, got %d (failed=%d)", summary.Enriched, summary.Failed)
	}
	if m["parent_run_id"] != parentID {
		t.Errorf("parent_run_id: want %s, got %v", parentID, m["parent_run_id"])
	}
	newRunID := summary.RunID
	if newRunID == "" {
		t.Fatal("new RunID empty")
	}
	var parentFK string
	if err := db.QueryRow(`SELECT parent_run_id::text FROM enrich_runs WHERE run_id=$1::uuid`, newRunID).Scan(&parentFK); err != nil {
		t.Fatalf("read parent_run_id: %v", err)
	}
	if parentFK != parentID {
		t.Errorf("new run parent_run_id: want %s, got %s", parentID, parentFK)
	}

	// Reset summaries on the retried modules so case 2 can re-evaluate.
	if _, err := db.Exec(`UPDATE modules SET summary=NULL WHERE id = ANY($1::bigint[])`,
		[]int64{modIDs[1], modIDs[2]}); err != nil {
		t.Fatalf("reset summaries: %v", err)
	}

	// Case 2: error_class filter narrows to mod1 only.
	in2 := EnrichRetryInput{DB: dsn, RunID: parentID, Model: "haiku", Concurrent: 1, ErrorClass: "json_parse"}
	_, payload2, err := handleKnowledgeEnrichRetryWithCallFn(context.Background(), nil, in2, fakeCall)
	if err != nil {
		t.Fatalf("retry handler 2: %v", err)
	}
	m2 := payload2.(map[string]any)
	sum2 := m2["summary"].(kbenrich.Summary)
	if sum2.Enriched != 1 {
		t.Errorf("Case2 enriched (json_parse only): want 1, got %d", sum2.Enriched)
	}
}
