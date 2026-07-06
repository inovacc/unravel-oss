//go:build integration

/*
Copyright (c) 2026 Security Research

Phase 45 / LLMC-04 — auto-mode classifier integration test.

Asserts that running `unravel kb classify --classifier=auto` against an
ephemeral postgres with NO MCP session wired:

 1. Exits without error (kbClassify RunE returns nil).
 2. Writes module_components rows with classifier='rule' (no MCP path).
 3. Produces bucket counts that match the golden baseline at
    pkg/knowledge/kb/component/classify/testdata/v1_baseline_buckets.json.

This locks D-45-INTEGRATION-RUNS-RULE-PATH and the LLMC-04 acceptance gate:
turning on --classifier=auto must NOT regress the v1 rule-only output
when the host lacks sampling capability.

Build-tag-gated to keep `go test -short ./...` Docker-free per CLAUDE.md
slow-test policy.
*/
package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime" // populate rule registry
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// goldenBucketsPath is the in-tree golden baseline (Task 4).
var goldenBucketsPath = filepath.Join(
	"..", "pkg", "knowledge", "kb", "component", "classify", "testdata",
	"v1_baseline_buckets.json",
)

// seedAutoCorpus seeds the canonical 3-module corpus that
// classify_integration_test.go::TestRun_HappyPath_LatestEpoch uses, so the
// baseline file applies to both. Returns the kb_id.
func seedAutoCorpus(t *testing.T, db *sql.DB) string {
	t.Helper()
	ctx := context.Background()
	const kb = "kb45auto00000001"

	if _, err := db.ExecContext(ctx,
		`INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at, metadata)
		 VALUES ($1, 'auto-test', 'Auto Test', 'unknown', 0, 0, '{}'::jsonb)
		 ON CONFLICT (kb_id) DO NOTHING`, kb); err != nil {
		t.Fatalf("seed kb_apps: %v", err)
	}

	var ksID int64
	if err := db.QueryRowContext(ctx,
		`INSERT INTO knowledge_sources (kb_id, app, epoch, source_path, source_kind, captured_at)
		 VALUES ($1, 'auto-test', 1, '/x', 'other', 1) RETURNING id`, kb).Scan(&ksID); err != nil {
		t.Fatalf("seed knowledge_sources: %v", err)
	}

	type mod struct {
		name, sha, syms string
	}
	mods := []mod{
		{"AuthService", "h-auth-auto", `{"oauth":1,"jwt":1,"refresh_token":1}`},
		{"AesGcmCipher", "h-crypto-auto", `{"AesGcm":1,"sha256":1}`},
		{"Foo", "h-other-auto", `{"bar":1}`},
	}
	for _, m := range mods {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
			 VALUES ($1, '\x00', 1, 0) ON CONFLICT (body_sha256) DO NOTHING`, m.sha); err != nil {
			t.Fatalf("seed module_bodies %s: %v", m.name, err)
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO modules (app, name, body_size, body_excerpt, body_sha256, symbols_json, first_source_id)
			 VALUES ($1, $2, 1, '', $3, $4, $5)`,
			"auto-test", m.name, m.sha, m.syms, ksID); err != nil {
			t.Fatalf("seed modules %s: %v", m.name, err)
		}
	}
	return kb
}

// TestKBClassify_AutoMode_NoSession_UsesRulePath drives runKbClassify
// directly with --classifier=auto. SetSession is NEVER called, so the
// HasSamplingCapability probe returns false and Select must fall through
// to plain RuleClassifier (no composite, no MCP).
func TestKBClassify_AutoMode_NoSession_UsesRulePath(t *testing.T) {
	db, dsn := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })
	kb := seedAutoCorpus(t, db)

	// Drive runKbClassify by setting package-level flag vars (mirrors
	// kb_classify_review_mode_test.go pattern). The cmd uses cmd.OutOrStdout
	// for output; we capture it via the cobra command's SetOut.
	pinDSNViaConfig(t, dsn)
	classifyEpoch = 0
	classifyJSON = true
	classifyMode = "auto"
	classifyEvalCorpus = ""
	classifyReviewMode = false
	classifyBy = ""
	classifyReason = ""
	t.Cleanup(func() {
		// Reset shared globals so subsequent tests get a clean slate.
		classifyJSON = false
		classifyMode = "auto"
	})

	var out bytes.Buffer
	classifyCmd.SetOut(&out)
	classifyCmd.SetErr(&out)

	if err := runKbClassify(classifyCmd, []string{kb}); err != nil {
		t.Fatalf("runKbClassify: %v", err)
	}

	// Assertion 1 + 2: every module_components row must use the rule path.
	rows, err := db.Query(
		`SELECT module_id, component, classifier FROM module_components
		 WHERE module_id IN (SELECT id FROM modules WHERE app='auto-test')`)
	if err != nil {
		t.Fatalf("read module_components: %v", err)
	}
	defer rows.Close()

	bucketCounts := map[string]int{}
	rowCount := 0
	for rows.Next() {
		var id int64
		var component, classifier string
		if err := rows.Scan(&id, &component, &classifier); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if classifier != "rule" {
			t.Fatalf("module %d classifier=%q want rule (auto-mode without MCP session must hit fallback)", id, classifier)
		}
		bucketCounts[component]++
		rowCount++
	}
	if rowCount != 3 {
		t.Fatalf("want 3 module_components rows, got %d", rowCount)
	}

	// Assertion 3: bucket counts match the golden baseline.
	rawBaseline, err := os.ReadFile(goldenBucketsPath)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var baseline struct {
		Buckets map[string]int `json:"buckets"`
	}
	if err := json.Unmarshal(rawBaseline, &baseline); err != nil {
		t.Fatalf("parse baseline: %v", err)
	}
	if len(baseline.Buckets) == 0 {
		t.Fatalf("baseline buckets empty — fixture corrupted at %s", goldenBucketsPath)
	}
	for bucket, want := range baseline.Buckets {
		if got := bucketCounts[bucket]; got != want {
			t.Errorf("bucket %q: got=%d want=%d (D-45-INTEGRATION-RUNS-RULE-PATH regression)", bucket, got, want)
		}
	}
	for bucket, got := range bucketCounts {
		if _, ok := baseline.Buckets[bucket]; !ok {
			t.Errorf("unexpected bucket %q (count=%d) not in baseline", bucket, got)
		}
	}
}
