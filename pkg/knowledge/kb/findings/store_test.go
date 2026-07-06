//go:build integration

package findings_test

import (
	"database/sql"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/findings"
)

// seedModule inserts a minimal modules row and returns the generated id.
func seedModule(t *testing.T, db *sql.DB, app, name string) int64 {
	t.Helper()
	// module_bodies is required by modules.body_sha256 FK in many configs;
	// insert a body first so FK surface stays consistent with seed fixtures.
	_, _ = db.Exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
	                VALUES ('findtest01', '\x61', 1, 0)
	                ON CONFLICT DO NOTHING`)
	var id int64
	if err := db.QueryRow(`
		INSERT INTO modules (app, name, body_size, body_excerpt, body_sha256, search_text)
		VALUES ($1, $2, 1, 'x', 'findtest01', 'x') RETURNING id`, app, name).Scan(&id); err != nil {
		t.Fatalf("seedModule: %v", err)
	}
	return id
}

func TestRecord_and_List(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	modID := seedModule(t, db, "testapp", "mod_a")

	f := findings.Finding{
		App:        "testapp",
		ModuleID:   &modID,
		Scope:      "module",
		TargetKind: "summary",
		Claim:      "module encrypts user data",
		Stance:     findings.StanceAffirm,
		Finding:    "evidence confirms encryption",
		Confidence: 0.9,
		Severity:   "info",
		Iterations: 2,
		Converged:  true,
		CreatedAt:  1000,
	}

	id, err := findings.Record(db, f)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if id <= 0 {
		t.Fatalf("Record returned id=%d", id)
	}

	// List by app
	rows, err := findings.List(db, findings.Filter{App: "testapp"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("List: expected 1 row, got %d", len(rows))
	}
	got := rows[0]
	if got.ID != id {
		t.Errorf("id mismatch: got %d, want %d", got.ID, id)
	}
	if got.Stance != findings.StanceAffirm {
		t.Errorf("stance: got %q, want %q", got.Stance, findings.StanceAffirm)
	}
	if got.ModuleID == nil || *got.ModuleID != modID {
		t.Errorf("module_id: got %v, want %d", got.ModuleID, modID)
	}

	// List by stance filter
	rows2, err := findings.List(db, findings.Filter{App: "testapp", Stance: "contradict"})
	if err != nil {
		t.Fatalf("List(contradict): %v", err)
	}
	if len(rows2) != 0 {
		t.Errorf("expected 0 contradict rows, got %d", len(rows2))
	}
}

func TestRecord_AppLevel(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)

	f := findings.Finding{
		App:        "testapp2",
		Scope:      "app",
		TargetKind: "app_fact",
		Claim:      "app uses AES-256",
		Stance:     findings.StanceContradict,
		Finding:    "no evidence of AES-256 found",
		Confidence: 0.75,
		Severity:   "medium",
		Iterations: 3,
		Converged:  false,
		CreatedAt:  2000,
	}

	id, err := findings.Record(db, f)
	if err != nil {
		t.Fatalf("Record app-level: %v", err)
	}

	rows, err := findings.List(db, findings.Filter{App: "testapp2", Stance: "contradict"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].ID != id {
		t.Errorf("id mismatch")
	}
	if rows[0].ModuleID != nil {
		t.Errorf("expected nil module_id for app-level finding")
	}
	if rows[0].Converged {
		t.Errorf("expected converged=false")
	}
}

func TestRecordIteration_Idempotent(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)

	f := findings.Finding{
		App:        "itapp",
		Scope:      "module",
		TargetKind: "role",
		Claim:      "handles auth",
		Stance:     findings.StanceAugment,
		Finding:    "augments with extra context",
		Iterations: 1,
		Converged:  true,
		CreatedAt:  3000,
	}
	id, err := findings.Record(db, f)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	it := findings.Iteration{
		FindingID:     id,
		Iter:          1,
		InterimStance: "augment",
		InterimConf:   0.8,
		Challenger:    "self-critique",
		Changed:       false,
		Note:          "stable on first pass",
		CreatedAt:     3100,
	}

	// First insert — should succeed.
	if err := findings.RecordIteration(db, it); err != nil {
		t.Fatalf("RecordIteration first: %v", err)
	}
	// Second insert of same (finding_id, iter) — must be a no-op, not an error.
	if err := findings.RecordIteration(db, it); err != nil {
		t.Fatalf("RecordIteration idempotent: %v", err)
	}

	// Verify only one row exists.
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM kb_ai_finding_iterations WHERE finding_id=$1 AND iter=1`, id).Scan(&cnt); err != nil {
		t.Fatalf("count: %v", err)
	}
	if cnt != 1 {
		t.Errorf("expected 1 iteration row, got %d", cnt)
	}
}

func TestResolve(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)

	f := findings.Finding{
		App:        "resolveapp",
		Scope:      "module",
		TargetKind: "summary",
		Claim:      "some claim",
		Stance:     findings.StanceUncertain,
		Finding:    "verdict",
		Iterations: 1,
		Converged:  false,
		CreatedAt:  4000,
	}
	id, err := findings.Record(db, f)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	if err := findings.Resolve(db, id, "accepted", "reviewer@example.com", 5000); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	rows, err := findings.List(db, findings.Filter{App: "resolveapp", Status: "accepted"})
	if err != nil {
		t.Fatalf("List after Resolve: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 accepted row, got %d", len(rows))
	}
	got := rows[0]
	if got.Status != findings.StatusAccepted {
		t.Errorf("status: got %q, want accepted", got.Status)
	}
	if got.ResolvedBy != "reviewer@example.com" {
		t.Errorf("resolved_by: got %q", got.ResolvedBy)
	}
	if got.ResolvedAt == nil || *got.ResolvedAt != 5000 {
		t.Errorf("resolved_at: got %v", got.ResolvedAt)
	}
}

func TestResolve_InvalidStatus(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	if err := findings.Resolve(db, 1, "bogus", "", 0); err == nil {
		t.Error("expected error for invalid status, got nil")
	}
}

func TestSummary(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)

	app := "summaryapp"
	for _, s := range []findings.Stance{findings.StanceAffirm, findings.StanceAffirm, findings.StanceContradict} {
		_, err := findings.Record(db, findings.Finding{
			App:        app,
			Scope:      "module",
			TargetKind: "summary",
			Claim:      "claim",
			Stance:     s,
			Finding:    "verdict",
			Iterations: 1,
			Converged:  true,
			CreatedAt:  6000,
		})
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	sum, err := findings.Summary(db, app)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if sum.TotalFindings != 3 {
		t.Errorf("TotalFindings: got %d, want 3", sum.TotalFindings)
	}
	if sum.ByStance["affirm"] != 2 {
		t.Errorf("ByStance[affirm]: got %d, want 2", sum.ByStance["affirm"])
	}
	if sum.ByStance["contradict"] != 1 {
		t.Errorf("ByStance[contradict]: got %d, want 1", sum.ByStance["contradict"])
	}
	if sum.ByStatus["open"] != 3 {
		t.Errorf("ByStatus[open]: got %d, want 3", sum.ByStatus["open"])
	}
}

func TestMigration_021_Schema(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)

	for _, table := range []string{"kb_ai_findings", "kb_ai_finding_iterations"} {
		var rel sql.NullString
		if err := db.QueryRow(`SELECT to_regclass('public.' || $1)::text`, table).Scan(&rel); err != nil {
			t.Fatalf("to_regclass %s: %v", table, err)
		}
		if !rel.Valid || rel.String != table {
			t.Fatalf("%s table not found: %+v", table, rel)
		}
	}

	wantFindingCols := []string{
		"id", "app", "module_id", "scope", "target_kind", "target_ref",
		"claim", "stance", "finding", "evidence", "confidence", "severity",
		"iterations", "converged", "model_used", "run_id",
		"status", "created_at", "resolved_at", "resolved_by",
	}
	for _, col := range wantFindingCols {
		var n int
		if err := db.QueryRow(`
			SELECT COUNT(*) FROM information_schema.columns
			 WHERE table_schema='public' AND table_name='kb_ai_findings' AND column_name=$1`, col).Scan(&n); err != nil {
			t.Fatalf("scan kb_ai_findings.%s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("kb_ai_findings.%s: expected 1, got %d", col, n)
		}
	}

	wantIterCols := []string{
		"finding_id", "iter", "interim_stance", "interim_conf",
		"challenger", "changed", "note", "created_at",
	}
	for _, col := range wantIterCols {
		var n int
		if err := db.QueryRow(`
			SELECT COUNT(*) FROM information_schema.columns
			 WHERE table_schema='public' AND table_name='kb_ai_finding_iterations' AND column_name=$1`, col).Scan(&n); err != nil {
			t.Fatalf("scan kb_ai_finding_iterations.%s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("kb_ai_finding_iterations.%s: expected 1, got %d", col, n)
		}
	}

	// Check indexes exist.
	wantIdxs := []string{
		"idx_kb_ai_findings_app",
		"idx_kb_ai_findings_module",
		"idx_kb_ai_findings_stance",
		"idx_kb_ai_findings_status",
		"idx_kb_ai_findings_run",
	}
	for _, idx := range wantIdxs {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pg_indexes WHERE schemaname='public' AND indexname=$1`, idx).Scan(&n); err != nil {
			t.Fatalf("scan idx %s: %v", idx, err)
		}
		if n != 1 {
			t.Errorf("index %s: expected 1, got %d", idx, n)
		}
	}
}
