//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for the Phase-34 FK VALIDATE primitive. Boot a
transient Postgres via dbtest.StartPostgres, exercise validatefk.ValidateFK
across the two D-34-VALIDATE-FAIL-MODE paths.

Coverage (per Plan 34-02 task 34-02-02):

  * TestValidateFK_Succeeds   — backfill populates legacy rows, then
    VALIDATE returns nil; second call also returns nil (idempotent).
  * TestValidateFK_OrphanError — knowledge_sources row with kb_id NOT
    matching any kb_apps row makes VALIDATE return an error whose
    message contains the orphan-count phrase and the diagnostic SELECT.
*/

package cmd_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/backfill"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/validatefk"
)

// seedLegacy inserts n knowledge_sources rows with kb_id=NULL across
// the apps slice. Mirrors the helper in pkg/knowledge/kb/backfill tests:
// each row gets a unique source_path / source_sha256 + per-app epoch
// counter to satisfy UNIQUE(app, epoch).
func seedLegacy(t *testing.T, db *sql.DB, n int, apps []string) {
	t.Helper()
	if len(apps) == 0 {
		t.Fatal("seedLegacy: empty apps slice")
	}
	now := time.Now().UnixMilli()
	epochCount := make(map[string]int, len(apps))
	for i := 0; i < n; i++ {
		app := apps[i%len(apps)]
		epochCount[app]++
		ep := epochCount[app]
		captured := now - int64(i)*1000
		sha := []byte("0000000000000000000000000000000000000000000000000000000000000000")
		hexCh := []byte("0123456789abcdef")
		for k := 0; k < 8; k++ {
			sha[63-k] = hexCh[(i>>(4*k))&0xF]
		}
		_, err := db.Exec(
			`INSERT INTO knowledge_sources
              (app, epoch, source_path, source_kind, source_sha256, captured_at)
              VALUES ($1, $2, $3, 'other', $4, $5)`,
			app, ep, "/tmp/legacy/"+app+"/"+string(sha[56:]), string(sha), captured,
		)
		if err != nil {
			t.Fatalf("seed insert (i=%d, app=%q): %v", i, app, err)
		}
	}
}

func TestValidateFK_Succeeds(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	apps := []string{"WhatsApp", "Cluely", "Pluely"}
	seedLegacy(t, db, 5, apps)

	ctx := context.Background()
	if _, err := backfill.Run(ctx, db, backfill.Options{}); err != nil {
		t.Fatalf("backfill.Run: %v", err)
	}

	if err := validatefk.ValidateFK(ctx, db); err != nil {
		t.Fatalf("first ValidateFK: %v", err)
	}
	// Idempotent: a second call against an already-validated FK is a no-op.
	if err := validatefk.ValidateFK(ctx, db); err != nil {
		t.Fatalf("second ValidateFK (idempotent): %v", err)
	}
}

func TestValidateFK_OrphanError(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)

	// The Phase-29 FK is NOT VALID, so we can insert a row whose kb_id has
	// no matching kb_apps parent. This is exactly what VALIDATE should
	// catch.
	const orphanKB = "deadbeefdeadbeef"
	_, err := db.Exec(
		`INSERT INTO knowledge_sources
          (app, epoch, source_path, source_kind, source_sha256, kb_id, captured_at)
          VALUES ($1, $2, $3, 'other', $4, $5, $6)`,
		"OrphanApp", 1,
		"/tmp/orphan/abcdef0123456789",
		"0000000000000000000000000000000000000000000000000000000000000001",
		orphanKB,
		time.Now().UnixMilli(),
	)
	if err != nil {
		t.Fatalf("seed orphan row: %v", err)
	}

	ctx := context.Background()
	err = validatefk.ValidateFK(ctx, db)
	if err == nil {
		t.Fatal("ValidateFK returned nil; want orphan error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "validate failed") {
		t.Errorf("err missing 'validate failed': %v", err)
	}
	if !strings.Contains(msg, "WHERE kb_id NOT IN (SELECT kb_id FROM kb_apps)") {
		t.Errorf("err missing diagnostic SELECT hint: %v", err)
	}
}
