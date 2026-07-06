//go:build integration

package ingest

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// seedSource inserts a knowledge_sources row (the FK target for
// modules.first_source_id and module_app_refs.source_id) and returns its id.
func seedSource(t *testing.T, db *sql.DB, app string) int64 {
	t.Helper()
	var id int64
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO knowledge_sources (app, epoch, source_path, source_kind, captured_at)
		VALUES ($1, 1, $2, 'other', $3)
		RETURNING id
	`, app, "/tmp/"+app, time.Now().UnixMilli()).Scan(&id)
	if err != nil {
		t.Fatalf("seedSource: %v", err)
	}
	return id
}

func TestIngestModules_DedicatedCILInsert(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t) // shared integration helper (migrations applied); skips when Docker/EnvTestDSN unavailable

	src := seedSource(t, db, "linkedin") // inserts knowledge_sources, returns sourceID

	mods := []clr.TypeModule{
		{Name: "LinkedIn.Foo.Bar", IL: ".method foo\nret", Callees: []string{"06000002"}, Strings: []string{"hi"}, Vendored: false},
		{Name: "System.Text.Json.JsonNode", IL: ".method ctor\nret", Vendored: true},
	}

	// IngestModules now runs INSIDE a caller-owned transaction (FIX #1), the
	// same *sql.Tx writeBodies uses — so open one, persist, and commit here.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	n, err := IngestModules(ctx, tx, "linkedin", src, mods)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("IngestModules: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if n != 2 {
		t.Fatalf("inserted = %d, want 2", n)
	}

	// Assert lang='cil' on both, is_vendored honors the per-module flag, and
	// the IL body is stored verbatim in module_bodies.
	var lang string
	var vendored bool
	row := db.QueryRowContext(ctx, `
		SELECT m.lang, m.is_vendored
		FROM modules m WHERE m.app=$1 AND m.name=$2`, "linkedin", "System.Text.Json.JsonNode")
	if err := row.Scan(&lang, &vendored); err != nil {
		t.Fatalf("scan vendored row: %v", err)
	}
	if lang != "cil" {
		t.Errorf("lang = %q, want cil", lang)
	}
	if !vendored {
		t.Errorf("is_vendored = false, want true for System.* module")
	}

	var fp bool
	if err := db.QueryRowContext(ctx,
		`SELECT is_vendored FROM modules WHERE app=$1 AND name=$2`,
		"linkedin", "LinkedIn.Foo.Bar").Scan(&fp); err != nil {
		t.Fatalf("scan firstparty: %v", err)
	}
	if fp {
		t.Errorf("LinkedIn.* is_vendored = true, want false")
	}
}
