//go:build integration

/*
Copyright (c) 2026 Security Research

Integration test for `unravel db migrate-from-sqlite`.

Boots a transient pgvector Postgres container via dbtest.StartPostgres,
builds a minimal SQLite fixture (3 modules + 3 bodies + empty satellite
tables), drives runDBMigrateFromSQLite in-process, and asserts:
  1. modules / module_bodies counts == 3 each in PG.
  2. Exactly one kb_apps row (canonical_name='legacy') + one knowledge_sources
     row (app='legacy', epoch=1) + 3 module_app_refs rows.
  3. The kb_search-shaped 4-way join resolves a 'sendMessage' lookup.
  4. Re-running the migrator leaves all counts unchanged (idempotency).
  5. Deleting one module_bodies row in PG causes runMigrateVerify to return
     a non-nil error.
*/

package cmd

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// createFixtureSQLite builds a temp SQLite file with the full set of tables
// that runDBMigrateFromSQLite's pre-count loop and copy* functions reference.
// All satellite tables are created empty; only modules + module_bodies are seeded.
func createFixtureSQLite(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "knowledge.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture sqlite: %v", err)
	}
	defer func() { _ = db.Close() }()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("fixture exec %q: %v", q, err)
		}
	}

	// ── primary tables ─────────────────────────────────────────────────
	exec(`CREATE TABLE modules (
		id              INTEGER PRIMARY KEY,
		app             TEXT,
		name            TEXT,
		synthetic_name  TEXT,
		prefix          TEXT,
		body_size       INTEGER,
		body_excerpt    TEXT,
		body_sha256     TEXT,
		symbols_json    TEXT,
		summary         TEXT,
		tags            TEXT,
		first_seen_at   INTEGER,
		last_seen_at    INTEGER,
		lang            TEXT,
		repo_root       TEXT
	)`)

	exec(`CREATE TABLE module_bodies (
		body_sha256 TEXT PRIMARY KEY,
		body        BLOB,
		body_size   INTEGER,
		stored_at   INTEGER
	)`)

	// ── satellite tables (empty — copier scanRows must not error) ───────
	exec(`CREATE TABLE module_sightings (
		module_id    INTEGER,
		source_file  TEXT,
		byte_offset  INTEGER,
		observed_at  INTEGER
	)`)

	exec(`CREATE TABLE module_enrichment (
		module_id    INTEGER,
		long_summary TEXT,
		role         TEXT,
		inputs_json  TEXT,
		outputs_json TEXT,
		side_effects TEXT
	)`)

	exec(`CREATE TABLE module_deps (
		from_id INTEGER,
		to_name TEXT,
		to_id   INTEGER
	)`)

	exec(`CREATE TABLE app_facts (
		id           INTEGER PRIMARY KEY,
		app          TEXT,
		category     TEXT,
		key          TEXT,
		value        TEXT,
		evidence_ids TEXT,
		source_step  TEXT,
		confidence   REAL,
		gap_prompt   TEXT,
		candidates_q TEXT,
		value_format TEXT,
		filled_at    INTEGER,
		updated_at   INTEGER
	)`)

	exec(`CREATE TABLE fact_history (
		fact_id      INTEGER,
		value        TEXT,
		evidence_ids TEXT,
		source_step  TEXT,
		confidence   REAL,
		observed_at  INTEGER
	)`)

	exec(`CREATE TABLE module_embeddings (
		module_id  INTEGER,
		model      TEXT,
		dim        INTEGER,
		vector     BLOB,
		created_at INTEGER
	)`)

	exec(`CREATE TABLE repos (
		slug         TEXT PRIMARY KEY,
		root         TEXT,
		vcs          TEXT,
		vcs_head     TEXT,
		indexed_at   INTEGER,
		module_count INTEGER,
		total_bytes  INTEGER
	)`)

	// ── seed 3 modules + 3 matching bodies ─────────────────────────────
	rows := []struct {
		id      int64
		sha256  string
		name    string
		excerpt string
		symbols string
	}{
		{1, "sha256aaa111", "sendMessageHandler", `sendMessage(payload)`, `{"fn":"sendMessage"}`},
		{2, "sha256bbb222", "ReceiptTracker", `trackReceipt(id)`, `{"fn":"trackReceipt"}`},
		{3, "sha256ccc333", "MediaUploader", `uploadMedia(file)`, `{"fn":"uploadMedia"}`},
	}
	for _, r := range rows {
		exec(`INSERT INTO modules
			(id, app, name, synthetic_name, prefix, body_size, body_excerpt, body_sha256,
			 symbols_json, summary, tags, first_seen_at, last_seen_at, lang, repo_root)
			VALUES (?, 'whatsapp', ?, NULL, NULL, 1000, ?, ?, ?, 'test summary', 'chat', 0, 0, 'js', '')`,
			r.id, r.name, r.excerpt, r.sha256, r.symbols)

		exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
			VALUES (?, ?, ?, 0)`,
			r.sha256, []byte("// "+r.name), len("// "+r.name))
	}

	return path
}

func TestDBMigrateIntegration(t *testing.T) {
	// Integration test: runs serially (no t.Parallel()) — mutates package-level
	// migrate flag vars and a process-global config DSN via pinDSNViaConfig.
	// Boot Postgres container + apply migrations.
	dstDB, dsn := dbtest.StartPostgres(t)

	// Wire kbOpenDB("") → container via config.yaml helper.
	pinDSNViaConfig(t, dsn)

	// Build SQLite fixture.
	fixturePath := createFixtureSQLite(t)

	// ── Reset package-level flag vars, restore on cleanup ──────────────
	origSrc := migrateSrcPath
	origBatch := migrateBatch
	origVerify := migrateVerify
	origDryRun := migrateDryRun
	t.Cleanup(func() {
		migrateSrcPath = origSrc
		migrateBatch = origBatch
		migrateVerify = origVerify
		migrateDryRun = origDryRun
	})

	migrateSrcPath = fixturePath
	migrateBatch = 2
	migrateVerify = true
	migrateDryRun = false

	// Build a minimal cobra.Command with a captured output buffer.
	var buf bytes.Buffer
	c := &cobra.Command{}
	c.SetOut(&buf)

	// ── First run ───────────────────────────────────────────────────────
	if err := runDBMigrateFromSQLite(c, nil); err != nil {
		t.Fatalf("first migrate run: %v", err)
	}

	// 1. modules + module_bodies counts == 3 each.
	assertCount(t, dstDB, "modules", 3)
	assertCount(t, dstDB, "module_bodies", 3)

	// 2. Anchor rows.
	assertCount(t, dstDB, "kb_apps WHERE canonical_name='legacy'", 1)
	assertCount(t, dstDB, "knowledge_sources WHERE app='legacy' AND epoch=1", 1)
	assertCount(t, dstDB, "module_app_refs", 3)

	// 3. kb_search-shaped join resolves 'sendMessage'.
	var hitCount int
	joinQ := `SELECT COUNT(*) FROM modules m
		JOIN module_app_refs mar ON mar.body_sha256 = m.body_sha256
		JOIN knowledge_sources ks  ON ks.id = mar.source_id
		JOIN kb_apps ka             ON ka.kb_id = ks.kb_id
		WHERE m.search_text ILIKE '%sendMessage%'`
	if err := dstDB.QueryRow(joinQ).Scan(&hitCount); err != nil {
		t.Fatalf("kb_search join: %v", err)
	}
	if hitCount < 1 {
		t.Fatalf("kb_search 4-way join: got %d hits for 'sendMessage', want >=1", hitCount)
	}

	// 4. Idempotency: second run must leave all counts unchanged.
	buf.Reset()
	if err := runDBMigrateFromSQLite(c, nil); err != nil {
		t.Fatalf("second migrate run (idempotency): %v", err)
	}
	assertCount(t, dstDB, "modules", 3)
	assertCount(t, dstDB, "module_bodies", 3)
	assertCount(t, dstDB, "module_app_refs", 3)
	assertCount(t, dstDB, "kb_apps WHERE canonical_name='legacy'", 1)
	assertCount(t, dstDB, "knowledge_sources WHERE app='legacy' AND epoch=1", 1)

	// 5. Parity verify fails when a module_bodies row is deleted from PG.
	if _, err := dstDB.Exec(`DELETE FROM module_bodies WHERE body_sha256='sha256aaa111'`); err != nil {
		t.Fatalf("delete module_bodies row: %v", err)
	}
	srcDB, err := sql.Open("sqlite", fixturePath)
	if err != nil {
		t.Fatalf("open fixture for verify: %v", err)
	}
	defer func() { _ = srcDB.Close() }()

	var verifyBuf bytes.Buffer
	verifyErr := runMigrateVerify(srcDB, dstDB, fixturePath, &verifyBuf)
	if verifyErr == nil {
		t.Fatal("runMigrateVerify: expected non-nil error after deleting a module_bodies row, got nil")
	}
}

// assertCount runs SELECT COUNT(*) FROM <tableExpr> and fatals if the result
// differs from want.
func assertCount(t *testing.T, db *sql.DB, tableExpr string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + tableExpr).Scan(&got); err != nil {
		t.Fatalf("count(%s): %v", tableExpr, err)
	}
	if got != want {
		t.Fatalf("count(%s) = %d, want %d", tableExpr, got, want)
	}
}
