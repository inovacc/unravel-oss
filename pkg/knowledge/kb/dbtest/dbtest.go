//go:build integration

// Package dbtest provides a testcontainers-go helper that boots a fresh
// postgres container, applies the embedded migrations, and returns a
// *sql.DB ready for kb tests. Used only by integration-tagged tests.
//
// Escape hatch: if UNRAVEL_TEST_DSN is set (a postgres:// URL to an
// already-running server, e.g. on hosts without Docker), StartPostgres
// skips testcontainers entirely. It creates a uniquely-named ephemeral
// database on that server, migrates only that database, and drops it on
// cleanup. The maintenance database in the DSN is never migrated or
// mutated, so pointing this at a real Postgres is non-destructive.
package dbtest

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
)

// EnvTestDSN is the opt-in env var that points dbtest at an existing
// Postgres instead of spawning a testcontainers container.
const EnvTestDSN = "UNRAVEL_TEST_DSN"

// StartPostgresOrSkip is the same as StartPostgres but calls t.Skip on the
// "no Docker / no DSN" provisioning failure path instead of t.Fatalf. Use
// this in new tests where the developer environment may not have Docker
// (e.g. Windows CI without Docker Desktop running). On any later, real
// failure (migration error, etc.) it still calls t.Fatalf.
func StartPostgresOrSkip(t *testing.T) (*sql.DB, string) {
	t.Helper()
	if adminDSN := strings.TrimSpace(os.Getenv(EnvTestDSN)); adminDSN != "" {
		return startExternalPostgres(t, adminDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	container, err := tcpostgres.Run(ctx,
		"pgvector/pgvector:pg16",
		tcpostgres.WithDatabase("unraveltest"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("dbtest: docker unavailable and %s unset (%v) — skipping", EnvTestDSN, err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("dbtest: dsn: %v", err)
	}

	conn, err := kbdb.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("dbtest: kbdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, dsn
}

// StartPostgres boots a transient pgvector/pgvector:pg16 container,
// applies unravel's embedded migrations (which require the pg_trgm and
// vector extensions), and returns a *sql.DB connected to it. Cleanup is
// registered on t — the container terminates when the test (or test
// package) exits. We use the pgvector image rather than postgres:16-
// alpine because migration 000001 declares CREATE EXTENSION vector.
func StartPostgres(t *testing.T) (*sql.DB, string) {
	t.Helper()
	if adminDSN := strings.TrimSpace(os.Getenv(EnvTestDSN)); adminDSN != "" {
		return startExternalPostgres(t, adminDSN)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	container, err := tcpostgres.Run(ctx,
		"pgvector/pgvector:pg16",
		tcpostgres.WithDatabase("unraveltest"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("dbtest: start pg: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("dbtest: dsn: %v", err)
	}

	conn, err := kbdb.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("dbtest: kbdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, dsn
}

// startExternalPostgres implements the UNRAVEL_TEST_DSN escape hatch.
// adminDSN must be a postgres:// URL to an already-running server. We
// connect to it via OpenPool (which does NOT run migrations, so the
// maintenance database is untouched), CREATE a uniquely-named database,
// then kbdb.Open that fresh database (which migrates only it). On cleanup
// the test connection is closed, the database is dropped WITH (FORCE),
// and the admin pool is closed.
func startExternalPostgres(t *testing.T, adminDSN string) (*sql.DB, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	u, err := url.Parse(adminDSN)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("dbtest: %s must be a postgres:// URL (got %q, err=%v)", EnvTestDSN, adminDSN, err)
	}

	// Self-generated, unique, valid unquoted identifier — never user input,
	// so inlining into CREATE/DROP DATABASE (which cannot be parameterized)
	// is safe.
	name := fmt.Sprintf("unraveltest_%d_%d", os.Getpid(), time.Now().UnixNano())

	adminPool, err := kbdb.OpenPool(ctx, adminDSN)
	if err != nil {
		t.Fatalf("dbtest: %s admin connect: %v", EnvTestDSN, err)
	}
	t.Cleanup(adminPool.Close)

	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("dbtest: create ephemeral db %s: %v", name, err)
	}
	t.Cleanup(func() {
		// Fresh context — the helper ctx is cancelled by the time cleanup runs.
		dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dcancel()
		if _, err := adminPool.Exec(dctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("dbtest: drop ephemeral db %s: %v (manual cleanup may be needed)", name, err)
		}
	})

	child := *u
	child.Path = "/" + name
	childDSN := child.String()

	conn, err := kbdb.Open(ctx, childDSN)
	if err != nil {
		t.Fatalf("dbtest: kbdb.Open ephemeral db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, childDSN
}

// SeedFixtures applies the canonical store-test seed (mirrors what the
// pre-deletion newDB helper inserted). Module rows use OVERRIDING SYSTEM
// VALUE so the legacy id=1/id=2 references stay stable across the suite,
// since Postgres modules.id is GENERATED ALWAYS AS IDENTITY.
func SeedFixtures(t *testing.T, db *sql.DB) {
	t.Helper()
	exec := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("dbtest: exec %q: %v", q, err)
		}
	}
	// Bodies are referenced by body_sha256 only — store_test never reads
	// them but inserting keeps the pg foreign-key surface honest if a
	// future migration adds an FK from modules.body_sha256.
	exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
	      VALUES ('aaa', '\x6661', 2, 0)`)
	exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
	      VALUES ('bbb', '\x6262', 2, 0)`)

	exec(`INSERT INTO modules
	      (id, app, name, synthetic_name, body_size, body_excerpt, body_sha256, symbols_json, summary, tags)
	      OVERRIDING SYSTEM VALUE
	      VALUES (1, 'whatsapp', 'WAWebMsgCollection', NULL, 1234, 'fetch("/api/messages")',
	              'aaa', '{"urls":["/api/messages"]}', 'message store', 'crypto')`)
	exec(`INSERT INTO modules
	      (id, app, name, synthetic_name, body_size, body_excerpt, body_sha256, symbols_json, summary, tags)
	      OVERRIDING SYSTEM VALUE
	      VALUES (2, 'teams', 'teams_module_42', 'TeamsChat', 2048, 'subscribeToPresence',
	              'bbb', NULL, NULL, NULL)`)

	exec(`INSERT INTO module_sightings (module_id, source_file, byte_offset, observed_at)
	      VALUES (1, '/cache/wa.js', 100, 1000), (1, '/cache/wa2.js', 200, 2000)`)

	exec(`INSERT INTO app_facts (app, category, key, value, source_step, confidence)
	      VALUES ('whatsapp', 'crypto', 'db_cipher', 'AES-CBC', 'fill', 0.9)`)
	exec(`INSERT INTO app_facts (app, category, key, value, source_step)
	      VALUES ('whatsapp', 'crypto', 'kdf', NULL, 'registry')`)
	exec(`INSERT INTO app_facts (app, category, key, value, source_step)
	      VALUES ('teams', 'auth', 'oauth_scope', NULL, 'registry')`)
}
