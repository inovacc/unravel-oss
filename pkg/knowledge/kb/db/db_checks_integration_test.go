//go:build integration

package db_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestOpenPoolConnects proves OpenPool returns a live pgxpool.Pool backed by
// the same DSN Open would use, independent of the database/sql wrapper.
func TestOpenPoolConnects(t *testing.T) {
	_, dsn := dbtest.StartPostgres(t)
	ctx := context.Background()

	pool, err := kbdb.OpenPool(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenPool: %v", err)
	}
	defer pool.Close()

	var one int
	if err := pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query via pool: %v", err)
	}
	if one != 1 {
		t.Fatalf("SELECT 1 = %d, want 1", one)
	}
}

// TestOpenRawSkipsMigrations proves OpenRaw connects WITHOUT applying
// migrations (unlike Open) — the documented contract recovery tooling
// (ForceVersion callers) depends on: a dirty catalog must be reachable via
// OpenRaw before any migration runs against it. We create a second,
// unmigrated database on the same postgres server dbtest already booted
// (reusing the container, not inventing a new harness), connect to it via
// OpenRaw, and confirm the `modules` table does not exist until Migrate is
// called explicitly.
func TestOpenRawSkipsMigrations(t *testing.T) {
	_, adminDSN := dbtest.StartPostgres(t)
	ctx := context.Background()

	adminPool, err := kbdb.OpenPool(ctx, adminDSN)
	if err != nil {
		t.Fatalf("OpenPool (admin): %v", err)
	}
	defer adminPool.Close()

	dbName := fmt.Sprintf("unravel_openraw_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create ephemeral db %s: %v", dbName, err)
	}
	t.Cleanup(func() {
		dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = adminPool.Exec(dctx, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
	})

	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatalf("parse admin dsn: %v", err)
	}
	u.Path = "/" + dbName
	freshDSN := u.String()

	raw, err := kbdb.OpenRaw(ctx, freshDSN)
	if err != nil {
		t.Fatalf("OpenRaw: %v", err)
	}
	defer func() { _ = raw.Close() }()

	if err := kbdb.Ping(ctx, raw); err != nil {
		t.Fatalf("Ping on raw connection: %v", err)
	}

	exists := func() bool {
		var got bool
		if err := raw.QueryRow(
			`SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'modules')`,
		).Scan(&got); err != nil {
			t.Fatalf("check modules table: %v", err)
		}
		return got
	}

	if exists() {
		t.Fatal("OpenRaw should not have applied migrations, but modules table exists")
	}

	if err := kbdb.Migrate(raw); err != nil {
		t.Fatalf("Migrate after OpenRaw: %v", err)
	}
	if !exists() {
		t.Fatal("modules table missing after explicit Migrate")
	}
}

// TestCheckOrphansDetectsMissingBodies exercises both branches of
// CheckOrphans against real rows: a modules row whose body_sha256 has no
// matching module_bodies entry, and a module_enrichment row whose
// body_sha256 likewise dangles. Both columns are documented "soft FKs" (no
// DB-level REFERENCES), so Postgres happily accepts the orphaned insert and
// CheckOrphans is the only thing that catches the drift.
func TestCheckOrphansDetectsMissingBodies(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)

	// Baseline: fresh catalog has zero orphans of either kind.
	modOrphans, enrichOrphans, err := kbdb.CheckOrphans(conn)
	if err != nil {
		t.Fatalf("CheckOrphans (baseline): %v", err)
	}
	if modOrphans != 0 || enrichOrphans != 0 {
		t.Fatalf("baseline orphans = (%d, %d), want (0, 0)", modOrphans, enrichOrphans)
	}

	// A module with a body that actually exists — NOT an orphan — used as
	// the parent row for the enrichment-orphan case below.
	if _, err := conn.Exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
	                         VALUES ('present', '\x2d2d', 2, 0)`); err != nil {
		t.Fatalf("seed module_bodies: %v", err)
	}
	var validID int64
	if err := conn.QueryRow(`INSERT INTO modules (app, name, body_sha256)
	                          VALUES ('orphantest', 'validMod', 'present') RETURNING id`).Scan(&validID); err != nil {
		t.Fatalf("seed valid module: %v", err)
	}

	// Orphan #1: modules row pointing at a body_sha256 that was never stored.
	if _, err := conn.Exec(`INSERT INTO modules (app, name, body_sha256)
	                         VALUES ('orphantest', 'danglingMod', 'ghost-body')`); err != nil {
		t.Fatalf("seed orphan module: %v", err)
	}

	// Orphan #2: enrichment row (valid module_id FK) with a dangling
	// body_sha256 — module_enrichment.body_sha256 carries no REFERENCES.
	if _, err := conn.Exec(`INSERT INTO module_enrichment (module_id, body_sha256)
	                         VALUES ($1, 'ghost-enrichment')`, validID); err != nil {
		t.Fatalf("seed orphan enrichment: %v", err)
	}

	modOrphans, enrichOrphans, err = kbdb.CheckOrphans(conn)
	if err != nil {
		t.Fatalf("CheckOrphans: %v", err)
	}
	if modOrphans != 1 {
		t.Errorf("modules orphans = %d, want 1", modOrphans)
	}
	if enrichOrphans != 1 {
		t.Errorf("enrichment orphans = %d, want 1", enrichOrphans)
	}
}

// TestCheckEmbeddingDimsAcceptsWellFormedVectors proves CheckEmbeddingDims
// reports zero drift for a vector whose byte length matches its declared
// dim under the f32 layout. The mismatched-length branch is guarded by the
// module_embeddings_layout_chk CHECK constraint at the schema level (see
// migration 000001), so a genuinely corrupt row can never be INSERTed
// through normal SQL — CheckEmbeddingDims exists as a defense-in-depth
// scan (e.g. for rows written before that constraint existed). This test
// documents both facts: the well-formed path reports clean, and the
// malformed path is rejected before it can reach the table at all.
func TestCheckEmbeddingDimsAcceptsWellFormedVectors(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)

	var validID int64
	if err := conn.QueryRow(`INSERT INTO modules (app, name, body_sha256)
	                          VALUES ('embedtest', 'embedMod', 'embed-body') RETURNING id`).Scan(&validID); err != nil {
		t.Fatalf("seed module: %v", err)
	}

	// dim=2, f32 layout => 8 bytes.
	vec := make([]byte, 8)
	if _, err := conn.Exec(`INSERT INTO module_embeddings (module_id, model, dim, vector, created_at)
	                         VALUES ($1, 'test-model', 2, $2, 0)`, validID, vec); err != nil {
		t.Fatalf("seed well-formed embedding: %v", err)
	}

	n, err := kbdb.CheckEmbeddingDims(conn)
	if err != nil {
		t.Fatalf("CheckEmbeddingDims: %v", err)
	}
	if n != 0 {
		t.Errorf("CheckEmbeddingDims = %d, want 0 for a well-formed row", n)
	}

	// Malformed vector (7 bytes fits neither dim*4=8 nor dim*2=4) must be
	// rejected at the DB layer by the layout CHECK constraint.
	bad := make([]byte, 7)
	if _, err := conn.Exec(`INSERT INTO module_embeddings (module_id, model, dim, vector, created_at)
	                         VALUES ($1, 'test-model', 2, $2, 0)`, validID, bad); err == nil {
		t.Fatal("expected CHECK constraint violation for mismatched vector length, got nil error")
	}
}

// TestCountFactHistoryCountsRows proves CountFactHistory reflects real
// fact_history rows keyed off a live app_facts parent (FK-enforced).
func TestCountFactHistoryCountsRows(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)

	n, err := kbdb.CountFactHistory(conn)
	if err != nil {
		t.Fatalf("CountFactHistory (baseline): %v", err)
	}
	if n != 0 {
		t.Fatalf("baseline CountFactHistory = %d, want 0", n)
	}

	var factID int64
	if err := conn.QueryRow(`INSERT INTO app_facts (app, category, key, value, source_step)
	                          VALUES ('facthist', 'crypto', 'cipher', 'AES', 'fill') RETURNING id`).Scan(&factID); err != nil {
		t.Fatalf("seed app_facts: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO fact_history (fact_id, value, source_step, observed_at)
	                         VALUES ($1, 'AES', 'fill', 1000), ($1, 'AES-CBC', 'revise', 2000)`, factID); err != nil {
		t.Fatalf("seed fact_history: %v", err)
	}

	n, err = kbdb.CountFactHistory(conn)
	if err != nil {
		t.Fatalf("CountFactHistory: %v", err)
	}
	if n != 2 {
		t.Errorf("CountFactHistory = %d, want 2", n)
	}
}
