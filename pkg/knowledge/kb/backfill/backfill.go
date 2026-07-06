/*
Copyright (c) 2026 Security Research

Package backfill is the Phase-34 service that derives kb_id values for
legacy knowledge_sources rows captured before the P29 identity migration
and synthesizes the corresponding kb_apps rows.

Per D-34-BACKFILL-ID, the legacy kb_id is the SHA-256 hex digest of
lower(app)||'|unknown' truncated to 16 hex chars (matching the live
identity allocator's truncation width). Per D-34-IDEMPOTENCY, the two
mutating statements gate on `WHERE kb_id IS NULL` and `ON CONFLICT
(kb_id) DO NOTHING`, so re-running the backfill is a no-op.

The backfill uses the pgcrypto extension (already required by migration
000004) — Run() pre-flights its presence and returns a wrapped error if
the extension is missing. Live ingest (Phase 30) does NOT depend on
pgcrypto; only this offline backfill does (per RESEARCH Pitfall 1 and
D-29-PGCRYPTO-REMOVAL-FROM-LIVE-PATH).
*/
package backfill

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Options configures a Run invocation.
type Options struct {
	// DryRun, when true, computes counts of rows that would be touched but
	// commits no changes; the returned Report still has RowsBackfilled and
	// AppsCreated populated.
	DryRun bool
}

// Report summarizes one backfill invocation.
type Report struct {
	RowsBackfilled int `json:"rows_backfilled"`
	AppsCreated    int `json:"apps_created"`
	SchemaVersion  int `json:"schema_version"`
}

// Run executes the legacy backfill. Implementation per D-34-BACKFILL-ID:
//
//  1. Pre-flight pgcrypto extension check (RESEARCH Pitfall 1).
//  2. Single READ COMMITTED tx wrapping two statements:
//     a) UPSERT kb_apps SELECT … FROM knowledge_sources WHERE kb_id IS NULL
//     GROUP BY app   ON CONFLICT (kb_id) DO NOTHING.
//     b) UPDATE knowledge_sources SET kb_id = … WHERE kb_id IS NULL.
//  3. Commit; report counts.
//
// Both statements are idempotent: the WHERE filter and ON CONFLICT clause
// guarantee a no-op on the second invocation.
func Run(ctx context.Context, db *sql.DB, opts Options) (*Report, error) {
	if db == nil {
		return nil, errors.New("nil db")
	}

	// Pre-flight: pgcrypto must be installed (used for digest()).
	var ext string
	if err := db.QueryRowContext(ctx,
		`SELECT extname FROM pg_extension WHERE extname = 'pgcrypto'`,
	).Scan(&ext); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("pgcrypto extension missing: %w", err)
		}
		return nil, fmt.Errorf("preflight pgcrypto: %w", err)
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rep := &Report{SchemaVersion: 1}

	if opts.DryRun {
		// Count distinct legacy apps that WOULD be inserted (excluding any
		// kb_apps row already present at the same derived kb_id).
		if err := tx.QueryRowContext(ctx, dryRunAppsSQL).Scan(&rep.AppsCreated); err != nil {
			return nil, fmt.Errorf("dry-run count apps: %w", err)
		}
		// Count rows in knowledge_sources that WOULD be updated.
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM knowledge_sources WHERE kb_id IS NULL`,
		).Scan(&rep.RowsBackfilled); err != nil {
			return nil, fmt.Errorf("dry-run count rows: %w", err)
		}
		// No commit — explicit rollback via deferred Rollback.
		return rep, nil
	}

	// Statement A: UPSERT kb_apps.
	resA, err := tx.ExecContext(ctx, upsertKBAppsSQL)
	if err != nil {
		return nil, fmt.Errorf("upsert kb_apps: %w", err)
	}
	appsCreated, err := resA.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("rows affected (kb_apps): %w", err)
	}
	rep.AppsCreated = int(appsCreated)

	// Statement B: UPDATE knowledge_sources.
	resB, err := tx.ExecContext(ctx, updateKnowledgeSourcesSQL)
	if err != nil {
		return nil, fmt.Errorf("update knowledge_sources: %w", err)
	}
	rowsBackfilled, err := resB.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("rows affected (knowledge_sources): %w", err)
	}
	rep.RowsBackfilled = int(rowsBackfilled)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return rep, nil
}

// linkedKBIDExpr resolves a knowledge_sources.app to either an EXISTING
// dissect-origin kb_apps.kb_id (matched on canonical_name, preferring rows
// that carry a real package_id) or, failing that, the legacy minted id
// sha256(lower(app)||'|unknown')[:16]. canonical_name is computed identically
// to identity.CanonicalName.
const linkedKBIDExpr = `
COALESCE(
  (SELECT a.kb_id FROM kb_apps a
     WHERE a.canonical_name = trim(both '-' FROM lower(regexp_replace(ks.app, '[^a-zA-Z0-9]+', '-', 'g')))
     ORDER BY (a.package_id IS NOT NULL) DESC, a.first_seen_at ASC
     LIMIT 1),
  substring(encode(digest(lower(ks.app) || '|unknown', 'sha256'), 'hex') FROM 1 FOR 16)
)`

// upsertKBAppsSQL synthesizes a kb_apps row ONLY for legacy apps that do not
// already resolve to an existing kb_apps row (link-first per T1.2). Idempotent
// via ON CONFLICT (kb_id) DO NOTHING.
const upsertKBAppsSQL = `
INSERT INTO kb_apps (
    kb_id, canonical_name, display_name, platform, publisher, publisher_cn,
    framework, package_id, first_seen_at, last_seen_at, tags, metadata
)
SELECT
    ` + linkedKBIDExpr + ` AS kb_id,
    trim(both '-' FROM lower(regexp_replace(ks.app, '[^a-zA-Z0-9]+', '-', 'g')))      AS canonical_name,
    ks.app                                                                            AS display_name,
    'unknown'                                                                         AS platform,
    NULL, NULL, NULL, NULL,
    MIN(ks.captured_at)                                                               AS first_seen_at,
    MAX(ks.captured_at)                                                               AS last_seen_at,
    NULL,
    '{"derivation":"legacy_app_text_only","source":"phase-34-backfill"}'::jsonb       AS metadata
FROM knowledge_sources ks
WHERE ks.kb_id IS NULL
GROUP BY ks.app
ON CONFLICT (kb_id) DO NOTHING
`

// updateKnowledgeSourcesSQL backfills knowledge_sources.kb_id, linking to an
// existing dissect-origin kb_id when canonical_name matches (no dup), else
// minting. Idempotent via WHERE kb_id IS NULL.
const updateKnowledgeSourcesSQL = `
UPDATE knowledge_sources ks
SET kb_id = ` + linkedKBIDExpr + `
WHERE ks.kb_id IS NULL
`

// dryRunAppsSQL counts only apps that would MINT (no existing canonical_name match).
const dryRunAppsSQL = `
SELECT count(*) FROM (
    SELECT ks.app
    FROM knowledge_sources ks
    WHERE ks.kb_id IS NULL
      AND NOT EXISTS (
        SELECT 1 FROM kb_apps a
        WHERE a.canonical_name = trim(both '-' FROM lower(regexp_replace(ks.app, '[^a-zA-Z0-9]+', '-', 'g')))
      )
    GROUP BY ks.app
) candidates
`
