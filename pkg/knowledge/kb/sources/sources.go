// Package sources is the typed write layer for the knowledge_sources
// catalog (migration 000002).
//
// Every long-running indexer (`unravel knowledge sweep`, `index`, `ingest`)
// allocates a row at start via Begin, threads the returned ID into
// modules.first_source_id / last_source_id and module_sightings.source_id
// upserts, then closes the row at end via Finish to persist final
// modules_indexed / bodies_indexed counters.
//
// epoch is computed atomically inside Begin as
//
//	SELECT COALESCE(MAX(epoch),0) + 1 FROM knowledge_sources WHERE app = $1
//
// guarded by a row-level advisory lock so two concurrent sweeps for the
// same app don't allocate the same epoch.
package sources

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"time"
)

// Kind enumerates known source asset shapes. The string is persisted so
// downstream queries can filter without remembering the constants.
type Kind string

const (
	KindMSIX     Kind = "msix"     // Windows Store / WindowsApps install dir
	KindSquirrel Kind = "squirrel" // Electron Squirrel app-* layout (Discord, etc.)
	KindAsar     Kind = "asar"     // ASAR archive
	KindCache    Kind = "cache"    // WebView2 / Electron HTTP cache directory
	KindRepo     Kind = "repo"     // source-code repository ingest
	KindOther    Kind = "other"
)

// Source captures the shape of a knowledge_sources row at write time.
// The ID + Epoch fields are filled by Begin; AppVersion / SourceSHA256
// / Notes are optional.
type Source struct {
	ID           int64
	App          string
	Epoch        int
	SourcePath   string
	Kind         Kind
	AppVersion   string
	SourceSHA256 string // hex (NULL when SourcePath is a directory)
	CapturedAt   time.Time
	Notes        string
	// ReuseEpoch, when > 0, makes Begin get-or-create the existing
	// (App, ReuseEpoch) row instead of allocating a fresh MAX+1 epoch.
	// Used to keep all source dirs of one build in a single epoch
	// (UNIQUE(app,epoch) forbids a second row per epoch). 0 = fresh.
	ReuseEpoch int
}

// Begin inserts a new knowledge_sources row, allocates the next epoch
// for app, and returns the populated Source. The caller must call Finish
// (or FinishWithCounts) when the indexer pass completes.
func Begin(ctx context.Context, db *sql.DB, s Source) (*Source, error) {
	if s.App == "" {
		return nil, fmt.Errorf("sources: app is required")
	}
	if s.Kind == "" {
		s.Kind = KindOther
	}
	if s.CapturedAt.IsZero() {
		s.CapturedAt = time.Now().UTC()
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("sources: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if s.ReuseEpoch > 0 {
		// Get-or-create the existing (app, epoch) row. UNIQUE(app,epoch)
		// means at most one row exists; return it so all source dirs of a
		// build share one epoch. If absent, fall through to INSERT below
		// with the caller-supplied epoch.
		//
		// Unlike the fresh path this takes NO advisory lock — concurrent
		// reuse-Begins for the same (app, epoch) could both miss the SELECT
		// and race the INSERT (the loser hits UNIQUE(app,epoch)). The sweep
		// drives reuse single-threaded per app, so the caller serialises it.
		s.Epoch = s.ReuseEpoch
		var existingID int64
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM knowledge_sources WHERE app = $1 AND epoch = $2`,
			s.App, s.ReuseEpoch,
		).Scan(&existingID)
		switch {
		case err == nil:
			if err := tx.Commit(); err != nil {
				return nil, fmt.Errorf("sources: commit: %w", err)
			}
			committed = true
			s.ID = existingID
			return &s, nil
		case errors.Is(err, sql.ErrNoRows):
			// fall through to INSERT below with s.Epoch = s.ReuseEpoch
		default:
			return nil, fmt.Errorf("sources: reuse lookup: %w", err)
		}
	} else {
		// Advisory lock keyed by app — serialises epoch allocation across
		// concurrent indexers for the same app. Auto-released at COMMIT.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, appLockKey(s.App)); err != nil {
			return nil, fmt.Errorf("sources: lock: %w", err)
		}
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(epoch), 0) + 1 FROM knowledge_sources WHERE app = $1`, s.App,
		).Scan(&s.Epoch); err != nil {
			return nil, fmt.Errorf("sources: epoch scan: %w", err)
		}
	}

	// Plain INSERT — every Begin() allocates a fresh monotonic epoch row.
	// Migration 000006 deliberately DROPPED the UNIQUE (app, source_sha256)
	// constraint so multiple epochs may share a source_sha256 (kb capture
	// --force). The old `ON CONFLICT (app, source_sha256)` clause therefore
	// references a constraint that no longer exists and raised SQLSTATE 42P10
	// on every fresh `knowledge index` pass. Application-level idempotency is
	// enforced upstream in ingest.Run, not here.
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO knowledge_sources
			(app, epoch, source_path, source_kind, app_version,
			 source_sha256, captured_at, notes)
		VALUES ($1, $2, $3, $4, NULLIF($5,''), NULLIF($6,''), $7, NULLIF($8,''))
		RETURNING id, epoch
	`, s.App, s.Epoch, s.SourcePath, string(s.Kind), s.AppVersion,
		s.SourceSHA256, s.CapturedAt.UnixMilli(), s.Notes,
	).Scan(&s.ID, &s.Epoch); err != nil {
		return nil, fmt.Errorf("sources: insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("sources: commit: %w", err)
	}
	committed = true
	return &s, nil
}

// FinishWithCounts updates the modules_indexed / bodies_indexed columns
// on the source row. Pass -1 for either counter to leave it unchanged.
func FinishWithCounts(ctx context.Context, db *sql.DB, sourceID int64, modules, bodies int64) error {
	_, err := db.ExecContext(ctx, `
		UPDATE knowledge_sources
		   SET modules_indexed = CASE WHEN $2 < 0 THEN modules_indexed ELSE $2 END,
		       bodies_indexed  = CASE WHEN $3 < 0 THEN bodies_indexed  ELSE $3 END
		 WHERE id = $1
	`, sourceID, modules, bodies)
	if err != nil {
		return fmt.Errorf("sources: finish: %w", err)
	}
	return nil
}

// AddCounts ADDS to modules_indexed / bodies_indexed (vs FinishWithCounts
// which SETs absolute values). Used by the reuse-epoch path so multiple
// index passes against the same (app, epoch) row accumulate rather than
// overwrite. Negative deltas are clamped to a no-op for that column.
func AddCounts(ctx context.Context, db *sql.DB, sourceID int64, modules, bodies int64) error {
	_, err := db.ExecContext(ctx, `
		UPDATE knowledge_sources
		   SET modules_indexed = COALESCE(modules_indexed,0) + GREATEST($2,0),
		       bodies_indexed  = COALESCE(bodies_indexed,0)  + GREATEST($3,0)
		 WHERE id = $1`, sourceID, modules, bodies)
	if err != nil {
		return fmt.Errorf("sources: add counts: %w", err)
	}
	return nil
}

// Finish is shorthand for FinishWithCounts(modules, -1).
func Finish(ctx context.Context, db *sql.DB, sourceID, modules int64) error {
	return FinishWithCounts(ctx, db, sourceID, modules, -1)
}

// LinkLastSource updates modules.last_source_id (and first_source_id when
// previously NULL) for every module currently associated with app. Used at
// end-of-pass so historical rows pick up the new source pointer without
// touching every per-row INSERT path.
func LinkLastSource(ctx context.Context, db *sql.DB, app string, sourceID int64) error {
	_, err := db.ExecContext(ctx, `
		UPDATE modules
		   SET last_source_id  = $2,
		       first_source_id = COALESCE(first_source_id, $2)
		 WHERE app = $1
		   AND last_seen_at >= (
		       SELECT captured_at - 60000  -- 60s grace window
		         FROM knowledge_sources WHERE id = $2)
	`, app, sourceID)
	if err != nil {
		return fmt.Errorf("sources: link: %w", err)
	}
	return nil
}

// appLockKey hashes app to a 64-bit advisory-lock key. fnv keeps the
// signature stable across runs without requiring Postgres functions.
func appLockKey(app string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("knowledge_sources:" + app))
	// pg_advisory_xact_lock takes a bigint; high bit set is fine.
	return int64(h.Sum64()) //nolint:gosec
}
