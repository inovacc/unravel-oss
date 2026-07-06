package ingest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/scanner"
)

// Sink receives native per-type CLR modules for KB persistence. The native
// decompiler emits through this seam so the capture path never buffers a
// LinkedIn-scale module set in memory.
type Sink interface {
	EmitModule(clr.TypeModule) error
}

// IngestModules persists native CLR modules with a DEDICATED INSERT that sets
// lang='cil' and is_vendored per module. It does NOT touch writeBodies (the
// .cs/extension-map walk is ilspy-only and dead for native). The IL text is
// the body: dedup key = sha256(IL). Returns the number of module rows written.
//
// It runs INSIDE the caller's transaction (the same *sql.Tx writeBodies uses)
// so cil modules commit atomically with the rest of the ingest epoch — there is
// no nested BeginTx/Commit here; the caller owns commit/rollback.
func IngestModules(ctx context.Context, tx *sql.Tx, app string, sourceID int64, mods []clr.TypeModule) (int, error) {
	if tx == nil {
		return 0, fmt.Errorf("ingest modules: tx is required")
	}

	now := time.Now().UnixMilli()
	written := 0
	for _, m := range mods {
		body := []byte(m.IL)
		sum := sha256.Sum256(body)
		sha := hex.EncodeToString(sum[:])

		// Vendored precedence (single source of truth = ingest):
		// AssemblyRef identity (engine flag) > namespace > name > body.
		vendored := m.Vendored ||
			scanner.IsVendoredAssembly(m.Name) ||
			scanner.IsVendoredName(m.Name) ||
			scanner.IsVendoredBody(body)

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (body_sha256) DO NOTHING
		`, sha, body, int64(len(body)), now); err != nil {
			return written, fmt.Errorf("insert module_bodies(cil): %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO modules (
				app, name, body_sha256, body_size, lang, is_vendored,
				first_seen_at, last_seen_at, first_source_id, last_source_id
			) VALUES ($1, $2, $3, NULL, 'cil', $4, $5, $5, $6, $6)
			ON CONFLICT DO NOTHING
		`, app, m.Name, sha, vendored, now, sourceID); err != nil {
			return written, fmt.Errorf("insert modules(cil): %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (body_sha256, app, source_id) DO NOTHING
		`, sha, app, sourceID, now); err != nil {
			return written, fmt.Errorf("insert module_app_refs(cil): %w", err)
		}
		written++
	}

	return written, nil
}
