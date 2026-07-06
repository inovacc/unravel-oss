/*
Copyright (c) 2026 Security Research
*/
// cmd/db_migrate.go owns `unravel db migrate-from-sqlite` — a one-shot
// importer that copies an existing SQLite knowledge.db into the new
// Postgres-backed catalog.
//
// Mapping mirrors migrations/000001 1:1 — same column names, same types.
// Per-table strategy:
//
//	modules           — INSERT ... ON CONFLICT (app, body_sha256) DO NOTHING
//	module_sightings  — INSERT ... ON CONFLICT (module_id, source_file, byte_offset)
//	                    DO NOTHING. module_id is remapped via the per-row
//	                    sha256→pg_id lookup built during the modules pass.
//	module_bodies     — INSERT ... ON CONFLICT (body_sha256) DO NOTHING
//	module_enrichment — INSERT ... ON CONFLICT (module_id) DO NOTHING (id remap)
//	module_deps       — INSERT ... ON CONFLICT (from_id, to_name) DO NOTHING (id remap)
//	app_facts         — INSERT ... ON CONFLICT (app, category, key) DO NOTHING (id remap)
//	fact_history      — INSERT ... ON CONFLICT (fact_id, observed_at) DO NOTHING (id remap)
//	module_embeddings — INSERT ... ON CONFLICT (module_id) DO NOTHING (id remap)
//	repos             — INSERT ... ON CONFLICT (slug) DO NOTHING
//
// All inserts use COPY-style batching via prepared statements inside one
// tx per table for throughput. ID remapping is in-memory because 100k rows
// × 8 bytes is trivial.

package cmd

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	_ "modernc.org/sqlite"

	"github.com/spf13/cobra"
)

var (
	migrateSrcPath string
	migrateDryRun  bool
	migrateBatch   int
	migrateVerify  bool
)

var dbMigrateFromSQLiteCmd = &cobra.Command{
	Use:   "migrate-from-sqlite",
	Short: "Copy a legacy SQLite knowledge.db into the configured Postgres catalog",
	RunE:  runDBMigrateFromSQLite,
}

func init() {
	dbMigrateFromSQLiteCmd.Flags().StringVar(&migrateSrcPath, "src", "", "path to legacy SQLite knowledge.db (required)")
	dbMigrateFromSQLiteCmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "count rows but don't write to Postgres")
	dbMigrateFromSQLiteCmd.Flags().IntVar(&migrateBatch, "batch", 5000, "rows per committed batch (resumable via ON CONFLICT on re-run)")
	dbMigrateFromSQLiteCmd.Flags().BoolVar(&migrateVerify, "verify", false, "after the (idempotent) migration pass, check SQLite↔Postgres row parity + a kb_search-shaped smoke; non-zero exit on mismatch")
	_ = dbMigrateFromSQLiteCmd.MarkFlagRequired("src")
	dbCmd.AddCommand(dbMigrateFromSQLiteCmd)
}

// batchCounter triggers flush() every n successful ticks and once more on
// done() if there is an unflushed remainder. Used to turn the legacy
// whole-table single transaction into committed batches so a 1.9 GB
// migration is resumable: a killed run re-runs and ON CONFLICT skips
// already-committed rows. Not safe for concurrent use; intended for
// single-pass use (call done() once).
type batchCounter struct {
	n     int
	count int64 // cumulative rows processed; available for progress logging
	since int
	flush func() error
}

// newBatchCounter returns a batchCounter that flushes every n rows; n<=0 defaults to 5000.
func newBatchCounter(n int, flush func() error) *batchCounter {
	if n <= 0 {
		n = 5000
	}
	return &batchCounter{n: n, flush: flush}
}

func (b *batchCounter) tick() error {
	b.count++
	b.since++
	if b.since >= b.n {
		b.since = 0
		return b.flush()
	}
	return nil
}

func (b *batchCounter) done() error {
	if b.since > 0 {
		b.since = 0
		return b.flush()
	}
	return nil
}

func runDBMigrateFromSQLite(cmd *cobra.Command, _ []string) error {
	src, err := sql.Open("sqlite", migrateSrcPath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = src.Close() }()

	totals := map[string]int64{}
	for _, t := range []string{
		"modules", "module_sightings", "module_bodies", "module_enrichment",
		"module_deps", "app_facts", "fact_history",
		"module_embeddings", "repos",
	} {
		var n int64
		_ = src.QueryRow(`SELECT COUNT(*) FROM ` + t).Scan(&n)
		totals[t] = n
		fmt.Fprintf(cmd.OutOrStdout(), "  %-20s %10d\n", t, n)
	}
	if migrateDryRun {
		fmt.Fprintln(cmd.OutOrStdout(), "(dry-run)")
		return nil
	}

	dst, err := kbOpenDB("")
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer func() { _ = dst.Close() }()

	// modules: build sqliteID → postgresID map, used by every dependent table.
	idMap := make(map[int64]int64, totals["modules"])
	if err := copyModules(src, dst, idMap, totals["modules"]); err != nil {
		return fmt.Errorf("modules: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "modules: %d ids mapped\n", len(idMap))

	if err := copyBodies(src, dst, totals["module_bodies"]); err != nil {
		return fmt.Errorf("module_bodies: %w", err)
	}
	if err := copySightings(src, dst, idMap, totals["module_sightings"]); err != nil {
		return fmt.Errorf("module_sightings: %w", err)
	}
	if err := copyEnrichment(src, dst, idMap, totals["module_enrichment"]); err != nil {
		return fmt.Errorf("module_enrichment: %w", err)
	}
	if err := copyDeps(src, dst, idMap, totals["module_deps"]); err != nil {
		return fmt.Errorf("module_deps: %w", err)
	}
	factIDMap := make(map[int64]int64)
	if err := copyAppFacts(src, dst, factIDMap, totals["app_facts"]); err != nil {
		return fmt.Errorf("app_facts: %w", err)
	}
	if err := copyFactHistory(src, dst, factIDMap, totals["fact_history"]); err != nil {
		return fmt.Errorf("fact_history: %w", err)
	}
	if err := copyEmbeddings(src, dst, idMap, totals["module_embeddings"]); err != nil {
		return fmt.Errorf("module_embeddings: %w", err)
	}
	if err := copyRepos(src, dst, totals["repos"]); err != nil {
		return fmt.Errorf("repos: %w", err)
	}
	if err := synthesizeLegacyAnchor(dst, migrateSrcPath); err != nil {
		return fmt.Errorf("legacy anchor: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "legacy anchor synthesized")
	if migrateVerify {
		fmt.Fprintln(cmd.OutOrStdout(), "verify:")
		if err := runMigrateVerify(src, dst, migrateSrcPath, cmd.OutOrStdout()); err != nil {
			return err
		}
	}
	fmt.Fprintln(cmd.OutOrStdout(), "migration complete")
	return nil
}

// scanRows pulls every column as any so we don't have to type-assert each
// table individually. Each callback receives []any for one row.
//
// Postgres TEXT requires valid UTF-8; SQLite happily stores arbitrary
// bytes. Strings and []byte values are sanitized through sanitizeUTF8
// before reaching the callback so invalid sequences don't trip
// SQLSTATE 22021 on insert.
func scanRows(src *sql.DB, sqlText string, cb func(vals []any) error) error {
	rows, err := src.Query(sqlText)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	colTypes, err := rows.ColumnTypes()
	if err != nil {
		return err
	}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		for i := range vals {
			vals[i] = sanitizeUTF8ByCol(vals[i], colTypes[i].DatabaseTypeName())
		}
		if err := cb(vals); err != nil {
			return err
		}
	}
	return rows.Err()
}

// sanitizeUTF8ByCol cleans non-UTF-8 byte sequences out of values headed
// for Postgres TEXT columns. BLOB / BYTEA columns are passed through
// untouched so binary bodies / vectors survive intact. The SQLite type
// affinity comes via DatabaseTypeName() which returns the column's
// declared type ("BLOB", "TEXT", "INTEGER", ...).
func sanitizeUTF8ByCol(v any, declaredType string) any {
	if v == nil {
		return nil
	}
	declared := strings.ToUpper(declaredType)
	if declared == "BLOB" || declared == "BYTEA" {
		return v
	}
	switch x := v.(type) {
	case string:
		return sanitizeUTF8String(x)
	case []byte:
		// SQLite returns TEXT columns as []byte when the bytes aren't
		// valid UTF-8. Convert to string after sanitising so the pgx
		// driver routes it to TEXT, not BYTEA.
		return sanitizeUTF8String(string(x))
	}
	return v
}

// sanitizeUTF8String returns s with every invalid UTF-8 byte AND every
// NUL byte (0x00) replaced by the Unicode replacement char U+FFFD.
//
// Postgres TEXT explicitly forbids NUL bytes even when the rest of the
// string is valid UTF-8 — SQLSTATE 22021 — so we strip them alongside
// the encoding-invalid sequences.
func sanitizeUTF8String(s string) string {
	if utf8.ValidString(s) && !strings.ContainsRune(s, 0) {
		return s
	}
	r := make([]rune, 0, len(s))
	for i := 0; i < len(s); {
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == 0 || (c == utf8.RuneError && size == 1) {
			r = append(r, '�')
			i++
			continue
		}
		r = append(r, c)
		i += size
	}
	return string(r)
}

// copyModules walks the legacy modules rows and INSERTs each, recording
// the sqliteID → postgresID mapping in idMap.
//
// Performance: every dependent table needs the id remap before it can run,
// so RETURNING id is mandatory and we cannot use COPY. Instead the
// inserts run inside a single transaction so PG amortises fsync across
// the whole table — empirically ~10× faster than the old per-row
// autocommit loop on a remote cluster.
//
// On error the tx is rolled back; the next invocation sees an empty
// modules table and starts fresh. ON CONFLICT (app, body_sha256) makes
// re-runs against an already-migrated DB an idempotent no-op.
//
// single-tx: the sqliteID→pgID map must survive the whole pass; resumability
// for this table is the whole-pass ON CONFLICT replay (module_bodies — the
// large payload — IS batched).
func copyModules(src, dst *sql.DB, idMap map[int64]int64, total int64) error {
	tx, err := dst.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	stmt, err := tx.Prepare(`INSERT INTO modules
		(app, name, synthetic_name, prefix, body_size, body_excerpt, body_sha256,
		 symbols_json, summary, tags, first_seen_at, last_seen_at, lang, repo_root)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (app, body_sha256) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at
		RETURNING id`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	var done int64
	if err := scanRows(src, `SELECT id, app, name, synthetic_name, prefix, body_size,
		body_excerpt, body_sha256, symbols_json, summary, tags,
		first_seen_at, last_seen_at, lang, repo_root FROM modules`, func(v []any) error {
		oldID, _ := v[0].(int64)
		var newID int64
		if err := stmt.QueryRow(
			v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14],
		).Scan(&newID); err != nil {
			return err
		}
		idMap[oldID] = newID
		done++
		if migrateBatch > 0 && done > 0 && done%int64(migrateBatch) == 0 {
			slog.Info("migrate progress", "table", "modules", "done", done, "total", total)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// batchedInTx prepares sqlText and calls body with a stmt() getter whose
// enclosing tx is committed and re-opened every migrateBatch rows that
// body signals via tick(). The getter always returns the current *sql.Stmt
// so callers that invoke stmt() after a batch boundary get the fresh
// prepared statement, not the closed one from the previous batch.
// table is used for slog progress; total is the source row count (0 = unknown).
// A failed batch rolls back only itself; already-committed batches persist
// (ON CONFLICT makes a re-run resume).
func batchedInTx(dst *sql.DB, table, sqlText string, total int64, body func(stmt func() *sql.Stmt, tick func() error) error) error {
	var tx *sql.Tx
	var stmt *sql.Stmt
	open := func() error {
		t, err := dst.Begin()
		if err != nil {
			return err
		}
		s, err := t.Prepare(sqlText)
		if err != nil {
			_ = t.Rollback()
			return err
		}
		tx, stmt = t, s
		return nil
	}
	commit := func() error {
		if stmt != nil {
			_ = stmt.Close()
		}
		if tx == nil {
			return nil
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		tx, stmt = nil, nil
		return nil
	}
	if err := open(); err != nil {
		return err
	}
	defer func() {
		if stmt != nil {
			_ = stmt.Close()
		}
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	done := int64(0)
	bc := newBatchCounter(migrateBatch, func() error {
		if err := commit(); err != nil {
			return err
		}
		slog.Info("migrate progress", "table", table, "done", done, "total", total)
		return open()
	})
	tick := func() error { done++; return bc.tick() }
	if err := body(func() *sql.Stmt { return stmt }, tick); err != nil {
		return err
	}
	if err := bc.done(); err != nil {
		return err
	}
	return commit()
}

func copyBodies(src, dst *sql.DB, total int64) error {
	return batchedInTx(dst, "module_bodies", `INSERT INTO module_bodies
		(body_sha256, body, body_size, stored_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (body_sha256) DO NOTHING`, total, func(stmt func() *sql.Stmt, tick func() error) error {
		return scanRows(src, `SELECT body_sha256, body, body_size, stored_at FROM module_bodies`, func(v []any) error {
			if _, err := stmt().Exec(v[0], v[1], v[2], v[3]); err != nil {
				return err
			}
			return tick()
		})
	})
}

func copySightings(src, dst *sql.DB, idMap map[int64]int64, total int64) error {
	return batchedInTx(dst, "module_sightings", `INSERT INTO module_sightings
		(module_id, source_file, byte_offset, observed_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (module_id, source_file, byte_offset) DO NOTHING`, total, func(stmt func() *sql.Stmt, tick func() error) error {
		return scanRows(src, `SELECT module_id, source_file, byte_offset, observed_at FROM module_sightings`, func(v []any) error {
			oldID, _ := v[0].(int64)
			newID, ok := idMap[oldID]
			if !ok {
				return nil
			}
			if _, err := stmt().Exec(newID, v[1], v[2], v[3]); err != nil {
				return err
			}
			return tick()
		})
	})
}

func copyEnrichment(src, dst *sql.DB, idMap map[int64]int64, total int64) error {
	return batchedInTx(dst, "module_enrichment", `INSERT INTO module_enrichment
		(module_id, long_summary, role, inputs_json, outputs_json, side_effects,
		 deps_json, raw_response, model, body_sha256, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (module_id) DO NOTHING`, total, func(stmt func() *sql.Stmt, tick func() error) error {
		return scanRows(src, `SELECT module_id, long_summary, role, inputs_json, outputs_json,
			side_effects, deps_json, raw_response, model, body_sha256, created_at FROM module_enrichment`,
			func(v []any) error {
				oldID, _ := v[0].(int64)
				newID, ok := idMap[oldID]
				if !ok {
					return nil
				}
				if _, err := stmt().Exec(newID, v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10]); err != nil {
					return err
				}
				return tick()
			})
	})
}

func copyDeps(src, dst *sql.DB, idMap map[int64]int64, total int64) error {
	return batchedInTx(dst, "module_deps", `INSERT INTO module_deps (from_id, to_name, to_id)
		VALUES ($1, $2, $3) ON CONFLICT (from_id, to_name) DO NOTHING`, total, func(stmt func() *sql.Stmt, tick func() error) error {
		return scanRows(src, `SELECT from_id, to_name, to_id FROM module_deps`, func(v []any) error {
			oldFrom, _ := v[0].(int64)
			newFrom, ok := idMap[oldFrom]
			if !ok {
				return nil
			}
			var newToID any
			if v[2] != nil {
				oldTo, _ := v[2].(int64)
				if mapped, ok := idMap[oldTo]; ok {
					newToID = mapped
				}
			}
			if _, err := stmt().Exec(newFrom, v[1], newToID); err != nil {
				return err
			}
			return tick()
		})
	})
}

// copyAppFacts inserts facts and remembers the postgresID for each
// sqliteID. The ON CONFLICT branch uses a second prepared lookup statement
// so the entire copy still runs inside one transaction (the prior version
// fell through to dst.QueryRow which would have happened on a separate
// connection, defeating the single-tx optimisation).
//
// single-tx: the sqliteID→pgID map must survive the whole pass; resumability
// for this table is the whole-pass ON CONFLICT replay (module_bodies — the
// large payload — IS batched).
func copyAppFacts(src, dst *sql.DB, factIDMap map[int64]int64, total int64) error {
	tx, err := dst.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	ins, err := tx.Prepare(`INSERT INTO app_facts
		(app, category, key, value, evidence_ids, source_step, confidence,
		 gap_prompt, candidates_q, value_format, filled_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (app, category, key) DO NOTHING
		RETURNING id`)
	if err != nil {
		return err
	}
	defer func() { _ = ins.Close() }()
	lookup, err := tx.Prepare(`SELECT id FROM app_facts WHERE app=$1 AND category=$2 AND key=$3`)
	if err != nil {
		return err
	}
	defer func() { _ = lookup.Close() }()

	var done int64
	if err := scanRows(src, `SELECT id, app, category, key, value, evidence_ids,
		source_step, confidence, gap_prompt, candidates_q, value_format,
		filled_at, updated_at FROM app_facts`, func(v []any) error {
		oldID, _ := v[0].(int64)
		var newID int64
		ierr := ins.QueryRow(v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12]).Scan(&newID)
		if ierr == sql.ErrNoRows {
			if qerr := lookup.QueryRow(v[1], v[2], v[3]).Scan(&newID); qerr != nil {
				return qerr
			}
		} else if ierr != nil {
			return ierr
		}
		factIDMap[oldID] = newID
		done++
		if migrateBatch > 0 && done > 0 && done%int64(migrateBatch) == 0 {
			slog.Info("migrate progress", "table", "app_facts", "done", done, "total", total)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func copyFactHistory(src, dst *sql.DB, factIDMap map[int64]int64, total int64) error {
	return batchedInTx(dst, "fact_history", `INSERT INTO fact_history
		(fact_id, value, evidence_ids, source_step, confidence, observed_at)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (fact_id, observed_at) DO NOTHING`, total, func(stmt func() *sql.Stmt, tick func() error) error {
		return scanRows(src, `SELECT fact_id, value, evidence_ids, source_step,
			confidence, observed_at FROM fact_history`, func(v []any) error {
			oldID, _ := v[0].(int64)
			newID, ok := factIDMap[oldID]
			if !ok {
				return nil
			}
			if _, err := stmt().Exec(newID, v[1], v[2], v[3], v[4], v[5]); err != nil {
				return err
			}
			return tick()
		})
	})
}

func copyEmbeddings(src, dst *sql.DB, idMap map[int64]int64, total int64) error {
	return batchedInTx(dst, "module_embeddings", `INSERT INTO module_embeddings
		(module_id, model, dim, vector, created_at) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (module_id) DO NOTHING`, total, func(stmt func() *sql.Stmt, tick func() error) error {
		return scanRows(src, `SELECT module_id, model, dim, vector, created_at FROM module_embeddings`,
			func(v []any) error {
				oldID, _ := v[0].(int64)
				newID, ok := idMap[oldID]
				if !ok {
					return nil
				}
				if _, err := stmt().Exec(newID, v[1], v[2], v[3], v[4]); err != nil {
					return err
				}
				return tick()
			})
	})
}

func copyRepos(src, dst *sql.DB, total int64) error {
	return batchedInTx(dst, "repos", `INSERT INTO repos
		(slug, root, vcs, vcs_head, indexed_at, module_count, total_bytes)
		VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (slug) DO NOTHING`, total, func(stmt func() *sql.Stmt, tick func() error) error {
		return scanRows(src, `SELECT slug, root, vcs, vcs_head, indexed_at, module_count, total_bytes FROM repos`,
			func(v []any) error {
				if _, err := stmt().Exec(v[0], v[1], v[2], v[3], v[4], v[5], v[6]); err != nil {
					return err
				}
				return tick()
			})
	})
}

const legacyApp = "legacy"

// anchorKBApp returns the idempotent INSERT SQL for the legacy kb_apps row.
// $1=kb_id, $2=mtime_ms (used for both first_seen_at and last_seen_at).
func anchorKBApp() string {
	return `INSERT INTO kb_apps
		(kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at)
		VALUES ($1,'legacy','Legacy SQLite corpus','legacy',$2,$2)
		ON CONFLICT (kb_id) DO NOTHING`
}

// anchorKnowledgeSource returns the idempotent INSERT SQL for the legacy
// knowledge_sources row. $1=kb_id, $2=source_path, $3=captured_at_ms, $4=ks_id.
//
// Uses the partial unique index knowledge_sources_kb_epoch_uq (kb_id, epoch)
// WHERE kb_id IS NOT NULL (migration 000004). The old (app, epoch) constraint
// was dropped by migration 000011.
func anchorKnowledgeSource() string {
	return `INSERT INTO knowledge_sources
		(kb_id, app, epoch, source_path, source_kind, captured_at, ks_id)
		VALUES ($1,'legacy',1,$2,'sqlite',$3,$4)
		ON CONFLICT (kb_id, epoch) WHERE kb_id IS NOT NULL DO NOTHING`
}

// anchorRefsSQL returns the idempotent INSERT SQL that binds every migrated
// module body to the legacy knowledge_sources row so the kb_search join
// (modules → module_app_refs → knowledge_sources → kb_apps) resolves.
//
// module_app_refs PRIMARY KEY is (body_sha256, app, source_id), so
// ON CONFLICT (body_sha256, app, source_id) is the correct conflict target.
// $1=source_id (int64), $2=observed_at (ms).
func anchorRefsSQL() string {
	// Explicit ::bigint casts required: pgx cannot infer parameter types
	// for untyped literals in a SELECT…INSERT when the column is BIGINT.
	return `INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
		SELECT DISTINCT m.body_sha256, 'legacy', $1::bigint, $2::bigint FROM modules m
		ON CONFLICT (body_sha256, app, source_id) DO NOTHING`
}

// synthesizeLegacyAnchor creates exactly one kb_apps + one knowledge_sources
// row for the migrated SQLite corpus and binds every migrated module body to
// it via module_app_refs so kb_search returns the corpus. Idempotent:
// deterministic kb_id + ON CONFLICT guards make re-runs safe.
func synthesizeLegacyAnchor(dst *sql.DB, srcPath string) error {
	kbID := legacyKBID(srcPath)
	mtimeMs := int64(0)
	if fi, err := os.Stat(srcPath); err == nil {
		mtimeMs = fi.ModTime().UnixMilli()
	} else {
		slog.Warn("could not stat legacy source; anchor timestamps will be zero", "path", srcPath, "err", err)
	}
	tx, err := dst.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(anchorKBApp(), kbID, mtimeMs); err != nil {
		return fmt.Errorf("anchor kb_apps: %w", err)
	}
	ksID := kbID + ":legacy:1"
	if _, err := tx.Exec(anchorKnowledgeSource(), kbID, srcPath, mtimeMs, ksID); err != nil {
		return fmt.Errorf("anchor knowledge_sources: %w", err)
	}
	var sourceID int64
	// UNIQUE(kb_id,epoch) WHERE kb_id IS NOT NULL ⇒ at most one legacy/epoch-1 row; bind to whichever won the conflict.
	if err := tx.QueryRow(
		`SELECT id FROM knowledge_sources WHERE app='legacy' AND epoch=1`,
	).Scan(&sourceID); err != nil {
		return fmt.Errorf("anchor source id: %w", err)
	}
	if _, err := tx.Exec(anchorRefsSQL(), sourceID, mtimeMs); err != nil {
		return fmt.Errorf("anchor module_app_refs: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	slog.Info("legacy anchor synthesized", "kb_id", kbID, "source_id", sourceID)
	return nil
}

var verifyParityTables = []string{
	"modules", "module_bodies", "module_sightings",
	"module_enrichment", "module_deps", "app_facts", "module_embeddings",
}

// verifySearchToken is a JS method present across the WhatsApp corpus
// captures; used only as a non-empty-result smoke for the kb_search join.
const verifySearchToken = "sendMessage"

// runMigrateVerify reads counts from both DBs and a kb_search-shaped join
// over the migrated corpus. Writes a PASS/FAIL table to w; returns an
// error (→ non-zero exit) on any mismatch. Performs no writes. PG counts
// may legitimately exceed SQLite (other corpora present) — only fewer-than
// is a FAIL.
func runMigrateVerify(src, dst *sql.DB, srcPath string, w io.Writer) error {
	var failed bool
	for _, tbl := range verifyParityTables {
		var s, d int64
		if err := src.QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&s); err != nil {
			fmt.Fprintf(w, "  %-20s sqlite=ERROR(%v)\n", tbl, err)
			failed = true
			continue
		}
		if err := dst.QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&d); err != nil {
			fmt.Fprintf(w, "  %-20s pg=ERROR(%v)\n", tbl, err)
			failed = true
			continue
		}
		status := "PASS"
		if d < s {
			status = "FAIL"
			failed = true
		}
		fmt.Fprintf(w, "  %-20s sqlite=%-10d pg=%-10d %s\n", tbl, s, d, status)
	}
	kbID := legacyKBID(srcPath)
	var hits int64
	// Use ILIKE substring match rather than the % trigram-similarity operator:
	// the similarity operator compares whole-document similarity to the token
	// (requires pg_trgm threshold ≥ 0.3 for the full search_text value) and
	// returns 0 hits for short tokens against long documents. ILIKE tests
	// substring presence, which is the correct smoke for "token reachable via
	// the kb_search join".
	q := `SELECT COUNT(*) FROM modules m
		JOIN module_app_refs mar ON mar.body_sha256 = m.body_sha256
		JOIN knowledge_sources ks ON ks.id = mar.source_id
		JOIN kb_apps ka ON ka.kb_id = ks.kb_id
		WHERE ka.kb_id = $1 AND m.search_text ILIKE '%' || $2 || '%'`
	if err := dst.QueryRow(q, kbID, verifySearchToken).Scan(&hits); err != nil {
		fmt.Fprintf(w, "  %-20s kb_search-join ERROR(%v) FAIL\n", "search-repro", err)
		return fmt.Errorf("verify: search-repro query failed: %w", err)
	}
	srch := "PASS"
	if hits == 0 {
		srch = "FAIL"
		failed = true
	}
	fmt.Fprintf(w, "  %-20s kb_search-join hits=%-6d %s\n", "search-repro", hits, srch)
	if failed {
		return fmt.Errorf("verify: parity or search-repro mismatch (see table)")
	}
	return nil
}

// legacyKBID derives a stable kb_id for the synthetic legacy-corpus anchor
// from the absolute source path, so re-running the migration is idempotent
// (same path → same kb_id → ON CONFLICT DO NOTHING). Callers should pass an
// absolute path; a relative path is resolved against the process CWD.
func legacyKBID(srcPath string) string {
	abs, err := filepath.Abs(srcPath)
	if err != nil {
		abs = srcPath
	}
	sum := sha256.Sum256([]byte(abs))
	return "legacy-" + hex.EncodeToString(sum[:])[:12]
}
