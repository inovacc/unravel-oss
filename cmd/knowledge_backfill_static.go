/*
Copyright (c) 2026 Security Research
*/

// cmd/knowledge_backfill_static.go owns the `unravel kb enrich backfill-static`
// command. It iterates already-stored module_bodies, runs the langs walker to
// produce (Imports, SymbolsJSON), upserts module_deps and replaces noisy
// symbols_json values.
//
// Design: pure-Go, no AI, parallel workers, idempotent, resumable.
// All progress goes to stderr; stdout is reserved for structured output.
package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"

	"github.com/lib/pq"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/backfill"
	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"

	// side-effect: registers all lang extractors
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/langs"
)

// ── flag-backing variables ───────────────────────────────────────────

var (
	backfillStaticDB      string
	backfillStaticApps    string
	backfillStaticWorkers int
	backfillStaticLimit   int
	backfillStaticVerify  bool
	backfillStaticDryRun  bool
)

// ── command wiring ──────────────────────────────────────────────────

var kbBackfillStaticCmd = &cobra.Command{
	Use:   "backfill-static",
	Short: "Populate module_deps and clean noisy symbols_json from stored bodies (pure-Go, no AI)",
	Long: `Iterate already-stored module_bodies, run the langs walker on each body,
upsert module_deps rows, and replace noisy symbols_json values.

This command repairs the gap left by db migrate-from-sqlite, which bypassed
the langs walker and left module_deps empty and symbols_json full of legacy
regex garbage.

Examples:
  unravel kb enrich backfill-static --apps wa,teams --workers 8
  unravel kb enrich backfill-static --limit 5000 --dry-run
  unravel kb enrich backfill-static --verify`,
	RunE: runKBBackfillStatic,
}

func init() {
	kbBackfillStaticCmd.Flags().StringVar(&backfillStaticDB, "database", "", "DSN override (defaults to config.yaml)")
	kbBackfillStaticCmd.Flags().StringVar(&backfillStaticApps, "apps", "", "comma-separated app names to backfill (default: all)")
	kbBackfillStaticCmd.Flags().IntVar(&backfillStaticWorkers, "workers", 4, "parallel worker count")
	kbBackfillStaticCmd.Flags().IntVar(&backfillStaticLimit, "limit", 0, "max rows to process (0 = no limit)")
	kbBackfillStaticCmd.Flags().BoolVar(&backfillStaticVerify, "verify", false, "read-only: count gaps and sample 10 rows; non-zero exit if gaps remain")
	kbBackfillStaticCmd.Flags().BoolVar(&backfillStaticDryRun, "dry-run", false, "compute what would be written, no DB writes")
	kbEnrichCmd.AddCommand(kbBackfillStaticCmd)
}

// ── row type ────────────────────────────────────────────────────────

type backfillRow struct {
	id          int64
	name        string
	lang        string
	symbolsJSON sql.NullString
	body        []byte
}

// ── implementation ──────────────────────────────────────────────────

func runKBBackfillStatic(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(backfillStaticDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	if backfillStaticVerify {
		return runBackfillVerify(db)
	}
	return runBackfillWorkers(db)
}

// runBackfillVerify counts gaps and samples rows — read-only.
func runBackfillVerify(db *sql.DB) error {
	var depsCount int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM module_deps`).Scan(&depsCount); err != nil {
		return fmt.Errorf("count module_deps: %w", err)
	}
	var noisyCount int64
	rows, err := db.Query(`SELECT symbols_json FROM modules WHERE symbols_json IS NOT NULL AND symbols_json != '' LIMIT 50000`)
	if err != nil {
		return fmt.Errorf("sample symbols_json: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s sql.NullString
		if err := rows.Scan(&s); err != nil {
			continue
		}
		if s.Valid && backfill.IsNoisy(s.String) {
			noisyCount++
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows error: %w", err)
	}

	// Sample 10 random rows.
	sampleRows, err := db.Query(`
		SELECT m.id, m.name, m.lang, m.symbols_json,
		       (SELECT COUNT(*) FROM module_deps WHERE from_id = m.id) AS dep_count
		FROM modules m
		ORDER BY random()
		LIMIT 10`)
	if err != nil {
		return fmt.Errorf("sample rows: %w", err)
	}
	defer func() { _ = sampleRows.Close() }()

	fmt.Fprintf(os.Stderr, "=== backfill-static --verify ===\n")
	fmt.Fprintf(os.Stderr, "module_deps total rows : %d\n", depsCount)
	fmt.Fprintf(os.Stderr, "noisy symbols_json     : %d (sampled up to 50k)\n", noisyCount)
	fmt.Fprintf(os.Stderr, "\n%-8s %-40s %-8s %-10s %s\n", "id", "name", "lang", "deps", "symbols_noisy")
	for sampleRows.Next() {
		var (
			id       int64
			name     string
			lang     sql.NullString
			symJSON  sql.NullString
			depCount int64
		)
		if err := sampleRows.Scan(&id, &name, &lang, &symJSON, &depCount); err != nil {
			continue
		}
		noisy := symJSON.Valid && backfill.IsNoisy(symJSON.String)
		fmt.Fprintf(os.Stderr, "%-8d %-40s %-8s %-10d %v\n",
			id, truncate(name, 40), lang.String, depCount, noisy)
	}

	if depsCount == 0 || noisyCount > 0 {
		fmt.Fprintf(os.Stderr, "\nVERIFY: GAPS REMAIN (deps=%d noisy=%d)\n", depsCount, noisyCount)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "\nVERIFY: OK\n")
	return nil
}

// runBackfillWorkers runs the parallel extraction + upsert loop.
func runBackfillWorkers(db *sql.DB) error {
	apps := parseApps(backfillStaticApps)
	workers := backfillStaticWorkers
	if workers < 1 {
		workers = 1
	}
	limit := backfillStaticLimit

	// Channel of pages; each page is a slice of backfillRow.
	pageCh := make(chan []backfillRow, workers*2)

	var (
		totalProcessed atomic.Int64
		totalDepsAdded atomic.Int64
		totalSymFixed  atomic.Int64
	)

	g, ctx := errgroup.WithContext(context.Background())

	// Producer: pages rows from DB.
	g.Go(func() error {
		defer close(pageCh)
		const pageSize = 500
		offset := 0
		for {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			fetchLimit := pageSize
			if limit > 0 {
				remaining := limit - int(totalProcessed.Load())
				if remaining <= 0 {
					return nil
				}
				if remaining < fetchLimit {
					fetchLimit = remaining
				}
			}
			page, err := fetchPage(db, apps, fetchLimit, offset)
			if err != nil {
				return fmt.Errorf("fetch page offset=%d: %w", offset, err)
			}
			if len(page) == 0 {
				return nil
			}
			select {
			case pageCh <- page:
			case <-ctx.Done():
				return ctx.Err()
			}
			offset += len(page)
			if len(page) < pageSize {
				return nil
			}
		}
	})

	// Consumers: N workers processing pages.
	for i := 0; i < workers; i++ {
		g.Go(func() error {
			for page := range pageCh {
				deps, syms, err := processPage(ctx, db, page)
				if err != nil {
					return err
				}
				totalProcessed.Add(int64(len(page)))
				totalDepsAdded.Add(deps)
				totalSymFixed.Add(syms)
				processed := totalProcessed.Load()
				if processed%1000 == 0 || processed == int64(len(page)) {
					slog.Info("backfill-static progress",
						"processed", processed,
						"deps_added", totalDepsAdded.Load(),
						"symbols_fixed", totalSymFixed.Load())
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// Resolve to_name → to_id for newly inserted deps.
	if !backfillStaticDryRun {
		resolved, err := kbstore.BackfillModuleDepsToID(db)
		if err != nil {
			slog.Warn("backfill to_id resolution failed", "err", err)
		} else {
			slog.Info("module_deps to_id resolved", "rows", resolved)
		}
	}

	fmt.Printf("backfill-static done: processed=%d deps_added=%d symbols_fixed=%d dry_run=%v\n",
		totalProcessed.Load(), totalDepsAdded.Load(), totalSymFixed.Load(), backfillStaticDryRun)
	return nil
}

// fetchPage fetches a page of candidate rows that need backfilling.
// Candidates: rows where module_deps don't exist OR symbols_json is null/empty.
// Noisy-but-non-empty symbols are fetched too (we re-check in Go).
func fetchPage(db *sql.DB, apps []string, pageSize, offset int) ([]backfillRow, error) {
	var (
		rows *sql.Rows
		err  error
	)
	// Candidate predicate: any module that has a stored body is eligible.
	// The Go layer decides per-row whether to write deps (always) and whether
	// to overwrite symbols_json (only when current value is NULL/empty/noisy
	// and extractor produced a better, non-noisy result).
	if len(apps) == 0 {
		rows, err = db.Query(`
			SELECT m.id, m.name, COALESCE(m.lang,''), m.symbols_json, b.body
			FROM modules m
			JOIN module_bodies b ON b.body_sha256 = m.body_sha256
			ORDER BY m.id
			LIMIT $1 OFFSET $2`, pageSize, offset)
	} else {
		rows, err = db.Query(`
			SELECT m.id, m.name, COALESCE(m.lang,''), m.symbols_json, b.body
			FROM modules m
			JOIN module_bodies b ON b.body_sha256 = m.body_sha256
			WHERE m.app = ANY($1)
			ORDER BY m.id
			LIMIT $2 OFFSET $3`, pq.Array(apps), pageSize, offset)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var page []backfillRow
	for rows.Next() {
		var r backfillRow
		if err := rows.Scan(&r.id, &r.name, &r.lang, &r.symbolsJSON, &r.body); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		page = append(page, r)
	}
	return page, rows.Err()
}

// processPage extracts symbols+imports for each row and writes to DB.
func processPage(ctx context.Context, db *sql.DB, page []backfillRow) (depsAdded, symsFixed int64, err error) {
	if backfillStaticDryRun {
		// Dry-run: compute but don't write.
		for _, r := range page {
			imports, symbolsJSON, _ := backfill.Extract(r.body, r.name, r.lang)
			if len(imports) > 0 {
				depsAdded += int64(len(imports))
			}
			shouldFix := r.symbolsJSON.Valid && backfill.IsNoisy(r.symbolsJSON.String) ||
				!r.symbolsJSON.Valid || r.symbolsJSON.String == ""
			if shouldFix && symbolsJSON != "" {
				symsFixed++
			}
		}
		return depsAdded, symsFixed, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	depStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO module_deps (from_id, to_name)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING`)
	if err != nil {
		return 0, 0, fmt.Errorf("prepare dep stmt: %w", err)
	}
	defer func() { _ = depStmt.Close() }()

	symStmt, err := tx.PrepareContext(ctx, `
		UPDATE modules SET symbols_json = $1 WHERE id = $2`)
	if err != nil {
		return 0, 0, fmt.Errorf("prepare sym stmt: %w", err)
	}
	defer func() { _ = symStmt.Close() }()

	for _, r := range page {
		imports, symbolsJSON, _ := backfill.Extract(r.body, r.name, r.lang)

		// Upsert deps.
		for _, imp := range imports {
			if imp == "" {
				continue
			}
			res, dErr := depStmt.ExecContext(ctx, r.id, imp)
			if dErr != nil {
				slog.Warn("dep insert failed", "module_id", r.id, "dep", imp, "err", dErr)
				continue
			}
			n, _ := res.RowsAffected()
			depsAdded += n
		}

		// Update symbols_json only when current is empty/noisy and we got something better.
		shouldFix := !r.symbolsJSON.Valid || r.symbolsJSON.String == "" ||
			backfill.IsNoisy(r.symbolsJSON.String)
		if shouldFix && symbolsJSON != "" && !backfill.IsNoisy(symbolsJSON) {
			if _, sErr := symStmt.ExecContext(ctx, symbolsJSON, r.id); sErr != nil {
				slog.Warn("symbols_json update failed", "module_id", r.id, "err", sErr)
			} else {
				symsFixed++
			}
		}
	}

	if err = tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit page: %w", err)
	}
	return depsAdded, symsFixed, nil
}

// ── helpers ─────────────────────────────────────────────────────────

func parseApps(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
