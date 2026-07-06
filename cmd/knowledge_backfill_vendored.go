/*
Copyright (c) 2026 Security Research
*/

// cmd/knowledge_backfill_vendored.go owns the `unravel knowledge
// backfill-vendored` command. It iterates already-stored module bodies, runs
// the pure-Go kbscan.IsVendoredBody detector on each, and sets
// modules.is_vendored = true for rows whose body is bundled OSS.
//
// This repairs the gap left by the ingest-time vendored gate (migration
// 000019): rows ingested before the gate landed stay is_vendored=false until
// re-ingested. This command marks them in place — no bundle, no AI, no quota.
//
// Design: pure-Go, no AI, parallel workers, idempotent (re-runs find no new
// candidates), resumable. All progress goes to stderr; stdout is reserved for
// structured output.
package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"

	"github.com/lib/pq"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	kbscan "github.com/inovacc/unravel-oss/pkg/knowledge/kb/scanner"
)

// ── flag-backing variables ───────────────────────────────────────────

var (
	backfillVendoredDB        string
	backfillVendoredApps      string
	backfillVendoredWorkers   int
	backfillVendoredLimit     int
	backfillVendoredDryRun    bool
	backfillVendoredVerify    bool
	backfillVendoredReconcile bool
)

// ── command wiring ──────────────────────────────────────────────────

var kbBackfillVendoredCmd = &cobra.Command{
	Use:   "backfill-vendored",
	Short: "Mark modules.is_vendored from stored bodies via the vendored detector (pure-Go, no AI)",
	Long: `Iterate already-stored module bodies, run kbscan.IsVendoredBody on each,
and set modules.is_vendored = true for bundled-OSS rows.

The ingest-time vendored gate (migration 000019) only marks rows captured
after it landed; rows ingested earlier stay is_vendored=false. This command
retro-marks them in place without a re-ingest — no bundle, no AI, no quota.

Idempotent: a re-run finds no new candidates. Use --dry-run to preview,
--verify for a read-only per-app coverage report, and --reconcile to also
UNMARK rows the detector no longer flags (corrects false positives after a
detector change — the default mark-only path never un-marks).

Examples:
  unravel knowledge backfill-vendored --apps cluely,angel,perssua,wispr --dry-run
  unravel knowledge backfill-vendored --apps cluely,angel,perssua,wispr
  unravel knowledge backfill-vendored --apps cluely --reconcile
  unravel knowledge backfill-vendored --verify`,
	RunE: runKBBackfillVendored,
}

func init() {
	kbBackfillVendoredCmd.Flags().StringVar(&backfillVendoredDB, "database", "", "DSN override (defaults to config.yaml)")
	kbBackfillVendoredCmd.Flags().StringVar(&backfillVendoredApps, "apps", "", "comma-separated app names to backfill (default: all)")
	kbBackfillVendoredCmd.Flags().IntVar(&backfillVendoredWorkers, "workers", 4, "parallel worker count")
	kbBackfillVendoredCmd.Flags().IntVar(&backfillVendoredLimit, "limit", 0, "max rows to scan (0 = no limit)")
	kbBackfillVendoredCmd.Flags().BoolVar(&backfillVendoredDryRun, "dry-run", false, "compute what would be marked, no DB writes")
	kbBackfillVendoredCmd.Flags().BoolVar(&backfillVendoredVerify, "verify", false, "read-only: print per-app vendored/first-party coverage and exit")
	kbBackfillVendoredCmd.Flags().BoolVar(&backfillVendoredReconcile, "reconcile", false, "also UNMARK rows the detector no longer flags (corrects false positives)")
	kbEnrichCmd.AddCommand(kbBackfillVendoredCmd)
}

// ── row type ────────────────────────────────────────────────────────

type vendoredRow struct {
	id          int64
	name        string
	alreadyVend bool
	body        []byte
}

// classifyVendored returns the ids that should be newly marked is_vendored.
// A row qualifies iff the detector flags it AND it is not already marked.
// The detector is injected so this decision is unit-testable without a DB.
func classifyVendored(rows []vendoredRow, isVendored func(name string, body []byte) bool) []int64 {
	var out []int64
	for _, r := range rows {
		if !r.alreadyVend && isVendored(r.name, r.body) {
			out = append(out, r.id)
		}
	}
	return out
}

// classifyUnvendored returns the ids currently marked vendored that the
// detector no longer flags — the --reconcile correction set. Lets a detector
// improvement (e.g. fixing an over-broad signal) propagate both directions.
func classifyUnvendored(rows []vendoredRow, isVendored func(name string, body []byte) bool) []int64 {
	var out []int64
	for _, r := range rows {
		if r.alreadyVend && !isVendored(r.name, r.body) {
			out = append(out, r.id)
		}
	}
	return out
}

// ── implementation ──────────────────────────────────────────────────

func runKBBackfillVendored(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(backfillVendoredDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	apps := parseApps(backfillVendoredApps)

	if backfillVendoredVerify {
		return printVendoredCoverage(db, apps)
	}

	if err := runVendoredWorkers(db, apps); err != nil {
		return err
	}
	// Always finish with a read-only coverage report so the operator sees the
	// resulting (or, under --dry-run, the still-current) split.
	return printVendoredCoverage(db, apps)
}

// runVendoredWorkers runs the parallel scan + mark loop. The fetch predicate
// ("has a stored body") does not change as rows are marked, so LIMIT/OFFSET
// paging stays stable across the run.
func runVendoredWorkers(db *sql.DB, apps []string) error {
	workers := max(backfillVendoredWorkers, 1)
	limit := backfillVendoredLimit

	pageCh := make(chan []vendoredRow, workers*2)

	var (
		totalProcessed atomic.Int64
		totalMarked    atomic.Int64
		totalUnmarked  atomic.Int64
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
			page, err := fetchVendoredPage(db, apps, fetchLimit, offset)
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

	// Consumers: N workers classifying + marking pages.
	for range workers {
		g.Go(func() error {
			for page := range pageCh {
				marked, unmarked, err := markVendoredPage(ctx, db, page)
				if err != nil {
					return err
				}
				totalProcessed.Add(int64(len(page)))
				totalMarked.Add(marked)
				totalUnmarked.Add(unmarked)
				processed := totalProcessed.Load()
				if processed%5000 == 0 {
					slog.Info("backfill-vendored progress",
						"processed", processed, "marked", totalMarked.Load(),
						"unmarked", totalUnmarked.Load())
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	fmt.Printf("backfill-vendored done: processed=%d marked=%d unmarked=%d reconcile=%v dry_run=%v\n",
		totalProcessed.Load(), totalMarked.Load(), totalUnmarked.Load(),
		backfillVendoredReconcile, backfillVendoredDryRun)
	return nil
}

// fetchVendoredPage fetches a page of (id, is_vendored, body). Every module
// with a stored body is a candidate; the Go layer skips already-marked rows.
func fetchVendoredPage(db *sql.DB, apps []string, pageSize, offset int) ([]vendoredRow, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if len(apps) == 0 {
		rows, err = db.Query(`
			SELECT m.id, m.name, m.is_vendored, b.body
			FROM modules m
			JOIN module_bodies b ON b.body_sha256 = m.body_sha256
			ORDER BY m.id
			LIMIT $1 OFFSET $2`, pageSize, offset)
	} else {
		rows, err = db.Query(`
			SELECT m.id, m.name, m.is_vendored, b.body
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

	var page []vendoredRow
	for rows.Next() {
		var r vendoredRow
		if err := rows.Scan(&r.id, &r.name, &r.alreadyVend, &r.body); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		page = append(page, r)
	}
	return page, rows.Err()
}

// markVendoredPage classifies a page and, unless --dry-run, applies the
// changes in guarded UPDATEs. Returns counts newly marked and (under
// --reconcile) un-marked.
func markVendoredPage(ctx context.Context, db *sql.DB, page []vendoredRow) (marked, unmarked int64, err error) {
	toTrue := classifyVendored(page, kbscan.IsVendored)
	var toFalse []int64
	if backfillVendoredReconcile {
		toFalse = classifyUnvendored(page, kbscan.IsVendored)
	}
	if backfillVendoredDryRun {
		return int64(len(toTrue)), int64(len(toFalse)), nil
	}
	if len(toTrue) > 0 {
		res, e := db.ExecContext(ctx,
			`UPDATE modules SET is_vendored = true WHERE id = ANY($1) AND is_vendored = false`,
			pq.Array(toTrue))
		if e != nil {
			return 0, 0, fmt.Errorf("mark vendored: %w", e)
		}
		n, _ := res.RowsAffected()
		marked = n
	}
	if len(toFalse) > 0 {
		res, e := db.ExecContext(ctx,
			`UPDATE modules SET is_vendored = false WHERE id = ANY($1) AND is_vendored = true`,
			pq.Array(toFalse))
		if e != nil {
			return marked, 0, fmt.Errorf("unmark vendored: %w", e)
		}
		n, _ := res.RowsAffected()
		unmarked = n
	}
	return marked, unmarked, nil
}

// printVendoredCoverage prints a read-only per-app vendored/first-party split.
func printVendoredCoverage(db *sql.DB, apps []string) error {
	var (
		rows *sql.Rows
		err  error
	)
	if len(apps) == 0 {
		rows, err = db.Query(`
			SELECT app, COUNT(*) AS total,
			       COUNT(*) FILTER (WHERE is_vendored) AS vendored
			FROM modules
			GROUP BY app
			ORDER BY app`)
	} else {
		rows, err = db.Query(`
			SELECT app, COUNT(*) AS total,
			       COUNT(*) FILTER (WHERE is_vendored) AS vendored
			FROM modules
			WHERE app = ANY($1)
			GROUP BY app
			ORDER BY app`, pq.Array(apps))
	}
	if err != nil {
		return fmt.Errorf("coverage query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	fmt.Fprintf(os.Stderr, "\n%-16s %10s %10s %12s\n", "app", "total", "vendored", "first_party")
	for rows.Next() {
		var (
			app      string
			total    int64
			vendored int64
		)
		if err := rows.Scan(&app, &total, &vendored); err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "%-16s %10d %10d %12d\n", app, total, vendored, total-vendored)
	}
	return rows.Err()
}
