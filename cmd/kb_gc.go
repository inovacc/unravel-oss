/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/fsutil"
)

var gcCmd = &cobra.Command{
	Use:   "gc",
	Short: "Garbage-collect stale snapshots",
	Long: `Garbage-collect stale snapshots from the knowledge base.

Stage 1 — DB Transaction (sql.LevelReadCommitted):
- Deletes rows from 'knowledge_sources' matching --older-than and --keep-latest.
- Foreign key cascades automatically purge related rows in 'module_app_refs',
  'file_app_refs', and 'kb_diffs'.
- Orphaned 'module_components' (those whose modules are no longer referenced
  by any active snapshot in 'module_app_refs') are cleaned up.

Stage 2 — Filesystem Cleanup:
- Best-effort 'os.RemoveAll' of each purged version folder in kb-store.
- Failures are logged to stderr but do not abort the command.

Filtering Logic (AND-combined):
- --older-than: purges snapshots captured before this threshold.
- --keep-latest: ensures at least N most recent snapshots are kept per app (kb_id),
  even if they are older than the threshold.

Note: Orphan module_bodies/files/folders cleanup is deferred to Phase 34
(unravel kb gc --orphan-folders).

Snapshot deletion should ideally run during quiet windows to avoid lock
contention on huge deletes.`,
	RunE: runKbGC,
}

var (
	gcOlderThan     string
	gcKeepLatest    int
	gcAll           bool
	gcDryRun        bool
	gcYes           bool
	gcJSON          bool
	gcDSN           string
	gcOrphanFolders bool
	gcOrphanBodies  bool
	gcOrphanFiles   bool
	gcEmptyOnly     bool
	gcApp           string
)

func init() {
	kbOpsCmd.AddCommand(gcCmd)

	gcCmd.Flags().StringVar(&gcOlderThan, "older-than", "", "purge snapshots older than (e.g. '30d', '2y', or RFC3339)")
	gcCmd.Flags().IntVar(&gcKeepLatest, "keep-latest", 0, "per-app retention count (keep top N most recent epochs)")
	gcCmd.Flags().BoolVar(&gcAll, "all", false, "rejected (use --older-than or --keep-latest)")
	gcCmd.Flags().BoolVar(&gcDryRun, "dry-run", false, "list matches without making changes")
	gcCmd.Flags().BoolVar(&gcYes, "yes", false, "skip safety prompt")
	gcCmd.Flags().BoolVar(&gcOrphanFolders, "orphan-folders", false, "remove FS folders under kb-store with no DB row")
	gcCmd.Flags().BoolVar(&gcOrphanBodies, "orphan-bodies", false, "DELETE module_bodies rows unreferenced by module_app_refs")
	gcCmd.Flags().BoolVar(&gcOrphanFiles, "orphan-files", false, "DELETE files rows unreferenced by file_app_refs")
	gcCmd.Flags().BoolVar(&gcEmptyOnly, "empty-only", false, "purge only snapshots with zero module refs")
	gcCmd.Flags().StringVar(&gcApp, "app", "", "restrict gc to a single kb_id")

	kb_output.BindJSONFlag(gcCmd, &gcJSON)
	kb_output.BindDSNFlag(gcCmd, &gcDSN)
}

type gcResult struct {
	PurgedCount   int      `json:"purged_count"`
	AppsAffected  int      `json:"apps_affected"`
	DBCommitted   bool     `json:"db_committed"`
	FSFailures    []string `json:"fs_failures,omitempty"`
	SchemaVersion int      `json:"schema_version"`
}

type gcCandidate struct {
	ID         int64
	KbID       string
	Epoch      int
	KsID       string
	CapturedAt time.Time
}

func runKbGC(cmd *cobra.Command, args []string) error {
	// D-34-ORPHAN-MUTEX: orphan modes are mutually exclusive and cannot
	// combine with --older-than / --keep-latest snapshot-purge filters.
	orphanModes := 0
	if gcOrphanFolders {
		orphanModes++
	}
	if gcOrphanBodies {
		orphanModes++
	}
	if gcOrphanFiles {
		orphanModes++
	}
	if orphanModes > 1 {
		return errors.New("kb gc orphan modes are mutually exclusive: pick one of --orphan-folders, --orphan-bodies, --orphan-files")
	}
	if orphanModes == 1 && (gcOlderThan != "" || gcKeepLatest != 0) {
		return errors.New("orphan modes cannot be combined with --older-than/--keep-latest")
	}
	if orphanModes == 1 {
		dsn, err := kb_output.ResolveDSN(gcDSN)
		if err != nil {
			return err
		}
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		defer db.Close()
		return runOrphanMode(cmd, db)
	}

	if gcAll {
		return errors.New("the --all flag is rejected; specify --older-than and/or --keep-latest")
	}

	if gcOlderThan == "" && gcKeepLatest == 0 && !gcEmptyOnly {
		return cmd.Help()
	}

	if gcKeepLatest < 0 {
		return errors.New("--keep-latest must be >= 1 (or 0 to disable)")
	}

	var cutoff *time.Time
	if gcOlderThan != "" {
		t, err := kb_output.ParseSince(gcOlderThan)
		if err != nil {
			return fmt.Errorf("invalid --older-than: %w", err)
		}
		cutoff = &t
	}

	var keepLatest *int
	if gcKeepLatest > 0 {
		keepLatest = &gcKeepLatest
	}

	dsn, err := kb_output.ResolveDSN(gcDSN)
	if err != nil {
		return err
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	ctx := cmd.Context()

	// 1. Selection query
	var candidates []gcCandidate
	if gcEmptyOnly {
		candidates, err = selectGCByEmpty(ctx, db, gcApp)
	} else {
		candidates, err = selectGCByCandidates(ctx, db, cutoff, keepLatest)
	}
	if err != nil {
		return fmt.Errorf("select candidates: %w", err)
	}

	if len(candidates) == 0 {
		if gcJSON {
			return kb_output.WriteJSON(cmd.OutOrStdout(), 1, gcResult{SchemaVersion: 1})
		}
		fmt.Fprintf(cmd.OutOrStdout(), "nothing to purge\n")
		return nil
	}

	appsAffectedMap := make(map[string]struct{})
	for _, c := range candidates {
		appsAffectedMap[c.KbID] = struct{}{}
	}
	appsAffected := len(appsAffectedMap)

	if gcDryRun {
		return printDryRun(cmd, candidates, appsAffected)
	}

	// Safety prompt
	if !gcYes {
		fmt.Printf("Delete %d snapshots from %d apps? [y/N]: ", len(candidates), appsAffected)
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			fmt.Fprintln(os.Stderr, "cancelled by user")
			os.Exit(2)
		}
	}

	// 2. DB Stage
	purgedIDs := make([]int64, len(candidates))
	for i, c := range candidates {
		purgedIDs[i] = c.ID
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete from knowledge_sources (cascades fire)
	_, err = tx.ExecContext(ctx, `DELETE FROM knowledge_sources WHERE id = ANY($1)`, pq.Array(purgedIDs))
	if err != nil {
		return fmt.Errorf("delete knowledge_sources: %w", err)
	}

	// Clean up orphan module_components
	_, err = tx.ExecContext(ctx, `
		DELETE FROM module_components
		WHERE module_id NOT IN (
			SELECT m.id
			FROM modules m
			JOIN module_app_refs mar ON m.app = mar.app AND m.body_sha256 = mar.body_sha256
		)
	`)
	if err != nil {
		return fmt.Errorf("cleanup module_components: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// 3. FS Stage (Best effort)
	storeRoot, err := fsutil.KBStoreRoot()
	var fsFailures []string
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: could not resolve KBStoreRoot for FS cleanup: %v\n", err)
		fsFailures = append(fsFailures, "resolve store root failure")
	} else {
		for _, c := range candidates {
			if c.KsID == "" {
				continue
			}
			ksIDFS, err := fsutil.EncodeKsID(c.KsID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARN: could not encode ks_id %q: %v\n", c.KsID, err)
				fsFailures = append(fsFailures, fmt.Sprintf("encode ks_id %s failure", c.KsID))
				continue
			}
			target := fsutil.WrapLongPath(filepath.Join(storeRoot, "apps", c.KbID, "versions", ksIDFS))
			if err := os.RemoveAll(target); err != nil {
				fmt.Fprintf(os.Stderr, "WARN: failed to remove %s: %v\n", target, err)
				fsFailures = append(fsFailures, target)
			}
		}
	}

	result := gcResult{
		PurgedCount:   len(candidates),
		AppsAffected:  appsAffected,
		DBCommitted:   true,
		FSFailures:    fsFailures,
		SchemaVersion: 1,
	}

	if gcJSON {
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, result)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Successfully purged %d snapshots from %d apps.\n", result.PurgedCount, result.AppsAffected)
	if len(fsFailures) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "FS cleanup had %d failures (logged to stderr).\n", len(fsFailures))
	}
	return nil
}

func selectGCByCandidates(ctx context.Context, db *sql.DB, cutoff *time.Time, keepLatest *int) ([]gcCandidate, error) {
	var cutoffMS *int64
	if cutoff != nil {
		ms := cutoff.UnixMilli()
		cutoffMS = &ms
	}

	query := `
		WITH ranked AS (
			SELECT id, kb_id, epoch, ks_id, captured_at,
			       ROW_NUMBER() OVER (PARTITION BY kb_id ORDER BY epoch DESC) AS rn
			FROM knowledge_sources
		)
		SELECT id, COALESCE(kb_id, ''), epoch, COALESCE(ks_id, ''), captured_at
		FROM ranked
		WHERE ($1::bigint IS NULL OR captured_at < $1)
		  AND ($2::int IS NULL OR rn > $2)
		ORDER BY kb_id, epoch
	`

	rows, err := db.QueryContext(ctx, query, cutoffMS, keepLatest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var candidates []gcCandidate
	for rows.Next() {
		var c gcCandidate
		var capturedAtMS int64
		if err := rows.Scan(&c.ID, &c.KbID, &c.Epoch, &c.KsID, &capturedAtMS); err != nil {
			return nil, err
		}
		c.CapturedAt = time.UnixMilli(capturedAtMS)
		candidates = append(candidates, c)
	}
	return candidates, nil
}

// buildEmptyGCQuery returns the candidate-selection SQL for empty epochs,
// optionally scoped to a single kb_id ($1). An empty snapshot is a
// knowledge_sources row with no referencing module_app_refs — i.e. the
// silent-empty epoch left by the old ilspy capture.
func buildEmptyGCQuery(app string) string {
	q := `
		SELECT ks.id, COALESCE(ks.kb_id,''), ks.epoch, COALESCE(ks.ks_id,''), ks.captured_at
		FROM knowledge_sources ks
		WHERE NOT EXISTS (
			SELECT 1 FROM module_app_refs mar WHERE mar.source_id = ks.id
		)`
	if app != "" {
		q += "\n		  AND ks.kb_id = $1"
	}
	q += "\n		ORDER BY ks.kb_id, ks.epoch"
	return q
}

// selectGCByEmpty selects empty-epoch candidates (zero module refs), optionally
// scoped to a single kb_id. captured_at is stored as INT64 milliseconds, so the
// scan mirrors selectGCByCandidates: scan into int64 then time.UnixMilli.
func selectGCByEmpty(ctx context.Context, db *sql.DB, app string) ([]gcCandidate, error) {
	query := buildEmptyGCQuery(app)

	var rows *sql.Rows
	var err error
	if app != "" {
		rows, err = db.QueryContext(ctx, query, app)
	} else {
		rows, err = db.QueryContext(ctx, query)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var candidates []gcCandidate
	for rows.Next() {
		var c gcCandidate
		var capturedAtMS int64
		if err := rows.Scan(&c.ID, &c.KbID, &c.Epoch, &c.KsID, &capturedAtMS); err != nil {
			return nil, err
		}
		c.CapturedAt = time.UnixMilli(capturedAtMS)
		candidates = append(candidates, c)
	}
	return candidates, nil
}

func printDryRun(cmd *cobra.Command, candidates []gcCandidate, appsAffected int) error {
	fmt.Fprintf(cmd.OutOrStdout(), "DRY RUN: would purge %d snapshots from %d apps\n\n", len(candidates), appsAffected)

	headers := []string{"KB_ID", "EPOCH", "KS_ID", "CAPTURED_AT"}
	rows := make([][]string, 0, len(candidates))

	limit := len(candidates)
	if limit > 20 {
		limit = 20
	}

	for i := 0; i < limit; i++ {
		c := candidates[i]
		rows = append(rows, []string{
			c.KbID,
			fmt.Sprintf("%d", c.Epoch),
			c.KsID,
			c.CapturedAt.Format(time.RFC3339),
		})
	}

	if err := kb_output.WriteTable(cmd.OutOrStdout(), headers, rows); err != nil {
		return err
	}

	if len(candidates) > 20 {
		fmt.Fprintf(cmd.OutOrStdout(), "\n... and %d more snapshots\n", len(candidates)-20)
	}

	return nil
}
