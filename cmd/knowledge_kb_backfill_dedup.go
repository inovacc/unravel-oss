/*
Copyright (c) 2026 Security Research
*/

// knowledge_kb_backfill_dedup.go — `unravel knowledge backfill-dedup`.
//
// T1.4 (KB-OVERSEG P1) operational companion. The inline cross-app dedup
// fan-out in writeEnrichment only helps FUTURE writes; rows already stuck
// pending behind an already-enriched identical-body sibling are never
// re-selected, so they never benefit. This command drains that existing
// backlog: for every pending module (summary IS NULL) whose non-empty
// body_sha256 matches an already-enriched sibling, copy that sibling's
// enrichment over. Idempotent + supports --dry-run. Direct-PG via kbOpenDB
// (supervisor-independent), matching `knowledge facts`/`gaps`.
package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var (
	backfillDedupDB     string
	backfillDedupApp    string
	backfillDedupDryRun bool
)

var kbBackfillDedupCmd = &cobra.Command{
	Use:   "backfill-dedup",
	Short: "Backfill enrichment to modules stuck pending behind an already-enriched identical-body sibling (KB-OVERSEG P1)",
	Long: `Drain the existing dedup backlog.

modules has UNIQUE(app, body_sha256), so identical bodies appear only as
siblings across DIFFERENT apps. The inline fan-out in writeEnrichment fills
siblings on each new write, but rows already stuck pending behind a sibling
that was enriched BEFORE the fan-out shipped are never re-selected. This
command copies the enriched representative's summary/tags + module_enrichment
to those pending siblings (same non-empty body_sha256). Idempotent; skips
human-flagged rows; never touches un-hashed (empty body_sha256) modules.`,
	RunE: runKBBackfillDedup,
}

// buildBackfillCountQuery counts pending modules that have an already-enriched
// identical-body sibling (the backfill candidates).
func buildBackfillCountQuery(app string) (string, []any) {
	q := `SELECT COUNT(*) FROM modules p
		WHERE p.summary IS NULL AND p.body_sha256 <> '' AND p.needs_human_verification = false
		  AND EXISTS (SELECT 1 FROM modules e
		               WHERE e.body_sha256 = p.body_sha256
		                 AND e.summary IS NOT NULL AND e.id <> p.id)`
	args := []any{}
	if app != "" {
		args = append(args, app)
		q += fmt.Sprintf(" AND p.app = $%d", len(args))
	}
	return q, args
}

// buildBackfillEnrichInsert inserts module_enrichment rows for pending siblings
// from the lowest-id enriched representative per body_sha256. ts binds as $1.
func buildBackfillEnrichInsert(app string, ts int64) (string, []any) {
	args := []any{ts}
	appClause := ""
	if app != "" {
		args = append(args, app)
		appClause = fmt.Sprintf(" AND p.app = $%d", len(args))
	}
	q := fmt.Sprintf(`WITH rep AS (
		SELECT DISTINCT ON (m.body_sha256) m.body_sha256,
		       me.long_summary, me.role, me.inputs_json, me.outputs_json,
		       me.side_effects, me.deps_json, me.raw_response, me.model
		  FROM modules m JOIN module_enrichment me ON me.module_id = m.id
		 WHERE m.summary IS NOT NULL AND m.body_sha256 <> ''
		 ORDER BY m.body_sha256, m.id
	)
	INSERT INTO module_enrichment
	  (module_id, long_summary, role, inputs_json, outputs_json, side_effects, deps_json, raw_response, model, body_sha256, created_at)
	SELECT p.id, rep.long_summary, rep.role, rep.inputs_json, rep.outputs_json,
	       rep.side_effects, rep.deps_json, rep.raw_response, rep.model, p.body_sha256, $1
	  FROM modules p JOIN rep ON rep.body_sha256 = p.body_sha256
	 WHERE p.summary IS NULL AND p.body_sha256 <> '' AND p.needs_human_verification = false%s
	   AND NOT EXISTS (SELECT 1 FROM module_enrichment x WHERE x.module_id = p.id)
	ON CONFLICT(module_id) DO NOTHING`, appClause)
	return q, args
}

// buildBackfillSummaryUpdate copies summary/tags from the lowest-id enriched
// representative per body_sha256 onto its still-pending siblings.
func buildBackfillSummaryUpdate(app string) (string, []any) {
	args := []any{}
	appClause := ""
	if app != "" {
		args = append(args, app)
		appClause = fmt.Sprintf(" AND p.app = $%d", len(args))
	}
	q := fmt.Sprintf(`WITH rep AS (
		SELECT DISTINCT ON (body_sha256) body_sha256, summary, tags
		  FROM modules
		 WHERE summary IS NOT NULL AND body_sha256 <> ''
		 ORDER BY body_sha256, id
	)
	UPDATE modules p SET summary = rep.summary, tags = rep.tags
	  FROM rep
	 WHERE p.body_sha256 = rep.body_sha256 AND p.summary IS NULL
	   AND p.body_sha256 <> '' AND p.needs_human_verification = false%s`, appClause)
	return q, args
}

func runKBBackfillDedup(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(backfillDedupDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	cq, cargs := buildBackfillCountQuery(backfillDedupApp)
	var n int
	if err := db.QueryRow(cq, cargs...).Scan(&n); err != nil {
		return fmt.Errorf("count backfillable: %w", err)
	}
	scope := "all apps"
	if backfillDedupApp != "" {
		scope = backfillDedupApp
	}
	fmt.Printf("backfill-dedup: %d pending module(s) in %s have an already-enriched identical-body sibling\n", n, scope)
	if backfillDedupDryRun {
		fmt.Println("[dry-run] no changes written")
		return nil
	}
	if n == 0 {
		fmt.Println("nothing to backfill")
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Enrichment rows first, then summary/tags — both gate on the target's
	// summary IS NULL, so clearing summary first would empty the set.
	eq, eargs := buildBackfillEnrichInsert(backfillDedupApp, time.Now().Unix())
	eres, err := tx.Exec(eq, eargs...)
	if err != nil {
		return fmt.Errorf("backfill enrichment rows: %w", err)
	}
	eAff, _ := eres.RowsAffected()

	uq, uargs := buildBackfillSummaryUpdate(backfillDedupApp)
	ures, err := tx.Exec(uq, uargs...)
	if err != nil {
		return fmt.Errorf("backfill summary/tags: %w", err)
	}
	uAff, _ := ures.RowsAffected()

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	fmt.Printf("backfilled: %d module_enrichment row(s) inserted, %d module(s) cleared from pending\n", eAff, uAff)
	return nil
}
