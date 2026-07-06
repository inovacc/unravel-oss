/*
Copyright (c) 2026 Security Research
*/
// Package cmd / knowledge_kb_query.go houses the read/query subcommands now
// folded into the kb tree: `kb enrich pending`, `kb enrich summarize`,
// `kb catalog stats`, `kb catalog facts`, and `kb gaps list`. Registration
// happens in cmd/knowledge.go's init() function.
//
// Symbols owned by this file:
//
//	kbPendingCmd / kbSummarizeCmd /
//	kbStatsCmd / kbDissectAppCmd /
//	kbGapsListCmd / kbFactsCmd        — cobra command declarations.
//	runKBPending / runKBSummarize /
//	runKBStats / runKBDissectApp /
//	runKBGaps / runKBFacts           — RunE entry points.
//	type gap                         — open-fact row (primary caller
//	                                   runKBGaps via nextGapBatch).
//	nextGapBatch(db, app, n)         — gap-batch fetcher (primary caller
//	                                   runKBFill in knowledge_kb_enrich.go,
//	                                   but originates from the gap-query
//	                                   lifecycle; type gap lives here per
//	                                   D-66-03 because the type is named for
//	                                   the query cohort and the read path).
//
// Cross-file references (resolved via package-scoped `package cmd`):
//
//	kbOpenDB                         — declared in knowledge_kb_extract_index.go
//	sweepRegistry                    — declared in cmd/knowledge.go (sweep
//	                                   cohort owner; Plan 04 will move it).
//	processFillBatch                 — declared in cmd/knowledge.go (enrich
//	                                   cohort owner; Plan 04 will move it).
//	                                   It consumes []gap defined in this file.
//	kbstore.Pending, kbstore.Stats   — knowledge KB store package.
//	registry.Load, registry.Materialize — registry helpers.
//
// Transitive-sweep additions beyond D-66-03: NONE.
//
// Note re: pendingRow — the plan's <symbol_inventory> listed pendingRow as a
// query-cohort type. Grep across cmd/ shows pendingRow's only consumer is
// runKBEnrich (the enrich cohort owned by Plan 04). Per D-66-03 (co-locate
// with PRIMARY caller), pendingRow stays in cmd/knowledge.go and moves with
// runKBEnrich in Plan 04. Documented as a deviation in 66-03-SUMMARY.md.
package cmd

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
	"github.com/inovacc/unravel-oss/pkg/knowledge/registry"

	"github.com/spf13/cobra"
)

// ─────────────────────────────────────────────────────────────────────
// cobra command declarations
// ─────────────────────────────────────────────────────────────────────

var kbPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List modules whose summary is empty (id<TAB>app<TAB>name)",
	RunE:  runKBPending,
}

var kbSummarizeCmd = &cobra.Command{
	Use:   "summarize",
	Short: "Persist a natural-language summary against a module id",
	RunE:  runKBSummarize,
}

var kbStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Per-app row counts, summarized counts, average body size",
	RunE:  runKBStats,
}

var kbDissectAppCmd = &cobra.Command{
	Use:   "dissect-app",
	Short: "Seed app_facts from the YAML registry (and run mechanical dissect steps)",
	Long: `For every category in the embedded registry whose applies_to list
includes --app, insert a row in app_facts with value=NULL and the registry-
defined gap_prompt + candidates_q. Re-runs are idempotent — existing rows
keep their value if already filled.

This is the entry point of the gap-driven pipeline: dissect-app provisions
the questions, then 'fill' answers them.`,
	RunE: runKBDissectApp,
}

// kbGapsListCmd is the former `knowledge gaps` command, now `kb gaps list`
// (the verb no longer repeats its group name, per COMMAND-TAXONOMY §5).
var kbGapsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List app_facts rows whose value is NULL (open questions)",
	RunE:  runKBGaps,
}

var kbFactsCmd = &cobra.Command{
	Use:   "facts",
	Short: "Show answered facts in a readable layout",
	RunE:  runKBFacts,
}

// ─────────────────────────────────────────────────────────────────────
// catalog: pending / summarize / stats
// ─────────────────────────────────────────────────────────────────────

func runKBPending(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(kbPendingDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	rows, err := kbstore.Pending(db, kbPendingApp, kbPendingLimit)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(os.Stdout)
	defer func() { _ = w.Flush() }()
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\n", r.ID, r.App, r.Name)
	}
	return nil
}

func runKBSummarize(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(kbSumDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	res, err := db.Exec(`UPDATE modules SET summary = $1, tags = $2 WHERE id = $3`, kbSumSummary, kbSumTags, kbSumID)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	n, _ := res.RowsAffected()
	fmt.Printf("updated %d row(s)\n", n)
	return nil
}

var kbQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Execute raw SQL query against the Knowledge Base",
	RunE:  runKBQuery,
}

func runKBQuery(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB("") // Use default config
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query(kbQuerySQL)
	if err != nil {
		return err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return err
	}

	// Print headers
	fmt.Println(strings.Join(cols, "\t"))

	// Dynamic scanning
	values := make([]any, len(cols))
	valuePtrs := make([]any, len(cols))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return err
		}

		var rowStrs []string
		for _, v := range values {
			if v == nil {
				rowStrs = append(rowStrs, "NULL")
			} else {
				rowStrs = append(rowStrs, fmt.Sprintf("%v", v))
			}
		}
		fmt.Println(strings.Join(rowStrs, "\t"))
	}

	return rows.Err()
}

func runKBStats(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(kbStatsDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	stats, err := kbstore.Stats(db)
	if err != nil {
		return err
	}

	if kbStatsJSON {
		data, err := json.MarshalIndent(stats, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "APP\tTOTAL\tSUMMARIZED\tAVG_BYTES\tUNIQ_HASHES")
	for _, s := range stats {
		fmt.Fprintf(w, "%s\t%d\t%d\t%.0f\t%d\n", s.App, s.Total, s.Summarized, s.AvgBytes, s.UniqHashes)
	}
	return w.Flush()
}

// ─────────────────────────────────────────────────────────────────────
// facts: dissect-app / gaps / facts (gap type + nextGapBatch helper)
// ─────────────────────────────────────────────────────────────────────

func runKBDissectApp(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(dissectAppDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	cats, err := registry.Load("")
	if err != nil {
		return fmt.Errorf("load registry: %w", err)
	}

	knownApps := []string{}
	for _, a := range sweepRegistry {
		knownApps = append(knownApps, a.name)
	}
	if dissectAppApp != "" {
		knownApps = []string{dissectAppApp}
	}

	mat := registry.Materialize(cats, knownApps)
	now := time.Now().Unix()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO app_facts
	  (app, category, key, source_step, gap_prompt, candidates_q, value_format, updated_at)
	  VALUES ($1, $2, $3, 'registry', $4, $5, $6, $7)
	  ON CONFLICT(app, category, key) DO UPDATE SET
	    gap_prompt   = excluded.gap_prompt,
	    candidates_q = excluded.candidates_q,
	    value_format = excluded.value_format,
	    updated_at   = excluded.updated_at`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	provisioned := 0
	for _, m := range mat {
		if _, err := stmt.Exec(m.App, m.Category, m.Key, m.GapPrompt, m.CandidatesQ, m.ValueFormat, now); err != nil {
			fmt.Fprintf(os.Stderr, "warn: provision %s/%s/%s: %v\n", m.App, m.Category, m.Key, err)
			continue
		}
		provisioned++
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	fmt.Printf("provisioned %d fact rows across %d apps from %d categories\n",
		provisioned, len(knownApps), len(cats))
	return nil
}

func runKBGaps(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(gapsDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	q, args := buildGapsQuery(gapsApp, gapsCat)
	rows, err := db.Query(q, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	count := 0
	for rows.Next() {
		var id int
		var app, cat, key string
		_ = rows.Scan(&id, &app, &cat, &key)
		fmt.Printf("[%5d] %-10s %-12s %s\n", id, app, cat, key)
		count++
	}
	fmt.Fprintf(os.Stderr, "%d open gaps\n", count)
	if count == 0 {
		populated := sqlitePopulatedCategories(db, gapsApp, true)
		fmt.Printf("[honest-empty] layer_status=empty populated_categories=%v\n", populated)
	}
	return nil
}

type gap struct {
	id          int
	app, cat    string
	key, prompt string
	candidates  string
	format      string
}

func runKBFacts(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(factsDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	q, args := buildFactsQuery(factsApp, factsCat)
	rows, err := db.Query(q, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	count := 0
	for rows.Next() {
		var app, cat, key, val, ev string
		var conf sql.NullFloat64
		_ = rows.Scan(&app, &cat, &key, &val, &conf, &ev)
		c := 0.0
		if conf.Valid {
			c = conf.Float64
		}
		fmt.Printf("%-10s %-12s %-32s = %-40s conf=%.2f ev=%s\n",
			app, cat, key, val, c, ev)
		count++
	}
	if count == 0 {
		populated := sqlitePopulatedCategories(db, factsApp, false)
		fmt.Printf("[honest-empty] layer_status=empty populated_categories=%v\n", populated)
	}
	return nil
}

// buildFactsQuery assembles the `knowledge facts` SELECT with optional app /
// category filters. The KB is Postgres (pgx via kbOpenDB), so it uses
// positional `$N` placeholders — NOT the SQLite `?` token, which Postgres
// parses as a JSON operator and then rejects (SQLSTATE 42601 at the next
// keyword, e.g. "syntax error at/near ORDER"). Filters are appended before
// ORDER BY; `$N` indices track append order.
func buildFactsQuery(app, cat string) (string, []any) {
	q := `SELECT app, category, key, value, confidence, evidence_ids
	  FROM app_facts WHERE value IS NOT NULL`
	args := []any{}
	if app != "" {
		args = append(args, app)
		q += fmt.Sprintf(" AND app = $%d", len(args))
	}
	if cat != "" {
		args = append(args, cat)
		q += fmt.Sprintf(" AND category = $%d", len(args))
	}
	q += " ORDER BY app, category, key"
	return q, args
}

// buildGapsQuery assembles the `knowledge gaps` SELECT (rows with value IS
// NULL) with the same Postgres `$N` placeholder discipline as buildFactsQuery.
func buildGapsQuery(app, cat string) (string, []any) {
	q := `SELECT id, app, category, key FROM app_facts WHERE value IS NULL`
	args := []any{}
	if app != "" {
		args = append(args, app)
		q += fmt.Sprintf(" AND app = $%d", len(args))
	}
	if cat != "" {
		args = append(args, cat)
		q += fmt.Sprintf(" AND category = $%d", len(args))
	}
	q += " ORDER BY app, category, key"
	return q, args
}

// populatedCategories returns distinct categories in app_facts with ≥1
// matching row (gapsOnly=true → value IS NULL, false → value IS NOT NULL).
// Postgres `$N` placeholder (kbOpenDB path). Returns nil on error.
func sqlitePopulatedCategories(db *sql.DB, app string, gapsOnly bool) []string {
	if db == nil {
		return nil
	}
	valFilter := "value IS NOT NULL"
	if gapsOnly {
		valFilter = "value IS NULL"
	}
	q := fmt.Sprintf("SELECT DISTINCT category FROM app_facts WHERE %s", valFilter)
	args := []any{}
	if app != "" {
		args = append(args, app)
		q += fmt.Sprintf(" AND app = $%d", len(args))
	}
	q += " ORDER BY category"
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var cats []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err == nil {
			cats = append(cats, c)
		}
	}
	return cats
}
