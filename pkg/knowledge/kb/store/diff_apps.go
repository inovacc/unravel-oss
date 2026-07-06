/*
Copyright (c) 2026 Security Research
*/
// DiffApps — cross-app behavioural diff over enriched modules.
//
// Extracted out of pkg/mcp/tools/kb_diff_apps.go so the supervisor
// dispatcher (internal/supervisor/kb_dispatch.go) and the MCP tool
// share one source of truth. See
// docs/superpowers/plans/2026-05-27-v2.17-thinclient-refactor.md
// (Phase A1).
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// DiffAppsModule is one row of either side of the diff result.
type DiffAppsModule struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Tags string `json:"tags,omitempty"`
	Role string `json:"role,omitempty"`
}

// DiffAppsResult is the response body shared by the MCP tool and the
// supervisor dispatcher. JSON shape is byte-for-byte compatible with
// what unravel_kb_diff_apps emitted prior to the A1 extraction.
type DiffAppsResult struct {
	AppA        string           `json:"app_a"`
	AppB        string           `json:"app_b"`
	Category    string           `json:"category,omitempty"`
	AOnly       []DiffAppsModule `json:"a_only"`
	BOnly       []DiffAppsModule `json:"b_only"`
	AOnlyCount  int              `json:"a_only_count"`
	BOnlyCount  int              `json:"b_only_count"`
	CommonCount int              `json:"common_count"`
}

// DiffAppsOptions narrows the diff. Limit defaults to 100, hard-capped
// at 1000. Category is matched as a `tags ILIKE '%cat%'` substring on
// each side.
type DiffAppsOptions struct {
	Category string
	Limit    int
}

// DiffApps computes the cross-app behavioural diff between two apps.
//
// It returns enriched modules unique to each side (named modules in one
// app's enrichment set but not the other, capped by Limit) along with a
// count of names common to both sides. Modules without a summary are
// excluded — only enriched rows participate.
//
// appA and appB must differ and be non-empty.
func DiffApps(ctx context.Context, db *sql.DB, appA, appB string, opts DiffAppsOptions) (*DiffAppsResult, error) {
	if appA == "" || appB == "" {
		return nil, fmt.Errorf("app_a and app_b are required")
	}
	if appA == appB {
		return nil, fmt.Errorf("app_a and app_b must differ")
	}
	limit := opts.Limit
	if limit < 1 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	aOnly, err := queryDiffSideUnique(ctx, db, appA, appB, opts.Category, limit)
	if err != nil {
		return nil, fmt.Errorf("a_only: %w", err)
	}
	bOnly, err := queryDiffSideUnique(ctx, db, appB, appA, opts.Category, limit)
	if err != nil {
		return nil, fmt.Errorf("b_only: %w", err)
	}
	common, err := queryDiffCommonCount(ctx, db, appA, appB, opts.Category)
	if err != nil {
		return nil, fmt.Errorf("common: %w", err)
	}
	return &DiffAppsResult{
		AppA:        appA,
		AppB:        appB,
		Category:    opts.Category,
		AOnly:       aOnly,
		BOnly:       bOnly,
		AOnlyCount:  len(aOnly),
		BOnlyCount:  len(bOnly),
		CommonCount: common,
	}, nil
}

// queryDiffSideUnique returns up to `limit` enriched modules in `app`
// whose `name` is NOT present in the enrichment set of `other`.
// The category filter narrows by a tags substring (ILIKE).
func queryDiffSideUnique(ctx context.Context, db *sql.DB, app, other, category string, limit int) ([]DiffAppsModule, error) {
	args := []any{app, other}
	q := `
		SELECT m.id, m.name, COALESCE(m.tags,''), COALESCE(me.role,'')
		  FROM modules m
	 LEFT JOIN module_enrichment me ON me.module_id = m.id
		 WHERE m.app = $1
		   AND m.summary IS NOT NULL
		   AND NOT EXISTS (
		     SELECT 1 FROM modules m2
		      WHERE m2.app = $2 AND m2.name = m.name AND m2.summary IS NOT NULL
		   )`
	if category != "" {
		args = append(args, "%"+category+"%")
		q += fmt.Sprintf(" AND m.tags ILIKE $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY m.name LIMIT $%d", len(args))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []DiffAppsModule{}
	for rows.Next() {
		var m DiffAppsModule
		if err := rows.Scan(&m.ID, &m.Name, &m.Tags, &m.Role); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// queryDiffCommonCount counts enriched modules whose `name` exists in
// BOTH apps' enrichment sets (subject to the category filter).
func queryDiffCommonCount(ctx context.Context, db *sql.DB, appA, appB, category string) (int, error) {
	args := []any{appA, appB}
	q := `
		SELECT COUNT(*) FROM (
		  SELECT m.name FROM modules m
		   WHERE m.app = $1 AND m.summary IS NOT NULL
		` + appendCategoryFilter(category, &args, "m") + `
		  INTERSECT
		  SELECT m.name FROM modules m
		   WHERE m.app = $2 AND m.summary IS NOT NULL
		` + appendCategoryFilter(category, &args, "m") + `
		) AS shared`
	var n int
	if err := db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("scan count: %w", err)
	}
	return n, nil
}

// appendCategoryFilter appends the category arg (once per call) and
// returns the SQL fragment that references the freshly-added
// placeholder. Called twice by the INTERSECT in queryDiffCommonCount —
// once per branch — so each branch gets its own positional arg.
func appendCategoryFilter(category string, args *[]any, alias string) string {
	if category == "" {
		return ""
	}
	*args = append(*args, "%"+category+"%")
	return fmt.Sprintf(" AND %s.tags ILIKE $%d", alias, len(*args))
}
