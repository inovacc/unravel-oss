/*
Copyright (c) 2026 Security Research
*/
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// SearchOptions controls the trigram + FTS-fallback search used by the
// unravel_kb_search MCP tool.
//
// Cursor pagination: pass nil for the first page. When the response's
// NextCursor is non-nil the caller may pass it back to fetch the next
// page. Cursor stability is best-effort — the underlying corpus is
// expected to mutate between pages.
//
// SinceMillis is a Unix-epoch milliseconds bound (>=); 0 means no filter.
// Higher-level human-readable "30d" / "RFC3339" parsing stays caller-side.
type SearchOptions struct {
	Query       string
	App         string
	Component   string
	Topic       string
	FactType    string
	Lang        string
	SinceMillis int64
	Limit       int
	Cursor      *SearchCursor
}

// SearchCursor is the opaque-ish wire cursor used to continue a previous
// search. The MCP layer base64-encodes/decodes this struct so external
// callers never see the field names; the supervisor + store work with
// the typed shape directly.
type SearchCursor struct {
	Similarity float32 `json:"s"`
	CapturedAt int64   `json:"c"`
	ModuleID   int64   `json:"m"`
}

// SearchItem is one search hit. Snake_case JSON tags so the supervisor
// can alias SearchPayload as the wire shape without translation.
type SearchItem struct {
	ModuleID           int64   `json:"module_id"`
	Name               string  `json:"name"`
	BodyExcerptSnippet string  `json:"body_excerpt_snippet"`
	Similarity         float32 `json:"similarity"`
	AppKbID            string  `json:"app_kb_id"`
	AppDisplayName     string  `json:"app_display_name"`
	CapturedAt         int64   `json:"captured_at"`
	Lang               string  `json:"lang"`
	Component          string  `json:"component"`
	Summary            string  `json:"summary"`
	Role               string  `json:"role"`
	Tags               string  `json:"tags"`
	SyntheticName      string  `json:"synthetic_name"`
	Topic              string  `json:"topic,omitempty"`
}

// SearchPayload is the wire shape returned by Search. The supervisor
// kb.search verb aliases this as KBSearchResult (v2.17 thin-client B1.1).
type SearchPayload struct {
	Query                 string        `json:"query"`
	Returned              int           `json:"returned"`
	NextCursor            *SearchCursor `json:"next_cursor,omitempty"`
	Items                 []SearchItem  `json:"items"`
	EnrichmentCoveragePct int           `json:"enrichment_coverage_pct"`
	FallbackUsed          string        `json:"fallback_used"` // "none" | "fts_over_bodies"
}

// ChunkSearchItem is one hit from the module_chunks table.
type ChunkSearchItem struct {
	ChunkID        int64   `json:"chunk_id"`
	ModuleID       int64   `json:"module_id"`
	ModuleName     string  `json:"module_name"`
	AppKbID        string  `json:"app_kb_id"`
	AppDisplayName string  `json:"app_display_name"`
	Title          string  `json:"title"`
	Content        string  `json:"content"`
	Similarity     float32 `json:"similarity"`
}

// ChunkSearchPayload is the wire shape for high-precision chunk search.
type ChunkSearchPayload struct {
	Query    string            `json:"query"`
	Returned int               `json:"returned"`
	Items    []ChunkSearchItem `json:"items"`
}

// SearchChunks performs a high-precision search over semantic slices.
// Uses the Trigram index on module_chunks.content.
func SearchChunks(ctx context.Context, db *sql.DB, opts SearchOptions) (*ChunkSearchPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("SearchChunks: nil db")
	}
	if opts.Query == "" {
		return nil, fmt.Errorf("SearchChunks: query is required")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 20
	}

	likePattern := "%" + escapeLike(opts.Query) + "%"
	args := []any{opts.Query, likePattern}
	nextArg := 3
	where := []string{`(mc.content % $1 OR mc.content ILIKE $2 ESCAPE '\')`}

	if opts.App != "" {
		where = append(where, fmt.Sprintf("ka.kb_id = $%d", nextArg))
		args = append(args, opts.App)
		nextArg++
	}

	sql := fmt.Sprintf(`
		SELECT mc.id, mc.module_id, m.name, ka.kb_id, ka.display_name,
		       mc.title, mc.content, similarity(mc.content, $1) AS sim
		FROM module_chunks mc
		JOIN modules m ON m.id = mc.module_id
		JOIN module_app_refs mar ON mar.body_sha256 = m.body_sha256
		JOIN knowledge_sources ks ON ks.id = mar.source_id
		JOIN kb_apps ka ON ka.kb_id = ks.kb_id
		WHERE %s
		ORDER BY sim DESC
		LIMIT $%d
	`, strings.Join(where, " AND "), nextArg)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query chunks: %w", err)
	}
	defer rows.Close()

	var items []ChunkSearchItem
	for rows.Next() {
		var it ChunkSearchItem
		if err := rows.Scan(
			&it.ChunkID, &it.ModuleID, &it.ModuleName, &it.AppKbID, &it.AppDisplayName,
			&it.Title, &it.Content, &it.Similarity,
		); err != nil {
			return nil, err
		}
		items = append(items, it)
	}

	return &ChunkSearchPayload{
		Query:    opts.Query,
		Returned: len(items),
		Items:    items,
	}, nil
}

// SearchAdvanced runs the trigram-ranked query first; if that returns
// zero rows it transparently falls back to ILIKE over
// modules.body_excerpt (matching cmd/kb_search.go + the pre-B1.1 MCP
// handler behaviour). Enrichment coverage is computed best-effort.
//
// The caller-facing snippet extraction (kbExtractSnippet) stays in the
// MCP handler — body_excerpt is returned raw so the caller can trim it
// against the query string. (The handler post-processes Items to set
// BodyExcerptSnippet; this function leaves it equal to body_excerpt.)
//
// Distinct from the simpler Search(db, app, query, limit) below: this
// is the richer multi-filter + FTS-fallback + cursor variant powering
// the supervisor kb.search verb (v2.17 thin-client B1.1). The simpler
// Search is retained for cmd/-side callers that don't need the extras.
func SearchAdvanced(ctx context.Context, db *sql.DB, opts SearchOptions) (*SearchPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("Search: nil db")
	}
	if opts.Query == "" {
		return nil, fmt.Errorf("Search: query is required")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return nil, fmt.Errorf("Search: limit must be <= 500")
	}

	// $1 = raw query (trigram % operator + similarity ranking).
	// $2 = LIKE-escaped query wrapped in wildcards; the ILIKE clauses use
	// ESCAPE '\' so a query containing %, _ or \ is matched literally and
	// can't trigger a full-table slow scan (LIKE-injection DoS).
	likePattern := "%" + escapeLike(opts.Query) + "%"
	args := []any{opts.Query, likePattern}
	nextArg := 3
	where := []string{
		`(m.search_text % $1 OR m.search_text ILIKE $2 ESCAPE '\')`,
	}
	if opts.App != "" {
		where = append(where, fmt.Sprintf("ks.kb_id = $%d", nextArg))
		args = append(args, opts.App)
		nextArg++
	}
	if opts.Component != "" {
		where = append(where, fmt.Sprintf("mc.component = $%d", nextArg))
		args = append(args, opts.Component)
		nextArg++
	}
	if opts.Topic != "" {
		where = append(where, fmt.Sprintf("m.topic = $%d", nextArg))
		args = append(args, opts.Topic)
		nextArg++
	}
	if opts.FactType != "" {
		where = append(where, fmt.Sprintf("EXISTS (SELECT 1 FROM app_facts af WHERE af.app = ka.canonical_name AND af.category = $%d)", nextArg))
		args = append(args, opts.FactType)
		nextArg++
	}
	if opts.Lang != "" {
		where = append(where, fmt.Sprintf("m.lang = $%d", nextArg))
		args = append(args, opts.Lang)
		nextArg++
	}
	if opts.SinceMillis > 0 {
		where = append(where, fmt.Sprintf("ks.captured_at >= $%d", nextArg))
		args = append(args, opts.SinceMillis)
		nextArg++
	}
	if opts.Cursor != nil {
		where = append(where, fmt.Sprintf(
			"(similarity(m.search_text, $1) < $%d OR (similarity(m.search_text, $1) = $%d AND (ks.captured_at < $%d OR (ks.captured_at = $%d AND m.id > $%d))))",
			nextArg, nextArg, nextArg+1, nextArg+1, nextArg+2,
		))
		args = append(args, opts.Cursor.Similarity, opts.Cursor.CapturedAt, opts.Cursor.ModuleID)
		nextArg += 3
	}

	ranked := fmt.Sprintf(`
		SELECT m.id AS module_id, m.name, m.lang, m.body_excerpt,
		       similarity(m.search_text, $1) AS sim,
		       ks.kb_id, ka.display_name, ks.captured_at,
		       COALESCE(mc.component, 'other') AS component,
		       m.summary, m.tags, COALESCE(me.role, '') AS role, m.synthetic_name, COALESCE(m.topic,'') AS topic
		FROM modules m
		JOIN module_app_refs mar ON mar.body_sha256 = m.body_sha256
		JOIN knowledge_sources ks ON ks.id = mar.source_id
		JOIN kb_apps ka ON ka.kb_id = ks.kb_id
		LEFT JOIN module_components mc ON mc.module_id = m.id
		LEFT JOIN module_enrichment me ON me.module_id = m.id
		WHERE %s
		ORDER BY sim DESC, ks.captured_at DESC, m.id ASC
		LIMIT $%d
	`, strings.Join(where, " AND "), nextArg)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, ranked, args...)
	if err != nil {
		return nil, fmt.Errorf("search ranked: %w", err)
	}
	items, scanErr := scanSearchRows(rows)
	_ = rows.Close()
	if scanErr != nil {
		return nil, scanErr
	}

	fallback := "none"
	if len(items) == 0 {
		// FTS fallback: ILIKE over body_excerpt, no similarity score.
		ftsArgs := []any{likePattern}
		ftsNext := 2
		ftsWhere := []string{`m.body_excerpt ILIKE $1 ESCAPE '\'`}
		if opts.App != "" {
			ftsWhere = append(ftsWhere, fmt.Sprintf("ks.kb_id = $%d", ftsNext))
			ftsArgs = append(ftsArgs, opts.App)
			ftsNext++
		}
		if opts.Component != "" {
			ftsWhere = append(ftsWhere, fmt.Sprintf("mc.component = $%d", ftsNext))
			ftsArgs = append(ftsArgs, opts.Component)
			ftsNext++
		}
		if opts.Topic != "" {
			ftsWhere = append(ftsWhere, fmt.Sprintf("m.topic = $%d", ftsNext))
			ftsArgs = append(ftsArgs, opts.Topic)
			ftsNext++
		}
		if opts.Lang != "" {
			ftsWhere = append(ftsWhere, fmt.Sprintf("m.lang = $%d", ftsNext))
			ftsArgs = append(ftsArgs, opts.Lang)
			ftsNext++
		}
		ftsSQL := fmt.Sprintf(`
			SELECT m.id AS module_id, m.name, m.lang, m.body_excerpt,
			       0.0::real AS sim,
			       ks.kb_id, ka.display_name, ks.captured_at,
			       COALESCE(mc.component, 'other') AS component,
			       m.summary, m.tags, COALESCE(me.role, '') AS role, m.synthetic_name, COALESCE(m.topic,'') AS topic
			FROM modules m
			JOIN module_app_refs mar ON mar.body_sha256 = m.body_sha256
			JOIN knowledge_sources ks ON ks.id = mar.source_id
			JOIN kb_apps ka ON ka.kb_id = ks.kb_id
			LEFT JOIN module_components mc ON mc.module_id = m.id
			LEFT JOIN module_enrichment me ON me.module_id = m.id
			WHERE %s
			ORDER BY ks.captured_at DESC, m.id ASC
			LIMIT $%d
		`, strings.Join(ftsWhere, " AND "), ftsNext)
		ftsArgs = append(ftsArgs, limit)

		ftsRows, ftsErr := db.QueryContext(ctx, ftsSQL, ftsArgs...)
		if ftsErr != nil {
			return nil, fmt.Errorf("search fts fallback: %w", ftsErr)
		}
		items, scanErr = scanSearchRows(ftsRows)
		_ = ftsRows.Close()
		if scanErr != nil {
			return nil, scanErr
		}
		if len(items) > 0 {
			fallback = "fts_over_bodies"
		}
	}

	coveragePct := enrichmentCoveragePct(ctx, db, opts.App)

	var nextCursor *SearchCursor
	if fallback == "none" && len(items) == limit {
		last := items[len(items)-1]
		nextCursor = &SearchCursor{
			Similarity: last.Similarity,
			CapturedAt: last.CapturedAt,
			ModuleID:   last.ModuleID,
		}
	}

	return &SearchPayload{
		Query:                 opts.Query,
		Returned:              len(items),
		NextCursor:            nextCursor,
		Items:                 items,
		EnrichmentCoveragePct: coveragePct,
		FallbackUsed:          fallback,
	}, nil
}

func scanSearchRows(r *sql.Rows) ([]SearchItem, error) {
	var out []SearchItem
	for r.Next() {
		var it SearchItem
		var lang sql.NullString
		var body sql.NullString
		var summary, tags, role, synth, topic sql.NullString
		if err := r.Scan(
			&it.ModuleID, &it.Name, &lang, &body,
			&it.Similarity, &it.AppKbID, &it.AppDisplayName, &it.CapturedAt,
			&it.Component,
			&summary, &tags, &role, &synth, &topic,
		); err != nil {
			return nil, fmt.Errorf("search scan: %w", err)
		}
		it.Lang = lang.String
		// Snippet extraction stays caller-side — leave the raw excerpt here.
		it.BodyExcerptSnippet = body.String
		it.Summary = summary.String
		it.Tags = tags.String
		it.Role = role.String
		it.SyntheticName = synth.String
		it.Topic = topic.String
		out = append(out, it)
	}
	return out, nil
}

// enrichmentCoveragePct returns the percentage of modules (optionally
// filtered by app kb_id) that have a non-NULL summary. Returns 0 on any
// error (best-effort, same semantics as the pre-extraction
// kbEnrichmentCoveragePct).
func enrichmentCoveragePct(ctx context.Context, db *sql.DB, appKbID string) int {
	if db == nil {
		return 0
	}
	var q string
	var args []any
	if appKbID != "" {
		q = `SELECT COALESCE(SUM(CASE WHEN m.summary IS NOT NULL THEN 1 ELSE 0 END) * 100 / NULLIF(COUNT(*),0), 0)
			 FROM modules m
			 JOIN module_app_refs mar ON mar.body_sha256 = m.body_sha256
			 JOIN knowledge_sources ks ON ks.id = mar.source_id
			 WHERE ks.kb_id = $1`
		args = []any{appKbID}
	} else {
		q = `SELECT COALESCE(SUM(CASE WHEN summary IS NOT NULL THEN 1 ELSE 0 END) * 100 / NULLIF(COUNT(*),0), 0)
			 FROM modules`
	}
	var pct int
	if err := db.QueryRowContext(ctx, q, args...).Scan(&pct); err != nil {
		return 0
	}
	return pct
}
