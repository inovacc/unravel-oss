// Package store wraps typed read queries against the Postgres knowledge
// catalog. cmd/* and pkg/mcptools call these helpers instead of inlining
// the same SQL across multiple files.
package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
)

// SearchHit is one row returned by Search.
type SearchHit struct {
	ID        int            `json:"id"`
	App       string         `json:"app"`
	Name      string         `json:"name"`
	Synthetic sql.NullString `json:"synthetic"`
	Sightings int            `json:"sightings"`
	Snippet   string         `json:"snippet"`
}

// Search runs a pg_trgm substring match against the generated search_text
// column on modules, optionally filtered by app. Results are ordered by
// trigram similarity DESC and capped at limit.
//
// pg_trgm + ILIKE drives the match; substring queries like "deriveKey"
// still hit inside minified-renamed identifiers because the GIN trigram
// index covers all 3-char windows.
func Search(db *sql.DB, app, query string, limit int) ([]SearchHit, error) {
	limit = clampLimit(limit)
	pattern := "%" + escapeLike(query) + "%"
	args := []any{pattern, query}
	q := `
SELECT m.id, m.app, m.name, m.synthetic_name,
       (SELECT COUNT(*) FROM module_sightings WHERE module_id = m.id) AS sightings,
       substring(m.search_text FROM greatest(1, position(lower($2) IN lower(m.search_text)) - 16) FOR 64) AS snippet
  FROM modules m
 WHERE m.search_text ILIKE $1
`
	if app != "" {
		args = append(args, app)
		q += fmt.Sprintf(" AND m.app = $%d\n", len(args))
	}
	args = append(args, limit)
	// KBC-VI-RECALL fix: weight name+summary above generic search_text
	// trigram. Bare search_text trigram dilutes name matches against the
	// concatenated body+symbols+tags payload, so HeroInteractionContext-
	// style queries previously needed --limit 60 to surface. Coefficients
	// chosen empirically — name match dominates (2.0), summary second
	// (1.5), search_text catch-all third (1.0).
	q += fmt.Sprintf(" ORDER BY (similarity(coalesce(m.name,''), $2) * 2.0 + similarity(coalesce(m.summary,''), $2) * 1.5 + similarity(m.search_text, $2)) DESC, m.id LIMIT $%d", len(args))

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []SearchHit
	for rows.Next() {
		var h SearchHit
		if err := rows.Scan(&h.ID, &h.App, &h.Name, &h.Synthetic, &h.Sightings, &h.Snippet); err != nil {
			slog.Warn("kb store: skipping unscannable row", "fn", "Search", "err", err)
			continue
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// escapeLike escapes ILIKE wildcards so the user's query is treated as a
// literal substring.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// maxQueryLimit bounds any caller-supplied LIMIT to keep a single query from
// scanning/returning an unbounded result set (matches SearchAdvanced's 500
// ceiling).
const maxQueryLimit = 500

// clampLimit floors a caller-supplied limit at 1 and caps it at
// maxQueryLimit. A non-positive limit is treated as "use the cap".
func clampLimit(limit int) int {
	if limit <= 0 {
		return maxQueryLimit
	}
	if limit > maxQueryLimit {
		return maxQueryLimit
	}
	return limit
}

// DumpRow is the full module row Dump returns.
type DumpRow struct {
	ID          int            `json:"id"`
	App         string         `json:"app"`
	Name        string         `json:"name"`
	Synthetic   sql.NullString `json:"synthetic_name"`
	BodySize    int            `json:"body_size"`
	Sha256      string         `json:"sha256"`
	BodyExcerpt string         `json:"body_excerpt"`
	Body        []byte         `json:"body"`
	Symbols     sql.NullString `json:"symbols"`
	Summary     sql.NullString `json:"summary"`
	Tags        sql.NullString `json:"tags"`
	// Rich enrichment from module_enrichment (NULL when not enriched / vendored).
	LongSummary sql.NullString `json:"long_summary"`
	Role        sql.NullString `json:"role"`
	Inputs      sql.NullString `json:"inputs_json"`
	Outputs     sql.NullString `json:"outputs_json"`
	SideEffects sql.NullString `json:"side_effects"`
	Deps        sql.NullString `json:"deps_json"`
	Sightings   []Sighting     `json:"sightings"`
}

// Sighting is one (source_file, byte_offset) record from module_sightings.
type Sighting struct {
	SourceFile string `json:"source_file"`
	Offset     int    `json:"byte_offset"`
}

// Dump fetches one module by id including its most recent sightings (up to
// sightingsLimit, ordered by observed_at DESC). Returns sql.ErrNoRows when
// the id does not exist.
func Dump(db *sql.DB, id, sightingsLimit int) (*DumpRow, error) {
	var o DumpRow
	o.ID = id
	if err := db.QueryRow(`SELECT m.app, m.name, m.synthetic_name, m.body_size, m.body_sha256,
	    m.body_excerpt, m.symbols_json, m.summary, m.tags,
	    me.long_summary, me.role, me.inputs_json, me.outputs_json, me.side_effects, me.deps_json
	    FROM modules m
	    LEFT JOIN module_enrichment me ON me.module_id = m.id
	    WHERE m.id = $1`, id).Scan(
		&o.App, &o.Name, &o.Synthetic, &o.BodySize, &o.Sha256,
		&o.BodyExcerpt, &o.Symbols, &o.Summary, &o.Tags,
		&o.LongSummary, &o.Role, &o.Inputs, &o.Outputs, &o.SideEffects, &o.Deps); err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}

	// Fetch full body from module_bodies
	if err := db.QueryRow(`SELECT body FROM module_bodies WHERE body_sha256 = $1`, o.Sha256).Scan(&o.Body); err != nil {
		if err != sql.ErrNoRows {
			return nil, fmt.Errorf("query body: %w", err)
		}
	}

	if sightingsLimit > 0 {
		srows, sErr := db.Query(`SELECT source_file, byte_offset FROM module_sightings
		    WHERE module_id = $1 ORDER BY observed_at DESC LIMIT $2`, id, sightingsLimit)
		if sErr != nil {
			slog.Warn("kb store: sightings query failed", "module_id", id, "err", sErr)
		} else {
			for srows.Next() {
				var s Sighting
				if err := srows.Scan(&s.SourceFile, &s.Offset); err != nil {
					slog.Warn("kb store: skipping unscannable sighting", "module_id", id, "err", err)
					continue
				}
				o.Sightings = append(o.Sightings, s)
			}
			if err := srows.Err(); err != nil {
				slog.Warn("kb store: sightings iteration error", "module_id", id, "err", err)
			}
			_ = srows.Close()
		}
	}
	return &o, nil
}

// PendingRow is one (id, app, name) tuple for a module without a summary.
type PendingRow struct {
	ID   int
	App  string
	Name string
}

// Pending returns modules whose summary is empty, optionally filtered by app.
func Pending(db *sql.DB, app string, limit int) ([]PendingRow, error) {
	limit = clampLimit(limit)
	args := []any{}
	q := `SELECT id, app, name FROM modules WHERE (summary IS NULL OR summary = '')`
	if app != "" {
		args = append(args, app)
		q += fmt.Sprintf(" AND app = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY id LIMIT $%d", len(args))

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PendingRow
	for rows.Next() {
		var r PendingRow
		if err := rows.Scan(&r.ID, &r.App, &r.Name); err != nil {
			slog.Warn("kb store: skipping unscannable row", "fn", "Pending", "err", err)
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FactRow is one row from app_facts. Used by both Facts and Gaps.
type FactRow struct {
	ID         int             `json:"id"`
	App        string          `json:"app"`
	Category   string          `json:"category"`
	Key        string          `json:"key"`
	Value      sql.NullString  `json:"value"`
	Confidence sql.NullFloat64 `json:"confidence"`
	Evidence   sql.NullString  `json:"evidence_ids"`
}

// Facts returns rows from app_facts. When gapsOnly is true, only rows where
// value IS NULL are returned; otherwise only rows with non-NULL values.
func Facts(db *sql.DB, app, category string, gapsOnly bool) ([]FactRow, error) {
	args := []any{}
	q := `SELECT id, app, category, key, value, confidence, evidence_ids
	  FROM app_facts WHERE 1=1`
	if gapsOnly {
		q += " AND value IS NULL"
	} else {
		q += " AND value IS NOT NULL"
	}
	if app != "" {
		args = append(args, app)
		q += fmt.Sprintf(" AND app = $%d", len(args))
	}
	if category != "" {
		args = append(args, category)
		q += fmt.Sprintf(" AND category = $%d", len(args))
	}
	// Bounded LIMIT: Facts had no ceiling, so an unfiltered call could pull
	// the entire app_facts table into memory. Cap at maxQueryLimit.
	args = append(args, maxQueryLimit)
	q += fmt.Sprintf(" ORDER BY app, category, key LIMIT $%d", len(args))

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []FactRow
	for rows.Next() {
		var r FactRow
		if err := rows.Scan(&r.ID, &r.App, &r.Category, &r.Key, &r.Value, &r.Confidence, &r.Evidence); err != nil {
			slog.Warn("kb store: skipping unscannable row", "fn", "Facts", "err", err)
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Gaps is shorthand for Facts(db, app, category, true).
func Gaps(db *sql.DB, app, category string) ([]FactRow, error) {
	return Facts(db, app, category, true)
}

// StatsRow aggregates per-app counts from the modules table.
type StatsRow struct {
	App        string  `json:"app"`
	Total      int     `json:"total"`
	Summarized int     `json:"summarized"`
	AvgBytes   float64 `json:"avg_bytes"`
	UniqHashes int     `json:"unique_hashes"`
}

// Stats returns one StatsRow per app present in modules.
func Stats(db *sql.DB) ([]StatsRow, error) {
	rows, err := db.Query(`SELECT app, COUNT(*)::bigint AS total,
	    SUM(CASE WHEN summary IS NOT NULL AND summary <> '' THEN 1 ELSE 0 END)::bigint AS summarized,
	    COALESCE(AVG(body_size), 0)::float8 AS avg_bytes,
	    COUNT(DISTINCT body_sha256)::bigint AS uniq
	  FROM modules GROUP BY app ORDER BY app`)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []StatsRow
	for rows.Next() {
		var r StatsRow
		if err := rows.Scan(&r.App, &r.Total, &r.Summarized, &r.AvgBytes, &r.UniqHashes); err != nil {
			slog.Warn("kb store: skipping unscannable row", "fn", "Stats", "err", err)
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
