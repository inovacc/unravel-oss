/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/summaryview"

	"github.com/spf13/cobra"

	_ "github.com/lib/pq"
)

var (
	searchApp       string
	searchComponent string
	searchTopic     string
	searchFactType  string
	searchLang      string
	searchSince     string
	searchLimit     int
	searchCursor    string
	searchJSON      bool
	searchChunks    bool
	searchDSN       string
)

// FallbackKind identifies which search strategy produced the result set.
type FallbackKind string

const (
	// FallbackNone means the ranked trigram path returned results.
	FallbackNone FallbackKind = "none"
	// FallbackFTSOverBodies means the trigram path returned 0 rows and we
	// fell back to ILIKE over modules.body_excerpt.
	FallbackFTSOverBodies FallbackKind = "fts_over_bodies"
)

// FormatFallbackBanner returns the human-readable one-liner shown when the
// FTS fallback fires. coveragePct is the enrichment coverage percentage
// (0–100). Exported so it can be unit-tested without a DB.
func FormatFallbackBanner(coveragePct int, kind FallbackKind) string {
	if kind == FallbackNone {
		return ""
	}
	return fmt.Sprintf("enrichment coverage %d%% — falling back to FTS over raw bodies", coveragePct)
}

type cursorTok struct {
	Similarity float32 `json:"s"`
	CapturedAt int64   `json:"c"` // unix ms
	ModuleID   int64   `json:"m"`
}

var kbSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search knowledge base modules using trigram fuzzy match",
	Args:  cobra.ExactArgs(1),
	RunE:  runKbSearch,
}

func init() {
	kbCatalogCmd.AddCommand(kbSearchCmd)
	kbSearchCmd.Flags().StringVar(&searchApp, "app", "", "Filter by app kb_id")
	kbSearchCmd.Flags().StringVar(&searchComponent, "component", "", "Filter by component bucket")
	kbSearchCmd.Flags().StringVar(&searchTopic, "topic", "", "filter by deterministic topic")
	kbSearchCmd.Flags().StringVar(&searchFactType, "fact-type", "", "Filter by fact type category")
	kbSearchCmd.Flags().StringVar(&searchLang, "lang", "", "Filter by language")
	kbSearchCmd.Flags().StringVar(&searchSince, "since", "", "Filter by time (e.g. 30d, 2y, or RFC3339)")
	kbSearchCmd.Flags().IntVar(&searchLimit, "limit", 50, "Limit results (max 500)")
	kbSearchCmd.Flags().StringVar(&searchCursor, "cursor", "", "Opaque cursor token for pagination")
	kbSearchCmd.Flags().BoolVar(&searchChunks, "chunks", false, "High-precision search over semantic slices (H1, JSON keys, etc.)")

	kb_output.BindJSONFlag(kbSearchCmd, &searchJSON)
	kb_output.BindDSNFlag(kbSearchCmd, &searchDSN)
}

func runKbSearch(cmd *cobra.Command, args []string) error {
	query := args[0]

	if searchLimit > 500 {
		return errors.New("limit must be <= 500")
	}

	dsn, err := kb_output.ResolveDSN(searchDSN)
	if err != nil {
		return err
	}

	// BUG-08: lib/pq does not support sslmode=prefer (only require/verify-full/verify-ca/disable).
	// pgx-style DSNs from config.yaml may include sslmode=prefer, which lib/pq rejects.
	// Normalize to sslmode=disable for the kb search lib/pq driver. Local KB never requires TLS.
	dsn = strings.ReplaceAll(dsn, "sslmode=prefer", "sslmode=disable")

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	if searchChunks {
		return runChunkSearch(db, query)
	}

	var cursor *cursorTok
	if searchCursor != "" {
		data, err := base64.URLEncoding.DecodeString(searchCursor)
		if err != nil {
			return errors.New("invalid cursor token")
		}
		var c cursorTok
		if err := json.Unmarshal(data, &c); err != nil {
			return errors.New("invalid cursor token")
		}
		cursor = &c
	}

	var sqlArgs []any
	sqlArgs = append(sqlArgs, query)
	nextArg := 2

	var whereClauses []string
	whereClauses = append(whereClauses, fmt.Sprintf("(m.search_text %% $%d OR m.search_text ILIKE '%%' || $%d || '%%')", 1, 1))

	if searchApp != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("ks.kb_id = $%d", nextArg))
		sqlArgs = append(sqlArgs, searchApp)
		nextArg++
	}

	if searchComponent != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("mc.component = $%d", nextArg))
		sqlArgs = append(sqlArgs, searchComponent)
		nextArg++
	}

	if searchTopic != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("m.topic = $%d", nextArg))
		sqlArgs = append(sqlArgs, searchTopic)
		nextArg++
	}

	if searchFactType != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("EXISTS (SELECT 1 FROM app_facts af WHERE af.app = ka.canonical_name AND af.category = $%d)", nextArg))
		sqlArgs = append(sqlArgs, searchFactType)
		nextArg++
	}

	if searchLang != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("m.lang = $%d", nextArg))
		sqlArgs = append(sqlArgs, searchLang)
		nextArg++
	}

	if searchSince != "" {
		t, err := kb_output.ParseSince(searchSince)
		if err != nil {
			return fmt.Errorf("parse since: %w", err)
		}
		whereClauses = append(whereClauses, fmt.Sprintf("ks.captured_at >= $%d", nextArg))
		sqlArgs = append(sqlArgs, t.UnixMilli())
		nextArg++
	}

	if cursor != nil {
		// (sim, ks.captured_at, m.id) < (cursor.Similarity, cursor.CapturedAt, cursor.ModuleID)
		// but similarity is DESC, captured_at is DESC, module_id is ASC
		// (sim < $cs OR (sim = $cs AND (ks.captured_at < $cc OR (ks.captured_at = $cc AND m.id > $cm))))
		whereClauses = append(whereClauses, fmt.Sprintf(
			"(similarity(m.search_text, $1) < $%d OR (similarity(m.search_text, $1) = $%d AND (ks.captured_at < $%d OR (ks.captured_at = $%d AND m.id > $%d))))",
			nextArg, nextArg, nextArg+1, nextArg+1, nextArg+2,
		))
		sqlArgs = append(sqlArgs, cursor.Similarity, cursor.CapturedAt, cursor.ModuleID)
		nextArg += 3
	}

	sqlQuery := fmt.Sprintf(`
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
	`, strings.Join(whereClauses, " AND "), nextArg)

	sqlArgs = append(sqlArgs, searchLimit)

	rows, err := db.Query(sqlQuery, sqlArgs...)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	type item struct {
		ModuleID           int64   `json:"module_id" jsonschema:"unique module identifier in the modules table"`
		Name               string  `json:"name" jsonschema:"module name (typically file path or symbolic name)"`
		BodyExcerptSnippet string  `json:"body_excerpt_snippet" jsonschema:"context window from the module body around the matched query (max ~200 chars)"`
		Similarity         float32 `json:"similarity" jsonschema:"trigram similarity score (0.0-1.0) between query and module search_text"`
		AppKbID            string  `json:"app_kb_id" jsonschema:"canonical knowledge-base identifier of the app containing this module"`
		AppDisplayName     string  `json:"app_display_name" jsonschema:"human-readable display name of the app containing this module"`
		CapturedAt         int64   `json:"captured_at" jsonschema:"unix-millisecond timestamp of the capture that produced this module"`
		Lang               string  `json:"lang" jsonschema:"detected source language for the module (e.g. javascript, java, kotlin); empty when unknown"`
		Component          string  `json:"component" jsonschema:"classified component bucket (auth, network, ui, ipc, telemetry, ...); 'other' when unclassified"`
		Summary            string  `json:"summary"               jsonschema:"enriched one-sentence summary of the module; empty when not enriched"`
		Role               string  `json:"role"                  jsonschema:"enriched role classification (send|receive|auth|...); empty when not enriched"`
		Tags               string  `json:"tags"                  jsonschema:"enriched comma/space-separated tags; empty when not enriched"`
		SyntheticName      string  `json:"synthetic_name" jsonschema:"pure-Go derived name for teams_module_<N> placeholders; empty otherwise"`
		Topic              string  `json:"topic,omitempty" jsonschema:"deterministic coarse topic (messaging|crypto|media|ui|...); empty when not derived"`
	}

	scanRows := func(r *sql.Rows) ([]item, error) {
		var out []item
		for r.Next() {
			var it item
			var bodyExcerpt sql.NullString
			var lang sql.NullString
			var summaryNS, tagsNS, roleNS sql.NullString
			var synthNS sql.NullString
			var topicNS sql.NullString
			if err := r.Scan(
				&it.ModuleID, &it.Name, &lang, &bodyExcerpt,
				&it.Similarity, &it.AppKbID, &it.AppDisplayName, &it.CapturedAt,
				&it.Component,
				&summaryNS, &tagsNS, &roleNS, &synthNS, &topicNS,
			); err != nil {
				return nil, fmt.Errorf("scan: %w", err)
			}
			it.Lang = lang.String
			it.BodyExcerptSnippet = extractSnippet(bodyExcerpt.String, query)
			it.Summary = summaryNS.String
			it.Tags = tagsNS.String
			it.Role = roleNS.String
			it.SyntheticName = synthNS.String
			it.Topic = topicNS.String
			out = append(out, it)
		}
		return out, nil
	}

	items, err := scanRows(rows)
	if err != nil {
		return err
	}

	// ── FTS fallback ──────────────────────────────────────────────────────
	// When the trigram/enrichment-dependent ranked path returns 0 rows,
	// automatically run an ILIKE search over modules.body_excerpt so consumers
	// always see results when the token literally appears in the corpus.
	fallback := FallbackNone
	if len(items) == 0 {
		ftsArgs := []any{query}
		ftsNext := 2
		var ftsWhere []string
		ftsWhere = append(ftsWhere, "m.body_excerpt ILIKE '%' || $1 || '%'")
		if searchApp != "" {
			ftsWhere = append(ftsWhere, fmt.Sprintf("ks.kb_id = $%d", ftsNext))
			ftsArgs = append(ftsArgs, searchApp)
			ftsNext++
		}
		if searchComponent != "" {
			ftsWhere = append(ftsWhere, fmt.Sprintf("mc.component = $%d", ftsNext))
			ftsArgs = append(ftsArgs, searchComponent)
			ftsNext++
		}
		if searchTopic != "" {
			ftsWhere = append(ftsWhere, fmt.Sprintf("m.topic = $%d", ftsNext))
			ftsArgs = append(ftsArgs, searchTopic)
			ftsNext++
		}
		if searchLang != "" {
			ftsWhere = append(ftsWhere, fmt.Sprintf("m.lang = $%d", ftsNext))
			ftsArgs = append(ftsArgs, searchLang)
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
		ftsArgs = append(ftsArgs, searchLimit)

		ftsRows, ftsErr := db.Query(ftsSQL, ftsArgs...)
		if ftsErr != nil {
			return fmt.Errorf("fts fallback query: %w", ftsErr)
		}
		defer ftsRows.Close()
		items, err = scanRows(ftsRows)
		if err != nil {
			return err
		}
		if len(items) > 0 {
			fallback = FallbackFTSOverBodies
		}
	}

	// ── Enrichment coverage ───────────────────────────────────────────────
	coveragePct := enrichmentCoveragePct(db, searchApp)
	banner := FormatFallbackBanner(coveragePct, fallback)

	var nextCursorStr *string
	if fallback == FallbackNone && len(items) == searchLimit {
		last := items[len(items)-1]
		c := cursorTok{
			Similarity: last.Similarity,
			CapturedAt: last.CapturedAt,
			ModuleID:   last.ModuleID,
		}
		data, _ := json.Marshal(c)
		token := base64.URLEncoding.EncodeToString(data)
		nextCursorStr = &token
	}

	if searchJSON {
		payload := map[string]any{
			"query":                   query,
			"returned":                len(items),
			"next_cursor":             nextCursorStr,
			"items":                   items,
			"enrichment_coverage_pct": coveragePct,
			"fallback_used":           string(fallback),
			"fallback_banner":         banner,
		}
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, payload)
	}

	if banner != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "[!] %s\n\n", banner)
	}

	headers := []string{"SIM", "KB_ID", "APP", "COMPONENT", "TOPIC", "LANG", "MODULE", "SNIPPET"}
	var tableRows [][]string
	for _, it := range items {
		cell := it.BodyExcerptSnippet
		if summaryview.Prefer(it.Summary) {
			cell = summaryview.Line(it.Summary, it.Role, it.Tags)
		}
		if len(cell) > 80 {
			cell = cell[:77] + "..."
		}
		tableRows = append(tableRows, []string{
			fmt.Sprintf("%.3f", it.Similarity),
			it.AppKbID,
			it.AppDisplayName,
			it.Component,
			it.Topic,
			it.Lang,
			summaryview.DisplayName(it.Name, it.SyntheticName),
			cell,
		})
	}

	if len(items) > 0 {
		if err := kb_output.WriteTable(cmd.OutOrStdout(), headers, tableRows); err != nil {
			return err
		}
		if nextCursorStr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "\nNext cursor: %s\n", *nextCursorStr)
		}
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "No results found.")
	}

	return nil
}

// enrichmentCoveragePct queries the fraction of modules that have a non-NULL
// summary, optionally scoped to a single app (by kb_id). Returns 0 on error
// (best-effort — never blocks the search result).
func enrichmentCoveragePct(db *sql.DB, appKbID string) int {
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
	if err := db.QueryRow(q, args...).Scan(&pct); err != nil {
		return 0
	}
	return pct
}

func runChunkSearch(db *sql.DB, query string) error {
	ctx := context.Background()
	opts := store.SearchOptions{
		Query: query,
		App:   searchApp,
		Limit: searchLimit,
	}

	payload, err := store.SearchChunks(ctx, db, opts)
	if err != nil {
		return err
	}

	if searchJSON {
		return kb_output.WriteJSON(os.Stdout, 1, payload)
	}

	if payload.Returned == 0 {
		fmt.Println("No semantic chunks found.")
		return nil
	}

	headers := []string{"SIM", "APP", "MODULE", "SEMANTIC TITLE", "CONTENT"}
	var tableRows [][]string
	for _, it := range payload.Items {
		snippet := strings.ReplaceAll(it.Content, "\n", " ")
		if len(snippet) > 80 {
			snippet = snippet[:77] + "..."
		}
		tableRows = append(tableRows, []string{
			fmt.Sprintf("%.3f", it.Similarity),
			it.AppDisplayName,
			it.ModuleName,
			it.Title,
			snippet,
		})
	}

	return kb_output.WriteTable(os.Stdout, headers, tableRows)
}

func extractSnippet(text, query string) string {
	if text == "" {
		return ""
	}

	idx := strings.Index(strings.ToLower(text), strings.ToLower(query))
	if idx == -1 {
		if len(text) > 200 {
			return text[:200]
		}
		return text
	}

	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := start + 200
	if end > len(text) {
		end = len(text)
		start = end - 200
		if start < 0 {
			start = 0
		}
	}

	snippet := text[start:end]
	return strings.ReplaceAll(snippet, "\n", " ")
}
