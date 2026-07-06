//go:build integration

// Integration: serial — mutates process config DSN + cobra flag state.

package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// seedSummaryViewModules seeds the minimal 4-way chain required by
// TestKbSearchUsesSummaryView. Returns the *sql.DB for further assertions.
//
//	kb_apps  (K, "App")
//	knowledge_sources (K, app, epoch=1)  → sourceID
//	modules  AlphaWidget (with summary+tags+enrichment) + BetaWidget (bare)
//	module_app_refs for both
//	module_enrichment for AlphaWidget only
func seedSummaryViewModules(t *testing.T, db *sql.DB) {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed exec: %v\nquery: %s", err, q)
		}
	}

	// ── 1. kb_apps ────────────────────────────────────────────────────────
	exec(`INSERT INTO kb_apps
		(kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at)
		VALUES ('K', 'app', 'App', 'electron', 0, 0)`)

	// ── 2. knowledge_sources ──────────────────────────────────────────────
	var sourceID int64
	err := db.QueryRow(`INSERT INTO knowledge_sources
		(app, epoch, source_path, source_kind, captured_at, kb_id)
		VALUES ('app', 1, '/tmp/test', 'other', 0, 'K')
		RETURNING id`).Scan(&sourceID)
	if err != nil {
		t.Fatalf("insert knowledge_sources: %v", err)
	}

	// ── 3. module_bodies + modules ────────────────────────────────────────
	shaA := "sha_sv_alpha_widgetflow"
	shaB := "sha_sv_beta_widgetflow"

	bodyA := []byte("function alphaImpl(){/*A code*/}")
	bodyB := []byte("function betaWidget(){/*B code*/}")

	exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
		VALUES ($1, $2, $3, 0)`, shaA, bodyA, len(bodyA))
	exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
		VALUES ($1, $2, $3, 0)`, shaB, bodyB, len(bodyB))

	// Module A — name contains "widgetflow" so trigram/ILIKE match returns it.
	// summary + tags set; body_excerpt is the code snippet fallback.
	exec(`INSERT INTO modules
		(app, name, body_size, body_excerpt, body_sha256, summary, tags)
		VALUES ('app', 'AlphaWidgetflow', $1, $2, $3, 'Coordinates the widget flow', 'widget,flow')`,
		len(bodyA), string(bodyA), shaA)

	var moduleAID int64
	if err := db.QueryRow(`SELECT id FROM modules WHERE body_sha256 = $1`, shaA).Scan(&moduleAID); err != nil {
		t.Fatalf("select moduleAID: %v", err)
	}

	// Module B — name contains "widgetflow"; no summary/tags/enrichment.
	exec(`INSERT INTO modules
		(app, name, body_size, body_excerpt, body_sha256)
		VALUES ('app', 'BetaWidgetflow', $1, $2, $3)`,
		len(bodyB), string(bodyB), shaB)

	var moduleBID int64
	if err := db.QueryRow(`SELECT id FROM modules WHERE body_sha256 = $1`, shaB).Scan(&moduleBID); err != nil {
		t.Fatalf("select moduleBID: %v", err)
	}

	// ── 4. module_app_refs ────────────────────────────────────────────────
	exec(`INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
		VALUES ($1, 'app', $2, 0)`, shaA, sourceID)
	exec(`INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
		VALUES ($1, 'app', $2, 0)`, shaB, sourceID)

	// ── 5. module_enrichment for A only ───────────────────────────────────
	exec(`INSERT INTO module_enrichment (module_id, role, created_at)
		VALUES ($1, 'ui', 0)`, moduleAID)
}

// startKBClientForSummaryTest spins up an in-memory MCP server with kb
// tools wired against db and returns a connected client session.
func startKBClientForSummaryTest(t *testing.T, ctx context.Context, db *sql.DB) *mcp.ClientSession {
	t.Helper()
	return newKBTestClient(t, ctx, db, "test-summary")
}

// readSummaryToolText extracts the first TextContent text from a tool result.
func readSummaryToolText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		t.Fatalf("empty content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] not TextContent: %T", res.Content[0])
	}
	return tc.Text
}

// TestKbSearchUsesSummaryView exercises the full summary-first surface:
//  1. CLI table mode: AlphaWidget shows summary cell, NOT its code; Beta shows code.
//  2. CLI JSON mode: AlphaWidget item carries summary/role/tags; Beta has empty fields.
//  3. MCP handler (via in-memory transport): same additive-field assertions.
//  4. Row-count parity: 4-way join count equals CLI item count.
func TestKbSearchUsesSummaryView(t *testing.T) {
	// ── 1. Boot Postgres container + apply migrations ─────────────────────
	db, dsn := dbtest.StartPostgres(t)
	pinDSNViaConfig(t, dsn)

	// ── 2. Seed the 4-way chain ───────────────────────────────────────────
	seedSummaryViewModules(t, db)

	// ── 3. Save + restore all mutated search flag vars ────────────────────
	savedSearchJSON := searchJSON
	savedSearchDSN := searchDSN
	savedSearchApp := searchApp
	savedSearchComponent := searchComponent
	savedSearchLang := searchLang
	savedSearchSince := searchSince
	savedSearchLimit := searchLimit
	savedSearchCursor := searchCursor
	t.Cleanup(func() {
		searchJSON = savedSearchJSON
		searchDSN = savedSearchDSN
		searchApp = savedSearchApp
		searchComponent = savedSearchComponent
		searchLang = savedSearchLang
		searchSince = savedSearchSince
		searchLimit = savedSearchLimit
		searchCursor = savedSearchCursor
	})

	// Set defaults for all sub-steps.
	searchDSN = "" // empty → uses config.yaml (pinned by pinDSNViaConfig)
	searchApp = ""
	searchComponent = ""
	searchLang = ""
	searchSince = ""
	searchLimit = 50
	searchCursor = ""

	// ── 4. CLI table assertion ────────────────────────────────────────────
	{
		searchJSON = false

		var buf bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&buf)

		if err := runKbSearch(cmd, []string{"widgetflow"}); err != nil {
			t.Fatalf("runKbSearch table: %v", err)
		}

		out := buf.String()

		// AlphaWidget: summary cell must appear, not the code.
		if !strings.Contains(out, "Coordinates the widget flow") {
			t.Errorf("table: want summary 'Coordinates the widget flow' in output; got:\n%s", out)
		}
		// BetaWidget: code snippet must appear (fallback).
		if !strings.Contains(out, "betaWidget") {
			t.Errorf("table: want 'betaWidget' snippet in output; got:\n%s", out)
		}
		// AlphaWidget code must NOT appear as the cell (summary took priority).
		if strings.Contains(out, "alphaImpl") {
			t.Errorf("table: 'alphaImpl' code must NOT appear when summary is set; got:\n%s", out)
		}
	}

	// cliItems is captured from the CLI-JSON step for use in section 7.
	type cliItem struct {
		Name               string `json:"name"`
		Summary            string `json:"summary"`
		Role               string `json:"role"`
		Tags               string `json:"tags"`
		BodyExcerptSnippet string `json:"body_excerpt_snippet"`
	}
	var cliItems []cliItem

	// ── 5. CLI JSON assertion ─────────────────────────────────────────────
	{
		searchJSON = true

		var buf bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&buf)

		if err := runKbSearch(cmd, []string{"widgetflow"}); err != nil {
			t.Fatalf("runKbSearch json: %v", err)
		}

		var payload struct {
			Items []cliItem `json:"items"`
		}
		if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
			t.Fatalf("json parse: %v\noutput: %s", err, buf.String())
		}

		cliItems = payload.Items

		if len(cliItems) != 2 {
			t.Fatalf("json: want 2 items, got %d", len(cliItems))
		}

		// Find Alpha and Beta items by name prefix (order is sim-DESC).
		var alpha, beta *cliItem
		for i := range cliItems {
			it := &cliItems[i]
			if strings.HasPrefix(it.Name, "Alpha") {
				alpha = it
			} else if strings.HasPrefix(it.Name, "Beta") {
				beta = it
			}
		}
		if alpha == nil {
			t.Fatalf("json: AlphaWidgetflow item missing; items: %+v", payload.Items)
		}
		if beta == nil {
			t.Fatalf("json: BetaWidgetflow item missing; items: %+v", payload.Items)
		}

		if alpha.Summary != "Coordinates the widget flow" {
			t.Errorf("json alpha summary = %q, want 'Coordinates the widget flow'", alpha.Summary)
		}
		if alpha.Role != "ui" {
			t.Errorf("json alpha role = %q, want 'ui'", alpha.Role)
		}
		if alpha.Tags != "widget,flow" {
			t.Errorf("json alpha tags = %q, want 'widget,flow'", alpha.Tags)
		}
		if beta.Summary != "" {
			t.Errorf("json beta summary = %q, want empty", beta.Summary)
		}
		if beta.Role != "" {
			t.Errorf("json beta role = %q, want empty", beta.Role)
		}
		if beta.Tags != "" {
			t.Errorf("json beta tags = %q, want empty", beta.Tags)
		}
		if beta.BodyExcerptSnippet == "" {
			t.Errorf("json beta body_excerpt_snippet must be non-empty")
		}
	}

	// ── 6. MCP assertion (in-memory transport) ────────────────────────────
	{
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		cs := startKBClientForSummaryTest(t, ctx, db)

		res, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "unravel_kb_catalog_search",
			Arguments: map[string]any{"query": "widgetflow"},
		})
		if err != nil {
			t.Fatalf("mcp call unravel_kb_catalog_search: %v", err)
		}
		if res.IsError {
			t.Fatalf("mcp tool returned error: %s", readSummaryToolText(t, res))
		}

		text := readSummaryToolText(t, res)

		var mcpPayload struct {
			Items []struct {
				Name               string `json:"name"`
				Summary            string `json:"summary"`
				Role               string `json:"role"`
				Tags               string `json:"tags"`
				BodyExcerptSnippet string `json:"body_excerpt_snippet"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(text), &mcpPayload); err != nil {
			t.Fatalf("mcp json parse: %v\ntext: %s", err, text)
		}

		if len(mcpPayload.Items) != 2 {
			t.Fatalf("mcp: want 2 items, got %d", len(mcpPayload.Items))
		}

		var mcpAlpha, mcpBeta *struct {
			Name               string `json:"name"`
			Summary            string `json:"summary"`
			Role               string `json:"role"`
			Tags               string `json:"tags"`
			BodyExcerptSnippet string `json:"body_excerpt_snippet"`
		}
		for i := range mcpPayload.Items {
			it := &mcpPayload.Items[i]
			if strings.HasPrefix(it.Name, "Alpha") {
				mcpAlpha = it
			} else if strings.HasPrefix(it.Name, "Beta") {
				mcpBeta = it
			}
		}
		if mcpAlpha == nil {
			t.Fatalf("mcp: AlphaWidgetflow item missing; items: %+v", mcpPayload.Items)
		}
		if mcpBeta == nil {
			t.Fatalf("mcp: BetaWidgetflow item missing; items: %+v", mcpPayload.Items)
		}

		// Alpha: additive fields must be non-empty AND body_excerpt_snippet retained.
		if mcpAlpha.Summary == "" {
			t.Errorf("mcp alpha summary must be non-empty")
		}
		if mcpAlpha.Role == "" {
			t.Errorf("mcp alpha role must be non-empty")
		}
		if mcpAlpha.Tags == "" {
			t.Errorf("mcp alpha tags must be non-empty")
		}
		if mcpAlpha.BodyExcerptSnippet == "" {
			t.Errorf("mcp alpha body_excerpt_snippet must be non-empty (additive, not replaced)")
		}

		// Beta: additive fields must be empty; snippet retained.
		if mcpBeta.Summary != "" {
			t.Errorf("mcp beta summary = %q, want empty", mcpBeta.Summary)
		}
		if mcpBeta.Role != "" {
			t.Errorf("mcp beta role = %q, want empty", mcpBeta.Role)
		}
		if mcpBeta.Tags != "" {
			t.Errorf("mcp beta tags = %q, want empty", mcpBeta.Tags)
		}
		if mcpBeta.BodyExcerptSnippet == "" {
			t.Errorf("mcp beta body_excerpt_snippet must be non-empty")
		}
	}

	// ── 7. Row-count parity ───────────────────────────────────────────────
	{
		var joinCount int
		joinQ := `SELECT COUNT(*) FROM modules m
			JOIN module_app_refs mar ON mar.body_sha256 = m.body_sha256
			JOIN knowledge_sources ks ON ks.id = mar.source_id
			JOIN kb_apps ka ON ka.kb_id = ks.kb_id
			WHERE m.search_text ILIKE '%widgetflow%'`
		if err := db.QueryRow(joinQ).Scan(&joinCount); err != nil {
			t.Fatalf("row-count parity query: %v", err)
		}
		// Sanity: we seeded exactly 2 rows.
		if joinCount != 2 {
			t.Errorf("row-count parity: 4-way join returned %d rows, want 2", joinCount)
		}
		// Dynamic invariant: the LEFT JOIN module_enrichment must introduce no
		// row-count change vs the bare 4-way join — CLI item count must match.
		if joinCount != len(cliItems) {
			t.Errorf("row-count parity: bare 4-way join=%d rows but CLI returned %d items; LEFT JOIN module_enrichment must not fan out rows", joinCount, len(cliItems))
		}
	}
}
