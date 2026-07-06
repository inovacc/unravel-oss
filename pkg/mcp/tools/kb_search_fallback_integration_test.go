//go:build integration

// Integration test for B3: MCP kb_search FTS fallback parity with CLI.
// Run with: go test -tags=integration ./pkg/mcptools/... -run TestKbSearchMCPFTSFallback
package mcptools

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// seedMCPFallbackCorpus seeds the same minimal corpus as cmd's fallback test:
// one module with "sendMessage" in body_excerpt but a non-matching name.
func seedMCPFallbackCorpus(t *testing.T, db *sql.DB) {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed exec: %v\nquery: %s", err, q)
		}
	}

	exec(`INSERT INTO kb_apps
		(kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at)
		VALUES ('mcp_fts_app', 'mcp_fts', 'MCPFTSApp', 'electron', 0, 0)`)

	var sourceID int64
	if err := db.QueryRow(`INSERT INTO knowledge_sources
		(app, epoch, source_path, source_kind, captured_at, kb_id)
		VALUES ('mcp_fts', 1, '/tmp/mcp_fts', 'other', 1000, 'mcp_fts_app')
		RETURNING id`).Scan(&sourceID); err != nil {
		t.Fatalf("insert knowledge_sources: %v", err)
	}

	sha := "sha_mcp_fts_fallback_module"
	bodyExcerpt := "function zz(){var r=sendMessage({type:'hello'});return r;}"

	exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
		VALUES ($1, $2, $3, 0)`, sha, []byte(bodyExcerpt), len(bodyExcerpt))

	var moduleID int64
	if err := db.QueryRow(`INSERT INTO modules
		(app, name, body_sha256, body_excerpt, body_size, first_seen_at, last_seen_at)
		VALUES ('mcp_fts', $1, $2, $3, $4, 0, 0)
		RETURNING id`,
		"zz_bundle_0001.js", sha, bodyExcerpt, len(bodyExcerpt)).Scan(&moduleID); err != nil {
		t.Fatalf("insert module: %v", err)
	}

	exec(`INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at) VALUES ($1, 'mcp_fts', $2, 0)`, sha, sourceID)
}

// startMCPFallbackClient spins up an in-memory MCP server wired to db and
// returns a connected client session — mirrors kb_search_summary integration test.
func startMCPFallbackClient(t *testing.T, ctx context.Context, db *sql.DB) *mcp.ClientSession {
	t.Helper()

	srv := NewServer(ServerConfig{
		OnServer: func(s *mcp.Server) { RegisterKB(s, db) },
	})

	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	c := mcp.NewClient(&mcp.Implementation{Name: "test-fts-fallback", Version: "v0"}, nil)
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// TestKbSearchMCPFTSFallback verifies the MCP handler mirrors the CLI fallback:
//  1. Ranked path returns 0 for "sendMessage" (no trigram match on opaque name).
//  2. FTS fallback fires → returned > 0.
//  3. Response contains fallback_used = "fts_over_bodies" and fallback_banner.
//  4. enrichment_coverage_pct present and = 0 (no enrichment seeded).
func TestKbSearchMCPFTSFallback(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	seedMCPFallbackCorpus(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cs := startMCPFallbackClient(t, ctx, db)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "unravel_kb_catalog_search",
		Arguments: map[string]any{
			"query": "sendMessage",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %+v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("empty content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] not TextContent: %T", res.Content[0])
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &payload); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, tc.Text)
	}

	// returned > 0
	returned, _ := payload["returned"].(float64)
	if returned == 0 {
		t.Fatalf("expected >0 results via FTS fallback, got 0; payload: %s", tc.Text)
	}

	// fallback_used = "fts_over_bodies"
	fallbackUsed, _ := payload["fallback_used"].(string)
	if fallbackUsed != "fts_over_bodies" {
		t.Errorf("fallback_used = %q, want 'fts_over_bodies'", fallbackUsed)
	}

	// fallback_banner contains "falling back to FTS"
	banner, _ := payload["fallback_banner"].(string)
	if !strings.Contains(banner, "falling back to FTS") {
		t.Errorf("fallback_banner = %q, want 'falling back to FTS'", banner)
	}

	// enrichment_coverage_pct present and 0
	covPct, hasCov := payload["enrichment_coverage_pct"]
	if !hasCov {
		t.Error("enrichment_coverage_pct field missing from MCP response")
	}
	if pct, _ := covPct.(float64); pct != 0 {
		t.Errorf("enrichment_coverage_pct = %v, want 0", covPct)
	}

	// Additive-only check: existing fields still present.
	if _, ok := payload["items"]; !ok {
		t.Error("items field missing — backward-compat broken")
	}
	if _, ok := payload["query"]; !ok {
		t.Error("query field missing — backward-compat broken")
	}
}

// TestKbSearchMCPFallbackFieldsAlwaysPresent verifies additive fields appear
// even when the ranked path returns results (no fallback needed).
func TestKbSearchMCPFallbackFieldsAlwaysPresent(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	seedMCPFallbackCorpus(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cs := startMCPFallbackClient(t, ctx, db)

	// Query that does match by name via ILIKE inside search_text.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "unravel_kb_catalog_search",
		Arguments: map[string]any{
			"query": "zz_bundle",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] not TextContent: %T", res.Content[0])
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, field := range []string{"fallback_used", "fallback_banner", "enrichment_coverage_pct"} {
		if _, ok := payload[field]; !ok {
			t.Errorf("additive field %q missing from MCP response", field)
		}
	}
}
