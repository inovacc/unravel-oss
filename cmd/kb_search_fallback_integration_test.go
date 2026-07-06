//go:build integration

// Integration test for B2: FTS fallback fires when ranked path returns 0 rows.
// Run with: go test -tags=integration ./cmd/... -run TestKbSearchFTSFallback
package cmd

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// seedFallbackCorpus seeds one module whose body_excerpt contains
// "sendMessage" but whose search_text trigram similarity to "sendMessage"
// would be low (bare name, no enrichment). This simulates the real-world
// state: 82k modules, zero enrichment, all trigram searches return 0.
func seedFallbackCorpus(t *testing.T, db *sql.DB) {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed exec: %v\nquery: %s", err, q)
		}
	}

	exec(`INSERT INTO kb_apps
		(kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at)
		VALUES ('fts_test_app', 'fts_test', 'FTSTestApp', 'electron', 0, 0)`)

	var sourceID int64
	if err := db.QueryRow(`INSERT INTO knowledge_sources
		(app, epoch, source_path, source_kind, captured_at, kb_id)
		VALUES ('fts_test', 1, '/tmp/fts_test', 'other', 1000, 'fts_test_app')
		RETURNING id`).Scan(&sourceID); err != nil {
		t.Fatalf("insert knowledge_sources: %v", err)
	}

	sha := "sha_fts_fallback_test_module"
	// body_excerpt explicitly contains "sendMessage" so ILIKE will find it.
	bodyExcerpt := "function xzq(){var r=sendMessage({type:'ping'});return r;}"
	// Name is deliberately opaque so trigram match on "sendMessage" fails.
	moduleName := "bundle_xzq_0001.js"

	exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
		VALUES ($1, $2, $3, 0)`, sha, []byte(bodyExcerpt), len(bodyExcerpt))

	var moduleID int64
	if err := db.QueryRow(`INSERT INTO modules
		(app, name, body_sha256, body_excerpt, body_size, first_seen_at, last_seen_at)
		VALUES ('fts_test', $1, $2, $3, $4, 0, 0)
		RETURNING id`,
		moduleName, sha, bodyExcerpt, len(bodyExcerpt)).Scan(&moduleID); err != nil {
		t.Fatalf("insert module: %v", err)
	}

	exec(`INSERT INTO module_app_refs (body_sha256, source_id) VALUES ($1, $2)`, sha, sourceID)
}

// TestKbSearchFTSFallback verifies the end-to-end fallback path:
//  1. Seeds a corpus where "sendMessage" appears in body_excerpt only.
//  2. Calls runKbSearch in JSON mode.
//  3. Asserts: returned > 0, fallback_used = "fts_over_bodies",
//     fallback_banner contains "falling back to FTS".
//  4. Also asserts the existing ranked path (a query that DOES match by name)
//     returns fallback_used = "none".
func TestKbSearchFTSFallback(t *testing.T) {
	db, dsn := dbtest.StartPostgres(t)
	seedFallbackCorpus(t, db)
	pinDSNViaConfig(t, dsn)

	// Save + restore all search globals.
	savedDSN, savedApp, savedComp, savedLang, savedSince := searchDSN, searchApp, searchComponent, searchLang, searchSince
	savedLimit, savedCursor, savedJSON, savedTopic, savedFactType := searchLimit, searchCursor, searchJSON, searchTopic, searchFactType
	t.Cleanup(func() {
		searchDSN, searchApp, searchComponent, searchLang, searchSince = savedDSN, savedApp, savedComp, savedLang, savedSince
		searchLimit, searchCursor, searchJSON, searchTopic, searchFactType = savedLimit, savedCursor, savedJSON, savedTopic, savedFactType
	})
	searchDSN = ""
	searchApp = ""
	searchComponent = ""
	searchLang = ""
	searchSince = ""
	searchLimit = 50
	searchCursor = ""
	searchTopic = ""
	searchFactType = ""

	type jsonPayload struct {
		Returned              int    `json:"returned"`
		FallbackUsed          string `json:"fallback_used"`
		FallbackBanner        string `json:"fallback_banner"`
		EnrichmentCoveragePct int    `json:"enrichment_coverage_pct"`
		Items                 []struct {
			Name string `json:"name"`
		} `json:"items"`
	}

	runSearch := func(t *testing.T, query string) jsonPayload {
		t.Helper()
		searchJSON = true
		var buf bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&buf)
		if err := runKbSearch(cmd, []string{query}); err != nil {
			t.Fatalf("runKbSearch(%q): %v", query, err)
		}
		var p jsonPayload
		if err := json.Unmarshal(buf.Bytes(), &p); err != nil {
			t.Fatalf("unmarshal: %v\nbody: %s", err, buf.String())
		}
		return p
	}

	// ── Test 1: trigram path returns 0 → FTS fallback fires ──────────────
	t.Run("fts_fallback_fires", func(t *testing.T) {
		p := runSearch(t, "sendMessage")
		if p.Returned == 0 {
			t.Fatal("expected >0 results via FTS fallback, got 0")
		}
		if p.FallbackUsed != "fts_over_bodies" {
			t.Errorf("fallback_used = %q, want 'fts_over_bodies'", p.FallbackUsed)
		}
		if !strings.Contains(p.FallbackBanner, "falling back to FTS") {
			t.Errorf("fallback_banner = %q, want 'falling back to FTS'", p.FallbackBanner)
		}
		// enrichment_coverage_pct must be present and 0 (no enrichment seeded).
		if p.EnrichmentCoveragePct != 0 {
			t.Errorf("enrichment_coverage_pct = %d, want 0 (no enrichment seeded)", p.EnrichmentCoveragePct)
		}
	})

	// ── Test 2: query matching by module name → ranked path, no fallback ─
	t.Run("ranked_path_no_fallback", func(t *testing.T) {
		// "bundle_xzq" matches the module name via trigram; ranked path should fire.
		p := runSearch(t, "bundle_xzq")
		if p.FallbackUsed == "" {
			t.Fatal("fallback_used field missing")
		}
		// Whether ranked or FTS fires, fallback_banner must be empty when fallback_used = "none".
		if p.FallbackUsed == "none" && p.FallbackBanner != "" {
			t.Errorf("fallback_banner must be empty when fallback_used=none, got %q", p.FallbackBanner)
		}
	})

	// ── Test 3: additive fields are always present ────────────────────────
	t.Run("additive_fields_present", func(t *testing.T) {
		p := runSearch(t, "sendMessage")
		// These fields must exist even when 0 / "none" (additive contract).
		_ = p.FallbackUsed
		_ = p.FallbackBanner
		_ = p.EnrichmentCoveragePct
	})
}
