//go:build integration

// Integration: serial — mutates package-level synth/search flag vars + config DSN.

package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

// seedSynthNamesModules seeds the minimal 4-way chain for TestSynthNamesIntegration.
//
//	kb_apps  (K, "App")
//	knowledge_sources  (K, app="teams", epoch=1) → sourceID
//	module_bodies + modules (3 rows, synthetic_name NULL)
//	module_app_refs for each module
func seedSynthNamesModules(t *testing.T, db *sql.DB) {
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
		VALUES ('K', 'teams', 'App', 'electron', 0, 0)`)

	// ── 2. knowledge_sources ──────────────────────────────────────────────
	var sourceID int64
	err := db.QueryRow(`INSERT INTO knowledge_sources
		(app, epoch, source_path, source_kind, captured_at, kb_id)
		VALUES ('teams', 1, '/tmp/test-synth', 'other', 0, 'K')
		RETURNING id`).Scan(&sourceID)
	if err != nil {
		t.Fatalf("insert knowledge_sources: %v", err)
	}

	// ── 3. module_bodies + modules ────────────────────────────────────────
	//
	// teams_module_1  — has AMD/define signal → should derive "TeamsChatService"
	// teams_module_2  — no signal → synthetic_name stays NULL
	// RealName        — semantic name, NOT a placeholder → excluded by placeholderNameSQL

	type mod struct {
		name string
		sha  string
		body string
	}
	mods := []mod{
		{"teams_module_1", "sha_synth_1", `__d("TeamsChatService",[],function{})`},
		{"teams_module_2", "sha_synth_2", `(function(){var a=1;return a})()`},
		{"RealName", "sha_synth_3", `class RealName{}`},
	}

	for _, m := range mods {
		exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
			VALUES ($1, $2, $3, 0)`, m.sha, []byte(m.body), len(m.body))

		exec(`INSERT INTO modules
			(app, name, body_size, body_excerpt, body_sha256)
			VALUES ('teams', $1, $2, $3, $4)`,
			m.name, len(m.body), m.body, m.sha)
	}

	// ── 4. module_app_refs ────────────────────────────────────────────────
	for _, m := range mods {
		exec(`INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
			VALUES ($1, 'teams', $2, 0)`, m.sha, sourceID)
	}
}

// newSynthCmd returns a minimal *cobra.Command whose OutOrStdout is buf.
func newSynthCmd(buf *bytes.Buffer) *cobra.Command {
	c := &cobra.Command{}
	c.SetOut(buf)
	return c
}

// saveSynthVars captures all package-level synth flag vars and returns a restore func.
func saveSynthVars() func() {
	savedDB := synthDB
	savedApp := synthApp
	savedLimit := synthLimit
	savedForce := synthForce
	savedDryRun := synthDryRun
	savedVerify := synthVerify
	return func() {
		synthDB = savedDB
		synthApp = savedApp
		synthLimit = savedLimit
		synthForce = savedForce
		synthDryRun = savedDryRun
		synthVerify = savedVerify
	}
}

// saveSearchVarsSynth captures all package-level search flag vars and returns a restore func.
func saveSearchVarsSynth() func() {
	savedSearchJSON := searchJSON
	savedSearchDSN := searchDSN
	savedSearchApp := searchApp
	savedSearchComponent := searchComponent
	savedSearchLang := searchLang
	savedSearchSince := searchSince
	savedSearchLimit := searchLimit
	savedSearchCursor := searchCursor
	return func() {
		searchJSON = savedSearchJSON
		searchDSN = savedSearchDSN
		searchApp = savedSearchApp
		searchComponent = savedSearchComponent
		searchLang = savedSearchLang
		searchSince = savedSearchSince
		searchLimit = savedSearchLimit
		searchCursor = savedSearchCursor
	}
}

// startKBClientForSynthTest spins up an in-memory MCP server with kb tools
// wired against db and returns a connected client session.
func startKBClientForSynthTest(t *testing.T, ctx context.Context, db *sql.DB) *mcp.ClientSession {
	t.Helper()
	return newKBTestClient(t, ctx, db, "test-synth")
}

// readSynthToolText extracts the first TextContent text from a tool result.
func readSynthToolText(t *testing.T, res *mcp.CallToolResult) string {
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

// assertSynthName reads the synthetic_name of a module by name from db.
func assertSynthName(t *testing.T, db *sql.DB, moduleName, wantSynth string) {
	t.Helper()
	var got sql.NullString
	if err := db.QueryRow(
		`SELECT synthetic_name FROM modules WHERE name = $1 AND app = 'teams'`,
		moduleName,
	).Scan(&got); err != nil {
		t.Fatalf("assertSynthName(%q): query: %v", moduleName, err)
	}
	actual := got.String
	if wantSynth == "" {
		if got.Valid && actual != "" {
			t.Errorf("assertSynthName(%q): want NULL/empty, got %q", moduleName, actual)
		}
	} else {
		if actual != wantSynth {
			t.Errorf("assertSynthName(%q): got %q, want %q", moduleName, actual, wantSynth)
		}
	}
}

func TestSynthNamesIntegration(t *testing.T) {
	// ── 1. Boot Postgres + apply migrations ───────────────────────────────
	db, dsn := dbtest.StartPostgres(t)
	pinDSNViaConfig(t, dsn)

	// ── 2. Seed the 4-way chain ───────────────────────────────────────────
	seedSynthNamesModules(t, db)

	// ── 3. Save + restore ALL mutated vars ───────────────────────────────
	t.Cleanup(saveSynthVars())
	t.Cleanup(saveSearchVarsSynth())

	// Common search defaults (unchanged throughout test).
	searchDSN = ""
	searchApp = ""
	searchComponent = ""
	searchLang = ""
	searchSince = ""
	searchLimit = 50
	searchCursor = ""

	// ── 4. Backfill run ───────────────────────────────────────────────────
	synthDB = "" // empty → uses config.yaml (pinned by pinDSNViaConfig)
	synthApp = "teams"
	synthLimit = 1000
	synthForce = false
	synthDryRun = false
	synthVerify = false

	var buf bytes.Buffer
	if err := runKBSynthNames(newSynthCmd(&buf), nil); err != nil {
		t.Fatalf("runKBSynthNames backfill: %v", err)
	}

	// ── 5. Assert SQL outcomes ────────────────────────────────────────────
	// teams_module_1: body has AMD __d("TeamsChatService",...) → derived "TeamsChatService"
	assertSynthName(t, db, "teams_module_1", "TeamsChatService")
	// teams_module_2: no signal → stays NULL/empty
	assertSynthName(t, db, "teams_module_2", "")
	// RealName: excluded by placeholderNameSQL (not teams_module_<N>) → stays NULL
	assertSynthName(t, db, "RealName", "")

	// ── 6. Idempotent second run ──────────────────────────────────────────
	// synthForce remains false → NULL-filter skips already-named module_1.
	buf.Reset()
	if err := runKBSynthNames(newSynthCmd(&buf), nil); err != nil {
		t.Fatalf("runKBSynthNames idempotent: %v", err)
	}
	// Value unchanged after second run.
	assertSynthName(t, db, "teams_module_1", "TeamsChatService")
	// The summary line should report named=0 (nothing new to name because
	// teams_module_1 was already filled and teams_module_2 has no signal).
	out2 := buf.String()
	if !strings.Contains(out2, "named=0") {
		t.Errorf("idempotent run: want 'named=0' in output (module_1 already filled, module_2 no signal); got: %s", out2)
	}

	// ── 7. Dry-run: new module must not be written ────────────────────────
	// Insert teams_module_3 with a derivable body.
	body3 := `class WidgetX{}`
	sha3 := "sha_synth_3b"
	if _, err := db.Exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
		VALUES ($1, $2, $3, 0)`, sha3, []byte(body3), len(body3)); err != nil {
		t.Fatalf("insert module_bodies for teams_module_3: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO modules (app, name, body_size, body_excerpt, body_sha256)
		VALUES ('teams', 'teams_module_3', $1, $2, $3)`,
		len(body3), body3, sha3); err != nil {
		t.Fatalf("insert teams_module_3: %v", err)
	}

	synthDryRun = true
	buf.Reset()
	if err := runKBSynthNames(newSynthCmd(&buf), nil); err != nil {
		// dry-run is allowed to return nil even with 0 named (no error when dryRun).
		// Only fail if an unexpected non-nil error is returned.
		t.Fatalf("runKBSynthNames dry-run: %v", err)
	}
	// teams_module_3 must NOT have been written.
	assertSynthName(t, db, "teams_module_3", "")
	// Output must mention dry-run.
	dryOut := buf.String()
	if !strings.Contains(dryOut, "dry-run") {
		t.Errorf("dry-run: want 'dry-run' in output; got: %s", dryOut)
	}
	synthDryRun = false

	// ── 8. --verify: filled passes; empty fails ───────────────────────────
	synthVerify = true
	buf.Reset()
	// After backfill, teams_module_1 is filled → verify should return nil.
	if err := runKBSynthNames(newSynthCmd(&buf), nil); err != nil {
		t.Errorf("--verify after backfill: want nil, got %v", err)
	}
	if !strings.Contains(buf.String(), "placeholders=") {
		t.Errorf("--verify output: want 'placeholders=' in output; got: %s", buf.String())
	}
	synthVerify = false

	// Now NULL-out all synthetic_names and re-verify → must return non-nil.
	if _, err := db.Exec(`UPDATE modules SET synthetic_name = NULL WHERE app = 'teams'`); err != nil {
		t.Fatalf("reset synthetic_name: %v", err)
	}
	if err := runSynthVerify(db, "teams", io.Discard); err == nil {
		t.Error("runSynthVerify: want non-nil error when placeholders>0 and filled==0")
	}

	// Restore by re-running backfill.
	synthForce = false
	synthDryRun = false
	synthVerify = false
	buf.Reset()
	if err := runKBSynthNames(newSynthCmd(&buf), nil); err != nil {
		t.Fatalf("re-backfill after verify test: %v", err)
	}
	assertSynthName(t, db, "teams_module_1", "TeamsChatService")

	// ── 9. Eligibility: teams_module_1 is returned by kbenrich.EligibleNameSQL ─────
	eligQ := `SELECT count(*) FROM modules m WHERE m.app = 'teams' AND (` + kbenrich.EligibleNameSQL + `)`
	var eligCount int
	if err := db.QueryRow(eligQ).Scan(&eligCount); err != nil {
		t.Fatalf("kbenrich.EligibleNameSQL count: %v", err)
	}
	if eligCount < 1 {
		t.Fatalf("kbenrich.EligibleNameSQL: want >=1 eligible modules, got %d", eligCount)
	}
	// Confirm teams_module_1 is specifically included.
	var m1Count int
	m1Q := `SELECT count(*) FROM modules m WHERE m.name = 'teams_module_1' AND m.app = 'teams' AND (` + kbenrich.EligibleNameSQL + `)`
	if err := db.QueryRow(m1Q).Scan(&m1Count); err != nil {
		t.Fatalf("kbenrich.EligibleNameSQL teams_module_1 check: %v", err)
	}
	if m1Count != 1 {
		t.Errorf("kbenrich.EligibleNameSQL: teams_module_1 must be included (synthetic_name set); got count=%d", m1Count)
	}

	// ── 10. Display: kb_search CLI + MCP show synthetic_name ──────────────
	{
		// ── 10a. CLI table ────────────────────────────────────────────────
		searchJSON = false
		var cliBuf bytes.Buffer
		cliCmd := &cobra.Command{}
		cliCmd.SetOut(&cliBuf)
		if err := runKbSearch(cliCmd, []string{"TeamsChatService"}); err != nil {
			t.Fatalf("runKbSearch table: %v", err)
		}
		cliOut := cliBuf.String()
		// MODULE column must show "TeamsChatService" (not the raw "teams_module_1").
		if !strings.Contains(cliOut, "TeamsChatService") {
			t.Errorf("CLI table: want 'TeamsChatService' in MODULE column; got:\n%s", cliOut)
		}

		// ── 10b. CLI JSON ─────────────────────────────────────────────────
		searchJSON = true
		var jsonBuf bytes.Buffer
		jsonCmd := &cobra.Command{}
		jsonCmd.SetOut(&jsonBuf)
		if err := runKbSearch(jsonCmd, []string{"TeamsChatService"}); err != nil {
			t.Fatalf("runKbSearch json: %v", err)
		}
		type cliItem struct {
			Name          string `json:"name"`
			SyntheticName string `json:"synthetic_name"`
		}
		var cliPayload struct {
			Items []cliItem `json:"items"`
		}
		if err := json.Unmarshal(jsonBuf.Bytes(), &cliPayload); err != nil {
			t.Fatalf("CLI JSON parse: %v\noutput: %s", err, jsonBuf.String())
		}
		var found *cliItem
		for i := range cliPayload.Items {
			if cliPayload.Items[i].Name == "teams_module_1" {
				found = &cliPayload.Items[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("CLI JSON: teams_module_1 not in items: %+v", cliPayload.Items)
		}
		if found.SyntheticName != "TeamsChatService" {
			t.Errorf("CLI JSON: synthetic_name=%q, want 'TeamsChatService'", found.SyntheticName)
		}
		searchJSON = false

		// ── 10c. MCP in-memory ────────────────────────────────────────────
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		cs := startKBClientForSynthTest(t, ctx, db)

		res, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "unravel_kb_catalog_search",
			Arguments: map[string]any{"query": "TeamsChatService"},
		})
		if err != nil {
			t.Fatalf("mcp call unravel_kb_catalog_search: %v", err)
		}
		if res.IsError {
			t.Fatalf("mcp tool returned error: %s", readSynthToolText(t, res))
		}

		text := readSynthToolText(t, res)

		var mcpPayload struct {
			Items []struct {
				Name          string `json:"name"`
				SyntheticName string `json:"synthetic_name"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(text), &mcpPayload); err != nil {
			t.Fatalf("mcp json parse: %v\ntext: %s", err, text)
		}

		var mcpItem *struct {
			Name          string `json:"name"`
			SyntheticName string `json:"synthetic_name"`
		}
		for i := range mcpPayload.Items {
			if mcpPayload.Items[i].Name == "teams_module_1" {
				mcpItem = &mcpPayload.Items[i]
				break
			}
		}
		if mcpItem == nil {
			t.Fatalf("mcp: teams_module_1 not in items: %+v", mcpPayload.Items)
		}
		if mcpItem.SyntheticName != "TeamsChatService" {
			t.Errorf("mcp: synthetic_name=%q, want 'TeamsChatService'", mcpItem.SyntheticName)
		}
	}
}
