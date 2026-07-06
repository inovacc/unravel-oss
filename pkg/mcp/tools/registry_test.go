/*
Copyright (c) 2026 Security Research

registry_test.go — single source of truth for the v2.5 MCP tool surface.

Phase 33 (kb-mcp-tools-and-grpc-bridge) bumps the count atomically from
129 → 133 by adding 5 kb_* tools and removing the legacy SQLite-FTS5
`unravel_kb_catalog_search` registration that collided with the new canonical
trigram-fuzzy `unravel_kb_catalog_search` in pkg/mcptools/kb.go (net +4 unique
names because of the collision). Any future surface change MUST update
this literal in the same atomic commit (D-33-TOOL-COUNT-ATOMIC).
*/
package mcptools_test

import (
	"testing"

	mcptools "github.com/inovacc/unravel-oss/pkg/mcp/tools"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestToolCountInvariant guards the registered tool surface. The count
// includes the 5 kb_* tools registered by RegisterKB even when the DB
// pool is nil — advertisement is decoupled from runtime DSN availability
// (D-33-DSN-FAIL-AT-CALL).
func TestToolCountInvariant(t *testing.T) {
	srv := mcptools.NewServer(mcptools.ServerConfig{
		OnServer: func(s *mcp.Server) {
			// Mirror cmd/mcp.go wiring: kb tools are registered
			// post-built-ins via OnServer with a (possibly nil) DB.
			mcptools.RegisterKB(s, nil)
			mcptools.RegisterKBImportExport(s)
		},
	})

	ctx := t.Context()

	// In-memory transports allow us to enumerate via ListTools without
	// stdio. Connect server + client over a paired transport.
	st, ct := mcp.NewInMemoryTransports()

	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer func() { _ = ss.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = cs.Close() }()

	res, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}

	const want = 173
	if got := len(res.Tools); got != want {
		t.Fatalf("MCP tool count: got %d, want %d (P46-03 lifted the surface to 136 "+
			"by adding unravel_app_inject (active code injection); P43-03 added "+
			"unravel_kb_transfer_export + unravel_kb_transfer_import; KBC-ENRICH-SESSION-MONITOR "+
			"added unravel_kb_enrich_status + unravel_kb_enrich_retry "+
			"(141). The 2026-05-23 unravel-enrich plugin pivot added "+
			"unravel_kb_enrich_pending + unravel_kb_enrich_write_enrichment (143). "+
			"Phase 20.1 (2026-05-23) added unravel_tpm_info + unravel_tpm_dump "+
			"(146). Phase 20.3 (2026-05-23) added unravel_registry_dump (147). "+
			"Phase 20.2 (2026-05-23) added unravel_dpapi_dump (148). "+
			"v2.14-prep (2026-05-24) added unravel_insights_record + "+
			"unravel_insights_start_goal + unravel_insights_complete_goal + "+
			"unravel_plugin_doctor (152). "+
			"KBC-ENRICH-MODEL-ESCALATION (2026-05-24) added "+
			"unravel_kb_enrich_human_review (153). "+
			"KBC Phase F (2026-05-24) added "+
			"unravel_kb_transfer_diff_apps (154). "+
			"Phase G drift detection (2026-05-27) added "+
			"unravel_kb_drift_check + unravel_kb_drift_baseline + "+
			"unravel_kb_drift_history (157). "+
			"KB cost accounting Phase 1 (2026-05-30) added "+
			"unravel_kb_enrich_cost_report (158). "+
			"Go release intelligence (2026-06-03) added "+
			"unravel_go_versions_list + unravel_go_release_info + "+
			"unravel_go_verify_artifact + unravel_go_cve_posture (162). "+
			"KB AI findings Phase A (2026-06-04) added "+
			"unravel_kb_findings_record + unravel_kb_findings_iteration + "+
			"unravel_kb_findings_list + unravel_kb_findings_resolve + "+
			"unravel_kb_findings_summary (167). "+
			"Transpile unification (2026-06-06) added unravel_transpile_detect + "+
			"unravel_transpile_run + unravel_transpile_coverage + "+
			"unravel_transpile_analyze + unravel_transpile_resource_list + "+
			"unravel_transpile_resource_get (173). "+
			"Adding/removing tools requires updating this invariant in the "+
			"same atomic commit per D-33-TOOL-COUNT-ATOMIC)", got, want)
	}

	// Spot-check the 5 new kb_* tools are present.
	wantKB := map[string]bool{
		"unravel_kb_catalog_apps":     false,
		"unravel_kb_catalog_timeline": false,
		"unravel_kb_transfer_diff":    false,
		"unravel_kb_catalog_search":   false,
		"unravel_kb_capture":          false,
	}
	for _, tool := range res.Tools {
		if _, ok := wantKB[tool.Name]; ok {
			wantKB[tool.Name] = true
		}
	}
	for name, found := range wantKB {
		if !found {
			t.Errorf("missing required kb_* tool: %s", name)
		}
	}
}
