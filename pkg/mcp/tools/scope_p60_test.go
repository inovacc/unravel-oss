/*
Copyright (c) 2026 Security Research
*/

package mcptools

import (
	"path/filepath"
	"strings"
	"testing"
)

// p60BaselineMCPFileCount is the non-test source file count under
// pkg/mcp/tools/ at the start of P60 (60-00 Wave-0 capture). P60 ships
// ZERO new MCP tools per Q6/D-Q6 — heatmap is a CLI subcommand, not an
// MCP tool. If a future phase legitimately adds an MCP tool, that phase
// updates this constant.
const p60BaselineMCPFileCount = 73 // phase-84 added kb_resolve.go; +1 knowledge_enrich.go; +1 capture_webview2_attach.go (unravel_capture_webview2_attach MCP tool); +2 knowledge_enrich_status.go + knowledge_enrich_retry.go (KBC-ENRICH-SESSION-MONITOR); +1 kb_pending_enrich.go (unravel-enrich plugin pivot 2026-05-23); +3 kb_drift_check.go + kb_drift_baseline.go + kb_drift_history.go (Phase G drift detection 2026-05-27); +1 client_singleton.go (v2.17 thin-client refactor B0); +1 kb_cost_report.go (KB cost accounting Phase 1 2026-05-30); +1 goversions.go (go release intelligence MCP tools, 2026-06-03); +1 findings.go (KB AI findings Phase A 2026-06-04); +1 transpile.go (transpile unification native MCP tools, 2026-06-06); +1 dotnet_info.go (INT-8 pure-Go M0 dotnet_info reader; serves the EXISTING unravel_dotnet_info tool, no new registration, tool-count stays 173)

// TestP60ScopeGuard fails if any source file has been added under
// pkg/mcp/tools/ as a side-effect of P60. Pairs with TestToolCountInvariant
// (which guards the runtime registry count at 136).
func TestP60ScopeGuard(t *testing.T) {
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	nonTest := 0
	for _, m := range matches {
		if !strings.HasSuffix(m, "_test.go") {
			nonTest++
		}
	}
	if nonTest != p60BaselineMCPFileCount {
		t.Fatalf("pkg/mcp/tools/ non-test file count drift: got %d, expected %d (P60 ships zero MCP tools per D-Q6; if a future phase adds one, update p60BaselineMCPFileCount)",
			nonTest, p60BaselineMCPFileCount)
	}
}
