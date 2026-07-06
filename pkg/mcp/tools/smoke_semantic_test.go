/*
Copyright (c) 2026 Security Research

smoke_semantic_test.go — locks the RESULT SHAPE of the tools that
return either a real result or a structured IsError on empty arguments.
Complements smoke_all_test.go (which only proves protocol round-trip) by
asserting that the response envelope's keys + types don't silently drift.

Tools covered:

	ok=3 (no supervisor/DB needed)
	  unravel_android_tools_status                 (lists detected RE-tools)
	  unravel_extension_gather              (enumerates installed extensions)
	  unravel_extension_list                (lists known extensions)

	isError=7 (supervisor-routed; clean IsError with no daemon/DB)
	  unravel_app_scan                       (required path missing -> IsError)
	  unravel_kb_catalog_apps                (needs daemon; IsError on no DB)
	  unravel_kb_ops_doctor                  (needs daemon; IsError on no DB)
	  unravel_kb_catalog_facts               (needs daemon; IsError on no DB)
	  unravel_kb_gaps_list                   (needs daemon; IsError on no DB)
	  unravel_kb_enrich_pending              (needs daemon; IsError on no DB)
	  unravel_kb_catalog_stats               (needs daemon; IsError on no DB)
	  unravel_kb_enrich_status               (needs daemon; IsError on no DB)

The supervisor-routed kb_ / knowledge_ tools are isolated from any real
daemon via isolateNoDaemon(t), so each deterministically exercises its
no-DB contract: a clean IsError, never a panic. Tests run under -short
and complete in well under 5s combined.
*/
package mcptools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// isolateNoDaemon makes a semantic smoke test genuinely DB-free and
// independent of run order. The kb_* / knowledge_* tools route through the
// supervisor thin-client singleton (a package-global). Without this, a test's
// no-DB outcome depends on whether some earlier test happened to poison the
// singleton with a cached "supervisor unavailable" — and the first un-poisoned
// caller blocks for the full ~15s production cold-start budget before falling
// back. Forcing the dial to always fail (dialAlwaysFails) under the shrunk
// withFastDialTiming budget makes the no-daemon state deterministic and prompt,
// so each test truly exercises its no-DB contract on its own.
func isolateNoDaemon(t *testing.T) {
	t.Helper()
	withFastDialTiming(t)
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)
}

// setupSmokeClient returns a connected client over an in-memory transport.
// Mirrors the wiring in TestSmokeAllTools.
func setupSmokeClient(t *testing.T) (context.Context, *mcp.ClientSession) {
	t.Helper()
	srv := NewServer(ServerConfig{
		OnServer: func(s *mcp.Server) {
			RegisterKB(s, nil)
			RegisterKBImportExport(s)
		},
	})
	ctx := t.Context()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "smoke-semantic", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return ctx, cs
}

// callOK calls a tool expecting a real (non-error) result; returns the
// first text-content payload parsed as a generic JSON value (object or
// array — both are MCP-valid shapes).
func callOK(t *testing.T, ctx context.Context, cs *mcp.ClientSession, name string, args map[string]any) any {
	t.Helper()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: CallTool: %v", name, err)
	}
	if res == nil {
		t.Fatalf("%s: nil result", name)
	}
	if res.IsError {
		var msg string
		if len(res.Content) > 0 {
			if tc, ok := res.Content[0].(*mcp.TextContent); ok {
				msg = tc.Text
			}
		}
		t.Fatalf("%s: IsError=true (drift?), text=%q", name, msg)
	}
	if len(res.Content) == 0 {
		t.Fatalf("%s: empty Content", name)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s: first content not *TextContent, got %T", name, res.Content[0])
	}
	var out any
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("%s: unmarshal text content: %v\n%s", name, err, tc.Text)
	}
	return out
}

// callOKObject is callOK + asserts the response is a JSON object.
func callOKObject(t *testing.T, ctx context.Context, cs *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	got := callOK(t, ctx, cs, name, args)
	obj, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("%s: expected object shape, got %T", name, got)
	}
	return obj
}

// callOKArray is callOK + asserts the response is a JSON array.
func callOKArray(t *testing.T, ctx context.Context, cs *mcp.ClientSession, name string, args map[string]any) []any {
	t.Helper()
	got := callOK(t, ctx, cs, name, args)
	arr, ok := got.([]any)
	if !ok {
		t.Fatalf("%s: expected array shape, got %T", name, got)
	}
	return arr
}

// callIsError calls a tool expecting IsError=true; returns the error text.
func callIsError(t *testing.T, ctx context.Context, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: unexpected JSON-RPC error: %v", name, err)
	}
	if res == nil {
		t.Fatalf("%s: nil result", name)
	}
	if !res.IsError {
		t.Fatalf("%s: expected IsError=true (drift?)", name)
	}
	if len(res.Content) == 0 {
		return ""
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return ""
	}
	return tc.Text
}

// ───────────────────────── ok (no daemon/DB needed) ─────────────────────────

func TestSemantic_AndroidTools(t *testing.T) {
	ctx, cs := setupSmokeClient(t)
	got := callOKObject(t, ctx, cs, "unravel_android_tools_status", map[string]any{})
	if len(got) == 0 {
		t.Errorf("unravel_android_tools_status: empty response object")
	}
}

func TestSemantic_ExtensionGather(t *testing.T) {
	ctx, cs := setupSmokeClient(t)
	_ = callOKArray(t, ctx, cs, "unravel_extension_gather", map[string]any{})
}

func TestSemantic_ExtensionList(t *testing.T) {
	ctx, cs := setupSmokeClient(t)
	_ = callOKArray(t, ctx, cs, "unravel_extension_list", map[string]any{})
}

// The kb_* / knowledge_* tools below route through the supervisor
// thin-client. With no reachable daemon (hence no Postgres pool) the
// honest contract is a clean IsError ("daemon unavailable"), never a
// silent empty success or a panic. isolateNoDaemon(t) forces that
// no-daemon state deterministically (no autospawn, fast dial budget),
// mirroring TestSemantic_KBApps_RequiresDB.

func TestSemantic_KBDoctor_RequiresDB(t *testing.T) {
	isolateNoDaemon(t)
	ctx, cs := setupSmokeClient(t)
	msg := callIsError(t, ctx, cs, "unravel_kb_ops_doctor", map[string]any{})
	if msg == "" {
		t.Error("unravel_kb_ops_doctor: empty error message on no daemon")
	}
}

func TestSemantic_KBFacts_RequiresDB(t *testing.T) {
	isolateNoDaemon(t)
	ctx, cs := setupSmokeClient(t)
	msg := callIsError(t, ctx, cs, "unravel_kb_catalog_facts", map[string]any{})
	if msg == "" {
		t.Error("unravel_kb_catalog_facts: empty error message on no daemon")
	}
}

func TestSemantic_KBGaps_RequiresDB(t *testing.T) {
	isolateNoDaemon(t)
	ctx, cs := setupSmokeClient(t)
	msg := callIsError(t, ctx, cs, "unravel_kb_gaps_list", map[string]any{})
	if msg == "" {
		t.Error("unravel_kb_gaps_list: empty error message on no daemon")
	}
}

func TestSemantic_KBPendingEnrich_RequiresDB(t *testing.T) {
	isolateNoDaemon(t)
	ctx, cs := setupSmokeClient(t)
	msg := callIsError(t, ctx, cs, "unravel_kb_enrich_pending", map[string]any{})
	if msg == "" {
		t.Error("unravel_kb_enrich_pending: empty error message on no daemon")
	}
}

func TestSemantic_KBStats_RequiresDB(t *testing.T) {
	isolateNoDaemon(t)
	ctx, cs := setupSmokeClient(t)
	msg := callIsError(t, ctx, cs, "unravel_kb_catalog_stats", map[string]any{})
	if msg == "" {
		t.Error("unravel_kb_catalog_stats: empty error message on no daemon")
	}
}

func TestSemantic_KnowledgeEnrichStatus_RequiresDB(t *testing.T) {
	isolateNoDaemon(t)
	ctx, cs := setupSmokeClient(t)
	msg := callIsError(t, ctx, cs, "unravel_kb_enrich_status", map[string]any{})
	if msg == "" {
		t.Error("unravel_kb_enrich_status: empty error message on no daemon")
	}
}

// ───────────────────────── isError (supervisor-routed) ─────────────────────────

func TestSemantic_Analyze_RequiresPath(t *testing.T) {
	ctx, cs := setupSmokeClient(t)
	msg := callIsError(t, ctx, cs, "unravel_app_scan", map[string]any{})
	if msg == "" {
		t.Error("unravel_app_scan: empty error message on missing path")
	}
}

func TestSemantic_KBApps_RequiresDB(t *testing.T) {
	// Genuinely exercise the no-DB branch: with no reachable daemon (hence
	// no Postgres pool), kbAppsHandler must surface a clean IsError, not a
	// silent empty success.
	isolateNoDaemon(t)
	ctx, cs := setupSmokeClient(t)
	msg := callIsError(t, ctx, cs, "unravel_kb_catalog_apps", map[string]any{})
	if msg == "" {
		t.Error("unravel_kb_catalog_apps: empty error message on nil DB")
	}
}

// TestSemantic_KnowledgeEnrich_Deprecated was removed 2026-05-24.
// The legacy sampling-based enrich deprecation-redirect stub it asserted
// against has been fully removed by the v2.13 plugin pivot — the tool
// no longer registers at all. TestToolCountInvariant above already
// guards absence; a separate test for the now-unregistered tool
// served no purpose and produced a "unknown tool" failure.
