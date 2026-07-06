/*
Copyright (c) 2026 Security Research

Phase 11-03 Task 2: end-to-end integration test for the frida enrichment
orchestrator. Wires an in-memory transport stub host whose CreateMessage
handler returns a canned EnrichResponse JSON, calls Orchestrator.Enrich
with mcpinternal.FridaClient(), and asserts the produced script contains
JSDoc derived from the canned per-hook summary.
*/
package enrich_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	mcpinternal "github.com/inovacc/unravel-oss/internal/mcp"
	"github.com/inovacc/unravel-oss/pkg/frida/enrich"
	pkgmcp "github.com/inovacc/unravel-oss/pkg/mcp"
)

const integrationSampleScript = `Java.perform(function () {
  var sslHook = Java.use("javax.net.ssl.SSLContext");
  Interceptor.attach(sslHook, {
    onEnter: function (args) {},
    onLeave: function (ret) {}
  });
});
`

// newStubHostFrida is a local copy of the stub-host helper from
// internal/mcp/sampling_test.go (kept duplicated per 11-03 plan).
func newStubHostFrida(t *testing.T, handler func(context.Context, *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error)) *gomcp.ServerSession {
	t.Helper()
	ctx := context.Background()
	ct, st := gomcp.NewInMemoryTransports()
	host := gomcp.NewClient(&gomcp.Implementation{Name: "test-host", Version: "0.0.0"}, &gomcp.ClientOptions{
		CreateMessageHandler: handler,
	})
	srv := gomcp.NewServer(&gomcp.Implementation{Name: "unravel-test", Version: "0.0.0"}, nil)
	// 11-01 SUMMARY diagnostic: server.Connect MUST run before host.Connect.
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := host.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("host connect: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Close()
	})
	return ss
}

func quietLoggerFrida() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestOrchestrator_AI_InMemoryHost proves: stub host -> sample() ->
// fridaAdapter.EnrichScript -> json.Unmarshal -> renderArtifacts. The hook
// summary string from the canned EnrichResponse must appear as JSDoc above
// the matching Interceptor.attach in the rewritten script.
func TestOrchestrator_AI_InMemoryHost(t *testing.T) {
	canned := enrich.EnrichResponse{
		HeaderSummary: "InMemoryHost-test: SSL pinning bypass surface",
		Hooks: []enrich.HookEnrichment{
			{
				ID:           "sslHook",
				Summary:      "InMemoryHost-test summary: hooks SSLContext.init for cert-pin defeat",
				WhyItMatters: "Demonstrates round-trip from stub host to JSDoc",
				WatchFor:     "Calls with non-null TrustManager arrays",
				Expected: enrich.Expected{
					Args:   []enrich.ExpectedArg{{Index: 0, Op: "present"}},
					Return: &enrich.ExpectedValue{Op: "present"},
				},
			},
		},
	}
	body, err := json.Marshal(canned)
	if err != nil {
		t.Fatalf("marshal canned: %v", err)
	}

	ss := newStubHostFrida(t, func(_ context.Context, _ *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error) {
		return &gomcp.CreateMessageResult{
			Content: &gomcp.TextContent{Text: string(body)},
			Model:   "test-model",
			Role:    "assistant",
		}, nil
	})
	pkgmcp.SetSession(ss, quietLoggerFrida())
	t.Cleanup(func() { pkgmcp.SetSession(nil, quietLoggerFrida()) })

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "ssl.frida.js")
	if err := os.WriteFile(scriptPath, []byte(integrationSampleScript), 0o644); err != nil {
		t.Fatalf("seed script: %v", err)
	}
	o := enrich.New()
	o.MCP = mcpinternal.FridaClient()
	o.CacheDir = filepath.Join(dir, "cache")

	res, err := o.Enrich(context.Background(), scriptPath, "")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if res.CacheHit {
		t.Errorf("first run must be cache miss")
	}
	scriptOut, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read enriched script: %v", err)
	}
	got := string(scriptOut)
	if !strings.Contains(got, "InMemoryHost-test summary") {
		t.Fatalf("JSDoc summary missing from rewritten script:\n%s", got)
	}
	if !strings.Contains(got, "Hook: sslHook") {
		t.Fatalf("per-hook JSDoc heading missing")
	}

	// Sibling criteria.json should also exist with the canned hook.
	critPath := strings.TrimSuffix(scriptPath, ".frida.js") + ".criteria.json"
	if _, err := os.Stat(critPath); err != nil {
		t.Fatalf("criteria.json missing: %v", err)
	}
}

// TestFrida_GracefulDegrade_NoSession exercises the D-06 path: with no
// session wired, FridaClient() returns NilMCPClient which errors on
// EnrichScript. Orchestrator.Enrich propagates the error -- the caller
// (cmd/frida.go or pkg/mcptools/frida_phase9.go) is responsible for the
// final "no enrichment" outcome. We assert the error path fires without
// panic and without the canned-host JSDoc leaking in.
func TestFrida_GracefulDegrade_NoSession(t *testing.T) {
	pkgmcp.SetSession(nil, quietLoggerFrida())

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "ssl.frida.js")
	if err := os.WriteFile(scriptPath, []byte(integrationSampleScript), 0o644); err != nil {
		t.Fatalf("seed script: %v", err)
	}
	o := enrich.New()
	o.MCP = mcpinternal.FridaClient()
	o.CacheDir = filepath.Join(dir, "cache")

	_, err := o.Enrich(context.Background(), scriptPath, "")
	if err == nil {
		t.Fatalf("expected error from NilMCPClient when no session is wired")
	}
	// Source script must still be the original (no host-canned content
	// could have been written because there was no host).
	body, _ := os.ReadFile(scriptPath)
	if strings.Contains(string(body), "InMemoryHost-test") {
		t.Fatalf("graceful-degrade leaked stub content into script")
	}
}
