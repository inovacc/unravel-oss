/*
Copyright (c) 2026 Security Research

kb_export_test.go — Wave 0 unit tests for unravel_kb_transfer_export
(P43-03 / KBIM-04).

These tests exercise the registration + DSN-fail-at-call path without
requiring a live Postgres. Schema validation + library logic are
covered by pkg/knowledge/kb/export/export_test.go (Plan 43-01).
*/
package mcptools

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestKbExport_ToolRegistered asserts unravel_kb_transfer_export appears in
// ListTools after RegisterKBImportExport runs (D-12 advertisement
// independent of runtime DSN availability).
func TestKbExport_ToolRegistered(t *testing.T) {
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
	for _, tool := range res.Tools {
		if tool.Name == "unravel_kb_transfer_export" {
			return
		}
	}
	t.Fatalf("unravel_kb_transfer_export not found among %d tools", len(res.Tools))
}

// TestKbExport_AcceptsRequiredKbID asserts the handler short-circuits
// with the canonical daemon-unavailable hint when no supervisor is
// reachable, and reports a clear error when kb_id is empty.
// withSingletonHooks forces the dial to always fail so this test is
// deterministic regardless of whether a live daemon is running.
func TestKbExport_AcceptsRequiredKbID(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)

	res, _, err := kbExportHandler(t.Context(), nil, kbExportInput{KbID: "test-app-windows-fakehash12"})
	if err != nil {
		t.Fatalf("handler returned go error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true when supervisor unavailable")
	}
	if len(res.Content) == 0 {
		t.Fatal("expected error content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	// v2.17 / B2: handler routes through the supervisor thin-client; with
	// no daemon running the error reports "daemon unavailable".
	if !strings.Contains(tc.Text, "daemon unavailable") {
		t.Fatalf("expected daemon-unavailable hint, got: %q", tc.Text)
	}
}
