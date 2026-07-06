/*
Copyright (c) 2026 Security Research

kb_import_test.go — Wave 0 unit tests for unravel_kb_transfer_import
(P43-03 / KBIM-04).

These tests exercise the registration + DSN-fail-at-call path without
requiring a live Postgres. Schema/checksum/path-traversal validation +
library logic are covered by pkg/knowledge/kb/import_/import_test.go
(Plan 43-02).
*/
package mcptools

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestKbImport_ToolRegistered asserts unravel_kb_transfer_import appears in
// ListTools after RegisterKBImportExport runs (D-12 advertisement
// independent of runtime DSN availability).
func TestKbImport_ToolRegistered(t *testing.T) {
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
		if tool.Name == "unravel_kb_transfer_import" {
			return
		}
	}
	t.Fatalf("unravel_kb_transfer_import not found among %d tools", len(res.Tools))
}

// TestKbImport_AcceptsRequiredBundlePath asserts the handler
// short-circuits with the daemon-unavailable hint when no supervisor is
// reachable, even when a valid absolute bundle_path is supplied.
// withSingletonHooks forces the dial to always fail so this test is
// deterministic regardless of whether a live daemon is running.
func TestKbImport_AcceptsRequiredBundlePath(t *testing.T) {
	withSingletonHooks(t, dialAlwaysFails, spawnNoop)

	// Path validation runs first; supply an absolute path (cross-platform
	// via t.TempDir) so we reach the supervisor dial and observe the
	// "daemon unavailable" mapping.
	bundle := filepath.Join(t.TempDir(), "example.kbb.tar.gz")
	res, _, err := kbImportHandler(t.Context(), nil, kbImportInput{BundlePath: bundle})
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
	if !strings.Contains(tc.Text, "daemon unavailable") {
		t.Fatalf("expected daemon-unavailable hint, got: %q", tc.Text)
	}
}
