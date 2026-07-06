//go:build integration

// Integration: shared helpers for the kb integration tests.

package cmd

import (
	"context"
	"database/sql"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcptools "github.com/inovacc/unravel-oss/pkg/mcp/tools"
)

// newKBTestClient spins up an in-memory MCP server with the kb tools wired
// against db and returns a connected client session. clientName labels the MCP
// client implementation. Shared by the kb summary/synth integration tests.
func newKBTestClient(t *testing.T, ctx context.Context, db *sql.DB, clientName string) *mcp.ClientSession {
	t.Helper()

	srv := mcptools.NewServer(mcptools.ServerConfig{
		OnServer: func(s *mcp.Server) { mcptools.RegisterKB(s, db) },
	})

	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	c := mcp.NewClient(&mcp.Implementation{Name: clientName, Version: "v0"}, nil)
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	return cs
}
