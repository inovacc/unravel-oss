/*
Copyright (c) 2026 Security Research

Test helpers for internal/mcp tests. These replicate the stub-host wiring
that used to live in sampling_test.go (now in pkg/mcp/sampling_test.go) so
that sampling_adapter_test.go can remain a white-box test of this package.
*/
package mcp

import (
	"context"
	"io"
	"log/slog"
	"testing"

	pkgmcp "github.com/inovacc/unravel-oss/pkg/mcp"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// newStubHost wires an in-memory transport pair, attaches a CreateMessageHandler
// on the host (client) side, and returns the *ServerSession bound to that host.
func newStubHost(t *testing.T, handler func(context.Context, *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error)) *gomcp.ServerSession {
	t.Helper()
	ctx := context.Background()
	ct, st := gomcp.NewInMemoryTransports()

	host := gomcp.NewClient(&gomcp.Implementation{Name: "test-host", Version: "0.0.0"}, &gomcp.ClientOptions{
		CreateMessageHandler: handler,
	})
	srv := gomcp.NewServer(&gomcp.Implementation{Name: "unravel-test", Version: "0.0.0"}, nil)

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

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// SetSession forwards to pkgmcp.SetSession so tests can use the same call
// pattern as before without importing pkgmcp directly.
func SetSession(ss *gomcp.ServerSession, log *slog.Logger) {
	pkgmcp.SetSession(ss, log)
}

// resetSession clears the package singleton; defer this in every test that
// calls SetSession(non-nil) so other tests start clean.
func resetSession(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { pkgmcp.SetSession(nil, quietLogger()) })
}
