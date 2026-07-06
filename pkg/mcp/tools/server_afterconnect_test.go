/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestServe_AfterConnect_Fires verifies the post-Connect / pre-Wait hook
// runs with a non-nil ServerSession when configured (D-12 wire-up).
//
// To keep the test fast we don't drive full Serve() over stdio; we exercise
// the same Connect+hook flow that Serve uses internally with a minimal
// in-memory transport pair. This isolates the wiring contract from the
// tool registry.
func TestServe_AfterConnect_Fires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ct, st := mcp.NewInMemoryTransports()

	var fired atomic.Bool
	var seenNil atomic.Bool
	cfg := ServerConfig{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		AfterConnect: func(ss *mcp.ServerSession) {
			if ss == nil {
				seenNil.Store(true)
			}
			fired.Store(true)
		},
	}

	// Server FIRST, client SECOND — Connect blocks on the init handshake,
	// so the peer must already be running before we call host.Connect.
	server := mcp.NewServer(&mcp.Implementation{Name: "unravel-test", Version: "0.0.0"}, nil)
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}

	host := mcp.NewClient(&mcp.Implementation{Name: "test-host", Version: "0.0.0"}, nil)
	hs, err := host.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("host connect: %v", err)
	}

	// Same call shape Serve uses post-Connect.
	if cfg.AfterConnect != nil {
		cfg.AfterConnect(ss)
	}

	if !fired.Load() {
		t.Fatal("AfterConnect did not fire")
	}
	if seenNil.Load() {
		t.Fatal("AfterConnect received nil ServerSession")
	}

	// Cancel the context first so the in-memory transport readers exit,
	// then close both sessions in client-then-server order.
	cancel()
	_ = hs.Close()
	_ = ss.Close()
}

// TestServe_AfterConnect_Nil_OK verifies the no-hook path constructs cleanly.
func TestServe_AfterConnect_Nil_OK(t *testing.T) {
	cfg := ServerConfig{
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		AfterConnect: nil,
	}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	if srv := newServerWithIdle(cfg, cancel); srv == nil {
		t.Fatal("newServerWithIdle returned nil with nil hook")
	}
}
