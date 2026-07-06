package cdp

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestDiscoverTargetsBoundedOnWedgedEndpoint is the regression gate for
// .planning/debug/phase84-cdp-wait-hang-wa.md: a CDP /json endpoint that
// accepts the TCP socket but never sends an HTTP response must produce a
// bounded error, NOT an infinite hang. Before the fix this blocked
// forever (http.DefaultClient has no Timeout and the caller ctx had no
// deadline) — the exact idle/blocked-on-recv signature observed on
// WhatsApp Desktop after cache_check.
func TestDiscoverTargetsBoundedOnWedgedEndpoint(t *testing.T) {
	// A listener that accepts connections but never writes a response.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			// Hold the connection open, never respond.
			_ = conn
		}
	}()

	// Tight timeout so the test stays fast while still proving the bound.
	old := DiscoverTargetsTimeout
	DiscoverTargetsTimeout = 300 * time.Millisecond
	defer func() { DiscoverTargetsTimeout = old }()

	c := New(ln.Addr().String(), nil, func() int { return 0 })

	done := make(chan error, 1)
	go func() {
		// Pass an UNBOUNDED context on purpose — this mirrors the real
		// scorecard/cdp_source.go discovery call and is precisely the
		// scenario the original bug hung in.
		_, derr := c.DiscoverTargets(context.Background())
		done <- derr
	}()

	select {
	case derr := <-done:
		if derr == nil {
			t.Fatal("expected a bounded error from wedged endpoint, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DiscoverTargets did not return within bound — regression: unbounded CDP discovery wait")
	}
}
