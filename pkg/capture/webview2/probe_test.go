/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// portOf extracts the numeric port from an httptest server URL (mirrors
// spectra probe_test.go portOf).
func portOf(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	_, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}
	return port
}

// TestProbe scaffolds the spectra probe_test httptest /json server shape.
// 83-03 owns the real Probe(ctx, Target) implementation + un-skip; this
// stands up the canonical /json body (webSocketDebuggerUrl + url) the real
// probe will parse.
func TestProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"url":"https://teams.microsoft.com/v2/x",` +
			`"webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/ABC"}]`))
	}))
	defer srv.Close()
	port := portOf(t, srv)

	t.Run("url_contains_gate_hit", func(t *testing.T) {
		att, err := Probe(context.Background(), Target{
			Port:        port,
			URLContains: "teams.microsoft.com/v2/",
		})
		if err != nil {
			t.Fatalf("Probe: %v", err)
		}
		if att.WebSocketDebugURL != "ws://127.0.0.1:9222/devtools/page/ABC" {
			t.Fatalf("unexpected ws url: %q", att.WebSocketDebugURL)
		}
		if att.Spawned {
			t.Fatalf("Probe must return Spawned=false")
		}
	})

	t.Run("url_contains_gate_miss_is_not_ready", func(t *testing.T) {
		_, err := Probe(context.Background(), Target{
			Port:        port,
			URLContains: "web.whatsapp.com", // no match in served body
		})
		if !errors.Is(err, ErrNoMatchingTarget) {
			t.Fatalf("expected ErrNoMatchingTarget, got %v", err)
		}
		// Must unwrap to ErrPortDown so the wait loop keeps retrying.
		if !errors.Is(err, ErrPortDown) {
			t.Fatalf("ErrNoMatchingTarget must unwrap to ErrPortDown, got %v", err)
		}
	})

	t.Run("port_down_wraps_ErrPortDown", func(t *testing.T) {
		_, err := Probe(context.Background(), Target{Port: 1})
		if !errors.Is(err, ErrPortDown) {
			t.Fatalf("expected ErrPortDown on closed port, got %v", err)
		}
	})
}
