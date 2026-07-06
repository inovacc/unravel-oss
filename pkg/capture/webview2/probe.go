/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// Probe issues the CDP target discovery against http://127.0.0.1:{Port}/json
// by REUSING the in-repo cdp.Client.DiscoverTargets — no hand-rolled HTTP.
// Binds/queries 127.0.0.1 only (T-83-03-01).
//
// Success: DiscoverTargets returns and, when URLContains is set, at least
// one page target's `url` contains it (T-83-03-04 spoofing gate). The first
// matching target's webSocketDebuggerUrl is returned in Attached.
//
// Not-ready (NOT a hard error in the orchestration sense): any transport
// error wraps ErrPortDown; an empty/no-match result wraps
// ErrNoMatchingTarget (which unwraps to ErrPortDown so the wait-for-port
// loop keeps retrying naturally).
//
// Always emits one webview2.probe slog event per call (stderr only).
func Probe(ctx context.Context, t Target) (Attached, error) {
	t = t.defaults()
	start := time.Now()
	base := fmt.Sprintf("http://127.0.0.1:%d", t.Port)

	// WR-04: cdp.New only allocates maps — it starts no goroutines, opens
	// no sockets, and holds no OS handles. DiscoverTargets issues a single
	// http.DefaultClient GET with a deferred resp.Body.Close(); no
	// WebSocket is dialed until Connect (which Probe never calls). So
	// constructing a fresh client per poll iteration with nil events/seq
	// and no Close() is verified leak-free for this code path.
	client := cdp.New(fmt.Sprintf("127.0.0.1:%d", t.Port), nil, nil)
	targets, err := client.DiscoverTargets(ctx)
	if err != nil {
		t.Logger.Debug("webview2.probe",
			"kind", t.Kind,
			"port", t.Port,
			"result", "down",
			"elapsed_ms", time.Since(start).Milliseconds(),
			"err", err.Error(),
		)
		return Attached{}, fmt.Errorf("%w: %v", ErrPortDown, err)
	}

	// Gate on URLContains. Empty URLContains => first target is fine
	// (port-up legacy behaviour); a set URLContains with no match is a
	// not-ready ErrNoMatchingTarget.
	var wsURL string
	matched := 0
	for _, tg := range targets {
		if t.URLContains == "" || strings.Contains(tg.URL, t.URLContains) {
			if wsURL == "" {
				wsURL = tg.WebSocketDebugURL
			}
			matched++
		}
	}

	if matched == 0 {
		t.Logger.Debug("webview2.probe",
			"kind", t.Kind,
			"port", t.Port,
			"result", "down",
			"elapsed_ms", time.Since(start).Milliseconds(),
			"targets", len(targets),
			"matched", 0,
			"url_contains", t.URLContains,
		)
		return Attached{}, fmt.Errorf("%w: 0 of %d targets match %q",
			ErrNoMatchingTarget, len(targets), t.URLContains)
	}

	t.Logger.Debug("webview2.probe",
		"kind", t.Kind,
		"port", t.Port,
		"result", "up",
		"elapsed_ms", time.Since(start).Milliseconds(),
		"targets", len(targets),
		"matched", matched,
	)
	return Attached{BaseURL: base, WebSocketDebugURL: wsURL, Spawned: false, PID: 0}, nil
}
