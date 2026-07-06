/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — live CDP JS/CSS source pull (P84 Task 1).
//
// PullSourcesOverCDP attaches to a live WebView2 page target over the existing
// pkg/capture/cdp client and recovers decoded JavaScript
// (Debugger.getScriptSource) and CSS (CSS.getStyleSheetText). It composes the
// existing CDP primitives exactly as scorecard/cdp_source.go does (DiscoverTargets
// → page filter → New → Connect → spawn Listen BEFORE SendAndWait → Close).
//
// Honest-empty: a reachable endpoint with zero scripts/sheets returns a non-nil
// empty *PulledSources and a nil error — never synthesized content. Non-fatal:
// per-item CDP errors are skipped, never propagated. Bounded: total source
// count, per-source bytes, combined JS bytes, and the overall context deadline
// are all hard-capped. Never panics, never blocks past timeout.
//
// D-09 (MCP-only AI invariant) preserved — no anthropic-sdk-go imports. Pure
// Go; no CGO.
package scorecard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// Bounds. Mirrors pkg/dissect.maxRecoveredJSConcatBytes (32MiB) without
// importing dissect.
const (
	maxPulledSources     = 1024
	maxPulledSourceSize  = 8 * 1024 * 1024
	maxPulledConcatBytes = 32 * 1024 * 1024
)

// ScriptSrc is one recovered JavaScript source.
type ScriptSrc struct {
	URL      string
	ScriptID string
	Source   string
}

// StyleSrc is one recovered CSS stylesheet source.
type StyleSrc struct {
	URL          string
	StyleSheetID string
	Source       string
}

// PulledSources is the typed result of a live CDP source pull. Both slices are
// non-nil (possibly empty) on a successful, honest-empty pull.
type PulledSources struct {
	JS  []ScriptSrc
	CSS []StyleSrc
}

// scriptRef / sheetRef capture the {id,url} announced via async CDP events.
type scriptRef struct{ id, url string }
type sheetRef struct{ id, url string }

// PullSourcesOverCDP discovers the first page-type CDP target on host:port,
// attaches, and recovers JS + CSS source. Bounded by timeout. Honest-empty and
// non-fatal per the package contract above.
func PullSourcesOverCDP(ctx context.Context, host string, port int, timeout time.Duration) (*PulledSources, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hostPort := host
	if port != 0 {
		hostPort = fmt.Sprintf("%s:%d", host, port)
	}

	// Discovery client — /json HTTP enumeration only; not WS-connected.
	discovery := cdp.New(hostPort, nil, func() int { return 0 })
	targets, err := discovery.DiscoverTargets(ctx)
	if err != nil {
		return nil, fmt.Errorf("cdp source pull: %w", err)
	}
	var page *cdp.Target
	for i := range targets {
		if targets[i].Type == "page" && targets[i].WebSocketDebugURL != "" {
			page = &targets[i]
			break
		}
	}
	if page == nil {
		// Reachable endpoint, no page target — honest-empty.
		return &PulledSources{JS: []ScriptSrc{}, CSS: []StyleSrc{}}, nil
	}

	events := make(chan capture.Event, 1)
	c := cdp.New(hostPort, events, func() int { return 0 })
	if err := c.Connect(ctx, page.WebSocketDebugURL); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("cdp source pull: %w", err)
	}
	defer func() { _ = c.Close() }()

	var (
		mu      sync.Mutex
		scripts []scriptRef
		sheets  []sheetRef
		lastAdd = time.Now()
	)

	c.OnEvent("Debugger.scriptParsed", func(p json.RawMessage) {
		var ev struct {
			ScriptID string `json:"scriptId"`
			URL      string `json:"url"`
		}
		if json.Unmarshal(p, &ev) != nil {
			return
		}
		mu.Lock()
		if len(scripts) < maxPulledSources {
			scripts = append(scripts, scriptRef{id: ev.ScriptID, url: ev.URL})
			lastAdd = time.Now()
		}
		mu.Unlock()
	})
	c.OnEvent("CSS.styleSheetAdded", func(p json.RawMessage) {
		var ev struct {
			Header struct {
				StyleSheetID string `json:"styleSheetId"`
				SourceURL    string `json:"sourceURL"`
			} `json:"header"`
		}
		if json.Unmarshal(p, &ev) != nil {
			return
		}
		mu.Lock()
		if len(sheets) < maxPulledSources {
			sheets = append(sheets, sheetRef{id: ev.Header.StyleSheetID, url: ev.Header.SourceURL})
			lastAdd = time.Now()
		}
		mu.Unlock()
	})

	// CRITICAL: spawn Listen BEFORE the first SendAndWait or it deadlocks —
	// SendAndWait blocks on the pending channel fed only by Listen's dispatch.
	go func() { _ = c.Listen(ctx) }()

	for _, m := range []string{"Debugger.enable", "Page.enable", "CSS.enable"} {
		if _, err := c.SendAndWait(ctx, m, nil); err != nil {
			// Non-fatal: a domain we cannot enable simply yields fewer sources.
			continue
		}
	}

	// Bounded settle: events arrive asynchronously via Listen. Wait until no
	// new ids for ~750ms, or ctx done, or a ~10s hard cap.
	const quiet = 750 * time.Millisecond
	const hardCap = 10 * time.Second
	settleDeadline := time.Now().Add(hardCap)
	for {
		mu.Lock()
		idle := time.Since(lastAdd)
		mu.Unlock()
		if idle >= quiet || time.Now().After(settleDeadline) {
			break
		}
		select {
		case <-ctx.Done():
			break
		case <-time.After(50 * time.Millisecond):
		}
		if ctx.Err() != nil {
			break
		}
	}

	mu.Lock()
	scriptsSnap := append([]scriptRef(nil), scripts...)
	sheetsSnap := append([]sheetRef(nil), sheets...)
	mu.Unlock()

	out := &PulledSources{JS: []ScriptSrc{}, CSS: []StyleSrc{}}
	var concat int

	for _, s := range scriptsSnap {
		if ctx.Err() != nil {
			break
		}
		if s.url == "" {
			continue
		}
		if strings.HasPrefix(s.url, "chrome-extension://") || strings.HasPrefix(s.url, "devtools://") {
			continue
		}
		raw, err := c.SendAndWait(ctx, "Debugger.getScriptSource", map[string]any{"scriptId": s.id})
		if err != nil {
			continue
		}
		var r struct {
			ScriptSource string `json:"scriptSource"`
		}
		if json.Unmarshal(raw, &r) != nil || r.ScriptSource == "" {
			continue
		}
		if len(r.ScriptSource) > maxPulledSourceSize {
			continue
		}
		if concat+len(r.ScriptSource) > maxPulledConcatBytes {
			break
		}
		concat += len(r.ScriptSource)
		out.JS = append(out.JS, ScriptSrc{URL: s.url, ScriptID: s.id, Source: r.ScriptSource})
	}

	for _, sh := range sheetsSnap {
		if ctx.Err() != nil {
			break
		}
		if sh.url == "" {
			continue
		}
		if strings.HasPrefix(sh.url, "chrome-extension://") || strings.HasPrefix(sh.url, "devtools://") {
			continue
		}
		raw, err := c.SendAndWait(ctx, "CSS.getStyleSheetText", map[string]any{"styleSheetId": sh.id})
		if err != nil {
			continue
		}
		var r struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(raw, &r) != nil || r.Text == "" {
			continue
		}
		if len(r.Text) > maxPulledSourceSize {
			continue
		}
		out.CSS = append(out.CSS, StyleSrc{URL: sh.url, StyleSheetID: sh.id, Source: r.Text})
	}

	return out, nil
}

// applyPulledToResult concatenates pulled JS (banner + source per entry,
// 32MiB-bounded) and feeds it + pulled CSS into the dissect result via the
// shared dissect apply helpers. Honest-empty when ps is nil/empty: the
// underlying dissect.ApplyPulledJS/ApplyPulledCSS helpers leave
// r.JSAnalysis / r.RecoveredCSS nil rather than synthesizing.
func applyPulledToResult(r *dissect.DissectResult, ps *PulledSources) {
	if r == nil || ps == nil {
		return
	}

	var sb strings.Builder
	for _, e := range ps.JS {
		// Stop before exceeding the 32MiB concat bound. banner length is
		// included in the projected size so the cap is never overshot.
		addition := len("// pulled-from: ") + len(e.URL) + 1 + len(e.Source) + 1
		if sb.Len()+addition > maxPulledConcatBytes {
			break
		}
		sb.WriteString("// pulled-from: ")
		sb.WriteString(e.URL)
		sb.WriteString("\n")
		sb.WriteString(e.Source)
		sb.WriteString("\n")
	}
	dissect.ApplyPulledJS(r, sb.String())

	entries := make([]dissect.CSSEntry, 0, len(ps.CSS))
	for _, e := range ps.CSS {
		entries = append(entries, dissect.CSSEntry{Path: e.URL, Source: e.Source})
	}
	dissect.ApplyPulledCSS(r, entries)
}
