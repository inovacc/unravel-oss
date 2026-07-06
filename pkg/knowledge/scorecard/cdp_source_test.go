/*
Copyright (c) 2026 Security Research
*/

package scorecard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/dissect"

	"github.com/gorilla/websocket"
)

// fakeCDPServer stands up an httptest.Server that:
//
//   - serves GET /json with one page-type target whose webSocketDebuggerUrl
//     points back at the same server's /devtools/page/p1 endpoint
//   - upgrades /devtools/page/p1 via gorilla/websocket
//   - acks the incoming Network.enable RPC
//   - emits `frames` Network.webSocketFrameSent notifications spaced 20ms
//     apart so the deterministic 1s capture window comfortably collects them
//
// Cross-platform; sub-second; no real Chromium dependency.
func fakeCDPServer(t *testing.T, frames int) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	var srv *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/devtools/page/p1", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()

		// Read the incoming RPC frames; on Network.enable, ack and start
		// emitting fake webSocketFrameSent events.
		var emitOnce atomic.Bool
		for {
			var msg map[string]any
			if err := c.ReadJSON(&msg); err != nil {
				return
			}
			id, _ := msg["id"].(float64)
			method, _ := msg["method"].(string)
			// Ack with empty result. Encoded as the same id so SendAndWait
			// demultiplex resolves.
			_ = c.WriteJSON(map[string]any{
				"id":     int64(id),
				"result": map[string]any{},
			})
			if method == "Network.enable" && emitOnce.CompareAndSwap(false, true) {
				go func() {
					for i := 0; i < frames; i++ {
						time.Sleep(20 * time.Millisecond)
						err := c.WriteJSON(map[string]any{
							"method": "Network.webSocketFrameSent",
							"params": map[string]any{
								"requestId": "r1",
								"timestamp": float64(i),
								"response": map[string]any{
									"opcode":      1,
									"payloadData": "hello",
								},
							},
						})
						if err != nil {
							return
						}
					}
				}()
			}
		}
	})

	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		wsURL := strings.Replace(srv.URL, "http://", "ws://", 1) + "/devtools/page/p1"
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"id":                   "p1",
				"type":                 "page",
				"title":                "fake",
				"url":                  "https://web.example/fake",
				"webSocketDebuggerUrl": wsURL,
			},
		})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func portFromURL(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port from %q: %v", raw, err)
	}
	return p
}

// TestProductionCDPSource_FakeServer_FivesFrames is the positive regression
// guard. Pre-P63 (with noopFrameSource production wiring) this would return
// 0; post-P63 with cdpFrameSource it returns >= 5.
func TestProductionCDPSource_FakeServer_FivesFrames(t *testing.T) {
	srv := fakeCDPServer(t, 5)
	host := strings.TrimPrefix(srv.URL, "http://")

	src := newCDPFrameSource(host)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	n, err := src.Capture(ctx, 9999, 800*time.Millisecond)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if n < 5 {
		t.Fatalf("frames captured = %d, want >= 5", n)
	}
}

// TestNoopFrameSource_ReturnsZeroAgainstFakeServer is the sentinel. It locks
// in the noop's regression-guard semantic: even pointed at a fully
// functional fake CDP server, noopFrameSource returns (0, nil). If this
// test starts FAILING after a refactor, the noop's contract has been
// silently changed — investigate before adjusting.
func TestNoopFrameSource_ReturnsZeroAgainstFakeServer(t *testing.T) {
	srv := fakeCDPServer(t, 5)
	port := portFromURL(t, srv.URL)

	n, err := noopFrameSource{}.Capture(context.Background(), port, 800*time.Millisecond)
	if err != nil {
		t.Fatalf("noop Capture err: %v", err)
	}
	if n != 0 {
		t.Fatalf("noop returned %d frames; want 0 (regression guard — noop must stay noop)", n)
	}
}

// TestIterationsJsonl_SchemaParity_AgainstGolden is the D-10 byte-shape
// guard. Runs a real iterate cycle through the new CDP path against the
// fake server (so frames > 0 and at least one iteration is recorded), reads
// the produced iterations.jsonl, and asserts the top-level keys of every
// record are an EXACT SUBSET of the golden's keys. Any new top-level field
// added without updating the golden fails this test.
func TestIterationsJsonl_SchemaParity_AgainstGolden(t *testing.T) {
	srv := fakeCDPServer(t, 5)
	host := strings.TrimPrefix(srv.URL, "http://")

	// Install a factory pointed at the fake server so iterate's CDP path
	// drains real frames. ResetFrameSourceFactoryToNoop restores afterward
	// so test ordering is stable.
	SetFrameSourceFactory(func(cfg ProductionFrameSourceConfig) frameSource {
		return newCDPFrameSource(host)
	})
	t.Cleanup(ResetFrameSourceFactoryToNoop)

	// Also bypass the framework gate + CDP probe in iterate.go by stubbing
	// the test seams to "runtime available". Without these the iterate loop
	// short-circuits via runtime_capture_unavailable=true and never reaches
	// the dispatch path.
	origElec, origWV2, origDial := detectElectron, detectWebView2, defaultDialer
	detectElectron = func(string) bool { return true }
	detectWebView2 = func(string) bool { return false }
	defaultDialer = func(ctx context.Context, port int) error { return nil }
	t.Cleanup(func() {
		detectElectron = origElec
		detectWebView2 = origWV2
		defaultDialer = origDial
	})

	tmp := t.TempDir()
	target := &DissectTarget{
		Result:        &dissect.DissectResult{},
		AppDir:        tmp,
		KBOutputDir:   tmp,
		CDPPort:       portFromURL(t, srv.URL),
		FrameworkHint: "electron",
	}

	rb := New()
	opts := IterateOptions{
		MaxIter:        1, // one iteration is enough to populate iterations.jsonl
		Threshold:      80,
		RequireAll12:   false,
		PerIterTimeout: 1500 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// We don't care about the score outcome — only that the JSONL record was
	// emitted with a stable top-level key shape.
	_, _, err := rb.Iterate(ctx, target, opts)
	if err != nil {
		t.Fatalf("Iterate: %v", err)
	}

	// Load golden.
	goldenPath := filepath.Join("testdata", "iterations_schema.golden.json")
	goldenBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var goldenObj map[string]any
	if err := json.Unmarshal(goldenBytes, &goldenObj); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	goldenKeys := make(map[string]struct{}, len(goldenObj))
	for k := range goldenObj {
		// "_schema_doc" is a documentation-only key in the golden file —
		// generated records will not have it; exclude from the key set.
		if k == "_schema_doc" {
			continue
		}
		goldenKeys[k] = struct{}{}
	}

	jsonlPath := filepath.Join(tmp, "iterations.jsonl")
	jsonlBytes, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("read iterations.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(jsonlBytes)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("no iterations.jsonl records emitted")
	}

	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parse iter line %d: %v", i, err)
		}
		for k := range rec {
			if _, ok := goldenKeys[k]; !ok {
				t.Errorf("iter line %d: top-level key %q not in golden — D-10 schema drift; update testdata/iterations_schema.golden.json deliberately", i, k)
			}
		}
	}

	// Sanity: confirm the golden has the documented 12 record-shape keys.
	if got := len(goldenKeys); got != 12 {
		t.Errorf("golden has %d keys; expected 12 — golden may have drifted", got)
	}

	_ = fmt.Sprintf // keep fmt imported for future expansion
}
