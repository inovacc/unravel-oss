/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	"github.com/inovacc/unravel-oss/pkg/knowledge"

	"github.com/gorilla/websocket"
)

// orchTestServer fakes a CDP endpoint that always replies with canned answers
// for DOM.getDocument / Page.captureScreenshot / Runtime.evaluate /
// Runtime.addBinding / Page.addScriptToEvaluateOnNewDocument. Returns the
// client and a push channel for injecting events.
func orchTestServer(t *testing.T) (*cdp.Client, chan<- []byte, func()) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	push := make(chan []byte, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// 1×1 PNG, base64-encoded — well under 1024 bytes (triggers
		// content-protection warning per T-08-07 carry-forward).
		tinyPNG := base64.StdEncoding.EncodeToString([]byte{
			0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		})
		go func() {
			defer func() { _ = ws.Close() }()
			_ = ws.SetReadDeadline(time.Now().Add(20 * time.Second))
			for {
				var req struct {
					ID     int64           `json:"id"`
					Method string          `json:"method"`
					Params json.RawMessage `json:"params"`
				}
				if err := ws.ReadJSON(&req); err != nil {
					return
				}
				var result any = map[string]any{}
				switch req.Method {
				case "Page.captureScreenshot":
					result = map[string]any{"data": tinyPNG}
				case "DOM.getDocument":
					result = map[string]any{"root": map[string]any{
						"nodeId": 1, "nodeType": 9, "nodeName": "#document",
						"children": []map[string]any{{
							"nodeId": 2, "nodeType": 1, "nodeName": "HTML", "localName": "html",
						}},
					}}
				case "Runtime.evaluate":
					// Layout script returns []. Other evals (framework hooks) return null.
					result = map[string]any{"result": map[string]any{"value": json.RawMessage(`[]`)}}
				default:
					result = map[string]any{}
				}
				_ = ws.WriteJSON(map[string]any{"id": req.ID, "result": result})
			}
		}()
		go func() {
			for msg := range push {
				if err := ws.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			}
		}()
	}))
	u, _ := url.Parse(srv.URL)
	wsURL := "ws://" + u.Host + "/"
	client := cdp.New("", nil, nil)
	if err := client.Connect(context.Background(), wsURL); err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = client.Listen(ctx) }()
	cleanup := func() {
		cancel()
		close(push)
		_ = client.Close()
		srv.Close()
	}
	return client, push, cleanup
}

func TestPerStateCapture_Auto(t *testing.T) {
	client, _, cleanup := orchTestServer(t)
	defer cleanup()
	kb := t.TempDir()
	o, err := New(client, Options{
		Mode: ModeAuto, KBDir: kb, RunID: "run-1", Component: "auth",
		MaxStates: 1, ModalSettleMs: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Capture a single state directly (skip event-loop entry; the captureState
	// path is what matters for artifact verification).
	if err := o.captureState(context.Background(), StateEvent{Type: "route", Slug: "dashboard"}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	stateDir := filepath.Join(kb, "visual", "run-1", "auth", "dashboard")
	for _, f := range []string{"screenshot.png", "tree.json", "layout.json", "_meta.json"} {
		p := filepath.Join(stateDir, f)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing artifact %s: %v", f, err)
		}
	}
}

func TestComponentClassification(t *testing.T) {
	client, _, cleanup := orchTestServer(t)
	defer cleanup()
	kb := t.TempDir()
	// Empty Component → orchestrator falls through to components.Classify.
	o, err := New(client, Options{Mode: ModeAuto, KBDir: kb, RunID: "r", MaxStates: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := o.captureState(context.Background(), StateEvent{Type: "route", Slug: "login"}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	caps := o.Captures()
	if len(caps) != 1 {
		t.Fatalf("expected 1 capture, got %d", len(caps))
	}
	// "login" → unknown bucket without registered patterns; verify component
	// is at least populated and matches a valid bucket value (sanity test —
	// component classifier is Phase 7 territory).
	if caps[0].Component == "" {
		t.Errorf("component empty")
	}
}

func TestMetaJSON(t *testing.T) {
	client, _, cleanup := orchTestServer(t)
	defer cleanup()
	kb := t.TempDir()
	o, _ := New(client, Options{Mode: ModeAuto, KBDir: kb, RunID: "r", Component: "ui", MaxStates: 1})
	if err := o.captureState(context.Background(), StateEvent{Type: "route", Slug: "home"}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	metaPath := filepath.Join(kb, "visual", "r", "ui", "home", "_meta.json")
	b, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.RunID != "r" || m.Component != "ui" || m.StateSlug != "home" {
		t.Errorf("required fields wrong: %+v", m)
	}
	if m.CapturedAt == "" || m.Mode == "" {
		t.Errorf("captured_at/mode missing")
	}
	if m.Framework == "" {
		t.Errorf("framework should default to 'unknown'")
	}
	if !m.ContentProtectionWarned {
		t.Errorf("expected content_protection_warned=true (tiny png triggers heuristic)")
	}
}

func TestManifestCaptures(t *testing.T) {
	// Round-trip: build a Manifest with a synthetic Captures entry, marshal,
	// unmarshal — verify additive field round-trips and Files unaffected.
	cs := capture.CapturedState{
		RunID: "r", Component: "auth", StateSlug: "login",
		Viewport: capture.ViewportSpec{W: 1280, H: 720, Scale: 1.0},
	}
	m := &knowledge.Manifest{Version: 1, Captures: []capture.CapturedState{cs}}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back knowledge.Manifest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Version != 1 {
		t.Errorf("schema version drifted")
	}
	if len(back.Captures) != 1 || back.Captures[0].StateSlug != "login" {
		t.Errorf("captures round-trip failed: %+v", back.Captures)
	}
	// Legacy Manifest without Captures must round-trip cleanly.
	legacy := []byte(`{"version":1,"app_name":"x","sections":{},"summary":{"signed":false}}`)
	var legacyM knowledge.Manifest
	if err := json.Unmarshal(legacy, &legacyM); err != nil {
		t.Fatalf("legacy round-trip: %v", err)
	}
	if len(legacyM.Captures) != 0 {
		t.Errorf("legacy Captures should be empty")
	}
}

func TestMaxStatesCap(t *testing.T) {
	client, push, cleanup := orchTestServer(t)
	defer cleanup()
	kb := t.TempDir()
	var logBuf bytes.Buffer
	o, _ := New(client, Options{
		Mode: ModeAuto, KBDir: kb, RunID: "r", Component: "ui", MaxStates: 3, ModalSettleMs: 1,
	})
	o.opts.Logger = newBufLogger(&logBuf)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = o.runEventDriven(ctx); close(done) }()
	// Give the orchestrator a moment to capture the initial root + register
	// detectors.
	time.Sleep(200 * time.Millisecond)
	for i := range 5 {
		evt, _ := json.Marshal(map[string]any{
			"method": "Page.frameNavigated",
			"params": map[string]any{"frame": map[string]any{"url": "https://x/page" + string(rune('a'+i))}},
		})
		push <- evt
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
	}
	if !strings.Contains(logBuf.String(), "max-states reached") {
		t.Errorf("expected max-states log, got: %s", logBuf.String())
	}
}

func TestContentProtectionWarning(t *testing.T) {
	client, _, cleanup := orchTestServer(t)
	defer cleanup()
	kb := t.TempDir()
	var sink bytes.Buffer
	SetStderr(&sink)
	defer SetStderr(os.Stderr)
	o, _ := New(client, Options{
		Mode: ModeAuto, KBDir: kb, RunID: "r", Component: "ui", MaxStates: 1,
		ContentProtected: func() bool { return true },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = o.runEventDriven(ctx)
	if !strings.Contains(sink.String(), "content-protection enabled") {
		t.Errorf("expected stderr WARNING, got: %s", sink.String())
	}
}

func TestScriptedModeReplay(t *testing.T) {
	client, _, cleanup := orchTestServer(t)
	defer cleanup()
	kb := t.TempDir()
	scenario := filepath.Join(t.TempDir(), "scenario.json")
	body := `[
		{"action":"click","selector":"#login"},
		{"action":"wait","ms":10},
		{"action":"capture","slug":"after-login"}
	]`
	if err := os.WriteFile(scenario, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	o, _ := New(client, Options{
		Mode: ModeScripted, KBDir: kb, RunID: "r", Component: "auth",
		ScenarioPath: scenario, MaxStates: 5,
	})
	if err := o.runScripted(context.Background()); err != nil {
		t.Fatalf("scripted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(kb, "visual", "r", "auth", "after-login", "_meta.json")); err != nil {
		t.Errorf("expected captured state, got %v", err)
	}
}

func TestScriptedRejectsUnknownAction(t *testing.T) {
	body := []byte(`[{"action":"shell_exec","value":"rm -rf /"}]`)
	if _, err := parseScenario(body); err == nil {
		t.Fatal("expected rejection of unknown action")
	} else if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("err = %v", err)
	}
}

func TestSymlinkRejectOnExistingFile(t *testing.T) {
	// Plant a symlink at the screenshot.png target; verify
	// knowledge.WriteFileAtomic refuses to overwrite (T-08-02).
	kb := t.TempDir()
	stateDir := filepath.Join(kb, "visual", "r", "ui", "home")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(stateDir, "screenshot.png")
	link := filepath.Join(t.TempDir(), "elsewhere.bin")
	_ = os.WriteFile(link, []byte("attacker"), 0o644)
	if err := os.Symlink(link, target); err != nil {
		t.Skipf("cannot create symlink (likely insufficient privileges on this OS): %v", err)
	}
	if err := knowledge.WriteFileAtomic(target, []byte("data"), 0o644); err == nil {
		t.Errorf("expected symlink rejection")
	}
}

// newBufLogger returns a slog.Logger that writes to buf in text format.
func newBufLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
