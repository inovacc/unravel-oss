package replay

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

func TestProxyServesRecordedResponse(t *testing.T) {
	reqEvt, _ := capture.NewEvent(1, time.Now(), capture.EventNetworkRequest, capture.SourceCDP,
		capture.NetworkRequestData{Method: "GET", URL: "https://api.example.com/data"})
	respEvt, _ := capture.NewEvent(2, time.Now(), capture.EventNetworkResponse, capture.SourceCDP,
		capture.NetworkResponseData{Status: 200, URL: "https://api.example.com/data",
			Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"ok":true}`})

	session := &capture.CaptureSession{
		Version: "1.0",
		App:     capture.AppInfo{Name: "Test"},
		Events:  []capture.Event{reqEvt, respEvt},
	}

	proxy := NewProxy(session)
	addr, err := proxy.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Stop() }()

	resp, err := http.Get("http://" + addr + "/data")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q", string(body))
	}
}

func TestProxyReturns404ForUnknownPath(t *testing.T) {
	session := &capture.CaptureSession{Version: "1.0", App: capture.AppInfo{Name: "Test"}}
	proxy := NewProxy(session)
	addr, err := proxy.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Stop() }()

	resp, err := http.Get("http://" + addr + "/unknown")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}

	var errBody map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&errBody)
	if errBody["error"] != "no recorded response" {
		t.Errorf("error = %v", errBody["error"])
	}
}

func TestGeneratePreload(t *testing.T) {
	now := time.Now()
	evt, _ := capture.NewEvent(1, now.Add(time.Second), capture.EventIPCMessage, capture.SourceCDP,
		capture.IPCMessageData{Channel: "get-settings", Args: []any{}, Direction: "renderer_to_main"})

	session := &capture.CaptureSession{
		Version: "1.0",
		App:     capture.AppInfo{Name: "Test"},
		Capture: capture.CaptureMetadata{StartedAt: now},
		Events:  []capture.Event{evt},
	}

	preload := GeneratePreload(session)
	if preload == "" {
		t.Error("empty preload")
	}
	if !strings.Contains(preload, "get-settings") {
		t.Error("preload missing IPC channel")
	}
}

func TestFindStartURL(t *testing.T) {
	navEvt, _ := capture.NewEvent(1, time.Now(), capture.EventWindowState, capture.SourceCDP,
		capture.WindowStateData{Property: "navigation", Value: "https://app.example.com"})

	session := &capture.CaptureSession{Version: "1.0", Events: []capture.Event{navEvt}}
	if u := findStartURL(session); u != "https://app.example.com" {
		t.Errorf("url = %q", u)
	}

	empty := &capture.CaptureSession{Version: "1.0"}
	if u := findStartURL(empty); u != "about:blank" {
		t.Errorf("url = %q", u)
	}
}

func TestFindStartURL_FallbackToNetworkRequest(t *testing.T) {
	reqEvt, _ := capture.NewEvent(1, time.Now(), capture.EventNetworkRequest, capture.SourceCDP,
		capture.NetworkRequestData{Method: "GET", URL: "https://cdn.example.com/index.html"})

	session := &capture.CaptureSession{Version: "1.0", Events: []capture.Event{reqEvt}}
	if u := findStartURL(session); u != "https://cdn.example.com/index.html" {
		t.Errorf("url = %q, want https://cdn.example.com/index.html", u)
	}
}

func TestLevenshteinClose(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"GET /api/v1/users", "/api/v1/users", true},
		{"GET /api/v1/users", "/completely/different", false},
		{"GET /a/b/c/d", "/a/b/c/d", true},
		{"GET /x", "/y", false},
	}
	for _, tt := range tests {
		if got := levenshteinClose(tt.a, tt.b); got != tt.want {
			t.Errorf("levenshteinClose(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestClosestMatches_WithSuggestions(t *testing.T) {
	reqEvt1, _ := capture.NewEvent(1, time.Now(), capture.EventNetworkRequest, capture.SourceCDP,
		capture.NetworkRequestData{Method: "GET", URL: "https://api.example.com/api/v1/users"})
	respEvt1, _ := capture.NewEvent(2, time.Now(), capture.EventNetworkResponse, capture.SourceCDP,
		capture.NetworkResponseData{Status: 200, URL: "https://api.example.com/api/v1/users", Body: "ok"})
	reqEvt2, _ := capture.NewEvent(3, time.Now(), capture.EventNetworkRequest, capture.SourceCDP,
		capture.NetworkRequestData{Method: "GET", URL: "https://api.example.com/api/v1/settings"})
	respEvt2, _ := capture.NewEvent(4, time.Now(), capture.EventNetworkResponse, capture.SourceCDP,
		capture.NetworkResponseData{Status: 200, URL: "https://api.example.com/api/v1/settings", Body: "ok"})

	session := &capture.CaptureSession{
		Version: "1.0",
		Events:  []capture.Event{reqEvt1, respEvt1, reqEvt2, respEvt2},
	}

	proxy := NewProxy(session)

	// Should find partial match
	matches := proxy.closestMatches("/api/v1/users", 5)
	if len(matches) == 0 {
		t.Error("expected suggestions")
	}

	// Should return first N urls when no match
	matches = proxy.closestMatches("/zzz/no/match/at/all", 5)
	if len(matches) == 0 {
		t.Error("expected fallback suggestions")
	}
}

func TestProxyAddr_BeforeStart(t *testing.T) {
	session := &capture.CaptureSession{Version: "1.0"}
	proxy := NewProxy(session)
	if addr := proxy.Addr(); addr != "" {
		t.Errorf("addr before start = %q, want empty", addr)
	}
}

func TestProxyStop_NilServer(t *testing.T) {
	session := &capture.CaptureSession{Version: "1.0"}
	proxy := NewProxy(session)
	if err := proxy.Stop(); err != nil {
		t.Errorf("stop nil server: %v", err)
	}
}

func TestNewShell(t *testing.T) {
	session := &capture.CaptureSession{
		Version: "1.0",
		App:     capture.AppInfo{Name: "TestApp"},
	}
	shell := NewShell(session)
	if shell == nil {
		t.Fatal("NewShell returned nil")
	}
	if shell.session != session {
		t.Error("session not stored")
	}
	if shell.proxy == nil {
		t.Error("proxy not created")
	}
}

func TestShellProxyAddr_BeforeStart(t *testing.T) {
	session := &capture.CaptureSession{Version: "1.0", App: capture.AppInfo{Name: "Test"}}
	shell := NewShell(session)
	if addr := shell.ProxyAddr(); addr != "" {
		t.Errorf("proxy addr before start = %q, want empty", addr)
	}
}

func TestShellWait_NilCmd(t *testing.T) {
	session := &capture.CaptureSession{Version: "1.0", App: capture.AppInfo{Name: "Test"}}
	shell := NewShell(session)
	if err := shell.Wait(); err != nil {
		t.Errorf("wait nil cmd: %v", err)
	}
}

func TestShellStop_NilCmd(t *testing.T) {
	session := &capture.CaptureSession{Version: "1.0", App: capture.AppInfo{Name: "Test"}}
	shell := NewShell(session)
	if err := shell.Stop(); err != nil {
		t.Errorf("stop nil cmd: %v", err)
	}
}

func TestShellStop_WithTempDir(t *testing.T) {
	session := &capture.CaptureSession{Version: "1.0", App: capture.AppInfo{Name: "Test"}}
	shell := NewShell(session)
	shell.dir = t.TempDir()
	if err := shell.Stop(); err != nil {
		t.Errorf("stop with dir: %v", err)
	}
}

func TestGeneratePreload_SkipsNonIPCEvents(t *testing.T) {
	now := time.Now()
	netEvt, _ := capture.NewEvent(1, now, capture.EventNetworkRequest, capture.SourceCDP,
		capture.NetworkRequestData{Method: "GET", URL: "https://example.com"})

	session := &capture.CaptureSession{
		Version: "1.0",
		Capture: capture.CaptureMetadata{StartedAt: now},
		Events:  []capture.Event{netEvt},
	}

	preload := GeneratePreload(session)
	if !strings.Contains(preload, "ipcRenderer") {
		t.Error("preload should contain ipcRenderer require")
	}
	if strings.Contains(preload, "setTimeout") {
		t.Error("preload should not contain setTimeout for non-IPC events")
	}
}

func TestGeneratePreload_SkipsMainToRendererDirection(t *testing.T) {
	now := time.Now()
	evt, _ := capture.NewEvent(1, now.Add(time.Second), capture.EventIPCMessage, capture.SourceCDP,
		capture.IPCMessageData{Channel: "update-status", Args: []any{"ready"}, Direction: "main_to_renderer"})

	session := &capture.CaptureSession{
		Version: "1.0",
		Capture: capture.CaptureMetadata{StartedAt: now},
		Events:  []capture.Event{evt},
	}

	preload := GeneratePreload(session)
	if strings.Contains(preload, "update-status") {
		t.Error("preload should not replay main_to_renderer messages")
	}
}

func TestGeneratePreload_InvokeDirection(t *testing.T) {
	now := time.Now()
	evt, _ := capture.NewEvent(1, now.Add(2*time.Second), capture.EventIPCMessage, capture.SourceCDP,
		capture.IPCMessageData{Channel: "invoke-api", Args: []any{"arg1"}, Direction: "renderer_to_main_invoke"})

	session := &capture.CaptureSession{
		Version: "1.0",
		Capture: capture.CaptureMetadata{StartedAt: now},
		Events:  []capture.Event{evt},
	}

	preload := GeneratePreload(session)
	if !strings.Contains(preload, "invoke-api") {
		t.Error("preload should include renderer_to_main_invoke events")
	}
	if !strings.Contains(preload, "2000") {
		t.Error("preload should have 2s delay")
	}
}

func TestGeneratePreload_NegativeDelay(t *testing.T) {
	now := time.Now()
	evt, _ := capture.NewEvent(1, now.Add(-5*time.Second), capture.EventIPCMessage, capture.SourceCDP,
		capture.IPCMessageData{Channel: "early-msg", Args: []any{}, Direction: "renderer_to_main"})

	session := &capture.CaptureSession{
		Version: "1.0",
		Capture: capture.CaptureMetadata{StartedAt: now},
		Events:  []capture.Event{evt},
	}

	preload := GeneratePreload(session)
	if !strings.Contains(preload, "early-msg") {
		t.Error("preload should include event with negative delay")
	}
	// Delay should be clamped to 0
	if !strings.Contains(preload, ", 0);") {
		t.Error("negative delay should be clamped to 0")
	}
}

func TestNewProxy_MethodDefaultsToGET(t *testing.T) {
	// Response without a matching request should default method to GET
	respEvt, _ := capture.NewEvent(1, time.Now(), capture.EventNetworkResponse, capture.SourceCDP,
		capture.NetworkResponseData{Status: 200, URL: "https://example.com/no-request", Body: "hello"})

	session := &capture.CaptureSession{
		Version: "1.0",
		Events:  []capture.Event{respEvt},
	}

	proxy := NewProxy(session)
	addr, err := proxy.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Stop() }()

	resp, err := http.Get("http://" + addr + "/no-request")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNewProxy_POSTMethod(t *testing.T) {
	reqEvt, _ := capture.NewEvent(1, time.Now(), capture.EventNetworkRequest, capture.SourceCDP,
		capture.NetworkRequestData{Method: "POST", URL: "https://api.example.com/submit"})
	respEvt, _ := capture.NewEvent(2, time.Now(), capture.EventNetworkResponse, capture.SourceCDP,
		capture.NetworkResponseData{Status: 201, URL: "https://api.example.com/submit", Body: `{"created":true}`})

	session := &capture.CaptureSession{
		Version: "1.0",
		Events:  []capture.Event{reqEvt, respEvt},
	}

	proxy := NewProxy(session)
	addr, err := proxy.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Stop() }()

	resp, err := http.Post("http://"+addr+"/submit", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 201 {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
}

func TestShellStart_WritesFiles(t *testing.T) {
	now := time.Now()
	ipcEvt, _ := capture.NewEvent(1, now.Add(time.Second), capture.EventIPCMessage, capture.SourceCDP,
		capture.IPCMessageData{Channel: "test-chan", Args: []any{}, Direction: "renderer_to_main"})

	session := &capture.CaptureSession{
		Version: "1.0",
		App:     capture.AppInfo{Name: "TestApp"},
		Capture: capture.CaptureMetadata{StartedAt: now},
		Events:  []capture.Event{ipcEvt},
	}

	shell := NewShell(session)
	ctx := context.Background()

	// Start will write files but fail on npx electron (not installed in test env)
	err := shell.Start(ctx)
	// Clean up regardless
	defer func() { _ = shell.Stop() }()

	if err == nil {
		// If electron happens to be installed, that's fine too
		return
	}

	// Even if spawn failed, files should have been written
	if shell.dir != "" {
		if _, statErr := os.Stat(filepath.Join(shell.dir, "package.json")); statErr != nil {
			t.Error("package.json not written")
		}
		if _, statErr := os.Stat(filepath.Join(shell.dir, "main.js")); statErr != nil {
			t.Error("main.js not written")
		}
		if _, statErr := os.Stat(filepath.Join(shell.dir, "preload.js")); statErr != nil {
			t.Error("preload.js not written")
		}
	}

	// ProxyAddr should be set after Start
	if addr := shell.ProxyAddr(); addr == "" {
		t.Error("proxy addr should be set after Start")
	}
}

func TestProxyAddr_AfterStart(t *testing.T) {
	session := &capture.CaptureSession{Version: "1.0"}
	proxy := NewProxy(session)
	addr, err := proxy.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Stop() }()

	if got := proxy.Addr(); got != addr {
		t.Errorf("Addr() = %q, want %q", got, addr)
	}
}

func TestFindStartURL_WindowStateNonNavigation(t *testing.T) {
	// WindowState event with non-navigation property should be skipped
	wsEvt, _ := capture.NewEvent(1, time.Now(), capture.EventWindowState, capture.SourceCDP,
		capture.WindowStateData{Property: "title", Value: "My App"})
	reqEvt, _ := capture.NewEvent(2, time.Now(), capture.EventNetworkRequest, capture.SourceCDP,
		capture.NetworkRequestData{Method: "GET", URL: "https://fallback.example.com"})

	session := &capture.CaptureSession{Version: "1.0", Events: []capture.Event{wsEvt, reqEvt}}
	if u := findStartURL(session); u != "https://fallback.example.com" {
		t.Errorf("url = %q, want https://fallback.example.com", u)
	}
}
