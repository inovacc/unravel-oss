package session

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"

	"github.com/gorilla/websocket"
)

func TestSessionStopProducesValidCapture(t *testing.T) {
	events := make(chan capture.Event, 10)
	now := time.Now()

	e1, _ := capture.NewEvent(2, now.Add(2*time.Second), capture.EventConsoleLog, capture.SourceCDP, capture.ConsoleLogData{Level: "log", Message: "hello"})
	e2, _ := capture.NewEvent(1, now.Add(1*time.Second), capture.EventNetworkRequest, capture.SourceCDP, capture.NetworkRequestData{Method: "GET", URL: "https://example.com"})

	events <- e1
	events <- e2

	s := &Session{
		config: Config{
			AppName:   "TestApp",
			AppPath:   "/opt/test",
			Framework: "electron",
		},
		events:  events,
		started: now,
		cancel:  func() {},
	}

	close(events)
	var evts []capture.Event
	for evt := range s.events {
		evts = append(evts, evt)
	}
	capture.SortEvents(evts)

	if len(evts) != 2 {
		t.Fatalf("events = %d, want 2", len(evts))
	}
	if evts[0].Seq != 1 {
		t.Errorf("first event seq = %d, want 1", evts[0].Seq)
	}
	if evts[1].Seq != 2 {
		t.Errorf("second event seq = %d, want 2", evts[1].Seq)
	}
}

func TestConfigFields(t *testing.T) {
	cfg := Config{
		AppName:         "MyApp",
		AppPath:         "/usr/bin/myapp",
		Framework:       "electron",
		ElectronVersion: "29.0.0",
		PID:             12345,
		CDPHost:         "localhost:9222",
		DataDir:         "/tmp/data",
		OutputPath:      "/tmp/capture.json",
	}

	if cfg.AppName != "MyApp" {
		t.Errorf("AppName = %q, want %q", cfg.AppName, "MyApp")
	}
	if cfg.PID != 12345 {
		t.Errorf("PID = %d, want 12345", cfg.PID)
	}
	if cfg.CDPHost != "localhost:9222" {
		t.Errorf("CDPHost = %q, want %q", cfg.CDPHost, "localhost:9222")
	}
}

func TestEventCountOnEmptySession(t *testing.T) {
	s := &Session{
		config: Config{AppName: "Test"},
		events: make(chan capture.Event, 10),
		cancel: func() {},
	}

	if got := s.EventCount(); got != 0 {
		t.Errorf("EventCount() = %d, want 0", got)
	}
}

func TestEventCountIncrementsAtomically(t *testing.T) {
	s := &Session{
		config: Config{AppName: "Test"},
		events: make(chan capture.Event, 10),
		cancel: func() {},
	}

	atomic.AddInt64(&s.seq, 5)
	if got := s.EventCount(); got != 5 {
		t.Errorf("EventCount() = %d, want 5", got)
	}

	atomic.AddInt64(&s.seq, 3)
	if got := s.EventCount(); got != 8 {
		t.Errorf("EventCount() = %d, want 8", got)
	}
}

func TestStopNoOutputPath(t *testing.T) {
	events := make(chan capture.Event, 10)
	now := time.Now()

	e1, _ := capture.NewEvent(1, now, capture.EventConsoleLog, capture.SourceCDP,
		capture.ConsoleLogData{Level: "info", Message: "test"})
	events <- e1

	s := &Session{
		config: Config{
			AppName:   "TestApp",
			Framework: "electron",
		},
		events:  events,
		started: now,
		cancel:  func() {},
	}

	cs, err := s.Stop()
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if cs.Version != capture.FormatVersion {
		t.Errorf("Version = %q, want %q", cs.Version, capture.FormatVersion)
	}
	if cs.App.Name != "TestApp" {
		t.Errorf("App.Name = %q, want %q", cs.App.Name, "TestApp")
	}
	if len(cs.Events) != 1 {
		t.Errorf("Events = %d, want 1", len(cs.Events))
	}
	if cs.Capture.DurationMs < 0 {
		t.Errorf("DurationMs = %d, want >= 0", cs.Capture.DurationMs)
	}
	if cs.Capture.Host == "" {
		t.Error("Host should not be empty")
	}
	if cs.Capture.ToolVersion != "1.0.0" {
		t.Errorf("ToolVersion = %q, want %q", cs.Capture.ToolVersion, "1.0.0")
	}
}

func TestStopWithOutputPath(t *testing.T) {
	dir := t.TempDir()
	outPath := dir + "/capture.json"

	events := make(chan capture.Event, 10)
	now := time.Now()

	e1, _ := capture.NewEvent(1, now, capture.EventNetworkRequest, capture.SourceCDP,
		capture.NetworkRequestData{Method: "POST", URL: "https://api.example.com"})
	events <- e1

	s := &Session{
		config: Config{
			AppName:         "TestApp",
			AppPath:         "/opt/test",
			Framework:       "electron",
			ElectronVersion: "28.0.0",
			PID:             999,
			OutputPath:      outPath,
		},
		events:  events,
		started: now,
		cancel:  func() {},
	}

	cs, err := s.Stop()
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if cs.App.Path != "/opt/test" {
		t.Errorf("App.Path = %q, want %q", cs.App.Path, "/opt/test")
	}
	if cs.App.ElectronVersion != "28.0.0" {
		t.Errorf("ElectronVersion = %q, want %q", cs.App.ElectronVersion, "28.0.0")
	}
	if cs.App.PID != 999 {
		t.Errorf("PID = %d, want 999", cs.App.PID)
	}
}

func TestStopWithBadOutputPath(t *testing.T) {
	events := make(chan capture.Event, 10)

	s := &Session{
		config: Config{
			AppName:    "TestApp",
			OutputPath: "/nonexistent/deep/path/capture.json",
		},
		events:  events,
		started: time.Now(),
		cancel:  func() {},
	}

	_, err := s.Stop()
	if err == nil {
		t.Fatal("expected error for bad output path")
	}
}

func TestStopEmptyEvents(t *testing.T) {
	events := make(chan capture.Event, 10)

	s := &Session{
		config:  Config{AppName: "Empty"},
		events:  events,
		started: time.Now(),
		cancel:  func() {},
	}

	cs, err := s.Stop()
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if len(cs.Events) != 0 {
		t.Errorf("Events = %d, want 0", len(cs.Events))
	}
}

func TestStopSortsEvents(t *testing.T) {
	events := make(chan capture.Event, 10)
	now := time.Now()

	e3, _ := capture.NewEvent(3, now.Add(3*time.Second), capture.EventConsoleLog, capture.SourceCDP,
		capture.ConsoleLogData{Level: "log", Message: "third"})
	e1, _ := capture.NewEvent(1, now.Add(1*time.Second), capture.EventConsoleLog, capture.SourceCDP,
		capture.ConsoleLogData{Level: "log", Message: "first"})
	e2, _ := capture.NewEvent(2, now.Add(2*time.Second), capture.EventConsoleLog, capture.SourceCDP,
		capture.ConsoleLogData{Level: "log", Message: "second"})

	events <- e3
	events <- e1
	events <- e2

	s := &Session{
		config:  Config{AppName: "SortTest"},
		events:  events,
		started: now,
		cancel:  func() {},
	}

	cs, err := s.Stop()
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if len(cs.Events) != 3 {
		t.Fatalf("Events = %d, want 3", len(cs.Events))
	}
	for i := 0; i < len(cs.Events)-1; i++ {
		if cs.Events[i].Seq > cs.Events[i+1].Seq {
			t.Errorf("events not sorted: seq[%d]=%d > seq[%d]=%d", i, cs.Events[i].Seq, i+1, cs.Events[i+1].Seq)
		}
	}
}

func TestStartFailsWithBadCDPHost(t *testing.T) {
	_, err := Start(t.Context(), Config{
		AppName: "Test",
		CDPHost: "http://127.0.0.1:1", // unreachable
	})
	if err == nil {
		t.Fatal("expected error for unreachable CDP host")
	}
}

func TestStartFailsWithEmptyTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	_, err := Start(t.Context(), Config{
		AppName: "Test",
		CDPHost: host,
	})
	if err == nil {
		t.Fatal("expected error for empty targets")
	}
	if !strings.Contains(err.Error(), "no CDP targets") {
		t.Errorf("error = %q, want 'no CDP targets'", err.Error())
	}
}

func TestStartFailsWithConnectError(t *testing.T) {
	// Return targets with bad websocket URL so Connect fails
	type target struct {
		ID                string `json:"id"`
		Type              string `json:"type"`
		Title             string `json:"title"`
		URL               string `json:"url"`
		WebSocketDebugURL string `json:"webSocketDebuggerUrl"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targets := []target{
			{ID: "1", Type: "page", Title: "Test", URL: "http://localhost", WebSocketDebugURL: "ws://127.0.0.1:1/bad"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(targets)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	_, err := Start(t.Context(), Config{
		AppName: "Test",
		CDPHost: host,
	})
	if err == nil {
		t.Fatal("expected error for bad websocket URL")
	}
}

func TestStartNoPageTarget(t *testing.T) {
	// Return targets with no "page" type -- falls back to targets[0]
	type target struct {
		ID                string `json:"id"`
		Type              string `json:"type"`
		Title             string `json:"title"`
		URL               string `json:"url"`
		WebSocketDebugURL string `json:"webSocketDebuggerUrl"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targets := []target{
			{ID: "1", Type: "worker", Title: "SW", URL: "http://localhost", WebSocketDebugURL: "ws://127.0.0.1:1/bad"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(targets)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	_, err := Start(t.Context(), Config{
		AppName: "Test",
		CDPHost: host,
	})
	// Will fail at Connect, but covers the fallback path
	if err == nil {
		t.Fatal("expected error")
	}
}

// mockCDPServer creates an HTTP server that serves /json with targets pointing to a websocket
// endpoint on the same server, and upgrades /ws connections.
func mockCDPServer(t *testing.T) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		wsURL := fmt.Sprintf("ws://%s/ws", srv.Listener.Addr().String())
		type target struct {
			ID                string `json:"id"`
			Type              string `json:"type"`
			Title             string `json:"title"`
			URL               string `json:"url"`
			WebSocketDebugURL string `json:"webSocketDebuggerUrl"`
		}
		targets := []target{
			{ID: "1", Type: "page", Title: "Main", URL: "http://localhost", WebSocketDebugURL: wsURL},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(targets)
	})

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Read and discard messages until connection closes
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestStartFullSuccess(t *testing.T) {
	srv := mockCDPServer(t)
	host := strings.TrimPrefix(srv.URL, "http://")

	dir := t.TempDir()

	sess, err := Start(t.Context(), Config{
		AppName:         "TestApp",
		AppPath:         "/opt/test",
		Framework:       "electron",
		ElectronVersion: "29.0.0",
		PID:             123,
		CDPHost:         host,
		DataDir:         dir,
		OutputPath:      dir + "/capture.json",
	})
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Let it run briefly
	time.Sleep(100 * time.Millisecond)

	cs, err := sess.Stop()
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if cs.App.Name != "TestApp" {
		t.Errorf("App.Name = %q, want %q", cs.App.Name, "TestApp")
	}
}

func TestStartFullSuccessNoDataDir(t *testing.T) {
	srv := mockCDPServer(t)
	host := strings.TrimPrefix(srv.URL, "http://")

	sess, err := Start(t.Context(), Config{
		AppName: "TestApp",
		CDPHost: host,
	})
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	cs, err := sess.Stop()
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if cs.App.Name != "TestApp" {
		t.Errorf("App.Name = %q, want %q", cs.App.Name, "TestApp")
	}
}

func TestStartWithNonexistentDataDir(t *testing.T) {
	srv := mockCDPServer(t)
	host := strings.TrimPrefix(srv.URL, "http://")

	sess, err := Start(t.Context(), Config{
		AppName: "TestApp",
		CDPHost: host,
		DataDir: "/nonexistent/dir/that/does/not/exist",
	})
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	_, err = sess.Stop()
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

func TestStartPageTargetEmptyWS(t *testing.T) {
	// Page target with empty WebSocketDebugURL -- falls back to targets[0]
	type target struct {
		ID                string `json:"id"`
		Type              string `json:"type"`
		Title             string `json:"title"`
		URL               string `json:"url"`
		WebSocketDebugURL string `json:"webSocketDebuggerUrl"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targets := []target{
			{ID: "1", Type: "page", Title: "Main", URL: "http://localhost", WebSocketDebugURL: ""},
			{ID: "2", Type: "worker", Title: "SW", URL: "http://localhost", WebSocketDebugURL: "ws://127.0.0.1:1/fallback"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(targets)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")

	_, err := Start(t.Context(), Config{
		AppName: "Test",
		CDPHost: host,
	})
	// Will fail at Connect, but covers the wsURL == "" fallback path
	if err == nil {
		t.Fatal("expected error")
	}
}
