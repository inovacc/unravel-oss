package cdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"

	"github.com/gorilla/websocket"
)

func TestDiscoverTargets(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"abc","type":"page","title":"Test","url":"http://localhost","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/abc"}]`))
	}))
	defer ts.Close()

	host := ts.Listener.Addr().String()
	events := make(chan capture.Event, 10)
	var counter int64
	c := New(host, events, func() int { return int(atomic.AddInt64(&counter, 1)) })

	targets, err := c.DiscoverTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	if targets[0].ID != "abc" {
		t.Errorf("id = %q, want %q", targets[0].ID, "abc")
	}
}

func TestNetworkHandler(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterNetworkHandlers()

	params := json.RawMessage(`{"requestId":"1","request":{"method":"GET","url":"https://api.example.com/data","headers":{"Accept":"*/*"}}}`)
	c.handlers["Network.requestWillBeSent"](params)

	select {
	case evt := <-events:
		if evt.Type != capture.EventNetworkRequest {
			t.Errorf("type = %q, want %q", evt.Type, capture.EventNetworkRequest)
		}
		var req capture.NetworkRequestData
		_ = capture.DecodeEventData(evt, &req)
		if req.URL != "https://api.example.com/data" {
			t.Errorf("url = %q", req.URL)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestRuntimeIPCParsing(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterRuntimeHandlers()

	params := json.RawMessage(`{"type":"log","args":[{"type":"string","value":"{\"__capture\":\"ipc\",\"channel\":\"set-content-protection\",\"args\":[true],\"dir\":\"renderer_to_main\"}"}]}`)
	c.handlers["Runtime.consoleAPICalled"](params)

	select {
	case evt := <-events:
		if evt.Type != capture.EventIPCMessage {
			t.Errorf("type = %q, want %q", evt.Type, capture.EventIPCMessage)
		}
		var ipc capture.IPCMessageData
		_ = capture.DecodeEventData(evt, &ipc)
		if ipc.Channel != "set-content-protection" {
			t.Errorf("channel = %q", ipc.Channel)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestRuntimeRegularConsole(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterRuntimeHandlers()

	params := json.RawMessage(`{"type":"warn","args":[{"type":"string","value":"something went wrong"}]}`)
	c.handlers["Runtime.consoleAPICalled"](params)

	select {
	case evt := <-events:
		if evt.Type != capture.EventConsoleLog {
			t.Errorf("type = %q, want %q", evt.Type, capture.EventConsoleLog)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestPageHandler(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterPageHandlers()

	params := json.RawMessage(`{"frame":{"url":"https://app.example.com/dashboard"}}`)
	c.handlers["Page.frameNavigated"](params)

	select {
	case evt := <-events:
		if evt.Type != capture.EventWindowState {
			t.Errorf("type = %q, want %q", evt.Type, capture.EventWindowState)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestCloseNilConn(t *testing.T) {
	c := New("unused", nil, nil)
	if err := c.Close(); err != nil {
		t.Fatalf("Close() on nil conn should return nil, got %v", err)
	}
}

func TestEmitFullChannel(t *testing.T) {
	// Channel with zero capacity — Emit should not block (drops event).
	events := make(chan capture.Event)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })

	evt, _ := capture.NewEvent(1, time.Now(), capture.EventConsoleLog, capture.SourceCDP,
		capture.ConsoleLogData{Level: "info", Message: "test"})
	// Must not block.
	c.Emit(evt)
}

func TestIsTimeoutTrue(t *testing.T) {
	err := &timeoutErr{timeout: true}
	if !isTimeout(err) {
		t.Fatal("expected isTimeout to return true")
	}
}

func TestIsTimeoutFalse(t *testing.T) {
	err := &timeoutErr{timeout: false}
	if isTimeout(err) {
		t.Fatal("expected isTimeout to return false")
	}
}

func TestIsTimeoutNonTimeoutError(t *testing.T) {
	var v map[string]any
	err := json.Unmarshal([]byte("bad"), &v)
	if isTimeout(err) {
		t.Fatal("expected isTimeout to return false for non-timeout error")
	}
}

// timeoutErr is a helper that implements the Timeout() bool interface.
type timeoutErr struct {
	timeout bool
}

func (e *timeoutErr) Error() string { return "timeout error" }
func (e *timeoutErr) Timeout() bool { return e.timeout }

func TestDiscoverTargetsInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer ts.Close()

	host := ts.Listener.Addr().String()
	events := make(chan capture.Event, 10)
	var counter int64
	c := New(host, events, func() int { return int(atomic.AddInt64(&counter, 1)) })

	_, err := c.DiscoverTargets(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestDiscoverTargetsHTTPError(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("127.0.0.1:1", events, func() int { return int(atomic.AddInt64(&counter, 1)) })

	_, err := c.DiscoverTargets(context.Background())
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
}

func TestDiscoverTargetsCancelledContext(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("127.0.0.1:9222", events, func() int { return int(atomic.AddInt64(&counter, 1)) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.DiscoverTargets(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestNetworkResponseHandler(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterNetworkHandlers()

	params := json.RawMessage(`{"requestId":"1","response":{"status":200,"url":"https://api.example.com/data","headers":{"Content-Type":"application/json"}}}`)
	c.handlers["Network.responseReceived"](params)

	select {
	case evt := <-events:
		if evt.Type != capture.EventNetworkResponse {
			t.Errorf("type = %q, want %q", evt.Type, capture.EventNetworkResponse)
		}
		var resp capture.NetworkResponseData
		_ = capture.DecodeEventData(evt, &resp)
		if resp.Status != 200 {
			t.Errorf("status = %d, want 200", resp.Status)
		}
		if resp.URL != "https://api.example.com/data" {
			t.Errorf("url = %q", resp.URL)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestNetworkRequestBadJSON(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterNetworkHandlers()

	// Bad JSON should not panic — handler returns early.
	c.handlers["Network.requestWillBeSent"](json.RawMessage(`{bad`))

	select {
	case <-events:
		t.Fatal("should not have received event for bad JSON")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestNetworkResponseBadJSON(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterNetworkHandlers()

	c.handlers["Network.responseReceived"](json.RawMessage(`{bad`))

	select {
	case <-events:
		t.Fatal("should not have received event for bad JSON")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRuntimeEmptyArgs(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterRuntimeHandlers()

	// Empty args — should return early without emitting.
	c.handlers["Runtime.consoleAPICalled"](json.RawMessage(`{"type":"log","args":[]}`))

	select {
	case <-events:
		t.Fatal("should not have received event for empty args")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRuntimeBadJSON(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterRuntimeHandlers()

	c.handlers["Runtime.consoleAPICalled"](json.RawMessage(`{bad`))

	select {
	case <-events:
		t.Fatal("should not have received event for bad JSON")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRuntimeIPCBadInnerJSON(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterRuntimeHandlers()

	// Has the __capture prefix but the inner JSON is invalid — should fall through to console log.
	params := json.RawMessage(`{"type":"log","args":[{"type":"string","value":"{\"__capture\":\"ipc\" INVALID"}]}`)
	c.handlers["Runtime.consoleAPICalled"](params)

	select {
	case evt := <-events:
		if evt.Type != capture.EventConsoleLog {
			t.Errorf("type = %q, want %q (should fall through to console)", evt.Type, capture.EventConsoleLog)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestRuntimeMultipleConsoleArgs(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterRuntimeHandlers()

	params := json.RawMessage(`{"type":"log","args":[{"type":"string","value":"hello"},{"type":"string","value":"world"}]}`)
	c.handlers["Runtime.consoleAPICalled"](params)

	select {
	case evt := <-events:
		if evt.Type != capture.EventConsoleLog {
			t.Errorf("type = %q, want %q", evt.Type, capture.EventConsoleLog)
		}
		var log capture.ConsoleLogData
		_ = capture.DecodeEventData(evt, &log)
		if len(log.Args) != 2 {
			t.Errorf("args count = %d, want 2", len(log.Args))
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestPageHandlerBadJSON(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterPageHandlers()

	c.handlers["Page.frameNavigated"](json.RawMessage(`{bad`))

	select {
	case <-events:
		t.Fatal("should not have received event for bad JSON")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestOnEventRegistration(t *testing.T) {
	c := New("unused", nil, nil)
	called := false
	c.OnEvent("Test.method", func(params json.RawMessage) {
		called = true
	})
	if _, ok := c.handlers["Test.method"]; !ok {
		t.Fatal("handler not registered")
	}
	c.handlers["Test.method"](nil)
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestNewSetsFields(t *testing.T) {
	events := make(chan capture.Event, 5)
	seq := func() int { return 42 }
	c := New("myhost:9222", events, seq)

	if c.host != "myhost:9222" {
		t.Errorf("host = %q", c.host)
	}
	if c.seqFn() != 42 {
		t.Errorf("seqFn() = %d, want 42", c.seqFn())
	}
	if c.handlers == nil {
		t.Fatal("handlers map is nil")
	}
}

func TestConnectBadURL(t *testing.T) {
	events := make(chan capture.Event, 10)
	c := New("unused", events, nil)

	err := c.Connect(context.Background(), "ws://127.0.0.1:1/bad")
	if err == nil {
		t.Fatal("expected error connecting to bad URL")
	}
}

func TestIpcMonitorScriptNotEmpty(t *testing.T) {
	if len(IpcMonitorScript) == 0 {
		t.Fatal("IpcMonitorScript should not be empty")
	}
}

func TestDiscoverTargetsMultiple(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"id":"a","type":"page","title":"One","url":"http://a","webSocketDebuggerUrl":"ws://127.0.0.1/a"},
			{"id":"b","type":"page","title":"Two","url":"http://b","webSocketDebuggerUrl":"ws://127.0.0.1/b"}
		]`))
	}))
	defer ts.Close()

	host := ts.Listener.Addr().String()
	events := make(chan capture.Event, 10)
	var counter int64
	c := New(host, events, func() int { return int(atomic.AddInt64(&counter, 1)) })

	targets, err := c.DiscoverTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if targets[0].Title != "One" || targets[1].Title != "Two" {
		t.Errorf("titles = %q, %q", targets[0].Title, targets[1].Title)
	}
}

func TestDiscoverTargetsEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	host := ts.Listener.Addr().String()
	events := make(chan capture.Event, 10)
	var counter int64
	c := New(host, events, func() int { return int(atomic.AddInt64(&counter, 1)) })

	targets, err := c.DiscoverTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %d, want 0", len(targets))
	}
}

func TestPageHandlerWindowStateData(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterPageHandlers()

	c.handlers["Page.frameNavigated"](json.RawMessage(`{"frame":{"url":"chrome://settings"}}`))

	select {
	case evt := <-events:
		var ws capture.WindowStateData
		_ = capture.DecodeEventData(evt, &ws)
		if ws.Property != "navigation" {
			t.Errorf("property = %q, want %q", ws.Property, "navigation")
		}
		if ws.Value != "chrome://settings" {
			t.Errorf("value = %q", ws.Value)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

// wsServer creates a test WebSocket server and returns its URL and a cleanup function.
// The handler receives the connection for test-specific logic.
func wsServer(t *testing.T, handler func(*websocket.Conn)) string {
	t.Helper()
	upgrader := websocket.Upgrader{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		handler(conn)
	}))
	t.Cleanup(ts.Close)
	return "ws" + ts.URL[4:] // http -> ws
}

func TestSendAndReceive(t *testing.T) {
	var received []byte
	done := make(chan struct{})
	wsURL := wsServer(t, func(conn *websocket.Conn) {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		received = msg
		close(done)
	})

	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })

	err := c.Connect(context.Background(), wsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	_, err = c.Send(context.Background(), "Network.enable", nil)
	if err != nil {
		t.Fatal(err)
	}

	<-done
	var msg struct {
		ID     int64  `json:"id"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal(received, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Method != "Network.enable" {
		t.Errorf("method = %q, want %q", msg.Method, "Network.enable")
	}
	if msg.ID != 1 {
		t.Errorf("id = %d, want 1", msg.ID)
	}
}

func TestSendWithParams(t *testing.T) {
	var received []byte
	done := make(chan struct{})
	wsURL := wsServer(t, func(conn *websocket.Conn) {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		received = msg
		close(done)
	})

	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	_ = c.Connect(context.Background(), wsURL)
	defer func() { _ = c.Close() }()

	_, err := c.Send(context.Background(), "Runtime.evaluate", map[string]any{"expression": "1+1"})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !json.Valid(received) {
		t.Fatal("received invalid JSON")
	}
}

func TestEnableDomains(t *testing.T) {
	methods := make([]string, 0)
	var mu sync.Mutex
	done := make(chan struct{})

	wsURL := wsServer(t, func(conn *websocket.Conn) {
		for range 3 {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var m struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(msg, &m)
			mu.Lock()
			methods = append(methods, m.Method)
			mu.Unlock()
		}
		close(done)
	})

	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	_ = c.Connect(context.Background(), wsURL)
	defer func() { _ = c.Close() }()

	if err := c.EnableDomains(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-done

	mu.Lock()
	defer mu.Unlock()
	want := []string{"Network.enable", "Runtime.enable", "Page.enable"}
	if len(methods) != 3 {
		t.Fatalf("got %d methods, want 3", len(methods))
	}
	for i, m := range methods {
		if m != want[i] {
			t.Errorf("methods[%d] = %q, want %q", i, m, want[i])
		}
	}
}

func TestListenDispatchesEvents(t *testing.T) {
	wsURL := wsServer(t, func(conn *websocket.Conn) {
		// Send a CDP event
		msg := `{"method":"Page.frameNavigated","params":{"frame":{"url":"https://test.com"}}}`
		_ = conn.WriteMessage(websocket.TextMessage, []byte(msg))
		// Give client time to process
		time.Sleep(200 * time.Millisecond)
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		time.Sleep(100 * time.Millisecond)
	})

	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	_ = c.Connect(context.Background(), wsURL)
	defer func() { _ = c.Close() }()

	c.RegisterPageHandlers()

	err := c.Listen(context.Background())
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}

	select {
	case evt := <-events:
		if evt.Type != capture.EventWindowState {
			t.Errorf("type = %q, want %q", evt.Type, capture.EventWindowState)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event received")
	}
}

func TestListenContextCancelled(t *testing.T) {
	wsURL := wsServer(t, func(conn *websocket.Conn) {
		// Just keep the connection open
		time.Sleep(5 * time.Second)
	})

	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	_ = c.Connect(context.Background(), wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err := c.Listen(ctx)
	if err != nil {
		t.Fatalf("Listen should return nil on context cancel, got %v", err)
	}
}

func TestListenInvalidJSON(t *testing.T) {
	wsURL := wsServer(t, func(conn *websocket.Conn) {
		// Send invalid JSON — should be skipped
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`not json`))
		// Then a valid event
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"method":"Page.frameNavigated","params":{"frame":{"url":"https://ok.com"}}}`))
		time.Sleep(200 * time.Millisecond)
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		time.Sleep(100 * time.Millisecond)
	})

	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	_ = c.Connect(context.Background(), wsURL)
	defer func() { _ = c.Close() }()
	c.RegisterPageHandlers()

	_ = c.Listen(context.Background())

	select {
	case evt := <-events:
		if evt.Type != capture.EventWindowState {
			t.Errorf("type = %q", evt.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event after invalid JSON skip")
	}
}

func TestListenUnknownMethod(t *testing.T) {
	wsURL := wsServer(t, func(conn *websocket.Conn) {
		// Send event with no registered handler
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"method":"Unknown.event","params":{}}`))
		time.Sleep(100 * time.Millisecond)
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		time.Sleep(100 * time.Millisecond)
	})

	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	_ = c.Connect(context.Background(), wsURL)
	defer func() { _ = c.Close() }()

	err := c.Listen(context.Background())
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}

	select {
	case <-events:
		t.Fatal("should not receive event for unknown method")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestInjectIPCMonitor(t *testing.T) {
	var received []byte
	done := make(chan struct{})
	wsURL := wsServer(t, func(conn *websocket.Conn) {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		received = msg
		close(done)
	})

	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	_ = c.Connect(context.Background(), wsURL)
	defer func() { _ = c.Close() }()

	err := c.InjectIPCMonitor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	<-done

	var msg struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	_ = json.Unmarshal(received, &msg)
	if msg.Method != "Runtime.evaluate" {
		t.Errorf("method = %q, want Runtime.evaluate", msg.Method)
	}
	expr, ok := msg.Params["expression"].(string)
	if !ok || len(expr) == 0 {
		t.Fatal("expression param missing or empty")
	}
}

func TestCloseAfterConnect(t *testing.T) {
	wsURL := wsServer(t, func(conn *websocket.Conn) {
		// Just keep alive
		time.Sleep(2 * time.Second)
	})

	events := make(chan capture.Event, 10)
	c := New("unused", events, nil)
	_ = c.Connect(context.Background(), wsURL)

	err := c.Close()
	if err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}

func TestNetworkRequestResponseFlow(t *testing.T) {
	events := make(chan capture.Event, 10)
	var counter int64
	c := New("unused", events, func() int { return int(atomic.AddInt64(&counter, 1)) })
	c.RegisterNetworkHandlers()

	// Send request then response with same requestId.
	c.handlers["Network.requestWillBeSent"](json.RawMessage(`{"requestId":"r1","request":{"method":"POST","url":"https://api.com/submit","headers":{"Content-Type":"application/json"}},"postData":"{\"key\":\"val\"}"}`))
	c.handlers["Network.responseReceived"](json.RawMessage(`{"requestId":"r1","response":{"status":201,"url":"https://api.com/submit","headers":{"X-Request-Id":"abc"}}}`))

	// Should get two events.
	evt1 := <-events
	evt2 := <-events
	if evt1.Type != capture.EventNetworkRequest {
		t.Errorf("first event type = %q, want %q", evt1.Type, capture.EventNetworkRequest)
	}
	if evt2.Type != capture.EventNetworkResponse {
		t.Errorf("second event type = %q, want %q", evt2.Type, capture.EventNetworkResponse)
	}
	var req capture.NetworkRequestData
	_ = capture.DecodeEventData(evt1, &req)
	if req.Body != `{"key":"val"}` {
		t.Errorf("body = %q", req.Body)
	}
}
