/*
Copyright (c) 2026 Security Research
*/
package cdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// newTestServer spins up a tiny CDP-style websocket server. The handler runs
// once per connection and is given the upgraded conn; tests use it to send
// canned responses.
func newTestServer(t *testing.T, handler func(t *testing.T, ws *websocket.Conn)) (*httptest.Server, string) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade: %v", err)
			return
		}
		defer func() { _ = ws.Close() }()
		handler(t, ws)
	}))
	u, _ := url.Parse(srv.URL)
	wsURL := "ws://" + u.Host + "/"
	return srv, wsURL
}

func dialClient(t *testing.T, wsURL string) *Client {
	t.Helper()
	c := New("", nil, nil)
	if err := c.Connect(context.Background(), wsURL); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return c
}

func TestSendAndWait(t *testing.T) {
	srv, wsURL := newTestServer(t, func(t *testing.T, ws *websocket.Conn) {
		var req struct {
			ID     int64           `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := ws.ReadJSON(&req); err != nil {
			return
		}
		_ = ws.WriteJSON(map[string]any{
			"id":     req.ID,
			"result": map[string]any{"value": 42},
		})
		// keep open briefly so Listen can read
		time.Sleep(50 * time.Millisecond)
	})
	defer srv.Close()

	c := dialClient(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = c.Listen(ctx) }()

	raw, err := c.SendAndWait(ctx, "Test.method", nil)
	if err != nil {
		t.Fatalf("SendAndWait: %v", err)
	}
	if !strings.Contains(string(raw), "42") {
		t.Fatalf("expected 42 in result, got %s", string(raw))
	}
}

func TestSendAndWaitTimeout(t *testing.T) {
	srv, wsURL := newTestServer(t, func(t *testing.T, ws *websocket.Conn) {
		// never reply
		var req map[string]any
		_ = ws.ReadJSON(&req)
		time.Sleep(2 * time.Second)
	})
	defer srv.Close()

	c := dialClient(t, wsURL)
	defer func() { _ = c.Close() }()

	go func() { _ = c.Listen(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.SendAndWait(ctx, "Test.method", nil)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "context") {
		t.Fatalf("expected context deadline error, got %v", err)
	}
}

func TestSendAndWaitConcurrent(t *testing.T) {
	srv, wsURL := newTestServer(t, func(t *testing.T, ws *websocket.Conn) {
		for {
			var req struct {
				ID     int64  `json:"id"`
				Method string `json:"method"`
			}
			if err := ws.ReadJSON(&req); err != nil {
				return
			}
			_ = ws.WriteJSON(map[string]any{
				"id":     req.ID,
				"result": map[string]any{"method": req.Method, "id": req.ID},
			})
		}
	})
	defer srv.Close()

	c := dialClient(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = c.Listen(ctx) }()

	const N = 10
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := range N {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			method := "Test.m" + string(rune('0'+i))
			raw, err := c.SendAndWait(ctx, method, nil)
			if err != nil {
				errs <- err
				return
			}
			if !strings.Contains(string(raw), method) {
				errs <- nil
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent send: %v", err)
		}
	}
}

func TestSendUnchanged(t *testing.T) {
	// Existing fire-and-forget Send must still return (nil, nil) on success.
	srv, wsURL := newTestServer(t, func(t *testing.T, ws *websocket.Conn) {
		var req map[string]any
		_ = ws.ReadJSON(&req)
		time.Sleep(50 * time.Millisecond)
	})
	defer srv.Close()

	c := dialClient(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	raw, err := c.Send(ctx, "Test.method", nil)
	if err != nil {
		t.Fatalf("Send returned err: %v", err)
	}
	if raw != nil {
		t.Fatalf("Send must return nil RawMessage, got %s", string(raw))
	}
}

func TestDispatchFrameMalformedNoPanic(t *testing.T) {
	c := New("", nil, nil)
	// must not panic on garbage
	c.dispatchFrame([]byte("not json"))
	c.dispatchFrame([]byte(`{"id": "stringid"}`))
	c.dispatchFrame([]byte(`{}`))
}
