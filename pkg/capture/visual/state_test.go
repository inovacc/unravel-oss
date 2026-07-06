/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"

	"github.com/gorilla/websocket"
)

// stateCDPServer mirrors fakeCDPServer from tree_test.go but exposes the
// websocket connection so the test can push CDP-style events at will.
func stateCDPServer(t *testing.T) (*cdp.Client, chan<- []byte, func()) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	push := make(chan []byte, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Goroutine 1: respond to inbound RPCs (id-keyed) so SendAndWait
		// completes during RegisterStateDetectors.
		go func() {
			defer func() { _ = ws.Close() }()
			_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
			for {
				var req struct {
					ID     int64  `json:"id"`
					Method string `json:"method"`
				}
				if err := ws.ReadJSON(&req); err != nil {
					return
				}
				_ = ws.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{}})
			}
		}()
		// Goroutine 2: push fake events on demand.
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

func TestStateDetectorRoute(t *testing.T) {
	client, push, cleanup := stateCDPServer(t)
	defer cleanup()
	got := make(chan StateEvent, 4)
	if err := RegisterStateDetectors(context.Background(), client, func(s StateEvent) { got <- s }); err != nil {
		t.Fatalf("register: %v", err)
	}
	evt, _ := json.Marshal(map[string]any{
		"method": "Page.frameNavigated",
		"params": map[string]any{"frame": map[string]any{"url": "https://app.example.com/login?q=1"}},
	})
	push <- evt
	select {
	case s := <-got:
		if s.Type != "route" || s.Slug != "login" {
			t.Errorf("got %+v", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event received")
	}
}

func TestStateDetectorModal(t *testing.T) {
	client, push, cleanup := stateCDPServer(t)
	defer cleanup()
	got := make(chan StateEvent, 4)
	if err := RegisterStateDetectors(context.Background(), client, func(s StateEvent) { got <- s }); err != nil {
		t.Fatalf("register: %v", err)
	}
	openEvt, _ := json.Marshal(map[string]any{
		"method": "Runtime.bindingCalled",
		"params": map[string]any{
			"name":    "__unravel_state_event",
			"payload": `{"type":"modal_open","label":"MFA"}`,
		},
	})
	push <- openEvt
	select {
	case s := <-got:
		if s.Type != "modal_open" || s.Slug != "modal-mfa" || s.Label != "MFA" {
			t.Errorf("got %+v", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no modal_open event")
	}
	closeEvt, _ := json.Marshal(map[string]any{
		"method": "Runtime.bindingCalled",
		"params": map[string]any{
			"name":    "__unravel_state_event",
			"payload": `{"type":"modal_close","label":"MFA"}`,
		},
	})
	push <- closeEvt
	select {
	case s := <-got:
		if s.Type != "modal_close" {
			t.Errorf("got type=%q", s.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no modal_close event")
	}
}

func TestStateDetectorIgnoresUnknownBinding(t *testing.T) {
	client, push, cleanup := stateCDPServer(t)
	defer cleanup()
	var mu sync.Mutex
	var hits int
	if err := RegisterStateDetectors(context.Background(), client, func(s StateEvent) { mu.Lock(); hits++; mu.Unlock() }); err != nil {
		t.Fatalf("register: %v", err)
	}
	evt, _ := json.Marshal(map[string]any{
		"method": "Runtime.bindingCalled",
		"params": map[string]any{
			"name":    "some_other_binding",
			"payload": `{"type":"modal_open"}`,
		},
	})
	push <- evt
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("unknown binding produced %d events", hits)
	}
}
