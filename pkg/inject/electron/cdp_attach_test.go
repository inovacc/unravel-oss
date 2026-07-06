/*
Copyright (c) 2026 Security Research
*/
package electron

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeCDP spins up a tiny server that:
//   - serves /json with one page-type target whose webSocketDebuggerUrl points
//     back at the same host's /ws endpoint
//   - upgrades /ws to a websocket and feeds incoming CDP frames to the handler
//
// The handler closes over the test's *testing.T to record observed methods.
func fakeCDP(t *testing.T, onMessage func(req map[string]any) any) (host string, stop func()) {
	t.Helper()

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	var wsHost string

	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"id":                   "T1",
				"type":                 "page",
				"title":                "App",
				"url":                  "https://app/",
				"webSocketDebuggerUrl": "ws://" + wsHost + "/ws",
			},
		})
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		for {
			var req map[string]any
			if err := ws.ReadJSON(&req); err != nil {
				return
			}
			result := onMessage(req)
			id, _ := req["id"].(float64)
			_ = ws.WriteJSON(map[string]any{
				"id":     int64(id),
				"result": result,
			})
		}
	})

	srv := httptest.NewServer(mux)
	u, _ := url.Parse(srv.URL)
	wsHost = u.Host
	return u.Host, srv.Close
}

func parsePort(t *testing.T, host string) int {
	t.Helper()
	var port int
	_, err := fmt.Sscanf(host[strings.LastIndex(host, ":")+1:], "%d", &port)
	if err != nil {
		t.Fatalf("parse port from %q: %v", host, err)
	}
	return port
}

func TestAttachAndInject_OneShot(t *testing.T) {
	var sawRuntimeEvaluate, sawAddScript int32
	host, stop := fakeCDP(t, func(req map[string]any) any {
		switch req["method"] {
		case "Runtime.evaluate":
			atomic.AddInt32(&sawRuntimeEvaluate, 1)
		case "Page.addScriptToEvaluateOnNewDocument":
			atomic.AddInt32(&sawAddScript, 1)
		}
		return map[string]any{}
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := AttachAndInject(ctx, parsePort(t, host), []byte("1+1"), AttachOpts{Persistent: false})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if atomic.LoadInt32(&sawRuntimeEvaluate) != 1 {
		t.Errorf("expected Runtime.evaluate, got %d", sawRuntimeEvaluate)
	}
	if atomic.LoadInt32(&sawAddScript) != 0 {
		t.Errorf("did not expect addScriptToEvaluateOnNewDocument, got %d", sawAddScript)
	}
}

func TestAttachAndInject_PersistentMainWorld(t *testing.T) {
	var addParams atomic.Value
	host, stop := fakeCDP(t, func(req map[string]any) any {
		if req["method"] == "Page.addScriptToEvaluateOnNewDocument" {
			addParams.Store(req["params"])
		}
		return map[string]any{}
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := AttachAndInject(ctx, parsePort(t, host), []byte("hi"), AttachOpts{Persistent: true})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	p, _ := addParams.Load().(map[string]any)
	if p == nil {
		t.Fatal("addScriptToEvaluateOnNewDocument was not called")
	}
	if _, ok := p["worldName"]; ok {
		t.Errorf("did not expect worldName for main-world inject, got %v", p["worldName"])
	}
	if p["source"] != "hi" {
		t.Errorf("source = %v", p["source"])
	}
}

func TestAttachAndInject_PersistentIsolatedWorld(t *testing.T) {
	var addParams atomic.Value
	host, stop := fakeCDP(t, func(req map[string]any) any {
		if req["method"] == "Page.addScriptToEvaluateOnNewDocument" {
			addParams.Store(req["params"])
		}
		return map[string]any{}
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := AttachAndInject(ctx, parsePort(t, host), []byte("iso"), AttachOpts{Persistent: true, World: "isolated"})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	p, _ := addParams.Load().(map[string]any)
	if p == nil {
		t.Fatal("addScriptToEvaluateOnNewDocument not called")
	}
	if w, _ := p["worldName"].(string); w == "" {
		t.Errorf("expected worldName set for isolated mode, got empty")
	}
}

func TestAttachAndInject_NoTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{}) // empty
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := AttachAndInject(ctx, parsePort(t, u.Host), []byte("x"), AttachOpts{})
	if err == nil {
		t.Fatal("expected error when no targets present")
	}
}
