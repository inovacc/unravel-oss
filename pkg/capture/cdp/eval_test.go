/*
Copyright (c) 2026 Security Research
*/
package cdp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestEval(t *testing.T) {
	srv, wsURL := newTestServer(t, func(t *testing.T, ws *websocket.Conn) {
		var req struct {
			ID int64 `json:"id"`
		}
		if err := ws.ReadJSON(&req); err != nil {
			return
		}
		_ = ws.WriteJSON(map[string]any{
			"id": req.ID,
			"result": map[string]any{
				"result": map[string]any{"value": "hello"},
			},
		})
		time.Sleep(50 * time.Millisecond)
	})
	defer srv.Close()

	c := dialClient(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = c.Listen(ctx) }()

	v, err := c.Eval(ctx, "'hello'", EvalOpts{})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !strings.Contains(string(v), "hello") {
		t.Fatalf("expected hello, got %s", string(v))
	}
}

func TestEvalThrows(t *testing.T) {
	srv, wsURL := newTestServer(t, func(t *testing.T, ws *websocket.Conn) {
		var req struct {
			ID int64 `json:"id"`
		}
		if err := ws.ReadJSON(&req); err != nil {
			return
		}
		_ = ws.WriteJSON(map[string]any{
			"id": req.ID,
			"result": map[string]any{
				"result":           map[string]any{"value": nil},
				"exceptionDetails": map[string]any{"text": "ReferenceError: foo"},
			},
		})
		time.Sleep(50 * time.Millisecond)
	})
	defer srv.Close()

	c := dialClient(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = c.Listen(ctx) }()

	_, err := c.Eval(ctx, "foo", EvalOpts{})
	if err == nil {
		t.Fatal("expected exception error, got nil")
	}
	if !strings.Contains(err.Error(), "threw") {
		t.Fatalf("expected 'threw' in err, got %v", err)
	}
}
