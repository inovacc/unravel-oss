/*
Copyright (c) 2026 Security Research
*/
package cdp

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestCaptureScreenshot(t *testing.T) {
	expected := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	encoded := base64.StdEncoding.EncodeToString(expected)
	srv, wsURL := newTestServer(t, func(t *testing.T, ws *websocket.Conn) {
		var req struct {
			ID int64 `json:"id"`
		}
		if err := ws.ReadJSON(&req); err != nil {
			return
		}
		_ = ws.WriteJSON(map[string]any{
			"id":     req.ID,
			"result": map[string]any{"data": encoded},
		})
		time.Sleep(50 * time.Millisecond)
	})
	defer srv.Close()

	c := dialClient(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = c.Listen(ctx) }()

	out, err := c.CaptureScreenshot(ctx, ScreenshotOpts{Format: "png"})
	if err != nil {
		t.Fatalf("CaptureScreenshot: %v", err)
	}
	if len(out) != len(expected) {
		t.Fatalf("expected %d bytes, got %d", len(expected), len(out))
	}
	for i := range expected {
		if out[i] != expected[i] {
			t.Fatalf("byte %d: expected %#x got %#x", i, expected[i], out[i])
		}
	}
}
