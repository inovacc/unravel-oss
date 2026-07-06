/*
Copyright (c) 2026 Security Research
*/
package cdp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestGetDocument(t *testing.T) {
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
				"root": map[string]any{
					"nodeId":   1,
					"nodeName": "#document",
					"nodeType": 9,
				},
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

	root, err := c.GetDocument(ctx, -1, false)
	if err != nil {
		t.Fatalf("GetDocument: %v", err)
	}
	if root.NodeName != "#document" {
		t.Fatalf("expected #document, got %q", root.NodeName)
	}
	// sanity: encodes back to JSON without error
	if _, err := json.Marshal(root); err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
}
