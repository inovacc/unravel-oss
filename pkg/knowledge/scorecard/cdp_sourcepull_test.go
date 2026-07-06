/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// newPullTestServer spins up a CDP-style HTTP+WS server: GET /json advertises
// one page target whose webSocketDebuggerUrl points back at /ws on the same
// server; the /ws handler is the per-connection CDP JSON-RPC speaker.
func newPullTestServer(t *testing.T, handler func(t *testing.T, ws *websocket.Conn)) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		u, _ := url.Parse(base)
		wsURL := "ws://" + u.Host + "/ws"
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"id":                   "page-1",
				"type":                 "page",
				"title":                "Test Page",
				"url":                  "https://x/",
				"webSocketDebuggerUrl": wsURL,
			},
		})
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade: %v", err)
			return
		}
		defer func() { _ = ws.Close() }()
		handler(t, ws)
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv
}

func hostPort(t *testing.T, srv *httptest.Server) (string, int) {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	var port int
	if _, err := fmtSscan(u.Port(), &port); err != nil {
		t.Fatalf("parse port %q: %v", u.Port(), err)
	}
	return u.Hostname(), port
}

func fmtSscan(s string, p *int) (int, error) {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	*p = n
	return 1, nil
}

func TestPullSourcesOverCDP_CollectsJSAndCSS(t *testing.T) {
	srv := newPullTestServer(t, func(t *testing.T, ws *websocket.Conn) {
		for {
			var req struct {
				ID     int64           `json:"id"`
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
			}
			if err := ws.ReadJSON(&req); err != nil {
				return
			}
			switch req.Method {
			case "Debugger.enable":
				_ = ws.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{}})
				_ = ws.WriteJSON(map[string]any{
					"method": "Debugger.scriptParsed",
					"params": map[string]any{"scriptId": "s1", "url": "https://x/a.js"},
				})
				_ = ws.WriteJSON(map[string]any{
					"method": "Debugger.scriptParsed",
					"params": map[string]any{"scriptId": "s2", "url": "https://x/b.js"},
				})
			case "Page.enable":
				_ = ws.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{}})
			case "CSS.enable":
				_ = ws.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{}})
				_ = ws.WriteJSON(map[string]any{
					"method": "CSS.styleSheetAdded",
					"params": map[string]any{
						"header": map[string]any{"styleSheetId": "c1", "sourceURL": "https://x/s.css"},
					},
				})
			case "Debugger.getScriptSource":
				var p struct {
					ScriptID string `json:"scriptId"`
				}
				_ = json.Unmarshal(req.Params, &p)
				src := "function a(){}"
				if p.ScriptID == "s2" {
					src = "const b=()=>1"
				}
				_ = ws.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{"scriptSource": src}})
			case "CSS.getStyleSheetText":
				_ = ws.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{"text": ".x{display:flex}"}})
			default:
				_ = ws.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{}})
			}
		}
	})
	defer srv.Close()

	host, port := hostPort(t, srv)
	got, err := PullSourcesOverCDP(context.Background(), host, port, 8*time.Second)
	if err != nil {
		t.Fatalf("PullSourcesOverCDP: %v", err)
	}
	if got == nil {
		t.Fatal("nil result")
	}
	if len(got.JS) != 2 {
		t.Fatalf("want 2 JS, got %d: %+v", len(got.JS), got.JS)
	}
	js := map[string]string{}
	for _, s := range got.JS {
		js[s.URL] = s.Source
	}
	if js["https://x/a.js"] != "function a(){}" {
		t.Errorf("a.js source mismatch: %q", js["https://x/a.js"])
	}
	if js["https://x/b.js"] != "const b=()=>1" {
		t.Errorf("b.js source mismatch: %q", js["https://x/b.js"])
	}
	if len(got.CSS) != 1 {
		t.Fatalf("want 1 CSS, got %d: %+v", len(got.CSS), got.CSS)
	}
	if got.CSS[0].URL != "https://x/s.css" || got.CSS[0].Source != ".x{display:flex}" {
		t.Errorf("css mismatch: %+v", got.CSS[0])
	}
}

func TestPullSourcesOverCDP_HonestEmpty(t *testing.T) {
	srv := newPullTestServer(t, func(t *testing.T, ws *websocket.Conn) {
		for {
			var req struct {
				ID     int64  `json:"id"`
				Method string `json:"method"`
			}
			if err := ws.ReadJSON(&req); err != nil {
				return
			}
			// Acknowledge every command but never push script/sheet events.
			_ = ws.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{}})
		}
	})
	defer srv.Close()

	host, port := hostPort(t, srv)
	got, err := PullSourcesOverCDP(context.Background(), host, port, 6*time.Second)
	if err != nil {
		t.Fatalf("PullSourcesOverCDP: %v", err)
	}
	if got == nil {
		t.Fatal("nil result on honest-empty")
	}
	if len(got.JS) != 0 || len(got.CSS) != 0 {
		t.Fatalf("want empty, got JS=%d CSS=%d", len(got.JS), len(got.CSS))
	}
}
