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
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	"github.com/inovacc/unravel-oss/pkg/jsdeob/framework"

	"github.com/gorilla/websocket"
)

// fakeCDPServer spins up a tiny CDP-like websocket server. The respond callback
// is invoked once per inbound message and returns the JSON to write back.
func fakeCDPServer(t *testing.T, respond func(method string, id int64) any) (*cdp.Client, func()) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			var req struct {
				ID     int64  `json:"id"`
				Method string `json:"method"`
			}
			if err := ws.ReadJSON(&req); err != nil {
				return
			}
			resp := respond(req.Method, req.ID)
			if resp == nil {
				continue
			}
			_ = ws.WriteJSON(resp)
		}
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
		_ = client.Close()
		srv.Close()
	}
	return client, cleanup
}

func loadTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func TestExtractDOMTree(t *testing.T) {
	raw := loadTestdata(t, "dom_getdocument.json")
	var doc cdp.DOMNode
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tree := BuildJSONTree(&doc)
	if tree == nil {
		t.Fatal("nil tree")
	}
	if tree.Tag != "html" {
		t.Errorf("root tag = %q want html", tree.Tag)
	}
	if len(tree.Children) != 1 || tree.Children[0].Tag != "body" {
		t.Fatalf("expected body child, got %+v", tree.Children)
	}
	app := tree.Children[0].Children[0]
	if app.Tag != "div" {
		t.Errorf("app tag = %q", app.Tag)
	}
	if app.Attrs["id"] != "app" || app.Role != "main" {
		t.Errorf("attrs = %+v role = %q", app.Attrs, app.Role)
	}
	// Text node (#text) must be dropped.
	if len(app.Children) != 1 || app.Children[0].Tag != "header" {
		t.Errorf("expected header child only (text dropped), got %+v", app.Children)
	}
}

func TestExtractReactTree(t *testing.T) {
	payload := loadTestdata(t, "fiber_react.json")
	client, cleanup := fakeCDPServer(t, func(method string, id int64) any {
		return map[string]any{
			"id":     id,
			"result": map[string]any{"result": map[string]any{"value": json.RawMessage(payload)}},
		}
	})
	defer cleanup()
	tree, err := extractReactTree(context.Background(), client)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if tree == nil {
		t.Fatal("nil tree")
	}
	if tree.Name != "App" {
		t.Errorf("root = %q want App", tree.Name)
	}
	if len(tree.Children) != 2 {
		t.Errorf("children=%d want 2", len(tree.Children))
	}
}

func TestExtractVue3Tree(t *testing.T) {
	payload := loadTestdata(t, "vue3_walk.json")
	client, cleanup := fakeCDPServer(t, func(method string, id int64) any {
		return map[string]any{
			"id":     id,
			"result": map[string]any{"result": map[string]any{"value": json.RawMessage(payload)}},
		}
	})
	defer cleanup()
	tree, err := extractVue3Tree(context.Background(), client)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if tree == nil || tree.Name != "App" {
		t.Fatalf("got %+v want App root", tree)
	}
}

func TestFrameworkDispatch(t *testing.T) {
	// High confidence → extractor selected.
	infos := []framework.FrameworkInfo{{Name: "React", Confidence: 0.9}}
	client, cleanup := fakeCDPServer(t, func(method string, id int64) any {
		// React extractor evals JS that returns null when hook absent — return null.
		return map[string]any{
			"id":     id,
			"result": map[string]any{"result": map[string]any{"value": json.RawMessage(`null`)}},
		}
	})
	defer cleanup()
	tree, name, err := ExtractFrameworkTree(context.Background(), client, infos)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if name != "react" {
		t.Errorf("name=%q want react", name)
	}
	if tree != nil {
		t.Errorf("expected nil tree (hook absent → null payload), got %+v", tree)
	}

	// Low confidence → silent fallback (D-06).
	low := []framework.FrameworkInfo{{Name: "React", Confidence: 0.3}}
	tree, name, err = ExtractFrameworkTree(context.Background(), client, low)
	if err != nil || tree != nil || name != "" {
		t.Errorf("low conf: got tree=%v name=%q err=%v want all zero", tree, name, err)
	}
}

func TestNextjsRoutedToReact(t *testing.T) {
	var calledMethod atomic.Value
	calledMethod.Store("")
	client, cleanup := fakeCDPServer(t, func(method string, id int64) any {
		calledMethod.Store(method)
		return map[string]any{
			"id":     id,
			"result": map[string]any{"result": map[string]any{"value": json.RawMessage(`null`)}},
		}
	})
	defer cleanup()
	for _, fwName := range []string{"Next.js", "Remix"} {
		_, routed, err := ExtractFrameworkTree(context.Background(), client, []framework.FrameworkInfo{{Name: fwName, Confidence: 0.9}})
		if err != nil {
			t.Fatalf("%s err: %v", fwName, err)
		}
		if routed != "react" {
			t.Errorf("%s routed to %q want react", fwName, routed)
		}
	}
	_, routed, err := ExtractFrameworkTree(context.Background(), client, []framework.FrameworkInfo{{Name: "Nuxt", Confidence: 0.9}})
	if err != nil {
		t.Fatalf("nuxt err: %v", err)
	}
	if routed != "vue" {
		t.Errorf("Nuxt routed to %q want vue", routed)
	}
}

func TestUnknownFramework(t *testing.T) {
	client, cleanup := fakeCDPServer(t, func(method string, id int64) any { return nil })
	defer cleanup()
	tree, name, err := ExtractFrameworkTree(context.Background(), client, nil)
	if err != nil {
		t.Errorf("err = %v want nil", err)
	}
	if tree != nil {
		t.Errorf("tree = %+v want nil", tree)
	}
	if name != "" {
		t.Errorf("name = %q want empty (D-06 silent fallback)", name)
	}
}

func TestFiberWalkPanicSafety(t *testing.T) {
	// Malformed payload: truncated brace. decodeFrameworkTree must return error, not panic.
	bad := json.RawMessage(`{"name": "App", "children": [`)
	_, err := decodeFrameworkTree(bad)
	if err == nil {
		t.Fatal("expected decode error on truncated JSON")
	}
}

func TestSvelteFallback(t *testing.T) {
	// Hook absent → eval returns null → extractor returns (nil, nil).
	client, cleanup := fakeCDPServer(t, func(method string, id int64) any {
		return map[string]any{
			"id":     id,
			"result": map[string]any{"result": map[string]any{"value": json.RawMessage(`null`)}},
		}
	})
	defer cleanup()
	tree, err := extractSvelteTree(context.Background(), client)
	if err != nil {
		t.Errorf("err = %v want nil (silent fallback)", err)
	}
	if tree != nil {
		t.Errorf("tree = %+v want nil", tree)
	}
}
