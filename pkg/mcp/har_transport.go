/*
Copyright (c) 2026 Security Research

HARTransport records every JSON-RPC message that crosses the wrapped
transport into one file per request/response pair (or one file per
notification). Designed to mirror the value of a Chrome HAR capture:
durable per-interaction audit log that survives the running process.

Wire format on disk — one file per interaction:

	<method>_<uuid-v7>.txt

Contents:

	REQUEST  <ISO timestamp>
	<one-line JSON of the request / outgoing message>

	RESPONSE <ISO timestamp>
	<one-line JSON of the response / incoming message>

Notifications (no id) get a single REQUEST block.

The wrapper makes a best-effort pairing on jsonrpc.ID equality; orphan
requests (response never arrived before close) get flushed in Close.
*/
package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// HARTransport wraps another mcp.Transport and writes each request/response
// pair to a dedicated file under Dir. Safe for nil — embed in code paths
// that may run without recording wired (e.g. tests, --no-record flag).
type HARTransport struct {
	Transport gomcp.Transport
	Dir       string
	// MaxFiles, if > 0, prunes oldest .txt files in Dir on Connect so the
	// directory keeps at most MaxFiles entries. Zero disables rotation.
	// At sustained 5 mod/min × 8h/day, ~10000 keeps ~30 days of audit.
	// Prune is best-effort: failures are silently swallowed so a broken
	// filesystem can't kill MCP startup.
	MaxFiles int
}

// Connect implements mcp.Transport.
func (h *HARTransport) Connect(ctx context.Context) (gomcp.Connection, error) {
	delegate, err := h.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(h.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("har: mkdir %s: %w", h.Dir, err)
	}
	if h.MaxFiles > 0 {
		pruneOldest(h.Dir, h.MaxFiles)
	}
	return &harConn{
		delegate: delegate,
		dir:      h.Dir,
		pending:  make(map[string]*pendingRec),
	}, nil
}

func pruneOldest(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type entry struct {
		path    string
		modTime time.Time
	}
	files := make([]entry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, entry{path: filepath.Join(dir, e.Name()), modTime: info.ModTime()})
	}
	if len(files) <= keep {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.Before(files[j].modTime) })
	for i := 0; i < len(files)-keep; i++ {
		_ = os.Remove(files[i].path)
	}
}

type pendingRec struct {
	path     string
	method   string
	openedAt time.Time
}

type harConn struct {
	delegate gomcp.Connection
	dir      string

	mu      sync.Mutex
	pending map[string]*pendingRec
}

func (c *harConn) SessionID() string { return c.delegate.SessionID() }

func (c *harConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	msg, err := c.delegate.Read(ctx)
	if err != nil {
		return msg, err
	}
	c.recordIncoming(msg)
	return msg, nil
}

func (c *harConn) Write(ctx context.Context, msg jsonrpc.Message) error {
	c.recordOutgoing(msg)
	return c.delegate.Write(ctx, msg)
}

func (c *harConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, rec := range c.pending {
		appendBlock(rec.path, "RESPONSE", fmt.Appendf(nil, `{"error":"connection closed before response (id=%s)"}`, id))
	}
	c.pending = nil
	return c.delegate.Close()
}

// recordIncoming logs messages that came FROM the wrapped transport. For a
// server connection these are client→server requests + notifications + sampling
// responses; for a client these are server→client responses + notifications.
func (c *harConn) recordIncoming(msg jsonrpc.Message) {
	switch m := msg.(type) {
	case *jsonrpc.Request:
		c.startRecord(m.ID, m.Method, msg)
	case *jsonrpc.Response:
		c.closeRecord(m.ID, msg)
	}
}

// recordOutgoing logs messages that went TO the wrapped transport.
func (c *harConn) recordOutgoing(msg jsonrpc.Message) {
	switch m := msg.(type) {
	case *jsonrpc.Request:
		c.startRecord(m.ID, m.Method, msg)
	case *jsonrpc.Response:
		c.closeRecord(m.ID, msg)
	}
}

func (c *harConn) startRecord(id jsonrpc.ID, method string, msg jsonrpc.Message) {
	idStr := idString(id)
	safeMethod := sanitizeMethod(method)
	if safeMethod == "" {
		safeMethod = "unknown"
	}
	path := filepath.Join(c.dir, fmt.Sprintf("%s_%s.txt", safeMethod, mustUUIDv7()))
	wire, _ := jsonrpc.EncodeMessage(msg)
	appendBlock(path, "REQUEST", wire)

	// Notifications (nil id) are one-shot; nothing to pair against.
	if idStr == "" {
		return
	}
	c.mu.Lock()
	c.pending[idStr] = &pendingRec{path: path, method: method, openedAt: time.Now()}
	c.mu.Unlock()
}

func (c *harConn) closeRecord(id jsonrpc.ID, msg jsonrpc.Message) {
	idStr := idString(id)
	if idStr == "" {
		return
	}
	c.mu.Lock()
	rec, ok := c.pending[idStr]
	if ok {
		delete(c.pending, idStr)
	}
	c.mu.Unlock()
	if !ok {
		// Response with no matching request — write as orphan.
		path := filepath.Join(c.dir, fmt.Sprintf("orphan_response_%s.txt", mustUUIDv7()))
		wire, _ := jsonrpc.EncodeMessage(msg)
		appendBlock(path, "RESPONSE", wire)
		return
	}
	wire, _ := jsonrpc.EncodeMessage(msg)
	appendBlock(rec.path, "RESPONSE", wire)
}

func appendBlock(path, kind string, body []byte) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	fmt.Fprintf(f, "%s %s\n%s\n\n", kind, time.Now().UTC().Format(time.RFC3339Nano), string(body))
}

func sanitizeMethod(method string) string {
	// MCP method names use '/' as a separator (e.g. tools/call,
	// notifications/initialized). Replace with '_' for filenames.
	method = strings.ReplaceAll(method, "/", "_")
	out := make([]rune, 0, len(method))
	for _, r := range method {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '-', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

func mustUUIDv7() string {
	id, err := uuid.NewV7()
	if err != nil {
		// Fallback to v4 if v7 generator fails (e.g. clock issue).
		return uuid.NewString()
	}
	return id.String()
}

// idString returns the canonical text form of a jsonrpc.ID. Notifications
// have a zero-value ID — IsValid is false — and we treat that as "".
//
// jsonrpc.ID keeps its value (a string or int64) in an unexported field and
// deliberately implements NO json.Marshaler, so json.Marshal(id) emits "{}"
// for every ID — collapsing all pairing keys together and mis-pairing
// concurrent in-flight requests. Read the underlying value via Raw() instead;
// distinct IDs then map to distinct keys.
func idString(id jsonrpc.ID) string {
	if !id.IsValid() {
		return ""
	}
	return fmt.Sprintf("%v", id.Raw())
}
