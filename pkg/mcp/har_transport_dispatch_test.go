/*
Copyright (c) 2026 Security Research

har_transport_dispatch_test.go — covers the request/response pairing,
notification, orphan-response, close-flush, and helper (sanitizeMethod /
idString / mustUUIDv7) logic in har_transport.go that
har_transport_prune_test.go does not exercise. Uses a fake in-process
gomcp.Transport/gomcp.Connection so no real MCP handshake, network, or
Postgres is required — pure deterministic logic, Docker-free default suite.
*/
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeConn is a minimal gomcp.Connection double: it replays a fixed sequence
// of Read results and records everything passed to Write, so tests can
// drive harConn's pairing logic without a live transport.
type fakeConn struct {
	mu sync.Mutex

	readMsgs []jsonrpc.Message
	readIdx  int
	readErr  error // returned once readMsgs is exhausted

	writeErr error
	written  []jsonrpc.Message

	closeErr error
	closed   bool

	sessionID string
}

func (f *fakeConn) SessionID() string { return f.sessionID }

func (f *fakeConn) Read(_ context.Context) (jsonrpc.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readIdx >= len(f.readMsgs) {
		if f.readErr != nil {
			return nil, f.readErr
		}
		return nil, io.EOF
	}
	m := f.readMsgs[f.readIdx]
	f.readIdx++
	return m, nil
}

func (f *fakeConn) Write(_ context.Context, msg jsonrpc.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written = append(f.written, msg)
	return f.writeErr
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.closeErr
}

// fakeTransport is a minimal gomcp.Transport double.
type fakeTransport struct {
	conn gomcp.Connection
	err  error
}

func (f *fakeTransport) Connect(_ context.Context) (gomcp.Connection, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.conn, nil
}

func mustID(t *testing.T, v any) jsonrpc.ID {
	t.Helper()
	id, err := jsonrpc.MakeID(v)
	if err != nil {
		t.Fatalf("MakeID(%v): %v", v, err)
	}
	return id
}

// readDirTxt returns the base names of every .txt file in dir.
func readDirTxt(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".txt") {
			names = append(names, e.Name())
		}
	}
	return names
}

func readFileContent(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// --- HARTransport.Connect ---------------------------------------------

func TestHARTransport_Connect_DelegateError(t *testing.T) {
	ht := &HARTransport{
		Transport: &fakeTransport{err: errors.New("dial failed")},
		Dir:       filepath.Join(t.TempDir(), "interacts"),
	}
	conn, err := ht.Connect(context.Background())
	if err == nil {
		t.Fatal("expected error from delegate.Connect")
	}
	if conn != nil {
		t.Fatalf("expected nil connection, got %v", conn)
	}
	if _, statErr := os.Stat(ht.Dir); statErr == nil {
		t.Error("Dir should not have been created when delegate.Connect fails")
	}
}

func TestHARTransport_Connect_MkdirFails(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	// blocker is a regular file, so MkdirAll(blocker/sub) must fail on every OS.
	badDir := filepath.Join(blocker, "sub")

	ht := &HARTransport{
		Transport: &fakeTransport{conn: &fakeConn{}},
		Dir:       badDir,
	}
	conn, err := ht.Connect(context.Background())
	if err == nil {
		t.Fatal("expected mkdir error")
	}
	if conn != nil {
		t.Fatalf("expected nil connection, got %v", conn)
	}
	if !strings.Contains(err.Error(), "har: mkdir") {
		t.Errorf("error %q missing har: mkdir prefix", err.Error())
	}
}

func TestHARTransport_Connect_Success_PrunesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	for i := range 5 {
		p := filepath.Join(dir, "old_"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("seed file %d: %v", i, err)
		}
	}

	ht := &HARTransport{
		Transport: &fakeTransport{conn: &fakeConn{}},
		Dir:       dir,
		MaxFiles:  2,
	}
	conn, err := ht.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection")
	}
	if _, ok := conn.(*harConn); !ok {
		t.Fatalf("expected *harConn, got %T", conn)
	}

	got := readDirTxt(t, dir)
	if len(got) != 2 {
		t.Errorf("after prune-on-connect: got %d .txt files, want 2", len(got))
	}
}

func TestHARTransport_Connect_MaxFilesZero_NoPrune(t *testing.T) {
	dir := t.TempDir()
	for i := range 5 {
		p := filepath.Join(dir, "old_"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("seed file %d: %v", i, err)
		}
	}

	ht := &HARTransport{
		Transport: &fakeTransport{conn: &fakeConn{}},
		Dir:       dir,
		// MaxFiles left at zero: rotation disabled.
	}
	if _, err := ht.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	got := readDirTxt(t, dir)
	if len(got) != 5 {
		t.Errorf("MaxFiles=0 should not prune: got %d .txt files, want 5", len(got))
	}
}

// --- harConn request/response pairing -----------------------------------

func TestHarConn_Read_RequestThenResponse_Pairs(t *testing.T) {
	dir := t.TempDir()
	// jsonrpc.MakeID only accepts nil, float64, or string (mirrors JSON
	// number/string decoding) — see internal/jsonrpc2.MakeID.
	id := mustID(t, float64(1))
	req := &jsonrpc.Request{ID: id, Method: "tools/call"}
	resp := &jsonrpc.Response{ID: id, Result: json.RawMessage(`{"ok":true}`)}

	fc := &fakeConn{readMsgs: []jsonrpc.Message{req, resp}}
	hc := &harConn{delegate: fc, dir: dir, pending: make(map[string]*pendingRec)}

	ctx := context.Background()
	if _, err := hc.Read(ctx); err != nil {
		t.Fatalf("Read (request): %v", err)
	}

	hc.mu.Lock()
	pendingLen := len(hc.pending)
	hc.mu.Unlock()
	if pendingLen != 1 {
		t.Fatalf("after request: pending len = %d, want 1", pendingLen)
	}

	if _, err := hc.Read(ctx); err != nil {
		t.Fatalf("Read (response): %v", err)
	}

	hc.mu.Lock()
	pendingLen = len(hc.pending)
	hc.mu.Unlock()
	if pendingLen != 0 {
		t.Fatalf("after response: pending len = %d, want 0", pendingLen)
	}

	files := readDirTxt(t, dir)
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1 (request+response share one file): %v", len(files), files)
	}
	if !strings.HasPrefix(files[0], "tools_call_") {
		t.Errorf("filename %q missing sanitized method prefix tools_call_", files[0])
	}

	content := readFileContent(t, dir, files[0])
	if !strings.Contains(content, "REQUEST") {
		t.Error("file missing REQUEST block")
	}
	if !strings.Contains(content, "RESPONSE") {
		t.Error("file missing RESPONSE block")
	}
	if !strings.Contains(content, `"ok":true`) {
		t.Error("file missing response payload")
	}
}

func TestHarConn_Read_Notification_NotTrackedAsPending(t *testing.T) {
	dir := t.TempDir()
	// Zero-value ID is invalid -> notification semantics.
	note := &jsonrpc.Request{Method: "notifications/initialized"}

	fc := &fakeConn{readMsgs: []jsonrpc.Message{note}}
	hc := &harConn{delegate: fc, dir: dir, pending: make(map[string]*pendingRec)}

	if _, err := hc.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}

	hc.mu.Lock()
	pendingLen := len(hc.pending)
	hc.mu.Unlock()
	if pendingLen != 0 {
		t.Errorf("notification should not create a pending entry, got %d", pendingLen)
	}

	files := readDirTxt(t, dir)
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if !strings.HasPrefix(files[0], "notifications_initialized_") {
		t.Errorf("filename %q missing sanitized method prefix", files[0])
	}
	content := readFileContent(t, dir, files[0])
	if !strings.Contains(content, "REQUEST") {
		t.Error("file missing REQUEST block")
	}
	if strings.Contains(content, "RESPONSE") {
		t.Error("notification file should have no RESPONSE block")
	}
}

func TestHarConn_Read_OrphanResponse(t *testing.T) {
	dir := t.TempDir()
	id := mustID(t, float64(99))
	resp := &jsonrpc.Response{ID: id, Result: json.RawMessage(`{}`)}

	fc := &fakeConn{readMsgs: []jsonrpc.Message{resp}}
	hc := &harConn{delegate: fc, dir: dir, pending: make(map[string]*pendingRec)}

	if _, err := hc.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}

	files := readDirTxt(t, dir)
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if !strings.HasPrefix(files[0], "orphan_response_") {
		t.Errorf("filename %q missing orphan_response_ prefix", files[0])
	}
}

func TestHarConn_Close_FlushesPendingAsError(t *testing.T) {
	dir := t.TempDir()
	id := mustID(t, float64(7))
	req := &jsonrpc.Request{ID: id, Method: "tools/call"}

	fc := &fakeConn{readMsgs: []jsonrpc.Message{req}}
	hc := &harConn{delegate: fc, dir: dir, pending: make(map[string]*pendingRec)}

	if _, err := hc.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if err := hc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fc.closed {
		t.Error("Close should call through to delegate.Close")
	}

	hc.mu.Lock()
	pendingNil := hc.pending == nil
	hc.mu.Unlock()
	if !pendingNil {
		t.Error("Close should nil out pending map")
	}

	files := readDirTxt(t, dir)
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	content := readFileContent(t, dir, files[0])
	if !strings.Contains(content, "connection closed before response") {
		t.Errorf("expected close-flush error text, got: %s", content)
	}
}

func TestHarConn_Close_DelegateErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	fc := &fakeConn{closeErr: errors.New("close failed")}
	hc := &harConn{delegate: fc, dir: dir, pending: make(map[string]*pendingRec)}

	if err := hc.Close(); err == nil {
		t.Fatal("expected delegate close error to propagate")
	}
}

// --- harConn.Write (outgoing) --------------------------------------------

func TestHarConn_Write_RequestThenResponse_Pairs(t *testing.T) {
	dir := t.TempDir()
	id := mustID(t, "abc")
	req := &jsonrpc.Request{ID: id, Method: "sampling/createMessage"}
	resp := &jsonrpc.Response{ID: id, Result: json.RawMessage(`{"text":"hi"}`)}

	fc := &fakeConn{}
	hc := &harConn{delegate: fc, dir: dir, pending: make(map[string]*pendingRec)}
	ctx := context.Background()

	if err := hc.Write(ctx, req); err != nil {
		t.Fatalf("Write (request): %v", err)
	}
	if err := hc.Write(ctx, resp); err != nil {
		t.Fatalf("Write (response): %v", err)
	}

	if len(fc.written) != 2 {
		t.Fatalf("delegate received %d messages, want 2", len(fc.written))
	}

	files := readDirTxt(t, dir)
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if !strings.HasPrefix(files[0], "sampling_createMessage_") {
		t.Errorf("filename %q missing sanitized method prefix", files[0])
	}
	content := readFileContent(t, dir, files[0])
	if !strings.Contains(content, `"text":"hi"`) {
		t.Error("file missing response payload")
	}
}

func TestHarConn_Write_DelegateError_StillRecords(t *testing.T) {
	// recordOutgoing runs unconditionally before delegate.Write, so even a
	// failed write should still leave an audit record on disk.
	dir := t.TempDir()
	id := mustID(t, float64(5))
	req := &jsonrpc.Request{ID: id, Method: "tools/call"}

	fc := &fakeConn{writeErr: errors.New("pipe broken")}
	hc := &harConn{delegate: fc, dir: dir, pending: make(map[string]*pendingRec)}

	if err := hc.Write(context.Background(), req); err == nil {
		t.Fatal("expected delegate write error to propagate")
	}

	files := readDirTxt(t, dir)
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1 even on write error", len(files))
	}
}

func TestHarConn_Read_DelegateError_NoRecord(t *testing.T) {
	dir := t.TempDir()
	fc := &fakeConn{readErr: errors.New("read failed")}
	hc := &harConn{delegate: fc, dir: dir, pending: make(map[string]*pendingRec)}

	if _, err := hc.Read(context.Background()); err == nil {
		t.Fatal("expected read error to propagate")
	}

	files := readDirTxt(t, dir)
	if len(files) != 0 {
		t.Errorf("delegate read error should not produce a record, got %d files", len(files))
	}
}

func TestHarConn_SessionID_Passthrough(t *testing.T) {
	fc := &fakeConn{sessionID: "session-xyz"}
	hc := &harConn{delegate: fc, dir: t.TempDir(), pending: make(map[string]*pendingRec)}
	if got := hc.SessionID(); got != "session-xyz" {
		t.Errorf("SessionID() = %q, want %q", got, "session-xyz")
	}
}

// --- sanitizeMethod / idString / mustUUIDv7 -------------------------------

func TestSanitizeMethod(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"slash separator", "tools/call", "tools_call"},
		{"multi slash", "notifications/initialized", "notifications_initialized"},
		{"empty", "", ""},
		{"spaces and punctuation", "a b!c@d", "a_b_c_d"},
		{"already safe", "foo.bar-baz_1", "foo.bar-baz_1"},
		{"alnum only", "Method123", "Method123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeMethod(tt.in); got != tt.want {
				t.Errorf("sanitizeMethod(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIdString(t *testing.T) {
	t.Run("invalid/zero ID", func(t *testing.T) {
		var id jsonrpc.ID
		if got := idString(id); got != "" {
			t.Errorf("idString(zero) = %q, want empty", got)
		}
	})

	// jsonrpc.ID (alias for internal jsonrpc2.ID) defines MarshalJSON on a
	// POINTER receiver over unexported fields, so idString must marshal &id to
	// invoke it — yielding the underlying scalar (a quoted string or a bare
	// number), which the trailing quote-trim reduces to the canonical key.
	// Distinct IDs therefore produce distinct keys (required for correct
	// request/response pairing of concurrent in-flight requests).
	t.Run("string ID yields the string value", func(t *testing.T) {
		id := mustID(t, "abc")
		if got := idString(id); got != "abc" {
			t.Errorf("idString(string) = %q, want %q", got, "abc")
		}
	})

	t.Run("numeric ID yields the number", func(t *testing.T) {
		id := mustID(t, float64(42))
		if got := idString(id); got != "42" {
			t.Errorf("idString(numeric) = %q, want %q", got, "42")
		}
	})

	t.Run("distinct valid IDs produce distinct keys", func(t *testing.T) {
		a := mustID(t, "abc")
		b := mustID(t, float64(42))
		if idString(a) == idString(b) {
			t.Fatalf("distinct IDs must not collide, both = %q", idString(a))
		}
	})
}

func TestMustUUIDv7_ProducesParsableUUID(t *testing.T) {
	got := mustUUIDv7()
	if got == "" {
		t.Fatal("mustUUIDv7 returned empty string")
	}
	parsed, err := uuid.Parse(got)
	if err != nil {
		t.Fatalf("mustUUIDv7 produced unparsable UUID %q: %v", got, err)
	}
	if parsed.Version() != 7 {
		t.Errorf("mustUUIDv7 version = %d, want 7", parsed.Version())
	}
}

// --- HasSession ------------------------------------------------------------

func TestHasSession(t *testing.T) {
	resetSession(t)

	SetSession(nil, quietLogger())
	if HasSession() {
		t.Error("HasSession() = true, want false after SetSession(nil)")
	}

	ss := newStubHost(t, func(_ context.Context, _ *gomcp.CreateMessageRequest) (*gomcp.CreateMessageResult, error) {
		return &gomcp.CreateMessageResult{Content: &gomcp.TextContent{Text: "ok"}, Model: "m", Role: "assistant"}, nil
	})
	SetSession(ss, quietLogger())
	if !HasSession() {
		t.Error("HasSession() = false, want true after SetSession(non-nil)")
	}
}
