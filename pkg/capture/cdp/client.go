package cdp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"

	"github.com/gorilla/websocket"
)

// DiscoverTargetsTimeout bounds the /json HTTP enumeration in
// DiscoverTargets. A wedged WebView2/UWP CDP endpoint (notably WhatsApp
// Desktop mid-load) can accept the TCP socket but never send an HTTP
// response. http.DefaultClient has no Timeout and discovery routinely
// runs with an unbounded caller context (the bounded capture context is
// only established AFTER discovery — see scorecard/cdp_source.go), so
// without an explicit deadline the caller hangs forever (idle goroutine
// blocked on the HTTP read). This is an honest hard bound: a healthy
// local endpoint answers in well under a second, so 15s never weakens a
// real capture — it only turns an infinite stall into a fast, actionable
// error. Configurable so callers/tests can tune it.
// See .planning/debug/phase84-cdp-wait-hang-wa.md.
var DiscoverTargetsTimeout = 15 * time.Second

// Target represents a CDP debugging target.
type Target struct {
	ID                string `json:"id"`
	Type              string `json:"type"`
	Title             string `json:"title"`
	URL               string `json:"url"`
	WebSocketDebugURL string `json:"webSocketDebuggerUrl"`
}

// Client connects to a Chrome DevTools Protocol endpoint.
type Client struct {
	host   string
	conn   *websocket.Conn
	events chan capture.Event
	seqFn  func() int
	msgID  int64
	mu     sync.Mutex

	// handlers keyed by CDP method name. handlersMu guards concurrent
	// OnEvent registrations vs Listen-loop dispatch reads (race fix:
	// Listen.dispatchFrame iterates concurrently with OnEvent calls
	// from per-target subscribe helpers). RWMutex because dispatch is
	// the hot path and reads dominate writes.
	handlersMu sync.RWMutex
	handlers   map[string]func(json.RawMessage)

	// pending request/response demultiplex for SendAndWait (D-22).
	pendingMu sync.Mutex
	pending   map[int64]chan rpcResponse
}

// rpcResponse carries the decoded result/error for a CDP request/response RPC.
type rpcResponse struct {
	Result json.RawMessage
	Error  *rpcError
}

// rpcError mirrors the CDP error envelope shape.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// New creates a CDP client targeting the given host:port.
func New(host string, events chan capture.Event, seqFn func() int) *Client {
	return &Client{
		host:     host,
		events:   events,
		seqFn:    seqFn,
		handlers: make(map[string]func(json.RawMessage)),
		pending:  make(map[int64]chan rpcResponse),
	}
}

// DiscoverTargets fetches available debugging targets.
//
// Hard-bounded by DiscoverTargetsTimeout via BOTH a derived context
// deadline and a client-level http.Client.Timeout, so the bound holds
// regardless of how the caller wired ctx (this path frequently runs with
// an unbounded caller context). Without this, a wedged endpoint that
// accepts the socket but never answers hangs the caller forever — see
// .planning/debug/phase84-cdp-wait-hang-wa.md.
func (c *Client) DiscoverTargets(ctx context.Context) ([]Target, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	to := DiscoverTargetsTimeout
	if to <= 0 {
		to = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	url := fmt.Sprintf("http://%s/json", c.host)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Timeout: to}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discover targets: %w (is --remote-debugging-port enabled?)", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var targets []Target
	if err := json.Unmarshal(body, &targets); err != nil {
		return nil, fmt.Errorf("parse targets: %w", err)
	}
	return targets, nil
}

// Connect establishes a WebSocket connection to the given target.
func (c *Client) Connect(ctx context.Context, wsURL string) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", wsURL, err)
	}
	c.conn = conn
	return nil
}

// Close closes the WebSocket connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Send sends a CDP command and returns the result.
func (c *Client) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := atomic.AddInt64(&c.msgID, 1)

	msg := struct {
		ID     int64  `json:"id"`
		Method string `json:"method"`
		Params any    `json:"params,omitempty"`
	}{ID: id, Method: method, Params: params}

	c.mu.Lock()
	err := c.conn.WriteJSON(msg)
	c.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("send %s: %w", method, err)
	}

	// For fire-and-forget commands we don't wait for response
	return nil, nil
}

// SendAndWait sends a CDP command and blocks until the matching id-keyed
// response frame is decoded by Listen. Additive to Send (which remains
// fire-and-forget). Returns ctx.Err() on cancellation/deadline. (D-22)
func (c *Client) SendAndWait(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := atomic.AddInt64(&c.msgID, 1)
	ch := make(chan rpcResponse, 1)
	c.pendingMu.Lock()
	if c.pending == nil {
		c.pending = make(map[int64]chan rpcResponse)
	}
	c.pending[id] = ch
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
	}()

	msg := struct {
		ID     int64  `json:"id"`
		Method string `json:"method"`
		Params any    `json:"params,omitempty"`
	}{ID: id, Method: method, Params: params}

	c.mu.Lock()
	err := c.conn.WriteJSON(msg)
	c.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("send %s: %w", method, err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.Error != nil {
			return nil, fmt.Errorf("cdp %s: %d %s", method, r.Error.Code, r.Error.Message)
		}
		return r.Result, nil
	}
}

// OnEvent registers a handler for a CDP event method.
func (c *Client) OnEvent(method string, handler func(json.RawMessage)) {
	c.handlersMu.Lock()
	c.handlers[method] = handler
	c.handlersMu.Unlock()
}

// Listen reads CDP messages and dispatches to handlers. Blocks until ctx is
// cancelled or the connection closes. Uses blocking ReadMessage; cancellation
// is implemented by closing the conn from a watcher goroutine, which causes
// ReadMessage to return an error and the loop to exit. Per-read deadlines are
// avoided because gorilla/websocket marks the connection unrecoverable after
// any timeout, panicking on the next ReadMessage.
func (c *Client) Listen(ctx context.Context) error {
	// Listen is contractually spawned BEFORE ConnectAndAttach (SendAndWait
	// blocks on this dispatch loop), so c.conn may still be nil here while the
	// dialer handshake is in flight. Wait for Connect() to populate it instead
	// of dereferencing nil and panicking (see
	// .planning/debug/wa-cdp-listen-nil-conn-panic.md). Return a typed error so
	// the caller can emit an honest D-09 BLOCK rather than crash.
	for {
		c.mu.Lock()
		ready := c.conn != nil
		c.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("listen: websocket not connected before ctx done: %w", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			if c.conn != nil {
				_ = c.conn.Close()
			}
			c.mu.Unlock()
		case <-stop:
		}
	}()

	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return nil
			}
			return fmt.Errorf("read message: %w", err)
		}
		c.dispatchFrame(msg)
	}
}

// dispatchFrame decodes a CDP frame and routes it to either an event handler
// (event-shaped: {"method": ..., "params": ...}) or a SendAndWait pending
// channel (response-shaped: {"id": ..., "result": ..., "error": ...}).
// Wrapped in defer/recover per D-22 — a malformed frame must not panic the
// listen loop.
func (c *Client) dispatchFrame(msg []byte) {
	defer func() {
		_ = recover()
	}()

	var envelope struct {
		ID     int64           `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(msg, &envelope); err != nil {
		return
	}

	// Response-shaped frame: route by id.
	if envelope.ID != 0 && envelope.Method == "" {
		c.pendingMu.Lock()
		ch, ok := c.pending[envelope.ID]
		c.pendingMu.Unlock()
		if ok {
			select {
			case ch <- rpcResponse{Result: envelope.Result, Error: envelope.Error}:
			default:
			}
		}
		return
	}

	// Event-shaped frame: dispatch to registered handler.
	c.handlersMu.RLock()
	handler, ok := c.handlers[envelope.Method]
	c.handlersMu.RUnlock()
	if ok && envelope.Method != "" {
		handler(envelope.Params)
	}
}

// EnableDomains enables Network, Runtime, and Page CDP domains.
func (c *Client) EnableDomains(ctx context.Context) error {
	for _, domain := range []string{"Network.enable", "Runtime.enable", "Page.enable"} {
		if _, err := c.Send(ctx, domain, nil); err != nil {
			return err
		}
	}
	return nil
}

// Emit sends a capture event to the event channel (non-blocking).
func (c *Client) Emit(evt capture.Event) {
	select {
	case c.events <- evt:
	default:
	}
}

func isTimeout(err error) bool {
	if ne, ok := err.(interface{ Timeout() bool }); ok {
		return ne.Timeout()
	}
	return false
}
