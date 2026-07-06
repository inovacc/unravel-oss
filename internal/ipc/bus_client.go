/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// ErrServerGone indicates the underlying connection closed mid-call.
var ErrServerGone = errors.New("ipc: server connection closed")

// Client is the multiplexed Bus implementation: many concurrent Call()s
// share one conn via id-keyed response routing.
type Client struct {
	conn     net.Conn
	nextID   atomic.Int64
	pending  map[int64]chan *Envelope
	mu       sync.Mutex
	writeMu  sync.Mutex
	closed   atomic.Bool
	readDone chan struct{}
}

// NewClient takes an established net.Conn and starts the reader goroutine.
// The caller retains ownership; Close() closes both reader and conn.
func NewClient(conn net.Conn) *Client {
	c := &Client{
		conn:     conn,
		pending:  make(map[int64]chan *Envelope),
		readDone: make(chan struct{}),
	}
	go c.readLoop()
	return c
}

func (c *Client) readLoop() {
	defer close(c.readDone)
	r := bufio.NewReader(c.conn)
	for {
		env, err := ReadEnvelope(r)
		if err == io.EOF {
			c.failAllPending(ErrServerGone)
			return
		}
		if err != nil {
			c.failAllPending(fmt.Errorf("bus_client: read: %w", err))
			return
		}
		if env.ID == nil {
			// Notification — v1 ignores; future: route to a notification handler.
			continue
		}
		c.mu.Lock()
		ch, ok := c.pending[*env.ID]
		if ok {
			delete(c.pending, *env.ID)
		}
		c.mu.Unlock()
		if ok {
			envCopy := env
			ch <- &envCopy
		}
	}
}

func (c *Client) failAllPending(err error) {
	c.mu.Lock()
	for id, ch := range c.pending {
		ch <- &Envelope{
			ID:    &[]int64{id}[0],
			Error: &ErrorBody{Code: CodeUnavailable, Message: err.Error()},
		}
		delete(c.pending, id)
	}
	c.mu.Unlock()
}

// Call performs a synchronous request/response over the bus.
func (c *Client) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if c.closed.Load() {
		return nil, ErrServerGone
	}
	id := c.nextID.Add(1)
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	req := Envelope{
		ID:     &id,
		Method: method,
		Params: paramsJSON,
	}

	ch := make(chan *Envelope, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()

	c.writeMu.Lock()
	err = WriteEnvelope(c.conn, req)
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("write request: %w", err)
	}

	select {
	case resp := <-ch:
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp.Result, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

// Notify sends a fire-and-forget notification (no id, no response wait).
func (c *Client) Notify(ctx context.Context, method string, params any) error {
	if c.closed.Load() {
		return ErrServerGone
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}
	req := Envelope{Method: method, Params: paramsJSON}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return WriteEnvelope(c.conn, req)
}

// NewAuthClient wraps conn, performs the mandatory sys.hello handshake with
// token, and returns a ready Client. On any handshake failure it closes the
// connection and returns an error. req.Token is overwritten with token.
func NewAuthClient(ctx context.Context, conn net.Conn, token string, req HelloRequest) (*Client, error) {
	c := NewClient(conn)
	req.Token = token
	if _, err := c.Call(ctx, MethodHello, req); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ipc auth handshake: %w", err)
	}
	return c, nil
}

// Close closes the underlying conn and stops the reader. Pending calls
// will receive ErrServerGone.
func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := c.conn.Close()
	<-c.readDone
	return err
}
