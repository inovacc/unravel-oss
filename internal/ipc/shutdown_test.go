/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

// TestServer_HandshakeReadDeadline pins #14: a peer that connects but never
// sends sys.hello must be dropped after the handshake deadline instead of
// pinning a goroutine forever.
func TestServer_HandshakeReadDeadline(t *testing.T) {
	prev := handshakeTimeout
	handshakeTimeout = 80 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = prev })

	s := NewServer()
	s.SetAuth("tok", okVerifier)

	srvConn, cliConn := net.Pipe()
	t.Cleanup(func() { _ = cliConn.Close() })

	done := make(chan struct{})
	go func() { s.ServeConn(context.Background(), srvConn); close(done) }()

	// Client connects but never writes the hello frame. ServeConn must return
	// once the handshake deadline elapses (net.Pipe honours SetReadDeadline).
	select {
	case <-done:
		// good — server gave up on the silent peer
	case <-time.After(2 * time.Second):
		t.Fatal("ServeConn did not return after handshake deadline; goroutine pinned")
	}
}

// TestServer_DisconnectCancelsHandlerCtx pins #5: when the client drops, the
// per-connection ctx threaded into in-flight handlers must be cancelled so
// long-running DB/CDP work can abort.
func TestServer_DisconnectCancelsHandlerCtx(t *testing.T) {
	s := NewServer()
	started := make(chan struct{})
	var gotCancel sync.WaitGroup
	gotCancel.Add(1)
	s.RegisterVerb("block", func(ctx context.Context, _ json.RawMessage) (any, *ErrorBody) {
		close(started)
		<-ctx.Done() // should unblock when the connection drops
		gotCancel.Done()
		return map[string]any{"ok": true}, nil
	})

	srvConn, cliConn := net.Pipe()
	go s.ServeConn(context.Background(), srvConn)

	// Fire a notification (no id ⇒ no response expected) to start the handler.
	id := int64(1)
	if err := WriteEnvelope(cliConn, Envelope{ID: &id, Method: "block", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never started")
	}

	// Drop the client. The per-connection ctx must cancel the handler.
	_ = cliConn.Close()

	doneCh := make(chan struct{})
	go func() { gotCancel.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
		// good — handler ctx was cancelled by the disconnect
	case <-time.After(2 * time.Second):
		t.Fatal("handler ctx not cancelled on client disconnect")
	}
}

// TestServer_ShutdownDrainsInFlight pins #17/#4/#6: Shutdown must wait for an
// in-flight handler to complete before returning.
func TestServer_ShutdownDrainsInFlight(t *testing.T) {
	s := NewServer()
	release := make(chan struct{})
	started := make(chan struct{})
	finished := make(chan struct{})
	s.RegisterVerb("slow", func(_ context.Context, _ json.RawMessage) (any, *ErrorBody) {
		close(started)
		<-release
		close(finished)
		return map[string]any{"ok": true}, nil
	})

	srvConn, cliConn := net.Pipe()
	t.Cleanup(func() { _ = cliConn.Close() })
	go s.ServeConn(context.Background(), srvConn)

	// Notification (nil ID) so dispatch does not try to write a reply back over
	// the unread net.Pipe and block — we only care about the drain semantics.
	if err := WriteEnvelope(cliConn, Envelope{Method: "slow", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	<-started

	shutdownReturned := make(chan struct{})
	go func() {
		_ = s.Shutdown(context.Background())
		close(shutdownReturned)
	}()

	// Shutdown must NOT return while the handler is still running.
	select {
	case <-shutdownReturned:
		t.Fatal("Shutdown returned before draining the in-flight handler")
	case <-time.After(150 * time.Millisecond):
	}

	close(release) // let the handler finish
	<-finished
	select {
	case <-shutdownReturned:
		// good — Shutdown returned only after the handler drained
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after in-flight handler finished")
	}
}

// TestServer_ShutdownBoundedByCtx pins the bounded-drain requirement: a wedged
// handler must not block Shutdown forever — it returns when ctx expires.
func TestServer_ShutdownBoundedByCtx(t *testing.T) {
	s := NewServer()
	started := make(chan struct{})
	s.RegisterVerb("wedged", func(_ context.Context, _ json.RawMessage) (any, *ErrorBody) {
		close(started)
		select {} // never returns
	})

	srvConn, cliConn := net.Pipe()
	t.Cleanup(func() { _ = cliConn.Close() })
	go s.ServeConn(context.Background(), srvConn)

	id := int64(1)
	if err := WriteEnvelope(cliConn, Envelope{ID: &id, Method: "wedged", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := s.Shutdown(ctx); err == nil {
		t.Fatal("Shutdown with wedged handler: want deadline error, got nil")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Shutdown took %v; should have honoured the 100ms deadline", elapsed)
	}
}

// TestServer_ShutdownRefusesNewDispatch pins that once draining, a new verb on
// an already-open connection is refused with CodeUnavailable rather than
// dispatched against a tearing-down owner.
func TestServer_ShutdownRefusesNewDispatch(t *testing.T) {
	s := NewServer()
	s.RegisterVerb("ping", func(_ context.Context, _ json.RawMessage) (any, *ErrorBody) {
		return map[string]any{"ok": true}, nil
	})
	srvConn, cliConn := net.Pipe()
	t.Cleanup(func() { _ = cliConn.Close() })
	go s.ServeConn(context.Background(), srvConn)

	// Begin draining with no in-flight work — returns immediately.
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	id := int64(7)
	if err := WriteEnvelope(cliConn, Envelope{ID: &id, Method: "ping", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = cliConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := ReadEnvelope(bufio.NewReader(cliConn))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != CodeUnavailable {
		t.Fatalf("want CodeUnavailable after Shutdown, got %+v", resp)
	}
}
