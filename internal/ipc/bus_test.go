/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func TestBus_PingRoundTrip(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	srv := NewServer()
	srv.RegisterVerb("ping", func(ctx context.Context, params json.RawMessage) (any, *ErrorBody) {
		return map[string]any{"ok": true}, nil
	})
	go srv.ServeConn(context.Background(), srvConn)

	cli := NewClient(cliConn)
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := cli.Call(ctx, "ping", map[string]any{})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}

	var out struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(result, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.OK {
		t.Errorf("ok = false, want true")
	}
}

func TestBus_UnknownMethod_ReturnsNotFound(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	srv := NewServer()
	go srv.ServeConn(context.Background(), srvConn)
	cli := NewClient(cliConn)
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := cli.Call(ctx, "no.such.verb", map[string]any{})
	if err == nil {
		t.Fatalf("Call: want err, got nil")
	}
	var eb *ErrorBody
	if !errors.As(err, &eb) {
		t.Fatalf("err = %v (%T), want *ErrorBody", err, err)
	}
	if eb.Code != CodeNotFound {
		t.Errorf("Code = %d, want %d", eb.Code, CodeNotFound)
	}
}

func TestBus_HandlerError_PropagatesCode(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	srv := NewServer()
	srv.RegisterVerb("err.invalid", func(ctx context.Context, params json.RawMessage) (any, *ErrorBody) {
		return nil, &ErrorBody{Code: CodeInvalidArg, Message: "bad input"}
	})
	go srv.ServeConn(context.Background(), srvConn)
	cli := NewClient(cliConn)
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := cli.Call(ctx, "err.invalid", map[string]any{})
	var eb *ErrorBody
	if !errors.As(err, &eb) {
		t.Fatalf("err = %v, want *ErrorBody", err)
	}
	if eb.Code != CodeInvalidArg {
		t.Errorf("Code = %d, want %d", eb.Code, CodeInvalidArg)
	}
}

func TestBus_HandlerPanic_ReturnsInternal(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	srv := NewServer()
	srv.RegisterVerb("boom", func(ctx context.Context, params json.RawMessage) (any, *ErrorBody) {
		panic("oh no")
	})
	go srv.ServeConn(context.Background(), srvConn)
	cli := NewClient(cliConn)
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := cli.Call(ctx, "boom", map[string]any{})
	var eb *ErrorBody
	if !errors.As(err, &eb) {
		t.Fatalf("err = %v, want *ErrorBody", err)
	}
	if eb.Code != CodeInternal {
		t.Errorf("Code = %d, want %d", eb.Code, CodeInternal)
	}
}

func TestBus_Notify_NoResponse(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	received := make(chan string, 1)
	srv := NewServer()
	srv.RegisterVerb("note.method", func(ctx context.Context, params json.RawMessage) (any, *ErrorBody) {
		received <- "hit"
		return nil, nil
	})
	go srv.ServeConn(context.Background(), srvConn)
	cli := NewClient(cliConn)
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cli.Notify(ctx, "note.method", map[string]any{}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	select {
	case <-received:
		// success — handler invoked
	case <-ctx.Done():
		t.Fatalf("notification handler not invoked within 2s")
	}
}
