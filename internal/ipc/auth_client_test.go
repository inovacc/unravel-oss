/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestNewAuthClient_GoodTokenWorks(t *testing.T) {
	s := NewServer()
	s.SetAuth("good", okVerifier)
	s.RegisterVerb("echo", func(_ context.Context, p json.RawMessage) (any, *ErrorBody) {
		return json.RawMessage(p), nil
	})
	srvConn, cliConn := net.Pipe()
	go s.ServeConn(context.Background(), srvConn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cli, err := NewAuthClient(ctx, cliConn, "good", HelloRequest{ClientVersion: "t", OS: "t", PID: 1})
	if err != nil {
		t.Fatalf("NewAuthClient: %v", err)
	}
	defer func() { _ = cli.Close() }()

	out, err := cli.Call(ctx, "echo", "hi")
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if string(out) != `"hi"` {
		t.Fatalf("echo = %s, want \"hi\"", out)
	}
}

func TestNewAuthClient_BadTokenFails(t *testing.T) {
	s := NewServer()
	s.SetAuth("good", okVerifier)
	srvConn, cliConn := net.Pipe()
	go s.ServeConn(context.Background(), srvConn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := NewAuthClient(ctx, cliConn, "WRONG", HelloRequest{ClientVersion: "t", OS: "t", PID: 1}); err == nil {
		t.Fatal("NewAuthClient with bad token: want error, got nil")
	}
}
