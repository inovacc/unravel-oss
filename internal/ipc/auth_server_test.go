/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func okVerifier(net.Conn) (PeerInfo, error) { return PeerInfo{UID: "self", PID: 1}, nil }

func helloEnv(id int64, token string) Envelope {
	p, _ := json.Marshal(HelloRequest{Token: token, ClientVersion: "t", OS: "t", PID: 1})
	return Envelope{ID: &id, Method: MethodHello, Params: p}
}

func newAuthPair(t *testing.T, token string) (*Server, net.Conn) {
	t.Helper()
	s := NewServer()
	s.SetAuth(token, okVerifier)
	s.RegisterVerb("echo", func(_ context.Context, p json.RawMessage) (any, *ErrorBody) {
		return json.RawMessage(p), nil
	})
	srvConn, cliConn := net.Pipe()
	go s.ServeConn(context.Background(), srvConn)
	t.Cleanup(func() { _ = cliConn.Close() })
	return s, cliConn
}

func TestServeConn_VerbBeforeHelloRejected(t *testing.T) {
	_, cli := newAuthPair(t, "good")
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	id := int64(1)
	if err := WriteEnvelope(cli, Envelope{ID: &id, Method: "echo", Params: json.RawMessage(`"hi"`)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	env, err := ReadEnvelope(bufio.NewReader(cli))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if env.Error == nil || env.Error.Code != CodeUnauthorized {
		t.Fatalf("want CodeUnauthorized, got %+v", env)
	}
}

func TestServeConn_BadTokenRejected(t *testing.T) {
	_, cli := newAuthPair(t, "good")
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	if err := WriteEnvelope(cli, helloEnv(1, "WRONG")); err != nil {
		t.Fatalf("write: %v", err)
	}
	env, err := ReadEnvelope(bufio.NewReader(cli))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if env.Error == nil || env.Error.Code != CodeUnauthorized {
		t.Fatalf("want CodeUnauthorized, got %+v", env)
	}
}

func TestServeConn_GoodTokenThenVerb(t *testing.T) {
	_, cli := newAuthPair(t, "good")
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(cli)
	if err := WriteEnvelope(cli, helloEnv(1, "good")); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	hresp, err := ReadEnvelope(r)
	if err != nil || hresp.Error != nil {
		t.Fatalf("hello rejected: %+v err=%v", hresp, err)
	}
	id := int64(2)
	if err := WriteEnvelope(cli, Envelope{ID: &id, Method: "echo", Params: json.RawMessage(`"hi"`)}); err != nil {
		t.Fatalf("write echo: %v", err)
	}
	resp, err := ReadEnvelope(r)
	if err != nil || resp.Error != nil {
		t.Fatalf("echo failed: %+v err=%v", resp, err)
	}
	if string(resp.Result) != `"hi"` {
		t.Fatalf("echo result = %s, want \"hi\"", resp.Result)
	}
}

func TestServeConn_RepeatHelloIdempotent(t *testing.T) {
	_, cli := newAuthPair(t, "good")
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(cli)
	// First handshake.
	if err := WriteEnvelope(cli, helloEnv(1, "good")); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if h, err := ReadEnvelope(r); err != nil || h.Error != nil {
		t.Fatalf("first hello rejected: %+v err=%v", h, err)
	}
	// A second sys.hello on the authenticated conn is an idempotent re-affirm,
	// NOT a CodeNotFound for an unregistered verb.
	if err := WriteEnvelope(cli, helloEnv(2, "good")); err != nil {
		t.Fatalf("write second hello: %v", err)
	}
	resp, err := ReadEnvelope(r)
	if err != nil {
		t.Fatalf("read second hello resp: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("repeat hello should be idempotent, got error: %+v", resp.Error)
	}
	if resp.ID == nil || *resp.ID != 2 {
		t.Fatalf("repeat hello resp id = %v, want 2", resp.ID)
	}
}
