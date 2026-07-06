/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

// TestRegisterVerb_CustomMethod confirms that custom verbs registered
// after New() are dispatched correctly via the wire layer.
func TestRegisterVerb_CustomMethod_DispatchedViaBus(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})

	sv.RegisterVerb("test.echo", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		return map[string]string{"echo": "hi"}, nil
	})

	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	go sv.server.ServeConn(context.Background(), srvConn)

	cli := ipc.NewClient(cliConn)
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := cli.Call(ctx, "test.echo", map[string]any{})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var out struct {
		Echo string `json:"echo"`
	}
	if err := json.Unmarshal(result, &out); err != nil {
		t.Fatal(err)
	}
	if out.Echo != "hi" {
		t.Errorf("echo = %q, want hi", out.Echo)
	}
}

func TestRegisterVerb_UnknownReturnsNotFound(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})

	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()
	go sv.server.ServeConn(context.Background(), srvConn)

	cli := ipc.NewClient(cliConn)
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := cli.Call(ctx, "no.such", nil)
	var eb *ipc.ErrorBody
	if !errors.As(err, &eb) || eb.Code != ipc.CodeNotFound {
		t.Errorf("err = %v, want CodeNotFound", err)
	}
}
