/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

func TestSupervisor_Start_WritesTokenAndEnforcesAuth(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sv.Stop() }()

	tokenPath := filepath.Join(tmp, "token")
	tokBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("token file not written: %v", err)
	}
	token := string(tokBytes)
	if len(token) < 40 {
		t.Fatalf("token too short: %q", token)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Good token → ping works.
	conn, err := ipc.Dial(ctx, sv.SocketPath())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cli, err := ipc.NewAuthClient(ctx, conn, token, ipc.HelloRequest{ClientVersion: "test", OS: "test", PID: os.Getpid()})
	if err != nil {
		t.Fatalf("auth with good token failed: %v", err)
	}
	if _, err := cli.Call(ctx, "ping", struct{}{}); err != nil {
		t.Fatalf("ping after auth: %v", err)
	}
	_ = cli.Close()

	// Wrong token → rejected.
	conn2, err := ipc.Dial(ctx, sv.SocketPath())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	if _, err := ipc.NewAuthClient(ctx, conn2, "WRONG-TOKEN", ipc.HelloRequest{ClientVersion: "test", OS: "test", PID: os.Getpid()}); err == nil {
		t.Fatal("auth with wrong token: want error, got nil")
	}
}

func TestSupervisor_Stop_RemovesToken(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})
	if err := sv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	tokenPath := filepath.Join(tmp, "token")
	if _, err := os.Stat(tokenPath); err != nil {
		t.Fatalf("token should exist after Start: %v", err)
	}
	if err := sv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("token should be removed after Stop, stat err = %v", err)
	}
}
