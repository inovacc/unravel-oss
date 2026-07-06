/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/internal/supervisor"
)

func findChildCmd(parent *cobra.Command, name string) *cobra.Command {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// TestDaemonServeCommandRegistered is the regression guard for the autospawn
// gap: internal/supervisor/autospawn.go execs `unravel daemon serve --detached`,
// so the binary MUST expose that command + flag or every thin-client KB/enrich
// tool fails with "supervisor unavailable".
func TestDaemonServeCommandRegistered(t *testing.T) {
	d := findChildCmd(rootCmd, "daemon")
	if d == nil {
		t.Fatal("daemon command not registered on rootCmd")
	}
	s := findChildCmd(d, "serve")
	if s == nil {
		t.Fatal("daemon serve subcommand not registered")
	}
	if s.Flags().Lookup("detached") == nil {
		t.Fatal("daemon serve missing --detached flag (autospawn passes it)")
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func waitDialReachable(t *testing.T, addr string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		conn, err := ipc.Dial(ctx, addr)
		cancel()
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// TestServeDaemon_StartsThenStopsOnCancel pins the lifecycle: serveDaemon binds
// the per-user endpoint (reachable), and returns nil once its context is
// cancelled (clean Stop). Uses an empty DSN so no DB is required.
func TestServeDaemon_StartsThenStopsOnCancel(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- serveDaemon(ctx, dir, "", quietLogger()) }()

	addr := supervisor.SocketPath(dir)
	if !waitDialReachable(t, addr, 4*time.Second) {
		cancel()
		t.Fatalf("supervisor never became reachable at %s", addr)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serveDaemon returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveDaemon did not return after context cancel")
	}
}

// TestServeDaemon_NoOpWhenAlreadyRunning pins the idempotency guard: a second
// serveDaemon against a live endpoint returns nil immediately rather than
// crashing on a double-bind (matters because autospawn may race).
func TestServeDaemon_NoOpWhenAlreadyRunning(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- serveDaemon(ctx, dir, "", quietLogger()) }()

	if !waitDialReachable(t, supervisor.SocketPath(dir), 4*time.Second) {
		t.Fatal("first supervisor never came up")
	}

	done := make(chan error, 1)
	go func() {
		c2, cancel2 := context.WithCancel(context.Background())
		defer cancel2()
		done <- serveDaemon(c2, dir, "", quietLogger())
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second serveDaemon should no-op nil, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second serveDaemon did not return (idempotency guard missing)")
	}

	cancel()
	<-errCh
}

// TestStartErrIsBenign pins the singleton contract: when Start reports that a
// peer already holds the host-singleton lock, `daemon serve` must treat it as a
// non-error ("detect the live endpoint and exit 0"), even when the sentinel is
// wrapped. Any other Start failure stays fatal so it surfaces / records a real
// spawn failure for the crash-loop guard.
func TestStartErrIsBenign(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not benign", nil, false},
		{"singleton-held is benign", supervisor.ErrSingletonHeld, true},
		{"wrapped singleton-held is benign", fmt.Errorf("daemon: start supervisor: %w", supervisor.ErrSingletonHeld), true},
		{"unrelated error is fatal", errors.New("bind listener: address in use"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := startErrIsBenign(tt.err); got != tt.want {
				t.Fatalf("startErrIsBenign(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
