/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

// TestSupervisor_StopDrainsInFlightVerb pins #4/#6: a verb still running when
// Stop() begins must be drained before Stop returns and the DB pool / lock are
// torn down. Run under -race to catch any field race on shutdown.
func TestSupervisor_StopDrainsInFlightVerb(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp, IdleTimeout: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	release := make(chan struct{})
	started := make(chan struct{})
	finished := make(chan struct{})
	sv.server.RegisterVerb("test.slow", func(_ context.Context, _ json.RawMessage) (any, *ipc.ErrorBody) {
		close(started)
		<-release
		close(finished)
		return map[string]any{"ok": true}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	tok, err := os.ReadFile(sv.cfg.SocketDir + string(os.PathSeparator) + "token")
	if err != nil {
		t.Fatalf("read token: %v", err)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dcancel()
	conn, err := ipc.Dial(dctx, sv.SocketPath())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cli, err := ipc.NewAuthClient(dctx, conn, string(tok), ipc.HelloRequest{ClientVersion: "t", OS: "t", PID: os.Getpid()})
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer func() { _ = cli.Close() }()

	// Fire the slow verb as a notification so the call doesn't block on a reply.
	go func() { _ = cli.Notify(context.Background(), "test.slow", struct{}{}) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("slow verb never started")
	}

	stopReturned := make(chan struct{})
	go func() { _ = sv.Stop(); close(stopReturned) }()

	// Stop must block until the in-flight handler drains.
	select {
	case <-stopReturned:
		t.Fatal("Stop returned before draining the in-flight verb")
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	<-finished
	select {
	case <-stopReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return after the verb drained")
	}
}

// TestSupervisor_StopConcurrentNoPanic pins #16: Stop must be safe to call
// from many goroutines at once without a double-close panic on stopCh.
func TestSupervisor_StopConcurrentNoPanic(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp, IdleTimeout: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sv.Stop() // must never panic, even when racing
		}()
	}
	wg.Wait()
}

// TestSupervisor_IdleWatcherExits pins #18: when ExitWhenIdle is set and the
// daemon has been idle (no agents, no recent activity) past IdleTimeout, the
// idle watcher triggers the injected shutdown hook exactly once.
func TestSupervisor_IdleWatcherExits(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{
		SocketDir:    tmp,
		IdleTimeout:  60 * time.Millisecond,
		ExitWhenIdle: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	exited := make(chan struct{}, 1)
	sv.onIdleExit = func() { exited <- struct{}{} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sv.Stop() }()

	select {
	case <-exited:
		// good — idle watcher fired the exit hook
	case <-time.After(2 * time.Second):
		t.Fatal("idle watcher never triggered exit despite zero agents past IdleTimeout")
	}
}

// TestSupervisor_IdleWatcherNoExitWhenDisabled confirms the default (off)
// preserves the previous no-exit behaviour so tests/long-lived daemons are
// not killed unexpectedly.
func TestSupervisor_IdleWatcherNoExitWhenDisabled(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{
		SocketDir:   tmp,
		IdleTimeout: 30 * time.Millisecond,
		// ExitWhenIdle defaults false
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fired := make(chan struct{}, 1)
	sv.onIdleExit = func() { fired <- struct{}{} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sv.Stop() }()

	select {
	case <-fired:
		t.Fatal("idle exit fired despite ExitWhenIdle=false")
	case <-time.After(200 * time.Millisecond):
		// good — no exit when disabled
	}
}
