/*
Copyright (c) 2026 Security Research
*/

package mcptools

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// TestWatchProcessCancelsOnTargetExit verifies the parent-watcher polling
// loop calls cancel() within one poll interval of the watched process
// exiting. Spawns a short-lived `sleep`/`timeout` subprocess, kills it,
// and observes ctx.Done(). Skipped under -short because it spawns a
// real process (typically <2s wall-clock).
func TestWatchProcessCancelsOnTargetExit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: spawns a real subprocess")
	}

	// Spawn a sleeper. Use platform-appropriate command.
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// timeout returns immediately on stdin redirection; ping is more
		// reliable as a busy-wait sleeper.
		cmd = exec.Command("ping", "-n", "30", "127.0.0.1")
	} else {
		cmd = exec.Command("sleep", "30")
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleeper: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pollEvery := 200 * time.Millisecond
	done := make(chan struct{})
	go func() {
		watchProcess(ctx, cancel, pid, pollEvery, nil)
		close(done)
	}()

	// Give the watcher one tick to confirm the process is alive.
	time.Sleep(2 * pollEvery)
	select {
	case <-ctx.Done():
		t.Fatal("ctx cancelled before sleeper was killed")
	default:
	}

	// Kill the sleeper; watcher should detect within ~pollEvery and cancel.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill sleeper: %v", err)
	}
	_ = cmd.Wait()

	select {
	case <-ctx.Done():
		// expected
	case <-time.After(3 * time.Second):
		t.Fatal("ctx not cancelled within 3s of sleeper death")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchProcess goroutine did not return after cancel")
	}
}

// TestWatchProcessStopsOnCtxCancel verifies the polling goroutine exits
// when the caller cancels ctx (i.e. doesn't leak when the server shuts
// down for an unrelated reason).
func TestWatchProcessStopsOnCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	// Use PID 1 as a process that almost certainly exists for the test
	// duration. The watcher will keep polling until we cancel ctx.
	go func() {
		watchProcess(ctx, cancel, 1, 50*time.Millisecond, nil)
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchProcess did not exit after ctx cancel")
	}
}
