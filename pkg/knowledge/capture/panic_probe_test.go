//go:build kb_panic_probe

/*
Copyright (c) 2026 Security Research
*/

package capture

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/sandbox"
)

// TestSandbox_KillsChildOnPanic verifies that sandbox.RunWithTimeout
// kills the child process even when the orchestrator panics inside the
// supervised window. Per Phase 23 D-13 / D-19, defer-kill MUST fire on
// every return path and the child process MUST exit within 5s.
//
// Build-tagged so production CI does not exercise it (D-16). Run with:
//
//	go test -tags=kb_panic_probe ./pkg/knowledge/capture/... -run TestSandbox_KillsChildOnPanic
func TestSandbox_KillsChildOnPanic(t *testing.T) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd.exe", "/c", "ping", "-n", "60", "127.0.0.1")
	default:
		cmd = exec.Command("/bin/sh", "-c", "sleep 60")
	}

	done := make(chan error, 1)
	go func() {
		defer func() {
			r := recover()
			if r == nil {
				done <- errors.New("expected panic but got none")
				return
			}
			done <- nil
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sandbox.RunWithTimeout(ctx, cmd, sandbox.ProcessOptions{
			Timeout: 2 * time.Second,
			OnReady: func() { panic("simulated orchestrator panic") },
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("panic recovery: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("panic test did not complete within 10s")
	}

	// Within 5s of return the child MUST be reaped (D-19).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("child process did not exit within 5s after panic — D-19 violation")
}
