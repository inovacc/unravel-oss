/*
Copyright (c) 2026 Security Research
*/

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// ErrProcessTimeout is returned when the supervised process exceeds the
// configured timeout.
var ErrProcessTimeout = errors.New("sandbox: process exceeded timeout")

// ProcessOptions configures RunWithTimeout.
type ProcessOptions struct {
	Timeout time.Duration // default 30s
	OnReady func()        // optional: invoked AFTER cmd.Start succeeds, BEFORE wait
}

// RunWithTimeout starts cmd, applies process-group isolation
// (best-effort, OS-dependent), and ensures the entire process group is
// killed when ctx expires, the timeout elapses, or the function
// returns. Returns ErrProcessTimeout on timeout, ctx.Err() on explicit
// cancel, or the process exit error otherwise.
//
// The supervisor takes ownership of cmd: callers MUST NOT have called
// cmd.Start() prior to this function.
//
// Per Phase 23 D-13: defer-kill on every return path.
func RunWithTimeout(ctx context.Context, cmd *exec.Cmd, opts ProcessOptions) error {
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	configureProcAttr(cmd) // OS-specific (process_unix.go / process_windows.go)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sandbox: start: %w", err)
	}

	// Always kill on return (D-13). Wait-goroutine started BEFORE
	// OnReady so a panic in OnReady still triggers cmd.Wait() once the
	// deferred kill fires and the child exits — keeping ProcessState
	// observable to D-19 leak checks.
	done := make(chan error, 1)
	waitStarted := make(chan struct{})
	go func() {
		close(waitStarted)
		done <- cmd.Wait()
	}()
	<-waitStarted

	defer killProcessGroup(cmd)

	if opts.OnReady != nil {
		opts.OnReady()
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("sandbox: wait: %w", err)
		}
		return nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ErrProcessTimeout
		}
		return ctx.Err()
	}
}

// ConfigureProcAttr exposes the OS-specific proc-attr setup so callers
// who need to manage process lifecycle outside RunWithTimeout (e.g.,
// the live-capture orchestrator that wraps the wait inside a CDP
// poll/capture loop) can still get process-group isolation.
func ConfigureProcAttr(cmd *exec.Cmd) { configureProcAttr(cmd) }

// KillProcessGroup exposes the OS-specific best-effort kill so
// orchestrators can defer-kill independently of RunWithTimeout.
func KillProcessGroup(cmd *exec.Cmd) { killProcessGroup(cmd) }
