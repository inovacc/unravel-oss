/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// Ensure is the public orchestration entry point: probe-first, kill+relaunch
// if needed, then wait-for-port until LaunchTimeout. Faithful port of the
// spectra cdpboot state machine (83-CONTEXT D-03).
//
// On wait-for-port timeout returns *LaunchTimeoutError carrying captured
// failure evidence — the D-09 honest BLOCK (errors.Is matches
// ErrCDPLaunchTimeout). There is no skip-cdp escape hatch and no fabricated
// Attached success.
func Ensure(ctx context.Context, t Target) (Attached, error) {
	t = t.defaults()
	return ensureWith(ctx, t, NewHost(t.Logger))
}

// ensureWith is the test seam — unit tests inject a fakeHost. Public Ensure
// wraps it with NewHost(t.Logger).
func ensureWith(ctx context.Context, t Target, host ProcessHost) (att Attached, err error) {
	// Defensive: the test seam injects via ensureWith directly (bypassing
	// Ensure's defaults()), so guarantee Logger/PollInterval/LaunchTimeout
	// are populated here too. Idempotent when Ensure already called it.
	t = t.defaults()
	started := time.Now()

	preset, ok := PresetFor(t.Kind)
	if !ok {
		return Attached{}, fmt.Errorf("webview2: unknown kind %q", t.Kind)
	}
	// Fill zero-valued Target fields from the preset (D-07 auto-detect with
	// per-kind override).
	if t.Port == 0 {
		t.Port = preset.Port
	}
	if t.Method == MethodDirect && preset.Method != MethodDirect {
		t.Method = preset.Method
	}
	if t.Method == MethodAUMID && t.AUMID == "" {
		t.AUMID = preset.AUMID
	}
	if t.URLContains == "" {
		t.URLContains = preset.URLContains
	}

	// AUMID cleanup must run on every exit path: success, error, panic
	// (D-04 transactional revert). Armed BEFORE Phase A — CleanupHKCUEnv
	// is idempotent.
	if t.Method == MethodAUMID {
		defer func() {
			r := recover()
			if cerr := host.CleanupHKCUEnv(context.Background()); cerr != nil {
				t.Logger.Warn("webview2.cleanup",
					"kind", t.Kind,
					"err", cerr.Error(),
				)
			}
			if r != nil {
				panic(r)
			}
		}()

		// CR-01 part 3: an os/signal handler so Ctrl-C / SIGTERM still
		// reverts HKCU before the process exits, narrowing the
		// unrecoverable leak window to SIGKILL / power-loss only. The
		// deferred recover-based revert above (D-04) remains the primary
		// path; this is an additional guard, not a replacement. Signal
		// delivery makes the process exit, so the deferred CleanupHKCUEnv
		// will NOT run — hence we revert here explicitly before re-raising
		// the default disposition.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		stopSig := make(chan struct{})
		defer func() {
			signal.Stop(sigCh)
			close(stopSig)
		}()
		go func() {
			select {
			case s := <-sigCh:
				t.Logger.Warn("webview2.signal.revert",
					"kind", t.Kind, "signal", s.String(),
					"note", "reverting HKCU before signal-driven exit")
				if cerr := host.CleanupHKCUEnv(context.Background()); cerr != nil {
					t.Logger.Warn("webview2.signal.revert.failed",
						"kind", t.Kind, "err", cerr.Error())
				}
				// Restore default disposition and re-raise so the process
				// exits with conventional signal semantics.
				signal.Stop(sigCh)
				if p, perr := os.FindProcess(os.Getpid()); perr == nil {
					_ = p.Signal(s)
				}
			case <-stopSig:
			}
		}()
	}

	// Phase A — probe-first. If port is up, return Spawned=false.
	if a, perr := Probe(ctx, t); perr == nil {
		t.Logger.Info("webview2.ready",
			"kind", t.Kind,
			"port", t.Port,
			"total_elapsed_ms", time.Since(started).Milliseconds(),
			"attempts", 1,
		)
		return a, nil
	}

	// Phase B — port down. Is the target already running?
	pids, ferr := host.Find(ctx, preset.ProcessName)
	if ferr != nil {
		return Attached{}, fmt.Errorf("webview2: find %s: %w", preset.ProcessName, ferr)
	}
	if len(pids) > 0 {
		if t.NoKill {
			return Attached{}, fmt.Errorf("%w: kind=%s pids=%v", ErrTargetRunningWithoutCDP, t.Kind, pids)
		}
		for _, pid := range pids {
			killStart := time.Now()
			if kerr := host.Kill(ctx, pid); kerr != nil {
				t.Logger.Warn("webview2.kill.failed",
					"kind", t.Kind, "pid", pid, "err", kerr.Error())
				continue
			}
			t.Logger.Info("webview2.kill",
				"kind", t.Kind, "pid", pid,
				"exit_elapsed_ms", time.Since(killStart).Milliseconds())
		}
		// Poll Find empty up to 3s so the next Spawn doesn't race with a
		// half-exited image.
		exitDeadline := time.Now().Add(3 * time.Second)
		var drainResidual []int
		var drainErr error
		drained := false
		for time.Now().Before(exitDeadline) {
			remaining, rerr := host.Find(ctx, preset.ProcessName)
			drainResidual, drainErr = remaining, rerr
			if rerr == nil && len(remaining) == 0 {
				drained = true
				break
			}
			select {
			case <-ctx.Done():
				return Attached{}, ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
		if !drained {
			// WR-05: drain deadline exceeded — the next Spawn may race a
			// half-exited image. Make it observable rather than silently
			// proceeding. For the strict NoKill case, surface an error.
			t.Logger.Warn("webview2.drain.deadline",
				"kind", t.Kind,
				"process", preset.ProcessName,
				"residual_pids", drainResidual,
				"last_err", fmt.Sprint(drainErr),
				"note", "proceeding to spawn with possible residual process — attach may race")
			if t.NoKill {
				return Attached{}, fmt.Errorf("%w: drain timeout, residual pids=%v last_err=%v",
					ErrTargetRunningWithoutCDP, drainResidual, drainErr)
			}
		}
	}

	// Phase C — spawn, dispatched on Method.
	var proc Process
	var exeOrAumid string
	switch t.Method {
	case MethodDirect:
		exePath := t.ExePath
		if exePath == "" {
			installLoc, rerr := host.ResolveExe(ctx, preset.PkgName)
			if rerr != nil {
				return Attached{}, fmt.Errorf("webview2: resolve exe: %w", rerr)
			}
			exePath = filepath.Join(installLoc, preset.ExeBasename)
		}
		exeOrAumid = exePath
		// Scoped loopback origin (origin.go) — same source of truth as the
		// HKCU path; never the any-origin wildcard (T-83-04-03 / IN-01).
		env := append(os.Environ(),
			"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="+browserArgs(t.Port),
		)
		proc, err = host.Spawn(ctx, exePath, env, nil)
		if err != nil {
			return Attached{}, fmt.Errorf("webview2: spawn %s: %w", exePath, err)
		}
	case MethodAUMID:
		aumid := t.AUMID
		if aumid == "" {
			aumid = preset.AUMID
		}
		if aumid == "" {
			return Attached{}, fmt.Errorf("webview2: aumid not set for kind %q", t.Kind)
		}
		exeOrAumid = aumid
		proc, err = host.SpawnAUMID(ctx, aumid, t.Port)
		if err != nil {
			// host.SpawnAUMID already wraps ErrUWPLaunch — wrap its error
			// once with %w to preserve the chain (WR-02), do not re-prefix
			// ErrUWPLaunch a second time.
			return Attached{}, fmt.Errorf("webview2: spawn aumid %s: %w", aumid, err)
		}
	default:
		return Attached{}, fmt.Errorf("webview2: unsupported method %v for kind %q", t.Method, t.Kind)
	}
	pid := proc.PID()
	t.Logger.Info("webview2.launch",
		"kind", t.Kind, "port", t.Port,
		"method", t.Method.String(),
		"exe_or_aumid", exeOrAumid, "pid", pid)

	// Phase D — wait-for-port. Re-probe at the top covers the Find→Spawn
	// race. D-09: one bounded retry on the flaky attach step before the
	// honest *LaunchTimeoutError BLOCK; never fabricate success.
	pollDeadline := started.Add(t.LaunchTimeout)
	var lastErr error
	attempts := 0
	attachRetried := false
	for time.Now().Before(pollDeadline) {
		attempts++
		a, perr := Probe(ctx, t)
		if perr == nil {
			_ = proc.Release()
			a.Spawned = true
			a.PID = pid
			t.Logger.Info("webview2.ready",
				"kind", t.Kind, "port", t.Port,
				"total_elapsed_ms", time.Since(started).Milliseconds(),
				"attempts", attempts)
			return a, nil
		}
		if !errors.Is(perr, ErrPortDown) &&
			!errors.Is(perr, context.Canceled) &&
			!errors.Is(perr, context.DeadlineExceeded) {
			// Unexpected (non-port-down) probe error: D-09 single bounded
			// retry before treating it as terminal evidence.
			if !attachRetried {
				attachRetried = true
				t.Logger.Warn("webview2.probe.retry",
					"kind", t.Kind, "err", perr.Error())
			} else {
				t.Logger.Debug("webview2.probe.unexpected_err",
					"kind", t.Kind, "err", perr.Error())
			}
		}
		lastErr = perr
		select {
		case <-ctx.Done():
			return Attached{}, ctx.Err()
		case <-time.After(t.PollInterval):
		}
	}
	elapsed := time.Since(started)
	t.Logger.Error("webview2.timeout",
		"kind", t.Kind, "port", t.Port,
		"exe_or_aumid", exeOrAumid,
		"elapsed_ms", elapsed.Milliseconds(),
		"last_err", fmt.Sprint(lastErr))
	// D-08/D-09 honest BLOCK: structured timeout with captured evidence,
	// no skip-cdp path, no fabricated Attached.
	return Attached{}, &LaunchTimeoutError{
		Kind:    t.Kind,
		Port:    t.Port,
		ExePath: exeOrAumid,
		Elapsed: elapsed,
		LastErr: lastErr,
	}
}
