/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"context"
	"log/slog"
)

// Process is an abstract handle for a spawned child. Ensure does not call
// Wait — the wait-for-port loop owns lifecycle observation; Release detaches
// from the OS handle on success so file descriptors don't leak.
//
// MethodAUMID launches return a nil-handle Process whose PID is 0 because
// the Windows COM activation broker detaches from the parent immediately.
type Process interface {
	// PID returns the OS process id, or 0 for broker-detached AUMID launches.
	PID() int
	// Wait blocks until the process exits. webview2 does not call this.
	Wait() error
	// Release detaches without killing — Ensure calls this on success.
	Release() error
}

// ProcessHost is the single OS-mediation seam (D-03). The Windows
// implementation (83-04) shells out to tasklist / taskkill / powershell;
// the unit-test seam injects a fakeHost.
type ProcessHost interface {
	// Find returns PIDs of processes whose IMAGENAME matches processName.
	// Empty result is (nil, nil), not an error.
	Find(ctx context.Context, processName string) ([]int, error)

	// Kill terminates pid and its child tree. Exit code 128 is
	// non-fatal (process already exited).
	Kill(ctx context.Context, pid int) error

	// ResolveExe returns the InstallLocation for pkgName via
	// Get-AppxPackage. Caller appends ExeBasename.
	ResolveExe(ctx context.Context, pkgName string) (string, error)

	// Spawn launches exe with env (incl. WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
	// for MethodDirect) and args.
	Spawn(ctx context.Context, exe string, env []string, args []string) (Process, error)

	// SpawnAUMID launches a true-UWP target via shell:AppsFolder: the
	// HKCU\Environment set + WM_SETTINGCHANGE broadcast + Start-Process
	// sequence. Returns a Process whose PID is 0 (broker detaches).
	// Caller must invoke CleanupHKCUEnv on every exit path.
	SpawnAUMID(ctx context.Context, aumid string, port int) (Process, error)

	// CleanupHKCUEnv removes WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS from
	// HKCU\Environment and re-broadcasts WM_SETTINGCHANGE. Idempotent,
	// best-effort.
	CleanupHKCUEnv(ctx context.Context) error
}

// NewHost returns a ProcessHost for the current platform. Windows builds
// (83-04) get the real implementation; non-Windows builds get a stub whose
// every method returns ErrUnsupportedPlatform. Dispatch via the
// build-tagged newPlatformHost.
func NewHost(logger *slog.Logger) ProcessHost {
	if logger == nil {
		logger = slog.Default()
	}
	return newPlatformHost(logger)
}
