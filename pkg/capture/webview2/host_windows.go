//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// hideConsoleAttr returns a SysProcAttr that prevents Windows from
// allocating a console window for the child process. Without this, every
// PowerShell / tasklist / taskkill / Spawn() invocation briefly flashes a
// conhost.exe window — which during heavy operation (daemon mode, agent
// fanout) makes the desktop unusable. CREATE_NO_WINDOW (0x08000000) is the
// load-bearing flag; HideWindow is belt-and-braces for shell verbs that
// honor SW_HIDE.
func hideConsoleAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
		HideWindow:    true,
	}
}

// hkcuEnvValueName is the HKCU\Environment value the launcher transiently
// writes so the WebView2 runtime (and the UWP COM activation broker) picks
// up the remote-debugging args. CleanupHKCUEnv removes the WHOLE value so
// --remote-allow-origins=* is never persisted (T-83-04-03).
const hkcuEnvValueName = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"

// hkcuEnvKeyPath is the per-user environment key. Pure-Go registry access
// (golang.org/x/sys/windows/registry) — no CGO, no PowerShell (RESEARCH
// Pattern 1, PATTERNS 133-143).
const hkcuEnvKeyPath = `Environment`

// envArgValue is the exact value written to HKCU\Environment. The debug
// port is 127.0.0.1-bound by the CDP client host literal AND the
// --remote-allow-origins allowlist is scoped to the exact loopback origin
// the in-repo cdp client connects with (http://127.0.0.1:PORT) — a
// wildcard (`*`) is NEVER written to a persistent hive value (CR-01). The
// whole value is reverted by CleanupHKCUEnv immediately after attach; if
// the revert is lost (hard kill), only this scoped loopback origin — not
// any-origin — can ever leak.
// It now delegates to the portable browserArgs (origin.go) so the HKCU
// path and the MethodDirect process-env path (ensure.go) cannot diverge
// (review IN-01 / T-83-04-03).
func envArgValue(port int) string {
	return browserArgs(port)
}

// isUnravelTaggedValue reports whether v is a value this launcher could
// have written — the "unravel tag" used by D-04 revert and D-05 self-heal
// to distinguish our transient value from an operator-set one. We require
// the --remote-debugging-port= prefix AND a scoped loopback
// --remote-allow-origins=http://127.0.0.1: allowlist. The legacy wildcard
// form (--remote-allow-origins=*) written by pre-CR-01 builds is ALSO
// matched so self-heal still reverts a value leaked by an older binary; an
// operator value missing the port prefix, or carrying a non-loopback
// origin, is left untouched.
func isUnravelTaggedValue(v string) bool {
	if !strings.HasPrefix(v, "--remote-debugging-port=") {
		return false
	}
	return strings.Contains(v, "--remote-allow-origins=http://127.0.0.1:") ||
		strings.Contains(v, "--remote-allow-origins=*")
}

// envRegistry is the HKCU\Environment seam. The production implementation
// (winEnvRegistry) uses golang.org/x/sys/windows/registry; unit tests inject
// a fakeRegistry (host_windows_test.go) so the D-04 transactional revert and
// D-05 self-heal logic are exercised without touching the real user hive.
type envRegistry interface {
	// Get returns (value, present). present=false maps to
	// registry.ErrNotExist on the production path.
	Get() (string, bool, error)
	// Set writes value (creating the value if absent).
	Set(value string) error
	// Delete removes the value entirely. Absent → no error (idempotent).
	Delete() error
}

// winEnvRegistry is the production envRegistry over HKCU\Environment.
type winEnvRegistry struct{}

func (winEnvRegistry) Get() (string, bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, hkcuEnvKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return "", false, fmt.Errorf("webview2/windows: open HKCU\\Environment (query): %w", err)
	}
	defer func() { _ = k.Close() }()
	v, _, getErr := k.GetStringValue(hkcuEnvValueName)
	if getErr != nil {
		if errors.Is(getErr, registry.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("webview2/windows: get %s: %w", hkcuEnvValueName, getErr)
	}
	return v, true, nil
}

func (winEnvRegistry) Set(value string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, hkcuEnvKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("webview2/windows: open HKCU\\Environment (set): %w", err)
	}
	defer func() { _ = k.Close() }()
	if err := k.SetStringValue(hkcuEnvValueName, value); err != nil {
		return fmt.Errorf("webview2/windows: set %s: %w", hkcuEnvValueName, err)
	}
	return nil
}

func (winEnvRegistry) Delete() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, hkcuEnvKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("webview2/windows: open HKCU\\Environment (delete): %w", err)
	}
	defer func() { _ = k.Close() }()
	if err := k.DeleteValue(hkcuEnvValueName); err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("webview2/windows: delete %s: %w", hkcuEnvValueName, err)
	}
	return nil
}

// broadcastFn broadcasts WM_SETTINGCHANGE so the COM activation broker (and
// new processes) re-read the user environment. The production impl uses the
// user32.dll SendMessageTimeoutW lazy proc; tests inject a no-op.
type broadcastFn func() error

const (
	hwndBroadcast   = 0xffff // HWND_BROADCAST
	wmSettingChange = 0x001A // WM_SETTINGCHANGE
	smtoAbortIfHung = 0x0002 // SMTO_ABORTIFHUNG
	settingTimeout  = 5000   // ms
)

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	procSendMessageTimeoutW = user32.NewProc("SendMessageTimeoutW")
)

// winBroadcastSettingChange invokes user32!SendMessageTimeoutW with
// HWND_BROADCAST / WM_SETTINGCHANGE / lParam="Environment". Pure-Go via the
// x/sys/windows lazy-DLL seam (RESEARCH Pattern 2) — no CGO.
func winBroadcastSettingChange() error {
	lParam, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return fmt.Errorf("webview2/windows: utf16 Environment: %w", err)
	}
	var result uintptr
	ret, _, callErr := procSendMessageTimeoutW.Call(
		uintptr(hwndBroadcast),
		uintptr(wmSettingChange),
		0,
		uintptr(unsafe.Pointer(lParam)),
		uintptr(smtoAbortIfHung),
		uintptr(settingTimeout),
		uintptr(unsafe.Pointer(&result)),
	)
	if ret == 0 {
		// SendMessageTimeout returns 0 on failure/timeout. Best-effort:
		// surface as a wrapped error; callers log-and-continue.
		return fmt.Errorf("webview2/windows: SendMessageTimeoutW failed: %w", callErr)
	}
	return nil
}

// windowsHost is the production ProcessHost on Windows. It performs the
// no-admin launch sequence: pure-Go HKCU\Environment snapshot/set + a
// WM_SETTINGCHANGE broadcast + shell:AppsFolder activation (MethodAUMID) or
// a per-process env exec (MethodDirect), with a transactional revert that
// runs on every exit path including panic (D-04, via Ensure's deferred
// CleanupHKCUEnv).
type windowsHost struct {
	logger    *slog.Logger
	reg       envRegistry
	broadcast broadcastFn
	exeCache  sync.Map // pkgName → InstallLocation

	// snapMu guards the HKCU snapshot captured by SetHKCUEnv and replayed
	// by CleanupHKCUEnv.
	snapMu      sync.Mutex
	snapTaken   bool
	snapPrev    string
	snapPresent bool
}

// newPlatformHost is the windows-tagged factory used by NewHost. It wires
// the production registry + broadcast seams. 83-04 real implementation.
func newPlatformHost(logger *slog.Logger) ProcessHost {
	if logger == nil {
		logger = slog.Default()
	}
	return &windowsHost{
		logger:    logger,
		reg:       winEnvRegistry{},
		broadcast: winBroadcastSettingChange,
	}
}

// newTestHost builds a windowsHost over injected seams (host_windows_test.go).
func newTestHost(logger *slog.Logger, reg envRegistry, b broadcastFn) *windowsHost {
	if logger == nil {
		logger = slog.Default()
	}
	if b == nil {
		b = func() error { return nil }
	}
	return &windowsHost{logger: logger, reg: reg, broadcast: b}
}

// SetHKCUEnv snapshots the prior HKCU\Environment value (capturing absence
// distinctly via errors.Is(registry.ErrNotExist) on the production path),
// writes the transient remote-debugging value, then broadcasts
// WM_SETTINGCHANGE. The snapshot is stored on the host so CleanupHKCUEnv
// replays it exactly (D-04 transactional revert).
func (h *windowsHost) SetHKCUEnv(_ context.Context, port int) error {
	prev, present, err := h.reg.Get()
	if err != nil {
		return fmt.Errorf("webview2/windows: snapshot HKCU env: %w", err)
	}
	h.snapMu.Lock()
	// Only take the snapshot once — if SetHKCUEnv is somehow called twice
	// keep the ORIGINAL operator state, never our own tagged value.
	if !h.snapTaken {
		h.snapTaken = true
		h.snapPrev = prev
		h.snapPresent = present
	}
	h.snapMu.Unlock()

	val := envArgValue(port)
	if err := h.reg.Set(val); err != nil {
		return fmt.Errorf("webview2/windows: set HKCU env: %w", err)
	}
	// CR-01: loud WARN so an operator interrupted before the deferred /
	// signal-handler revert (or a SIGKILL/power-loss) can manually restore
	// the hive. Includes the exact value and value-name written.
	h.logger.Warn("webview2.hkcu.live",
		"value_name", hkcuEnvValueName,
		"value", val,
		"note", "HKCU\\Environment value is LIVE until cleanup; if this process is hard-killed, "+
			"delete it manually or re-run unravel (self-heal reverts it on next start)",
	)
	if berr := h.broadcast(); berr != nil {
		h.logger.Warn("webview2.hkcu.broadcast.set", "err", berr.Error())
	}
	return nil
}

// CleanupHKCUEnv replays the snapshot taken by SetHKCUEnv: if the prior
// state was absent → DeleteValue; otherwise restore the prior value. Then it
// re-broadcasts WM_SETTINGCHANGE. Idempotent — safe to call repeatedly
// (D-04 deferred + D-05 self-heal both reuse it) and a no-op on the
// MethodDirect path where SetHKCUEnv was never called.
func (h *windowsHost) CleanupHKCUEnv(_ context.Context) error {
	h.snapMu.Lock()
	taken := h.snapTaken
	prev := h.snapPrev
	present := h.snapPresent
	h.snapMu.Unlock()

	if !taken {
		// MethodDirect / never-set: only revert if a stale unravel-tagged
		// value is sitting there (defensive; D-05 normally handles this).
		cur, curPresent, gerr := h.reg.Get()
		if gerr != nil {
			// WR-01: a registry read failure here must be observable, not
			// silently swallowed as "nothing to heal" — a stale tagged
			// value may still be present and undetected.
			h.logger.Warn("webview2.hkcu.cleanup.read_failed",
				"err", gerr.Error(),
				"note", "could not read HKCU env during cleanup; a stale unravel-tagged value may remain")
			return nil
		}
		if !curPresent || !isUnravelTaggedValue(cur) {
			return nil
		}
		if derr := h.reg.Delete(); derr != nil {
			return fmt.Errorf("webview2/windows: cleanup delete: %w", derr)
		}
		if berr := h.broadcast(); berr != nil {
			h.logger.Warn("webview2.hkcu.broadcast.cleanup", "err", berr.Error())
		}
		return nil
	}

	var opErr error
	if !present {
		opErr = h.reg.Delete()
	} else {
		opErr = h.reg.Set(prev)
	}
	if opErr != nil {
		return fmt.Errorf("webview2/windows: cleanup restore: %w", opErr)
	}
	if berr := h.broadcast(); berr != nil {
		h.logger.Warn("webview2.hkcu.broadcast.cleanup", "err", berr.Error())
	}
	// Clear the snapshot so a second call is a clean no-op (idempotent).
	h.snapMu.Lock()
	h.snapTaken = false
	h.snapMu.Unlock()
	return nil
}

// validateProcessName returns an error when processName contains characters
// that are invalid in a Windows image name or could corrupt the tasklist /FI
// filter string.  Windows process image names are restricted to alphanumeric,
// hyphen, dot, underscore, and the extension separator — no quotes, spaces, or
// shell metacharacters.
func validateProcessName(name string) error {
	if name == "" {
		return fmt.Errorf("webview2/windows: empty process name")
	}
	for _, r := range name {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("webview2/windows: process name %q contains disallowed character %q", name, r)
		}
	}
	return nil
}

// Find runs `tasklist /FO CSV /NH /FI "IMAGENAME eq <name>"` and parses the
// CSV body. The "INFO: No tasks…" empty-case is stdout with exit 0 — we
// distinguish it from a real CSV row by the leading byte (Pitfall: '"' is a
// CSV row, anything else is the INFO message). Spectra-faithful.
func (h *windowsHost) Find(ctx context.Context, processName string) ([]int, error) {
	// W5: reject process names that could corrupt the tasklist /FI filter or
	// inject additional /FI parameters via unescaped quotes or metacharacters.
	if err := validateProcessName(processName); err != nil {
		return nil, err
	}
	filter := fmt.Sprintf("IMAGENAME eq %s", processName)
	cmd := exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH", "/FI", filter)
	cmd.SysProcAttr = hideConsoleAttr()
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("webview2/windows: tasklist %s: %w: %s", processName, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("webview2/windows: tasklist %s: %w", processName, err)
	}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] != '"' {
		h.logger.Debug("webview2.find.empty", "process", processName)
		return nil, nil
	}
	r := csv.NewReader(bytes.NewReader(trimmed))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("webview2/windows: parse tasklist csv: %w", err)
	}
	pids := make([]int, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		pid, perr := strconv.Atoi(strings.TrimSpace(row[1]))
		if perr != nil {
			h.logger.Debug("webview2.find.bad_pid", "row", row, "err", perr.Error())
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// Kill runs `taskkill /F /PID <pid> /T`. Exit code 128 ("not found") is
// non-fatal: the process already exited (race with operator shutdown).
func (h *windowsHost) Kill(ctx context.Context, pid int) error {
	cmd := exec.CommandContext(ctx, "taskkill", "/F", "/PID", strconv.Itoa(pid), "/T")
	cmd.SysProcAttr = hideConsoleAttr()
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 128 {
		h.logger.Warn("webview2.kill.pid_not_found", "pid", pid, "stdout", strings.TrimSpace(string(out)))
		return nil
	}
	return fmt.Errorf("webview2/windows: taskkill pid=%d: %w: %s", pid, err, strings.TrimSpace(string(out)))
}

// validatePkgName validates an AppX/MSIX package family name before embedding
// it in a PowerShell -Command string.  Package names follow the pattern
// <Publisher>.<AppName>_<version>_<arch>__<publisherHash>; legal characters
// are alphanumeric, dot, underscore, and hyphen.  This rejects metacharacters
// that could survive psSingleQuoteEscape in a -Command context.
func validatePkgName(name string) error {
	if name == "" {
		return fmt.Errorf("webview2/windows: empty package name")
	}
	for _, r := range name {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == '~') {
			return fmt.Errorf("webview2/windows: package name %q contains disallowed character %q", name, r)
		}
	}
	return nil
}

// ResolveExe runs PowerShell to look up the MSIX install location. The
// package short-name is single-quoted (psSingleQuoteEscape) to defuse the
// digit-prefix landmine (Pitfall 2 / V5). Cached per pkgName.
func (h *windowsHost) ResolveExe(ctx context.Context, pkgName string) (string, error) {
	// W5: validate pkgName charset before embedding in PS -Command string.
	if err := validatePkgName(pkgName); err != nil {
		return "", err
	}
	// WR-06: validate the cached InstallLocation still exists before
	// returning it. MSIX apps relocate their versioned WindowsApps path on
	// every package update; a long-lived host (daemon mode) that resolved
	// once would otherwise hand back a stale path that no longer exists.
	// On a stale-path miss, drop the entry and re-resolve.
	if cached, ok := h.exeCache.Load(pkgName); ok {
		loc := cached.(string)
		if st, statErr := os.Stat(loc); statErr == nil && st.IsDir() {
			return loc, nil
		}
		h.exeCache.Delete(pkgName)
		h.logger.Debug("webview2.resolveexe.cache_invalidated",
			"pkg", pkgName, "stale_path", loc)
	}
	ps := fmt.Sprintf("Get-AppxPackage -Name '%s' | Select-Object -ExpandProperty InstallLocation", psSingleQuoteEscape(pkgName))
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
	cmd.SysProcAttr = hideConsoleAttr()
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("webview2/windows: Get-AppxPackage %s: %w: %s", pkgName, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("webview2/windows: Get-AppxPackage %s: %w", pkgName, err)
	}
	loc := strings.TrimSpace(string(out))
	if loc == "" {
		return "", fmt.Errorf("webview2/windows: package not found: %s", pkgName)
	}
	h.exeCache.Store(pkgName, loc)
	return loc, nil
}

// Spawn launches exe via os/exec.Cmd with the caller-supplied env (which
// embeds WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS). MethodDirect path only —
// no HKCU mutation (spectra :126-128).
func (h *windowsHost) Spawn(ctx context.Context, exe string, env []string, args []string) (Process, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = env
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = hideConsoleAttr()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("webview2/windows: spawn %s: %w", exe, err)
	}
	h.logger.Debug("webview2.spawn.direct", "exe", exe, "pid", cmd.Process.Pid)
	return &windowsProcess{cmd: cmd}, nil
}

// SpawnAUMID launches a true-UWP target via the COM activation broker.
// Order is load-bearing: pure-Go HKCU set + WM_SETTINGCHANGE broadcast →
// 2s propagation sleep (Pitfall 4, kept from spectra) → Start-Process
// 'shell:AppsFolder\<aumid>'. Direct exec of WhatsApp.Root.exe is
// ACL-denied; the broker re-reads HKCU after the broadcast. The AUMID is
// single-quoted via psSingleQuoteEscape (V5 / Pitfall 2). The returned
// Process has PID=0 (broker detaches). Caller (Ensure) pairs every
// SpawnAUMID with a panic-safe deferred CleanupHKCUEnv (D-04).
func (h *windowsHost) SpawnAUMID(ctx context.Context, aumid string, port int) (Process, error) {
	// W5: validate aumid charset. AUMIDs are "<PackageFamilyName>!<AppID>";
	// the '!' separator and alphanumeric/dot/underscore/hyphen are the only
	// valid characters. Reject anything else to prevent PS injection.
	for _, r := range aumid {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == '!' || r == '~') {
			return nil, fmt.Errorf("%w: aumid %q contains disallowed character %q", ErrUWPLaunch, aumid, r)
		}
	}
	if err := h.SetHKCUEnv(ctx, port); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUWPLaunch, err)
	}
	// Pitfall 4: keep the spectra 2s propagation sleep so the broadcast
	// settles before the broker activation re-reads the user hive.
	time.Sleep(2 * time.Second)

	ps := fmt.Sprintf("Start-Process 'shell:AppsFolder\\%s'", psSingleQuoteEscape(aumid))
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
	cmd.SysProcAttr = hideConsoleAttr()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w: aumid launch %s: %v: %s", ErrUWPLaunch, aumid, err, strings.TrimSpace(string(out)))
	}
	h.logger.Debug("webview2.spawn.aumid", "aumid", aumid, "port", port)
	return &windowsProcess{cmd: nil}, nil
}

// psSingleQuoteEscape sanitizes a value for embedding inside a PowerShell
// single-quoted string literal passed via -Command.
//
// Hardening beyond the original spectra single-quote doubling (W5):
//   - Null bytes are stripped (they can terminate PS string parsing early).
//   - Backtick (`) is escaped as “ because PowerShell -Command evaluates
//     backtick-escapes before entering the single-quote literal context,
//     allowing subexpression injection via `$(...) constructs.
//   - Single quotes are doubled per the PS single-quote rule.
func psSingleQuoteEscape(s string) string {
	// Strip null bytes first.
	s = strings.ReplaceAll(s, "\x00", "")
	// Escape backticks so PS -Command cannot interpret `$(...) subexpressions.
	s = strings.ReplaceAll(s, "`", "``")
	// Double single quotes — the canonical PS single-string escape.
	s = strings.ReplaceAll(s, "'", "''")
	return s
}

// windowsProcess wraps an os/exec.Cmd (MethodDirect) or carries a nil cmd
// for broker-detached AUMID launches.
type windowsProcess struct {
	cmd *exec.Cmd
}

func (p *windowsProcess) PID() int {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func (p *windowsProcess) Wait() error {
	if p.cmd == nil {
		return nil
	}
	return p.cmd.Wait()
}

func (p *windowsProcess) Release() error {
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Release()
}
