/*
Copyright (c) 2026 Security Research
*/

package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	"github.com/inovacc/unravel-oss/pkg/capture/launch"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	"github.com/inovacc/unravel-oss/pkg/sandbox"
)

// Framework selects the live-capture launcher.
type Framework string

const (
	FrameworkElectron Framework = "electron"
	FrameworkTauri    Framework = "tauri"
	FrameworkWebView2 Framework = "webview2"
)

// Options configures RunLive.
type Options struct {
	AppPath   string
	Framework Framework
	Timeout   time.Duration // default 30s (D-06)
}

// Result holds the captured live snapshot. Per D-05, the v2.4 fixed
// CDP capture batch covers six surfaces. Fields use json.RawMessage so
// the merge layer reshapes them; the orchestrator's job is capture,
// not interpretation.
type Result struct {
	ResourceTree     json.RawMessage `json:"resource_tree,omitempty"`      // Page.getResourceTree
	DOM              json.RawMessage `json:"dom,omitempty"`                // DOM.getDocument depth=-1 pierce=true
	ComputedStyles   json.RawMessage `json:"computed_styles,omitempty"`    // CSS.getComputedStyleForNode (bounded sample)
	WebpackCacheKeys json.RawMessage `json:"webpack_cache_keys,omitempty"` // Runtime.evaluate window.__webpack_require__?.cache
	Cookies          json.RawMessage `json:"cookies,omitempty"`            // Storage.getCookies
	DOMStorage       json.RawMessage `json:"dom_storage,omitempty"`        // Storage.getDOMStorageItems
	CapturedAt       time.Time       `json:"captured_at"`
}

// ErrLiveCaptureUnsupported indicates the host platform cannot run the
// live pass for this framework (e.g., Tauri on non-Windows).
var ErrLiveCaptureUnsupported = errors.New("live capture unsupported on this platform")

// RunLive performs the full live-capture flow. Caller treats any
// non-nil error as a graceful-degradation signal (D-14).
func RunLive(ctx context.Context, opts Options) (*Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	mainExe, err := discoverMainExe(opts.AppPath)
	if err != nil {
		return nil, fmt.Errorf("discover main exe: %w", err)
	}

	port, err := pickFreePort()
	if err != nil {
		return nil, fmt.Errorf("pick port: %w", err)
	}

	userDataDir, err := os.MkdirTemp("", "unravel-live-")
	if err != nil {
		return nil, fmt.Errorf("temp user-data-dir: %w", err)
	}
	defer os.RemoveAll(userDataDir)

	cmd, err := buildLaunchCmd(opts.Framework, mainExe, port, userDataDir)
	if err != nil {
		return nil, err
	}

	// Single ctx budget bounds the whole live pass (D-07).
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Process supervision (D-13). We use the exposed sandbox helpers
	// instead of RunWithTimeout because we need the child alive while
	// driving CDP from this goroutine.
	sandbox.ConfigureProcAttr(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cmd: %w", err)
	}
	// defer-kill on every return path (D-13).
	defer sandbox.KillProcessGroup(cmd)

	// Wait for CDP readiness.
	if err := waitCDPReady(ctx, port); err != nil {
		return nil, fmt.Errorf("cdp not ready: %w", err)
	}

	// Run the fixed v2.4 capture batch (D-05).
	return runCaptureBatch(ctx, port)
}

// discoverMainExe walks the app path via electron/binary.Analyze and
// picks an executable-shaped binary. Per D-02, we reuse the existing
// discovery rather than implementing a new walker.
func discoverMainExe(appPath string) (string, error) {
	info, err := os.Stat(appPath)
	if err != nil {
		return "", fmt.Errorf("stat app: %w", err)
	}
	if !info.IsDir() {
		// Already a file: use directly (single-binary apps).
		return appPath, nil
	}
	infos := binary.Analyze(appPath, false)
	if len(infos) == 0 {
		return "", fmt.Errorf("no binaries found under %s", appPath)
	}
	// Prefer PE (Windows) / Mach-O (macOS) / ELF (Linux) executables in
	// the top-level directory. Filter against extension heuristics.
	for _, b := range infos {
		base := strings.ToLower(filepath.Base(b.Path))
		if runtime.GOOS == "windows" && strings.HasSuffix(base, ".exe") {
			return b.Path, nil
		}
		if runtime.GOOS != "windows" && filepath.Ext(base) == "" {
			return b.Path, nil
		}
	}
	// Fallback: first reported binary.
	return infos[0].Path, nil
}

// pickFreePort returns an OS-assigned ephemeral port (D-03). There is
// a narrow race between close-and-launch but this is acceptable for
// v2.4 per the locked decision.
func pickFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	addr := l.Addr().(*net.TCPAddr)
	port := addr.Port
	_ = l.Close()
	return port, nil
}

// buildLaunchCmd dispatches to the framework-specific launcher.
func buildLaunchCmd(fw Framework, exe string, port int, udd string) (*exec.Cmd, error) {
	switch fw {
	case FrameworkElectron:
		return launch.LaunchElectron(exe, port, udd)
	case FrameworkTauri:
		if runtime.GOOS != "windows" {
			return nil, fmt.Errorf("%w: tauri requires windows", ErrLiveCaptureUnsupported)
		}
		return launch.LaunchTauri(exe, port, udd)
	case FrameworkWebView2:
		return launch.LaunchWebView2(exe, port, udd)
	default:
		return nil, fmt.Errorf("%w: unknown framework %q", ErrLiveCaptureUnsupported, fw)
	}
}

// waitCDPReady polls the /json/version endpoint until success or ctx.
func waitCDPReady(ctx context.Context, port int) error {
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/json/version"
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
	}
}

// runCaptureBatch executes the fixed v2.4 CDP capture batch (D-05).
func runCaptureBatch(ctx context.Context, port int) (*Result, error) {
	wsURL, err := discoverWSURL(ctx, port)
	if err != nil {
		return nil, fmt.Errorf("discover ws url: %w", err)
	}

	events := make(chan capture.Event, 64)
	go func() {
		// Drain to prevent backpressure on cdp event handlers.
		for range events {
		}
	}()
	seq := func() func() int {
		var i int
		return func() int { i++; return i }
	}()

	c := cdp.New("127.0.0.1:"+strconv.Itoa(port), events, seq)
	if err := c.Connect(ctx, wsURL); err != nil {
		return nil, fmt.Errorf("cdp connect: %w", err)
	}
	go c.Listen(ctx)

	r := &Result{CapturedAt: time.Now().UTC()}

	// Page.getResourceTree
	if raw, err := c.SendAndWait(ctx, "Page.getResourceTree", map[string]any{}); err == nil {
		r.ResourceTree = raw
	}

	// DOM.getDocument depth=-1 pierce=true
	if raw, err := c.SendAndWait(ctx, "DOM.getDocument", map[string]any{
		"depth":  -1,
		"pierce": true,
	}); err == nil {
		r.DOM = raw
	}

	// CSS.getComputedStyleForNode — bounded sample. We try with the root
	// document nodeId=1 (CDP convention). If the call fails, leave empty.
	if raw, err := c.SendAndWait(ctx, "CSS.getComputedStyleForNode", map[string]any{
		"nodeId": 1,
	}); err == nil {
		r.ComputedStyles = raw
	}

	// Runtime.evaluate window.__webpack_require__?.cache (returnByValue)
	if raw, err := c.SendAndWait(ctx, "Runtime.evaluate", map[string]any{
		"expression":    "Object.keys(window.__webpack_require__?.cache || {})",
		"returnByValue": true,
		"awaitPromise":  false,
	}); err == nil {
		r.WebpackCacheKeys = raw
	}

	// Storage.getCookies
	if raw, err := c.SendAndWait(ctx, "Storage.getCookies", map[string]any{}); err == nil {
		r.Cookies = raw
	}

	// Storage.getDOMStorageItems requires a storageId; for v2.4 we leave
	// best-effort empty if the call fails. The fixed-batch contract per
	// D-05 enumerates the call; the result schema permits an empty
	// payload as graceful when CDP rejects on missing storageId.
	if raw, err := c.SendAndWait(ctx, "Storage.getDOMStorageItems", map[string]any{
		"storageId": map[string]any{
			"securityOrigin": "http://localhost",
			"isLocalStorage": true,
		},
	}); err == nil {
		r.DOMStorage = raw
	}

	return r, nil
}

// discoverWSURL fetches /json/version and returns webSocketDebuggerUrl.
func discoverWSURL(ctx context.Context, port int) (string, error) {
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/json/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var v struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", err
	}
	if v.WebSocketDebuggerURL == "" {
		return "", errors.New("empty webSocketDebuggerUrl")
	}
	return v.WebSocketDebuggerURL, nil
}
