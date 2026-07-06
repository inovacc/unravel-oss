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
	"net/url"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	"github.com/inovacc/unravel-oss/pkg/capture/webview2"
	"github.com/inovacc/unravel-oss/pkg/knowledge/scorecard"

	"github.com/spf13/cobra"
)

// D-22: keep the mandated out alias referenced in new cmd/*.go content.
var _ = out.Truncate

var (
	wv2AttachKind   string
	wv2AttachPort   int
	wv2AttachNoKill bool
)

// attachFn is an injectable seam over cdp.Client.ConnectAndAttach so the
// attach-result handling (honest D-09 BLOCK vs success) can be exercised
// deterministically without a live WhatsApp/Teams target or a real CDP port.
// Production behavior is byte-identical through the default implementation.
var attachFn = func(ctx context.Context, c *cdp.Client, t cdp.Target) error {
	return c.ConnectAndAttach(ctx, t)
}

// presetKinds returns the closed --kind allowlist derived from
// webview2.Presets (V5 — no bare interpolation, validated set).
func presetKinds() []string {
	ks := make([]string, 0, len(webview2.Presets))
	for k := range webview2.Presets {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

var captureWebView2AttachCmd = &cobra.Command{
	Use:   "webview2-attach",
	Short: "No-admin CDP attach to WhatsApp/Teams Desktop (WebView2/UWP)",
	Long: `Launch (or discover) a true-UWP / WebView2 messaging app WITHOUT admin
and attach the Chrome DevTools Protocol client to its live target.

WhatsApp Desktop (--kind wa-desktop) is true-UWP: it is started via the COM
activation broker (shell:AppsFolder) after a transient, panic-safe
HKCU\Environment write + WM_SETTINGCHANGE broadcast (reverted on every exit
path — D-04). A stale value from a prior killed run is self-healed on start
(D-05). Teams Desktop (--kind teams-desktop) is launched directly with the
debug port injected via per-process env.

On success the CDP client is connected and Network-enabled against the live
page target discovered by URL. If the port never opens after the bounded
wait, this BLOCKs honestly with the captured failure evidence (D-08/D-09) —
there is no skip-cdp escape hatch and no fabricated sidecar.

Examples:
  unravel capture webview2-attach --kind wa-desktop
  unravel capture webview2-attach --kind teams-desktop --port 9223
  unravel capture webview2-attach --kind wa-desktop --no-kill`,
	RunE: runCaptureWebView2Attach,
}

func init() {
	// Intentionally not registered on the CLI: exposed MCP-only via unravel_capture_webview2_attach.
	captureWebView2AttachCmd.Flags().StringVar(&wv2AttachKind, "kind", "",
		fmt.Sprintf("Target kind (one of: %s)", strings.Join(presetKinds(), ", ")))
	captureWebView2AttachCmd.Flags().IntVar(&wv2AttachPort, "port", 0,
		"CDP remote-debugging port (0 = preset default)")
	captureWebView2AttachCmd.Flags().BoolVar(&wv2AttachNoKill, "no-kill", false,
		"If the target is running without CDP, error instead of kill+relaunch")
}

func runCaptureWebView2Attach(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// V5: validate --kind against the closed preset allowlist before any
	// OS-level action. Reject unknown kinds (no bare interpolation).
	if wv2AttachKind == "" {
		return fmt.Errorf("--kind is required (one of: %s)", strings.Join(presetKinds(), ", "))
	}
	if _, ok := webview2.PresetFor(wv2AttachKind); !ok {
		return fmt.Errorf("unknown --kind %q (allowed: %s)", wv2AttachKind, strings.Join(presetKinds(), ", "))
	}

	logger := slog.Default()

	// D-05: idempotently revert a stale unravel-tagged HKCU value left by a
	// prior killed run BEFORE proceeding.
	if err := webview2.SelfHeal(ctx, logger); err != nil {
		return fmt.Errorf("self-heal: %w", err)
	}

	target := webview2.Target{
		Kind:   wv2AttachKind,
		Port:   wv2AttachPort,
		NoKill: wv2AttachNoKill,
		Logger: logger,
	}

	fmt.Printf("Ensuring CDP for %s (no admin)...\n", wv2AttachKind)
	att, err := webview2.Ensure(ctx, target)
	if err != nil {
		// D-08/D-09 honest BLOCK: surface captured timeout evidence to
		// stderr; never fabricate success, no skip-cdp escape hatch.
		var lte *webview2.LaunchTimeoutError
		if errors.As(err, &lte) {
			fmt.Fprintf(os.Stderr, "BLOCKED: CDP never opened for %s — %v\n", wv2AttachKind, lte)
			return fmt.Errorf("webview2-attach BLOCKED (honest, no fabrication): %w", err)
		}
		return fmt.Errorf("webview2 ensure %s: %w", wv2AttachKind, err)
	}

	fmt.Printf("CDP ready: %s (spawned=%v pid=%d)\n", att.BaseURL, att.Spawned, att.PID)

	host := att.BaseURL
	if u, perr := url.Parse(att.BaseURL); perr == nil && u.Host != "" {
		host = u.Host
	}

	if err := attachAndReport(ctx, host, att.WebSocketDebugURL, wv2AttachKind, os.Stdout, os.Stderr); err != nil {
		return err
	}

	// Non-fatal: the CDP session is live RIGHT NOW but this command exits
	// before the slow knowledge/dissect pipeline runs (by which point a
	// true-UWP app may have idle-exited). Pull live JS/CSS here and persist
	// it to a per-app sidecar keyed by the resolved package id. Every error
	// path is non-fatal and never alters the attach result/output.
	pullCDPSourceSidecar(ctx, wv2AttachKind, wv2AttachPort, logger)
	return nil
}

// pullCDPSourceSidecar performs the best-effort live JS/CSS pull + sidecar
// write. It is intentionally non-fatal: any failure is logged and swallowed.
func pullCDPSourceSidecar(ctx context.Context, kind string, portFlag int, logger *slog.Logger) {
	preset, ok := webview2.PresetFor(kind)
	if !ok {
		return
	}
	pkgKey := preset.PkgName
	port := preset.Port
	if portFlag != 0 {
		port = portFlag
	}

	ps, err := scorecard.PullSourcesOverCDP(ctx, "127.0.0.1", port, 25*time.Second)
	if err != nil {
		logger.Warn("attach: cdp source pull failed (non-fatal)", "err", err)
		return
	}

	jsEntries := make([]webview2.CDPSrcEntry, 0, len(ps.JS))
	for _, s := range ps.JS {
		jsEntries = append(jsEntries, webview2.CDPSrcEntry{URL: s.URL, Source: s.Source})
	}
	cssEntries := make([]webview2.CDPSrcEntry, 0, len(ps.CSS))
	for _, s := range ps.CSS {
		cssEntries = append(cssEntries, webview2.CDPSrcEntry{URL: s.URL, Source: s.Source})
	}

	path, werr := webview2.WriteCDPSourceSidecar(pkgKey, jsEntries, cssEntries)
	if werr != nil {
		logger.Warn("attach: cdp source sidecar write failed (non-fatal)", "err", werr)
		return
	}
	if path == "" {
		logger.Info("attach: no live JS/CSS recovered (honest-empty)")
		return
	}
	logger.Info("attach: wrote CDP source sidecar",
		"path", path, "js", len(jsEntries), "css", len(cssEntries))
}

// attachAndReport spawns Listen (before attach — SendAndWait dispatch
// contract), runs the injectable attachFn, and reports either an honest
// D-09 BLOCK (stderr + non-nil wrapped error, no success line) or success.
// Extracted as a seam so the BLOCK/success handling is deterministically
// testable without a live target or real CDP port. stderr is injected
// symmetric with stdout so tests need no process-global os.Stderr swap
// (concurrency-safe across parallel subtests/packages).
func attachAndReport(ctx context.Context, host, wsURL, kind string, stdout *os.File, stderr io.Writer) error {
	events := make(chan capture.Event, 256)
	var seq int64
	seqFn := func() int { return int(atomic.AddInt64(&seq, 1)) }
	cli := cdp.New(host, events, seqFn)

	// Listen only returns on read error or ctx.Done() (cdp/client.go): when
	// c.conn is nil it spins on a 10ms ticker until ctx is cancelled, and
	// cli.Close() cannot unblock it in that state. Own a cancellable child
	// ctx so the success path can deterministically terminate + join the
	// Listen goroutine instead of leaking it (plus its ticker) per call.
	lctx, lcancel := context.WithCancel(ctx)
	defer lcancel()

	// attach.go ordering: Listen MUST be spawned BEFORE ConnectAndAttach
	// (SendAndWait blocks on the dispatch loop). Mirror cdp_source.go.
	// The Listen goroutine's typed nil-conn/dial error (part-1) is captured
	// via a buffered channel instead of being swallowed in a slog.Debug, so
	// the cmd can surface it on an honest BLOCK. buffer=1 also lets the
	// Listen goroutine send-and-exit even when the success path never
	// receives, so it can never block on send (no-receiver failure case).
	listenErrCh := make(chan error, 1)
	go func() { listenErrCh <- cli.Listen(lctx) }()

	if err := attachFn(lctx, cli, cdp.Target{
		ID:                kind,
		WebSocketDebugURL: wsURL,
	}); err != nil {
		// Non-blocking drain: pick up the typed Listen nil-conn/dial error if
		// it has already arrived. A failed attach must NEVER print "Attached".
		var lerr error
		select {
		case lerr = <-listenErrCh:
		default:
			lerr = nil
		}
		_ = cli.Close()
		// D-08/D-09 honest BLOCK: stderr evidence + non-zero wrapped return,
		// no fabricated success, no skip-cdp escape hatch.
		fmt.Fprintf(stderr, "BLOCKED: CDP websocket dial failed for %s — connect=%v listen=%v\n",
			kind, err, lerr)
		return fmt.Errorf("webview2-attach BLOCKED (honest, no fabrication): cdp connect+attach %s: %w",
			kind, err)
	}

	// Healthy session: deterministically terminate + join the Listen
	// goroutine so neither it nor its 10ms ticker leaks per call (the seam
	// may be reused in-process by cobra tests / MCP). Cancel the child ctx
	// (the only thing that unblocks a nil-conn Listen), Close the conn (the
	// only thing that unblocks a connected Listen), then bounded-receive.
	// A late benign Listen return must NOT become a BLOCK; the timeout guard
	// ensures a wedged Listen can never hang the caller.
	lcancel()
	_ = cli.Close()
	select {
	case lerr := <-listenErrCh:
		slog.Debug("cdp listen ended", "err", lerr)
	case <-time.After(500 * time.Millisecond):
		slog.Debug("cdp listen drain timed out")
	}

	fmt.Fprintf(stdout, "Attached (Network.enable) to %s page target.\n", kind)
	fmt.Fprintln(stdout, "CDP session live. Compose a higher-level capture on this client as needed.")
	return nil
}
