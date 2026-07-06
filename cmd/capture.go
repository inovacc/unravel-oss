package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	gonet "net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/capture"
	androidcap "github.com/inovacc/unravel-oss/pkg/capture/android"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	"github.com/inovacc/unravel-oss/pkg/capture/diff"
	"github.com/inovacc/unravel-oss/pkg/capture/launch"
	"github.com/inovacc/unravel-oss/pkg/capture/replay"
	"github.com/inovacc/unravel-oss/pkg/capture/session"
	"github.com/inovacc/unravel-oss/pkg/capture/visual"
	"github.com/inovacc/unravel-oss/pkg/sandbox"

	gonethttp "net/http"

	"github.com/spf13/cobra"
)

// Suppress unused-import diagnostics — out alias is mandated by D-22 for any
// new cmd/*.go content; reference a stable exported helper to keep imports tidy.
var _ = out.Truncate
var _ = errors.New

var (
	captureApp       string
	capturePort      int
	capturePID       int
	captureProxyPort int
	captureDiffJSON  bool
	captureAndroid   bool
	capturePackage   string
	captureSerial    string
	captureTcpdump   bool
	capturePollSec   int

	// Phase 8 (D-23): visual capture flag family.
	captureVisual          bool
	captureNoBehavior      bool
	captureNoVisual        bool
	captureCDPURL          string
	captureTargetPath      string
	captureMode            string
	captureScenarioPath    string
	captureViewports       string
	captureMaxStates       int
	capturePHashThreshold  int
	captureModalSettleMs   int
	captureAllowRemoteCDP  bool
	captureTargetFramework string
)

var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture and replay live Electron/Tauri/Android app behavior",
}

var captureStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a capture session against a running Electron/Tauri or Android app",
	Long: `Connect to an Electron/Tauri app via Chrome DevTools Protocol, or to an
Android device via ADB, and record live behavior.

For Electron/Tauri: Records network requests, IPC messages, console output,
window state changes, and storage mutations. The target app must be running
with --remote-debugging-port enabled.

For Android (--android): Records intents, broadcasts, logcat output, shared
preferences changes, and network traffic (tcpdump) via ADB shell commands.
Requires ADB in PATH and a connected device.

Examples:
  unravel capture start --port 9222 -o ./evidence/
  unravel capture start --app /opt/Cluely -o ./evidence/
  unravel capture start --android --package com.example.app -o ./evidence/
  unravel capture start --android --package com.example.app --tcpdump
  unravel capture start --android --serial emulator-5554 --package com.app`,
	Run: runCaptureStart,
}

var captureDiffCmd = &cobra.Command{
	Use:   "diff <before.json> <after.json>",
	Short: "Compare two capture files for behavioral changes",
	Long: `Compares network endpoints, IPC channels, storage mutations, console
patterns, and stealth behaviors between two capture sessions.

Examples:
  unravel capture diff ./v1.json ./v2.json
  unravel capture diff ./v1.json ./v2.json --json`,
	Args: cobra.ExactArgs(2),
	Run:  runCaptureDiff,
}

var captureReplayCmd = &cobra.Command{
	Use:   "replay <capture.json>",
	Short: "Replay a capture in an isolated Electron shell",
	Long: `Starts an HTTP proxy serving recorded responses and a minimal Electron
shell that replays the captured behavior. Requires Electron to be installed.

Examples:
  unravel capture replay ./capture.json
  unravel capture replay ./capture.json --port 8080`,
	Args: cobra.ExactArgs(1),
	Run:  runCaptureReplay,
}

var captureListCmd = &cobra.Command{
	Use:   "list [directory]",
	Short: "List capture files with summary metadata",
	Long: `Scan a directory for capture JSON files and display their metadata.

Examples:
  unravel capture list ./evidence/
  unravel capture list`,
	Args: cobra.MaximumNArgs(1),
	Run:  runCaptureList,
}

func init() {
	rootCmd.AddCommand(captureCmd)

	captureCmd.AddCommand(captureStartCmd)
	captureStartCmd.Flags().StringVar(&captureApp, "app", "", "Path to Electron/Tauri app directory")
	captureStartCmd.Flags().IntVar(&capturePort, "port", 9222, "Chrome DevTools Protocol port")
	captureStartCmd.Flags().IntVar(&capturePID, "pid", 0, "Target process PID")
	captureStartCmd.Flags().BoolVar(&captureAndroid, "android", false, "Capture from Android device via ADB")
	captureStartCmd.Flags().StringVar(&capturePackage, "package", "", "Android package name to monitor")
	captureStartCmd.Flags().StringVar(&captureSerial, "serial", "", "ADB device serial (optional)")
	captureStartCmd.Flags().BoolVar(&captureTcpdump, "tcpdump", false, "Enable tcpdump network capture (requires root)")
	captureStartCmd.Flags().IntVar(&capturePollSec, "poll", 5, "Poll interval in seconds for Android monitors")

	// Phase 8 (D-23): visual capture flag family.
	captureStartCmd.Flags().BoolVar(&captureVisual, "visual", false, "Capture screenshot+tree+layout artifacts (Phase 8)")
	captureStartCmd.Flags().BoolVar(&captureNoBehavior, "no-behavior", false, "Skip the existing behavior trace pass")
	captureStartCmd.Flags().BoolVar(&captureNoVisual, "no-visual", false, "Skip the Phase 8 visual capture pass")
	captureStartCmd.Flags().StringVar(&captureCDPURL, "cdp", "", "CDP endpoint URL (e.g., http://localhost:9222); loopback-only unless --allow-remote-cdp")
	captureStartCmd.Flags().StringVar(&captureTargetPath, "target", "", "Path to app binary to auto-launch with debug port injected")
	captureStartCmd.Flags().StringVar(&captureMode, "mode", "auto", "Capture mode: auto|interactive|scripted")
	captureStartCmd.Flags().StringVar(&captureScenarioPath, "scenario", "", "Path to scenario JSON when --mode=scripted")
	captureStartCmd.Flags().StringVar(&captureViewports, "viewports", "", "Comma-separated viewport list, e.g., 1920x1080,1280x720")
	captureStartCmd.Flags().IntVar(&captureMaxStates, "max-states", 50, "Maximum states to capture in --mode=auto/interactive")
	captureStartCmd.Flags().IntVar(&capturePHashThreshold, "phash-threshold", 5, "dHash Hamming threshold for visual diff PASS bucket")
	captureStartCmd.Flags().IntVar(&captureModalSettleMs, "modal-settle-ms", 300, "Delay (ms) after modal_open event before capture")
	captureStartCmd.Flags().BoolVar(&captureAllowRemoteCDP, "allow-remote-cdp", false, "Allow non-loopback --cdp URLs (T-08-04 opt-out)")
	captureStartCmd.Flags().StringVar(&captureTargetFramework, "target-framework", "electron", "Framework for --target auto-launch: electron|tauri|webview2")

	captureCmd.AddCommand(captureDiffCmd)
	captureDiffCmd.Flags().BoolVar(&captureDiffJSON, "json", false, "Output diff as JSON")

	captureCmd.AddCommand(captureReplayCmd)
	captureReplayCmd.Flags().IntVar(&captureProxyPort, "port", 0, "Fixed proxy port (default: random)")

	captureCmd.AddCommand(captureListCmd)
}

// validateCDPLoopback rejects non-loopback hosts in a --cdp URL unless
// allowRemote is set. Accepts localhost, 127.0.0.1, ::1, and any IP
// returning true from net.IP.IsLoopback (T-08-04).
func validateCDPLoopback(rawURL string, allowRemote bool) error {
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse --cdp: %w", err)
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil
	}
	if ip := gonet.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if allowRemote {
		slog.Warn("non-loopback CDP endpoint allowed by --allow-remote-cdp", "host", host)
		return nil
	}
	return fmt.Errorf("--cdp host %q is not loopback (127.0.0.1, ::1, localhost); pass --allow-remote-cdp to opt in", host)
}

// sanitizeOperatorPath rejects paths containing `..` segments and resolves
// the remaining path to an absolute clean form (T-08-01 / D-18).
func sanitizeOperatorPath(p, label string) (string, error) {
	if p == "" {
		return "", nil
	}
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return "", fmt.Errorf("%s: path traversal rejected: %q", label, p)
		}
	}
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("%s: resolve abs: %w", label, err)
	}
	return abs, nil
}

// resolveScenarioPath sanitizes and stat-checks the scenario file: must be
// a regular file (no symlink, no directory) per D-18 + T-08-03 path layer.
func resolveScenarioPath(p string) (string, error) {
	abs, err := sanitizeOperatorPath(p, "--scenario")
	if err != nil {
		return "", err
	}
	if abs == "" {
		return "", nil
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("--scenario stat: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("--scenario refuses symlink: %s", abs)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("--scenario must be a regular file: %s", abs)
	}
	return abs, nil
}

func runCaptureStart(cmd *cobra.Command, _ []string) {
	if captureAndroid {
		runCaptureStartAndroid()
		return
	}

	// Phase 8 visual branch: when --visual is set (or implied via --no-behavior
	// alone), run the visual capture pipeline. A future iteration can let
	// --visual coexist with the behavior trace; today --visual replaces it.
	if captureVisual && captureNoVisual {
		fmt.Println("Error: --visual and --no-visual are mutually exclusive")
		os.Exit(1)
	}
	if captureVisual {
		if err := runCaptureVisual(cmd.Context()); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if captureNoBehavior && !captureNoVisual {
		// --no-behavior without --visual is a no-op for now; surface guidance.
		fmt.Println("Error: --no-behavior requires --visual to do anything; specify --visual or omit --no-behavior")
		os.Exit(1)
	}

	host := fmt.Sprintf("127.0.0.1:%d", capturePort)

	outDir := output
	if outDir == "" {
		outDir = "."
	}

	ts := time.Now().Format("20060102_150405")
	outPath := filepath.Join(outDir, fmt.Sprintf("capture_%s.json", ts))

	appName := "unknown"
	if captureApp != "" {
		appName = filepath.Base(captureApp)
	}

	cfg := session.Config{
		AppName:    appName,
		AppPath:    captureApp,
		Framework:  "electron",
		PID:        capturePID,
		CDPHost:    host,
		OutputPath: outPath,
	}

	if captureApp != "" {
		home, _ := os.UserHomeDir()
		candidates := []string{
			filepath.Join(home, ".config", appName),
			filepath.Join(home, ".local/share", appName),
		}
		for _, c := range candidates {
			if info, err := os.Stat(c); err == nil && info.IsDir() {
				cfg.DataDir = c
				break
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("Connecting to CDP at %s...\n", host)

	s, err := session.Start(ctx, cfg)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nMake sure the target app is running with --remote-debugging-port enabled:")
		fmt.Printf("  %s --remote-debugging-port=%d\n", appName, capturePort)
		os.Exit(1)
	}

	fmt.Printf("Capture started. Recording to %s\n", outPath)
	fmt.Println("Press Ctrl+C to stop...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Println("\nStopping capture...")
			cs, err := s.Stop()
			if err != nil {
				fmt.Printf("Error writing capture: %v\n", err)
				os.Exit(1)
			}
			duration := cs.Capture.EndedAt.Sub(cs.Capture.StartedAt).Round(time.Second)
			fmt.Printf("\nCapture complete: %d events, %s\n", len(cs.Events), duration)
			fmt.Printf("Written to: %s\n", outPath)
			return
		case <-ticker.C:
			fmt.Printf("  [%s] %d events captured...\n", time.Now().Format("15:04:05"), s.EventCount())
		}
	}
}

func runCaptureStartAndroid() {
	if capturePackage == "" {
		fmt.Println("Error: --package is required for Android capture")
		fmt.Println("  unravel capture start --android --package com.example.app")
		os.Exit(1)
	}

	if err := androidcap.CheckADB(); err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nInstall Android SDK platform-tools and ensure 'adb' is in your PATH.")
		os.Exit(1)
	}

	outDir := output
	if outDir == "" {
		outDir = "."
	}

	ts := time.Now().Format("20060102_150405")
	outPath := filepath.Join(outDir, fmt.Sprintf("android_capture_%s.json", ts))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Check device connectivity
	devices, err := androidcap.ListDevices(ctx)
	if err != nil {
		fmt.Printf("Error listing devices: %v\n", err)
		os.Exit(1)
	}
	if len(devices) == 0 {
		fmt.Println("Error: no Android devices connected")
		fmt.Println("  Connect a device via USB or start an emulator, then run 'adb devices'")
		os.Exit(1)
	}

	serial := captureSerial
	if serial == "" {
		serial = devices[0]
		if len(devices) > 1 {
			fmt.Printf("Multiple devices found, using %s (use --serial to specify)\n", serial)
		}
	}

	pollInterval := time.Duration(capturePollSec) * time.Second

	cfg := androidcap.Config{
		Package:       capturePackage,
		Serial:        serial,
		PollInterval:  pollInterval,
		EnableTcpdump: captureTcpdump,
	}

	events := make(chan capture.Event, 1000)
	var seq int64
	seqFn := func() int { return int(atomic.AddInt64(&seq, 1)) }

	started := time.Now()

	fmt.Printf("Starting Android capture for %s on device %s...\n", capturePackage, serial)
	if captureTcpdump {
		fmt.Println("  Network capture enabled (tcpdump, requires root)")
	}

	s, err := androidcap.Start(ctx, cfg, events, seqFn)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Capture started. Recording to %s\n", outPath)
	fmt.Printf("  Polling interval: %s\n", pollInterval)
	fmt.Println("Press Ctrl+C to stop...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Println("\nStopping capture...")
			s.Stop()
			close(events)

			var collected []capture.Event
			for evt := range events {
				collected = append(collected, evt)
			}
			capture.SortEvents(collected)

			now := time.Now()
			cs := &capture.CaptureSession{
				Version: capture.FormatVersion,
				App: capture.AppInfo{
					Name:      capturePackage,
					Path:      "android://" + capturePackage,
					Framework: "android",
					PID:       0,
				},
				Capture: capture.CaptureMetadata{
					StartedAt:   started,
					EndedAt:     now,
					DurationMs:  now.Sub(started).Milliseconds(),
					Host:        "android:" + serial,
					ToolVersion: "1.0.0",
				},
				Events: collected,
			}

			if err := capture.WriteFile(outPath, cs); err != nil {
				fmt.Printf("Error writing capture: %v\n", err)
				os.Exit(1)
			}

			duration := now.Sub(started).Round(time.Second)
			fmt.Printf("\nCapture complete: %d events, %s\n", len(collected), duration)
			fmt.Printf("Written to: %s\n", outPath)
			return
		case <-ticker.C:
			fmt.Printf("  [%s] %d events captured...\n",
				time.Now().Format("15:04:05"), atomic.LoadInt64(&seq))
		}
	}
}

func runCaptureDiff(_ *cobra.Command, args []string) {
	before, err := capture.ReadFile(args[0])
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", args[0], err)
		os.Exit(1)
	}

	after, err := capture.ReadFile(args[1])
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", args[1], err)
		os.Exit(1)
	}

	result := diff.Compare(before, after, filepath.Base(args[0]), filepath.Base(args[1]))

	if captureDiffJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}

	fmt.Print(diff.FormatText(result))
}

func runCaptureReplay(_ *cobra.Command, args []string) {
	s, err := capture.ReadFile(args[0])
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", args[0], err)
		os.Exit(1)
	}

	shell := replay.NewShell(s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := shell.Start(ctx); err != nil {
		fmt.Printf("Error starting replay: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Replay started for %s\n", s.App.Name)
	fmt.Printf("  Proxy: http://%s\n", shell.ProxyAddr())
	fmt.Printf("  Events: %d\n", len(s.Events))
	fmt.Println("Press Ctrl+C to stop...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	fmt.Println("\nStopping replay...")
	_ = shell.Stop()
}

func runCaptureList(_ *cobra.Command, args []string) {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("Error reading directory: %v\n", err)
		os.Exit(1)
	}

	type captureInfo struct {
		File      string
		AppName   string
		Events    int
		Duration  time.Duration
		StartedAt time.Time
	}

	var captures []captureInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}

		path := filepath.Join(dir, e.Name())
		cs, err := capture.ReadFile(path)
		if err != nil || cs.Version == "" {
			continue
		}

		captures = append(captures, captureInfo{
			File:      e.Name(),
			AppName:   cs.App.Name,
			Events:    len(cs.Events),
			Duration:  time.Duration(cs.Capture.DurationMs) * time.Millisecond,
			StartedAt: cs.Capture.StartedAt,
		})
	}

	sort.Slice(captures, func(i, j int) bool {
		return captures[i].StartedAt.After(captures[j].StartedAt)
	})

	if len(captures) == 0 {
		fmt.Println("No capture files found.")
		return
	}

	fmt.Printf("%-40s  %-20s  %8s  %10s\n", "FILE", "APP", "EVENTS", "DURATION")
	fmt.Println(strings.Repeat("-", 85))
	for _, c := range captures {
		fmt.Printf("%-40s  %-20s  %8d  %10s\n", c.File, c.AppName, c.Events, c.Duration.Round(time.Second))
	}
}

// runCaptureVisual is the Phase 8 entry point. Validates flags, attaches via
// CDP, runs the visual orchestrator, and writes <kb>/visual/latest pointer.
//
// Threats: T-08-04 (loopback validator), T-08-01/D-18 (path-traversal
// sanitization on operator-supplied paths).
func runCaptureVisual(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}

	// T-08-04 loopback validation, fail fast.
	if err := validateCDPLoopback(captureCDPURL, captureAllowRemoteCDP); err != nil {
		return err
	}

	// Path sanitization (D-18 / T-08-01).
	kbDir := output
	if kbDir == "" {
		kbDir = "."
	}
	kbAbs, err := sanitizeOperatorPath(kbDir, "-o")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(kbAbs, 0o755); err != nil {
		return fmt.Errorf("mkdir kb: %w", err)
	}

	scenarioAbs, err := resolveScenarioPath(captureScenarioPath)
	if err != nil {
		return err
	}
	targetAbs, err := sanitizeOperatorPath(captureTargetPath, "--target")
	if err != nil {
		return err
	}

	if captureCDPURL == "" && targetAbs == "" {
		return errors.New("--visual requires either --cdp <url> or --target <path>")
	}
	if captureCDPURL != "" && targetAbs != "" {
		return errors.New("--cdp and --target are mutually exclusive")
	}

	// Run-id slug per D-12.
	runID := time.Now().UTC().Format("2006-01-02T15-04-05Z")

	// Parse viewports.
	viewports, err := visual.ParseViewports(captureViewports)
	if err != nil {
		return fmt.Errorf("--viewports: %w", err)
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// Build CDP host:port. Two sources:
	//   --cdp http://host:port/  → extract host:port and connect to an
	//                              already-running app.
	//   --target <path>          → auto-launch the binary with a debug port
	//                              injected, wait for CDP readiness, then
	//                              connect. Reuses the launch→wait→teardown
	//                              sequence from pkg/knowledge/capture (RunLive).
	var host string
	if targetAbs != "" {
		fw, err := parseTargetFramework(captureTargetFramework)
		if err != nil {
			return err
		}
		h, err := launchTargetForVisual(ctx, targetAbs, fw)
		if err != nil {
			return err
		}
		host = h
	} else {
		u, err := url.Parse(captureCDPURL)
		if err != nil {
			return fmt.Errorf("parse --cdp: %w", err)
		}
		host = u.Host
		if host == "" {
			return fmt.Errorf("--cdp missing host:port in %q", captureCDPURL)
		}
	}

	events := make(chan capture.Event, 256)
	var seq int64
	seqFn := func() int { return int(atomic.AddInt64(&seq, 1)) }
	cli := cdp.New(host, events, seqFn)

	targets, err := cli.DiscoverTargets(ctx)
	if err != nil {
		return fmt.Errorf("discover CDP targets at %s: %w", host, err)
	}
	var ws string
	for _, t := range targets {
		if t.Type == "page" && t.WebSocketDebugURL != "" {
			ws = t.WebSocketDebugURL
			break
		}
	}
	if ws == "" {
		return fmt.Errorf("no debuggable page target at %s (is the app running with --remote-debugging-port?)", host)
	}
	if err := cli.Connect(ctx, ws); err != nil {
		return fmt.Errorf("connect CDP ws: %w", err)
	}
	defer func() { _ = cli.Close() }()

	// Spawn the CDP read loop so SendAndWait responses are dispatched.
	// Without this goroutine, any RPC waiting on its pending channel deadlocks.
	go func() {
		if err := cli.Listen(ctx); err != nil {
			slog.Debug("cdp listen ended", "err", err)
		}
	}()

	mode := visual.Mode(strings.ToLower(strings.TrimSpace(captureMode)))
	switch mode {
	case visual.ModeAuto, visual.ModeInteractive, visual.ModeScripted, "":
	default:
		return fmt.Errorf("--mode %q invalid (auto|interactive|scripted)", captureMode)
	}

	orch, err := visual.New(cli, visual.Options{
		Mode:           mode,
		KBDir:          kbAbs,
		RunID:          runID,
		Viewports:      viewports,
		MaxStates:      captureMaxStates,
		ScenarioPath:   scenarioAbs,
		ModalSettleMs:  captureModalSettleMs,
		PHashThreshold: capturePHashThreshold,
	})
	if err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}

	fmt.Printf("Visual capture starting (run %s) → %s/visual/%s/\n", runID, kbAbs, runID)
	if err := orch.Run(ctx); err != nil {
		return fmt.Errorf("run: %w", err)
	}

	if err := visual.WriteLatestPointer(kbAbs, runID); err != nil {
		slog.Warn("could not write <kb>/visual/latest pointer", "err", err)
	}

	caps := orch.Captures()
	fmt.Printf("captured run %s: %d states under %s/visual/\n", runID, len(caps), kbAbs)
	return nil
}

// parseTargetFramework maps the --target-framework flag string to the
// corresponding launch.Framework constant, returning a clear error for
// unrecognised values.
func parseTargetFramework(s string) (launch.Framework, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "electron":
		return launch.FrameworkElectron, nil
	case "tauri":
		return launch.FrameworkTauri, nil
	case "webview2":
		return launch.FrameworkWebView2, nil
	default:
		return "", fmt.Errorf("invalid --target-framework %q (want electron|tauri|webview2)", s)
	}
}

// launchBuildFn is an injectable seam over launch.Build so the
// launch→wait→connect→teardown sequence can be exercised deterministically
// in tests without a real GUI binary. Production behavior is byte-identical
// through the default implementation.
var launchBuildFn = func(fw launch.Framework, path string, port int, userDataDir string) (*exec.Cmd, error) {
	return launch.Build(fw, path, port, userDataDir)
}

// visualCDPReadyTimeout bounds how long launchTargetForVisual waits for the
// auto-launched app's CDP endpoint to come up before giving up. Overridable
// in tests.
var visualCDPReadyTimeout = 30 * time.Second

// launchTargetForVisual auto-launches the target binary with a debug port
// injected, waits (bounded) for the CDP endpoint to become reachable, and
// returns the loopback host:port the caller connects to. The launched
// process and its temp user-data-dir are torn down on EVERY exit path —
// including the readiness-timeout error path — via deferred cleanup keyed to
// ctx cancellation. This mirrors RunLive in pkg/knowledge/capture/live.go.
func launchTargetForVisual(ctx context.Context, targetAbs string, fw launch.Framework) (string, error) {
	port, err := pickFreePortForVisual()
	if err != nil {
		return "", fmt.Errorf("pick debug port: %w", err)
	}

	userDataDir, err := os.MkdirTemp("", "unravel-visual-")
	if err != nil {
		return "", fmt.Errorf("temp user-data-dir: %w", err)
	}

	cmd, err := launchBuildFn(fw, targetAbs, port, userDataDir)
	if err != nil {
		_ = os.RemoveAll(userDataDir)
		return "", fmt.Errorf("build launch command: %w", err)
	}

	sandbox.ConfigureProcAttr(cmd)
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(userDataDir)
		return "", fmt.Errorf("start --target: %w", err)
	}

	// Teardown on ctx cancellation (the surrounding runCaptureVisual defers
	// cancel()): kill the launched process group and remove the temp dir on
	// every exit path. Both run regardless of whether readiness succeeds.
	context.AfterFunc(ctx, func() {
		sandbox.KillProcessGroup(cmd)
		_ = os.RemoveAll(userDataDir)
	})

	waitCtx, waitCancel := context.WithTimeout(ctx, visualCDPReadyTimeout)
	defer waitCancel()
	if err := waitVisualCDPReady(waitCtx, port); err != nil {
		// Tear down eagerly rather than waiting for ctx — the caller will
		// also cancel ctx, but killing now releases the process promptly.
		sandbox.KillProcessGroup(cmd)
		_ = os.RemoveAll(userDataDir)
		return "", fmt.Errorf("--target launched but its CDP endpoint on port %d never became ready within %s (is %s a %s app with --remote-debugging-port support?): %w", port, visualCDPReadyTimeout, filepath.Base(targetAbs), fw, err)
	}

	return "127.0.0.1:" + strconv.Itoa(port), nil
}

// pickFreePortForVisual returns an OS-assigned ephemeral loopback port. There
// is a narrow close-then-launch race, accepted here as it is in RunLive.
func pickFreePortForVisual() (int, error) {
	l, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*gonet.TCPAddr).Port
	_ = l.Close()
	return port, nil
}

// waitVisualCDPReady polls /json/version until it answers 200 or ctx is done.
func waitVisualCDPReady(ctx context.Context, port int) error {
	endpoint := "http://127.0.0.1:" + strconv.Itoa(port) + "/json/version"
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			req, err := gonethttp.NewRequestWithContext(ctx, gonethttp.MethodGet, endpoint, nil)
			if err != nil {
				continue
			}
			resp, err := gonethttp.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == gonethttp.StatusOK {
				return nil
			}
		}
	}
}
