/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/inovacc/unravel-oss/internal/idle"
	pkgmcp "github.com/inovacc/unravel-oss/pkg/mcp"
	"github.com/inovacc/unravel-oss/pkg/mcp/lifecycle"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// processAlive delegates to lifecycle.ProcessAlive so there is one
// implementation of the platform-specific probe. Kept as a private
// shim to minimize churn in existing callers within this package.
func processAlive(pid int) bool { return lifecycle.ProcessAlive(pid) }

// startParentWatcher polls the recorded initial parent PID and cancels ctx
// when the parent disappears. This catches the "zombie MCP daemon" failure
// mode: Claude Code crashes or its connection drops, the child unravel mcp
// process should exit on stdin EOF but in some host implementations EOF is
// never delivered and the child idles forever consuming RAM. Polling
// every 5s gives bounded teardown latency without measurable overhead.
func startParentWatcher(ctx context.Context, cancel context.CancelFunc, logger *slog.Logger) {
	ppid := os.Getppid()
	// PPID 0 / 1 mean we have no real parent (Unix init or already orphaned).
	// A PPID equal to our own PID indicates a bug in the runtime — ignore.
	if ppid <= 1 || ppid == os.Getpid() {
		return
	}
	go watchProcess(ctx, cancel, ppid, 5*time.Second, logger)
}

// watchProcess polls the given PID at pollEvery intervals until either
// ctx is cancelled or the process disappears, in which case it calls
// cancel(). Split out from startParentWatcher so unit tests can verify
// the polling/cancel mechanics against a controllable subprocess
// without depending on the real os.Getppid() of the test runner.
func watchProcess(ctx context.Context, cancel context.CancelFunc, pid int, pollEvery time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !processAlive(pid) {
				if logger != nil {
					logger.Warn("watched process exited, shutting down", "pid", pid)
				}
				cancel()
				return
			}
		}
	}
}

// stdioTransport returns the stdio transport wrapped in a HAR-style
// recorder when the per-session interaction-log directory can be resolved.
// Falls back to a bare stdio transport on any failure so the server
// stays usable when the local app-data tree is unavailable.
func stdioTransport() mcp.Transport {
	var base mcp.Transport = &mcp.StdioTransport{}
	dir := os.Getenv("UNRAVEL_MCP_HAR_DIR")
	if dir == "" {
		if appData := os.Getenv("LOCALAPPDATA"); appData != "" {
			dir = filepath.Join(appData, "Unravel", "mcp", "interacts")
		}
	}
	if dir == "" {
		return base
	}
	maxFiles := 10000
	if v := os.Getenv("UNRAVEL_HAR_MAX_FILES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			maxFiles = n
		}
	}
	return &pkgmcp.HARTransport{Transport: base, Dir: dir, MaxFiles: maxFiles}
}

// ServerConfig holds configuration for the MCP server.
type ServerConfig struct {
	Logger      *slog.Logger
	IdleTimeout time.Duration // auto-shutdown after inactivity (0 disables)
	// AfterConnect, if non-nil, fires once after the stdio session is
	// established and BEFORE Serve blocks on the session loop. Used by
	// cmd/mcp.go to wire the internal/mcp sampling singleton (D-12).
	AfterConnect func(*mcp.ServerSession)
	// OnServer, if non-nil, fires after all built-in tools are registered
	// and before the server starts accepting requests. Used by cmd/mcp.go
	// to wire optional, env-gated tool families such as the kb_* tools
	// that depend on UNRAVEL_KB_DSN being set at server start
	// (D-33-DSN-SOURCE).
	OnServer func(*mcp.Server)
}

// mcpState holds optional idle timer for tool activity tracking.
type mcpState struct {
	idle *idle.Timer
}

// touch resets the idle timer on activity.
func (s *mcpState) touch() {
	if s.idle != nil {
		s.idle.Reset()
	}
}

// NewServer creates an MCP server with all unravel tools registered.
func NewServer(cfgs ...ServerConfig) *mcp.Server {
	var cfg ServerConfig
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "unravel",
		Version: "1.0.0",
	}, &mcp.ServerOptions{
		Logger: logger,
		// CompletionHandler returns an empty result instead of letting the
		// SDK reply -32601 Method not found when a host probes completion
		// capabilities. The unravel server does not implement completions
		// (it's a tool-only surface) but emitting -32601 on every
		// completion/complete probe spams the HAR transport log with
		// orphan_response entries during stdio reconnects.
		CompletionHandler: func(_ context.Context, _ *mcp.CompleteRequest) (*mcp.CompleteResult, error) {
			return &mcp.CompleteResult{}, nil
		},
	})

	registerGarbleTools(server)
	registerTPMTools(server)
	registerRegistryTools(server)
	registerDPAPITools(server)
	registerCertTools(server)
	registerExtensionTools(server)
	registerAsarTools(server)
	registerAnalyzeTools(server)
	registerLeveldbTools(server)
	registerCacheTools(server)
	registerIPCTools(server)
	registerLicenseTools(server)
	registerJsdeobTools(server)
	registerAndroidTools(server)
	registerDebTools(server)
	registerRpmTools(server)
	registerDetectTools(server)
	registerDisasmTools(server)
	registerMsiTools(server)
	registerMsixTools(server)
	registerDissectTools(server)
	registerFridaTools(server)
	registerFridaPhase9Tools(server)
	registerCaptureTools(server)
	registerCapturePhase8Tools(server)
	registerCaptureWebView2AttachTool(server)
	registerSchemaTools(server)
	registerHeuristicTools(server)
	registerKnowledgeTools(server)
	registerKBLoopTools(server)
	registerKBPendingEnrichTool(server)
	registerKBCostReportTool(server)
	registerKBEnrichRecordTool(server)
	registerKBVendoredCandidatesTool(server)
	registerPluginDoctorTool(server)
	registerInsightsTools(server)
	registerJavaTools(server)
	registerDotnetTools(server)
	registerNpmTools(server)
	registerIOSTools(server)
	registerSourcemapTools(server)
	registerCSSTools(server)
	registerAdvinstallerTools(server)
	registerProbeTools(server)
	registerWasmTools(server)
	registerNodeaddonTools(server)
	registerForensicTools(server)
	registerReconstructTools(server)
	registerTranspileTools(server)
	registerWebView2Tools(server)
	registerWinUITools(server)
	registerUWPTools(server)
	registerBundleTools(server)
	registerInjectTools(server)
	registerGoversionsTools(server)
	registerFindingsTools(server)

	if cfg.OnServer != nil {
		cfg.OnServer(server)
	}

	return server
}

// Serve starts the MCP server with stdio transport.
// If cfg.IdleTimeout > 0, the server shuts down after inactivity.
// If cfg.AfterConnect is non-nil, it fires post-Connect / pre-Wait so callers
// can wire per-session state such as the sampling singleton (D-12).
func Serve(ctx context.Context, cfg ServerConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Registry: write a $LOCALAPPDATA/Unravel/mcp/instances/<pid>.json
	// record so `unravel mcp list` can enumerate live servers and
	// `unravel mcp clean` can prune orphaned ones. Best-effort: a
	// registry failure does not block server start.
	instDir, dirErr := lifecycle.DefaultDir()
	if dirErr != nil {
		logger.Info("mcp registry disabled", "err", dirErr)
	}
	inst, regErr := lifecycle.Register(instDir, lifecycle.Info{Version: "1.0.0"})
	if regErr != nil {
		logger.Info("mcp registry register failed", "err", regErr)
	}
	defer func() { _ = inst.Close() }()

	server := newServerWithIdle(cfg, cancel)
	// Activity middleware: touch the registry on every receive so
	// `mcp list` reports accurate last-activity, and `mcp clean`
	// distinguishes genuinely idle entries from active ones.
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			inst.Touch()
			return next(ctx, method, req)
		}
	})
	startParentWatcher(ctx, cancel, cfg.Logger)

	// When no AfterConnect hook is set, preserve the simpler server.Run path
	// to keep behaviour byte-identical for callers that don't need it.
	if cfg.AfterConnect == nil {
		return server.Run(ctx, stdioTransport())
	}

	ss, err := server.Connect(ctx, stdioTransport(), nil)
	if err != nil {
		return fmt.Errorf("unravel: mcp: %w", err)
	}
	cfg.AfterConnect(ss)

	ssClosed := make(chan error, 1)
	go func() { ssClosed <- ss.Wait() }()

	select {
	case <-ctx.Done():
		_ = ss.Close()
		<-ssClosed
		return ctx.Err()
	case err := <-ssClosed:
		return err
	}
}

// ServeSSE starts the MCP server with HTTP+SSE transport on the given address.
func ServeSSE(ctx context.Context, addr string, cfg ServerConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	handler := mcp.NewSSEHandler(func(_ *http.Request) *mcp.Server {
		return newServerWithIdle(cfg, cancel)
	}, nil)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout intentionally 0: MCP SSE streams are long-lived; a non-zero WriteTimeout terminates events.
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("unravel: mcp: %w", err)
	}

	logger.Info("MCP SSE server listening", "addr", ln.Addr().String())

	errCh := make(chan error, 1)

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("unravel: mcp: %w", err)
		}

		close(errCh)
	}()

	select {
	case <-ctx.Done():
		_ = srv.Close()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// newServerWithIdle creates a server with idle timeout support.
//
// When cfg.IdleTimeout > 0 the timer is wired into the server's receiving
// middleware so every incoming JSON-RPC request (initialize, tools/call,
// tools/list, ping, etc.) resets the countdown. Without this hook the
// timer was previously instantiated, immediately dropped on the floor,
// and fired at the raw timeout regardless of activity — i.e.
// --idle-timeout=30m would hard-kill the server 30 minutes after start
// even under continuous tool traffic.
func newServerWithIdle(cfg ServerConfig, cancel func()) *mcp.Server {
	server := NewServer(cfg)

	if cfg.IdleTimeout > 0 {
		logger := cfg.Logger
		if logger == nil {
			logger = slog.Default()
		}

		state := &mcpState{
			idle: idle.New(cfg.IdleTimeout, func() {
				logger.Warn("idle timeout reached, shutting down", "timeout", cfg.IdleTimeout)
				cancel()
			}),
		}

		server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				state.touch()
				return next(ctx, method, req)
			}
		})
	}

	return server
}
