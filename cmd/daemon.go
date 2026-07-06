/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/internal/supervisor"
)

// daemonCmd groups the host-singleton supervisor lifecycle commands.
var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the unravel host-singleton supervisor daemon",
	Long: `The supervisor is a long-lived, one-per-user daemon that owns the KB
Postgres pool and session/workspace state. MCP tool processes (one per Claude
Code session) dial it over IPC and never open their own DB. It is normally
autospawned by 'unravel mcp' on first tool call; 'daemon serve' runs it
explicitly for manual / debugging use.`,
}

// daemonServeCmd is the entrypoint that internal/supervisor/autospawn.go execs
// as 'daemon serve --detached'. Without it, autospawn cannot launch the
// supervisor and every thin-client KB/enrich tool fails.
var daemonServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the host-singleton supervisor (foreground; blocks until signal)",
	Long: `Run the supervisor daemon. Resolves the KB DSN the same way 'unravel mcp'
does (UNRAVEL_KB_DSN env, else config.yaml password_enc + OS keychain), binds
the per-user IPC endpoint (UDS on POSIX, named pipe on Windows), and serves
verbs until SIGINT/SIGTERM.

Autospawned form: 'unravel daemon serve --detached', launched detached by the
MCP server's first-tool-call autospawn. Safe to run when one is already up — it
detects the live endpoint and exits 0.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

		// Resolve the KB DSN exactly like cmd/mcp.go: env first, then the
		// config.yaml password_enc ciphertext decrypted via the OS keychain.
		// A miss is non-fatal — the supervisor still serves non-DB verbs and
		// kb.* report unavailable at call time.
		dsn, err := kb_output.ResolveDSN("")
		if err != nil {
			logger.Warn("daemon: KB DSN unresolved; kb.* verbs will report unavailable", "err", err)
		}

		return serveDaemon(ctx, supervisor.DefaultSocketDir(), dsn, logger)
	},
}

// serveDaemon brings up the supervisor on socketDir and blocks until ctx is
// cancelled, then shuts it down cleanly. If a supervisor is already listening
// on the endpoint it returns nil immediately (idempotent — autospawn races and
// manual re-invocation are harmless).
func serveDaemon(ctx context.Context, socketDir, dsn string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	if supervisorReachable(ctx, socketDir) {
		logger.Info("daemon: supervisor already running; nothing to do",
			"socket", supervisor.SocketPath(socketDir))
		return nil
	}

	sv, err := supervisor.New(supervisor.Config{
		SocketDir: socketDir,
		DSN:       dsn,
		Logger:    logger,
	})
	if err != nil {
		return fmt.Errorf("daemon: new supervisor: %w", err)
	}

	if err := sv.Start(ctx); err != nil {
		// Release resources opened by New (the DB pool) and any partial Start
		// state. Stop is idempotent and nil-safe for an early-bail Start.
		_ = sv.Stop()
		if startErrIsBenign(err) {
			// A peer won the host-singleton race after our reachable probe
			// missed it — the singleton serialization working as intended.
			// Honour the documented "detect the live endpoint and exit 0"
			// contract so the autospawn caller does not record a spurious
			// spawn failure into the crash-loop guard.
			logger.Info("daemon: another supervisor owns the host-singleton; nothing to do",
				"socket", sv.SocketPath())
			return nil
		}
		return fmt.Errorf("daemon: start supervisor: %w", err)
	}
	logger.Info("daemon: supervisor listening", "socket", sv.SocketPath())

	<-ctx.Done()
	logger.Info("daemon: shutdown signal received")
	return sv.Stop()
}

// supervisorReachable reports whether a supervisor is already listening on the
// endpoint derived from socketDir. A successful dial (the pipe/socket accepts a
// connection) is sufficient liveness evidence; we drop the connection without
// completing the handshake.
func supervisorReachable(ctx context.Context, socketDir string) bool {
	dctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	conn, err := ipc.Dial(dctx, supervisor.SocketPath(socketDir))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// startErrIsBenign reports whether a supervisor.Start error means a peer
// already owns the host-singleton lock. That is a non-error outcome for
// `daemon serve`: the singleton serialization did its job, so we exit 0 rather
// than surfacing a fatal error that the autospawn caller would mis-record as a
// spawn failure.
func startErrIsBenign(err error) bool {
	return errors.Is(err, supervisor.ErrSingletonHeld)
}

func init() {
	// --detached is the marker the MCP autospawn passes (`daemon serve
	// --detached`). The process is already detached from the parent console by
	// the platform-specific spawn flags, so the flag is accepted purely for
	// invocation compatibility; serveDaemon behaves identically with or without.
	daemonServeCmd.Flags().Bool("detached", false,
		"accepted for 'unravel mcp' autospawn compatibility (process is already detached)")
	daemonCmd.AddCommand(daemonServeCmd)
	rootCmd.AddCommand(daemonCmd)
}
