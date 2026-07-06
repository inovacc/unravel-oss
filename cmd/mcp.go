/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	"github.com/inovacc/unravel-oss/internal/ai"
	mcpinternal "github.com/inovacc/unravel-oss/internal/mcp"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	kbllm "github.com/inovacc/unravel-oss/pkg/knowledge/kb/llm"
	pkgmcp "github.com/inovacc/unravel-oss/pkg/mcp"
	mcptools "github.com/inovacc/unravel-oss/pkg/mcp/tools"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

// mcpCmd starts the stdio MCP server. CC registration moved to
// `unravel plugin install --claude` (single bootstrap for plugin + MCP).
// The former --install / --claude flags here were removed 2026-05-23 —
// pre-release, no users to support back-compat for.
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run the MCP stdio server",
	Long: `Start the MCP (Model Context Protocol) server. Spawned by Claude Code
(or Cursor / any MCP client) on demand — registered into ~/.claude/settings.json
by 'unravel plugin install --claude'.

Flags:
  --no-autospawn      Don't autospawn the supervisor on first tool call (returns ErrSupervisorUnavailable instead)
  --idle-timeout DUR  Auto-shutdown after inactivity (default 1h, 0 disables)

Install separately:
  unravel plugin install --claude   Register plugin + MCP into Claude Code`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Fprintln(os.Stderr, mcpServeStartupNotice())

		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		idleTimeout, _ := cmd.Flags().GetDuration("idle-timeout")

		// Direct-mode KB DSN init (D-33-DSN-SOURCE). Pool is opened ONCE at
		// server start so all five unravel_kb_* handlers share it. When
		// UNRAVEL_KB_DSN is unset (or db.Open fails) kbDB stays nil and
		// each kb_* handler returns IsError=true with the canonical hint
		// at call time (D-33-DSN-FAIL-AT-CALL). Tool advertisement remains
		// independent of runtime DSN availability so the tool-count
		// invariant holds globally.
		//
		// signal.NotifyContext propagates SIGINT/SIGTERM into the server
		// ctx so a Ctrl-C from a manual invocation, or a kill from a
		// supervising process, triggers an orderly shutdown (DB pool
		// closed, idle timer stopped) instead of a hard exit that leaves
		// stale state in the keychain-backed DSN pool.
		ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stopSignals()
		var kbDB *sql.DB
		// D-33-DSN-SOURCE expanded 2026-05-05: fall back to config.yaml
		// DPAPI-encrypted password when UNRAVEL_KB_DSN env var is empty.
		// Mirrors the CLI resolver (cmd/kb_output.ResolveDSN) so MCP-mode
		// users don't need to manually export the DSN if first-run config
		// already wired the keychain.
		dsn, dsnErr := kb_output.ResolveDSN("")
		if dsnErr != nil {
			logger.Info("kb DSN resolve failed; kb_* tools will report DSN error at call time", "err", dsnErr)
		} else if dsn != "" {
			pool, err := kbdb.Open(ctx, dsn)
			if err != nil {
				logger.Warn("kb DSN resolved but db.Open failed; kb_* tools will report DSN error at call time", "err", err)
			} else {
				kbDB = pool
				logger.Info("kb DSN connection pool opened for kb_* tools")
			}
		}
		// D-33-CONNECTION-LIFECYCLE: pool kept open for server lifetime.
		defer func() {
			if kbDB != nil {
				_ = kbDB.Close()
			}
		}()

		return mcptools.Serve(ctx, mcptools.ServerConfig{
			Logger: logger, IdleTimeout: idleTimeout,
			OnServer: func(s *gomcp.Server) {
				mcptools.RegisterKB(s, kbDB)
				mcptools.RegisterKBImportExport(s)
			},
			AfterConnect: func(ss *gomcp.ServerSession) {
				pkgmcp.SetSession(ss, logger)
				ai.SetMCPClient(mcpinternal.ForensicClient())
				kbllm.SetSamplingResolver(mcpinternal.EnrichClient)
				logger.Info("MCP sampling client wired")
			},
		})
	},
}

// mcpServeStartupNotice explains the CLI-first doctrine: this server is not
// auto-registered in Claude Code; it exists for external clients and
// flow-scoped subagents (see CLAUDE.md "MCP → CLI integration").
func mcpServeStartupNotice() string {
	return "unravel mcp serve: not auto-registered in Claude Code (CLI-first); for external clients and flow-scoped subagents"
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	// v2.17: supervisor singleton replaces the gRPC daemon. --no-autospawn
	// short-circuits getKBClient / getEnrichClient / etc to
	// ErrSupervisorUnavailable instead of attempting the autospawn fork.
	// Useful for tests + CI environments where the supervisor lifecycle is
	// managed externally.
	mcpCmd.Flags().Bool("no-autospawn", false, "Refuse to autospawn the supervisor on first tool call")
	// Default 1h. Idle = no incoming JSON-RPC request for the full window;
	// the receive middleware in pkg/mcptools/server.go resets the timer on
	// every initialize/tools/list/tools/call/ping. Pass --idle-timeout 0 to
	// disable (long-lived ops use). Per BACKLOG KBC-MCP-INSTANCE-CONTROL.
	mcpCmd.Flags().Duration("idle-timeout", time.Hour, "Auto-shutdown after inactivity (0 disables; default 1h)")
}
