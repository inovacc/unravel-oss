/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/aihost/claude"
)

// `unravel hook <name>` — Claude Code lifecycle hook handlers.
//
// The plugin's hooks/hooks.json (pkg/aihost/claude/hooks.go) wires Claude
// Code lifecycle events to direct invocations of this binary. Claude Code
// pipes the event JSON to the command's stdin. Each handler reads it and
// dials the supervisor for authoritative state.
//
// CONTRACT: a hook must NEVER block the session on missing wiring. Every
// handler — including unknown names — drains stdin and exits 0 until its
// real logic lands. That makes installing the hooks manifest always safe:
// an unimplemented handler is an invisible no-op, never a broken session.

var hookCmd = &cobra.Command{
	Use:   "hook <name>",
	Short: "Claude Code lifecycle hook handlers (invoked by the plugin's hooks.json)",
	Long: `Handlers for the Claude Code lifecycle hooks unravel ships in
hooks/hooks.json. Not meant to be run by hand — Claude Code invokes
` + "`unravel hook <name>`" + ` on lifecycle events and pipes the event JSON to
stdin. Unimplemented handlers drain stdin and exit 0 (safe no-op).`,
	// Catch-all: any `unravel hook <anything>` with no matching subcommand
	// falls through here and no-ops, so a future hooks.json entry can never
	// hard-fail a session before its handler exists.
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		name := "(none)"
		if len(args) > 0 {
			name = args[0]
		}

		return hookNoop(cmd, name)
	},
}

// hookNoop drains the hook event JSON from stdin and exits 0.
func hookNoop(cmd *cobra.Command, name string) error {
	_, _ = io.Copy(io.Discard, cmd.InOrStdin())
	fmt.Fprintf(os.Stderr, "[hook %s] no-op (handler not yet implemented)\n", name)

	return nil
}

// extractDissectPath decodes a Claude Code PostToolUse payload and returns the
// dissected artifact path, trying the common input keys. Returns "" on any
// parse failure or when no path key is present (no-op-safe).
func extractDissectPath(r io.Reader) string {
	var payload struct {
		ToolInput map[string]any `json:"tool_input"`
	}
	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return ""
	}
	for _, k := range []string{"path", "file", "target"} {
		if v, ok := payload.ToolInput[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// runHookKBCapture is the PostToolUse(unravel_app_dissect) handler. It
// auto-persists dissect output to the KB by calling buildKB on the dissected
// path. It is strictly no-op-safe: every failure logs to stderr and returns
// nil (exit 0), so a broken KB config never breaks the user's session.
func runHookKBCapture(cmd *cobra.Command, _ []string) error {
	path := extractDissectPath(cmd.InOrStdin())
	if path == "" {
		slog.Debug("[hook kb-capture] no dissect path in payload; no-op")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := buildKB(ctx, path, buildOpts{}); err != nil {
		slog.Warn("[hook kb-capture] buildKB failed (non-fatal)", "path", path, "err", err)
	}
	return nil
}

func init() {
	// Register a real subcommand for every hook the manifest references, so
	// `unravel hook resume`/`heal` are discoverable in --help and each has a
	// stable seam to grow its handler into. kb-capture is special-cased to
	// its real handler; every other name stays a no-op until its logic lands.
	for _, name := range claude.HookNames() {
		sub := &cobra.Command{
			Use:   name,
			Short: "hook handler: " + name,
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return hookNoop(cmd, name)
			},
		}
		if name == "kb-capture" {
			sub.RunE = runHookKBCapture
		}
		hookCmd.AddCommand(sub)
	}

	rootCmd.AddCommand(hookCmd)
}
