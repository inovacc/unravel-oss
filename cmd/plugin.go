/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// pluginCmd is the umbrella for plugin lifecycle commands. Concrete
// install/uninstall/status/extract handlers live in plugin_install.go
// (thin dispatchers that route to the selected aihost.Host).
var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Install / uninstall / inspect the unravel AI-host plugin",
	Long: `Manage the unravel plugin for any registered AI host (Claude Code,
Codex CLI, Gemini CLI). Host selection: --host=claude|codex|gemini, or
legacy --claude flag (implies --host=claude). Default: claude.

Subcommands:
  install [--host H] [--target PATH]   Render assets + patch host's marketplace/settings.
  uninstall [--host H]                  Reverse of install.
  status [--host H]                     Report current install state.
  extract [--host H] [--target PATH]    Dump rendered assets without JSON patches.
`,
}

func init() {
	rootCmd.AddCommand(pluginCmd)
	pluginCmd.AddCommand(pluginInstallCmd)
	pluginCmd.AddCommand(pluginUninstallCmd)
	pluginCmd.AddCommand(pluginStatusCmd)
	pluginCmd.AddCommand(pluginExtractCmd)

	for _, c := range []*cobra.Command{pluginInstallCmd, pluginUninstallCmd, pluginStatusCmd, pluginExtractCmd} {
		c.Flags().String("host", "", "AI host: claude (default), codex, gemini")
		c.Flags().Bool("claude", false, "[deprecated alias] equivalent to --host=claude")
	}
	pluginInstallCmd.Flags().String("target", "", "override install target directory (default: host's canonical path)")
	pluginInstallCmd.Flags().Bool("no-restart-hint", false, "suppress 'restart host' message")
	pluginExtractCmd.Flags().String("target", "", "target directory to write rendered assets (default: ./<host>-plugin)")
}
