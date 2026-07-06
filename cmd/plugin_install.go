/*
Copyright (c) 2026 Security Research
*/

// Thin cobra dispatcher for `unravel plugin install|uninstall|status|extract`.
// Host-specific install rituals (marketplace patches, settings.json,
// claude CLI shell-outs) live in pkg/aihost/<host>/install.go and
// pkg/aihost/<host>/doctor.go. This file only routes flags to the
// selected host. When --host is not given, --claude implies host=claude.

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/aihost"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/all" // register hosts

	"github.com/spf13/cobra"
)

const defaultHost = "claude"

func selectedHost(cmd *cobra.Command) (aihost.Host, error) {
	hostFlag, _ := cmd.Flags().GetString("host")
	claudeFlag, _ := cmd.Flags().GetBool("claude")
	switch {
	case hostFlag != "":
		// pass-through
	case claudeFlag:
		hostFlag = "claude"
	default:
		hostFlag = defaultHost
	}
	h, ok := aihost.ByName(hostFlag)
	if !ok {
		return nil, fmt.Errorf("unknown host %q (registered: see `unravel plugin hosts`)", hostFlag)
	}
	return h, nil
}

var pluginInstallCmd = &cobra.Command{
	Use:   "install [--host claude|codex|gemini] [--target PATH]",
	Short: "Install the unravel plugin into the selected AI host",
	RunE: func(cmd *cobra.Command, _ []string) error {
		h, err := selectedHost(cmd)
		if err != nil {
			return err
		}
		target, _ := cmd.Flags().GetString("target")
		noHint, _ := cmd.Flags().GetBool("no-restart-hint")
		if target == "" {
			target, err = h.InstallTarget()
			if err != nil {
				return fmt.Errorf("resolve install target: %w", err)
			}
		}

		inst, ok := h.(aihost.Installer)
		if !ok {
			return fmt.Errorf("host %q does not yet implement install (TODO)", h.Name())
		}
		n, err := inst.Install(target)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[install] host=%s target=%s files=%d\n", h.Name(), target, n)

		if statusCarrier, ok := h.(aihost.Status); ok {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "[install] status:")
			_ = statusCarrier.PrintStatus(os.Stderr)
			fmt.Fprintln(os.Stderr, "")
		}
		if !noHint {
			fmt.Fprintln(os.Stderr, "[install] done. Restart the host to load the plugin.")
		}
		return nil
	},
}

var pluginUninstallCmd = &cobra.Command{
	Use:   "uninstall [--host claude|codex|gemini]",
	Short: "Remove the unravel plugin from the selected AI host",
	RunE: func(cmd *cobra.Command, _ []string) error {
		h, err := selectedHost(cmd)
		if err != nil {
			return err
		}
		target, err := h.InstallTarget()
		if err != nil {
			return err
		}
		inst, ok := h.(aihost.Installer)
		if !ok {
			return fmt.Errorf("host %q does not yet implement uninstall (TODO)", h.Name())
		}
		if err := inst.Uninstall(target); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "[uninstall] done. Restart the host to drop the plugin.")
		return nil
	},
}

var pluginStatusCmd = &cobra.Command{
	Use:   "status [--host claude|codex|gemini]",
	Short: "Report install state for the selected AI host",
	RunE: func(cmd *cobra.Command, _ []string) error {
		h, err := selectedHost(cmd)
		if err != nil {
			return err
		}
		if statusCarrier, ok := h.(aihost.Status); ok {
			return statusCarrier.PrintStatus(os.Stdout)
		}
		return fmt.Errorf("host %q does not implement Status reporting", h.Name())
	},
}

var pluginExtractCmd = &cobra.Command{
	Use:   "extract --target PATH [--host claude|codex|gemini]",
	Short: "Dump rendered plugin assets to PATH (no JSON patches)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		h, err := selectedHost(cmd)
		if err != nil {
			return err
		}
		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			target = filepath.Join(cwd, h.Name()+"-plugin")
		}
		n := 0
		if err := h.Walk(func(p string, data []byte) error {
			dst := filepath.Join(target, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				return err
			}
			n++
			return nil
		}); err != nil {
			return err
		}
		mf, err := h.ManifestFiles()
		if err != nil {
			return err
		}
		for p, data := range mf {
			dst := filepath.Join(target, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				return err
			}
			n++
		}
		fmt.Fprintf(os.Stderr, "[extract] host=%s wrote %d files to %s\n", h.Name(), n, target)
		return nil
	},
}
