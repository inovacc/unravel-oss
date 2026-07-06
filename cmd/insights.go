/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/insights"

	"github.com/spf13/cobra"
)

var insightsCmd = &cobra.Command{
	Use:   "insights",
	Short: "Self-improvement insights for unravel itself (local-only)",
	Long: `Captures unravel-usage friction metrics into local jsonl/json files,
rolls them up into stats, and emits improvement suggestions for
unravel's own commands, agents, MCP tools, and prompts. No telemetry
leaves the machine.

Storage root (platform):
  Windows : %LOCALAPPDATA%\Unravel\insights\improving
  Linux   : $XDG_DATA_HOME/unravel/insights/improving (or ~/.local/share/...)
  macOS   : ~/Library/Application Support/Unravel/insights/improving

Disable globally with env: UNRAVEL_INSIGHTS=off
`,
}

var insightsStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Report storage root, event count, last rollup",
	RunE: func(_ *cobra.Command, _ []string) error {
		root, err := insights.Root()
		if err != nil {
			return err
		}
		fmt.Printf("root      : %s\n", root)
		fmt.Printf("disabled  : %v\n", insights.IsDisabled())
		eventsDir, _ := insights.SubPath(insights.SubdirEvents)
		entries, _ := os.ReadDir(eventsDir)
		fmt.Printf("event files: %d\n", len(entries))
		goalsDir, _ := insights.SubPath(insights.SubdirGoals)
		gentries, _ := os.ReadDir(goalsDir)
		fmt.Printf("goal files : %d\n", len(gentries))
		return nil
	},
}

var insightsRollupCmd = &cobra.Command{
	Use:   "rollup",
	Short: "Aggregate events into per-command + per-goal stats; write monthly digest",
	RunE: func(cmd *cobra.Command, _ []string) error {
		days, _ := cmd.Flags().GetInt("days")
		jsonOut, _ := cmd.Flags().GetBool("json")
		r, err := insights.DoRollup(days, true)
		if err != nil {
			return err
		}
		if jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(r)
		}
		fmt.Printf("rollup window=%dd events=%d goals_seen=%d closed=%d open=%d median_jumps=%.1f p95=%.1f max=%d commands_tracked=%d\n",
			r.WindowDays, r.TotalEvents, r.GoalsSeen, r.GoalsClosed, r.GoalsOpen, r.MedianJumps, r.P95Jumps, r.MaxJumps, len(r.PerCommand))
		return nil
	},
}

var insightsSuggestCmd = &cobra.Command{
	Use:   "suggest",
	Short: "Generate improvement-candidate suggestions from the latest rollup",
	RunE: func(cmd *cobra.Command, _ []string) error {
		days, _ := cmd.Flags().GetInt("days")
		jsonOut, _ := cmd.Flags().GetBool("json")
		r, err := insights.DoRollup(days, false)
		if err != nil {
			return err
		}
		suggestions, err := insights.Suggest(r, true)
		if err != nil {
			return err
		}
		if jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(suggestions)
		}
		fmt.Printf("generated %d suggestion(s)\n", len(suggestions))
		for _, s := range suggestions {
			fmt.Printf("  [%s] %s: %s\n", s.Confidence, s.Rule, s.What)
		}
		return nil
	},
}

var insightsRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Gzip event files older than N days (default 30)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		days, _ := cmd.Flags().GetInt("older-than-days")
		dir, err := insights.SubPath(insights.SubdirEvents)
		if err != nil {
			return err
		}
		cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
		entries, _ := os.ReadDir(dir)
		rotated := 0
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			info, statErr := os.Stat(path)
			if statErr != nil || info.ModTime().After(cutoff) {
				continue
			}
			raw, rerr := os.ReadFile(path)
			if rerr != nil {
				continue
			}
			gzPath := path + ".gz"
			gz, gErr := os.Create(gzPath)
			if gErr != nil {
				continue
			}
			gw := gzip.NewWriter(gz)
			if _, wErr := gw.Write(raw); wErr == nil {
				_ = gw.Close()
				_ = gz.Close()
				_ = os.Remove(path)
				rotated++
			} else {
				_ = gw.Close()
				_ = gz.Close()
				_ = os.Remove(gzPath)
			}
		}
		fmt.Printf("rotated %d file(s) older than %d days\n", rotated, days)
		return nil
	},
}

var insightsAcceptCmd = &cobra.Command{
	Use:   "accept <suggestion-id>",
	Short: "Record acceptance of a suggestion in docs/improving/ for human follow-up",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		note, _ := cmd.Flags().GetString("note")
		// Resolve repo root: assume the cwd or the repo containing
		// the binary. Cheap heuristic — write to ./docs/improving
		// relative to cwd.
		dir := filepath.Join(".", "docs", "improving")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		dateStr := time.Now().UTC().Format("2006-01-02")
		path := filepath.Join(dir, dateStr+"-accepted.md")
		entry := fmt.Sprintf("\n## %s (accepted at %s)\n\n%s\n",
			id, time.Now().UTC().Format(time.RFC3339), note)
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		if _, err := f.WriteString(entry); err != nil {
			return err
		}
		fmt.Printf("recorded acceptance of %s in %s\n", id, path)
		return nil
	},
}

var insightsWipeCmd = &cobra.Command{
	Use:   "wipe",
	Short: "Delete all captured insights data (irreversible)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		confirm, _ := cmd.Flags().GetBool("yes")
		if !confirm {
			return fmt.Errorf("pass --yes to confirm; this deletes all data under the insights root")
		}
		root, err := insights.Root()
		if err != nil {
			return err
		}
		if err := os.RemoveAll(root); err != nil {
			return fmt.Errorf("wipe %s: %w", root, err)
		}
		fmt.Printf("wiped %s\n", root)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(insightsCmd)
	insightsCmd.AddCommand(insightsStatusCmd)
	insightsCmd.AddCommand(insightsRollupCmd)
	insightsCmd.AddCommand(insightsSuggestCmd)
	insightsCmd.AddCommand(insightsAcceptCmd)
	insightsCmd.AddCommand(insightsRotateCmd)
	insightsCmd.AddCommand(insightsWipeCmd)
	insightsAcceptCmd.Flags().String("note", "", "free-text rationale for accepting this suggestion")
	insightsRotateCmd.Flags().Int("older-than-days", 30, "gzip event files modified before this cutoff")

	insightsRollupCmd.Flags().Int("days", 30, "lookback window in days")
	insightsRollupCmd.Flags().Bool("json", false, "emit rollup as JSON instead of one-liner")
	insightsSuggestCmd.Flags().Int("days", 30, "lookback window in days")
	insightsSuggestCmd.Flags().Bool("json", false, "emit suggestions as JSON")
	insightsWipeCmd.Flags().Bool("yes", false, "confirm destructive operation")
}
