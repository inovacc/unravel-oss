/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/inovacc/unravel-oss/pkg/mcp/lifecycle"

	"github.com/spf13/cobra"
)

// mcpListCmd enumerates the registry entries written by every `unravel
// mcp` stdio server on this host. Output is a single-line-per-instance
// table on stdout by default; `--json` prints the raw record array for
// scripting.
var mcpListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered unravel mcp instances on this host",
	Long: `Enumerate the per-PID JSON records under $LOCALAPPDATA/Unravel/mcp/instances/
(or $XDG_STATE_HOME/unravel/mcp/instances on Unix). Each row reports
process PID, parent PID, age, last-activity age, project dir, and whether
the process and its parent are still alive — so the operator can see
which instances are zombies before invoking 'unravel mcp clean'.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		dir, err := lifecycle.DefaultDir()
		if err != nil {
			return fmt.Errorf("registry dir: %w", err)
		}
		entries, err := lifecycle.List(dir)
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].PID < entries[j].PID })
		asJSON, _ := cmd.Flags().GetBool("json")
		if asJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(entries)
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PID\tPPID\tSELF\tPARENT\tAGE\tIDLE\tPROJECT")
		now := time.Now().UTC()
		for _, e := range entries {
			selfAlive := lifecycleProcessAlive(e.PID)
			parentAlive := lifecycleProcessAlive(e.ParentPID)
			fmt.Fprintf(w, "%d\t%d\t%s\t%s\t%s\t%s\t%s\n",
				e.PID, e.ParentPID,
				aliveString(selfAlive), aliveString(parentAlive),
				short(now.Sub(e.StartedAt)),
				short(now.Sub(e.LastActivityAt)),
				e.ProjectDir,
			)
		}
		return w.Flush()
	},
}

// mcpCleanCmd removes stale registry entries. Default policy: only
// remove entries whose process is dead OR whose parent is dead AND
// last activity is older than 10 minutes. --force drops the activity
// check (removes any record whose process or parent is dead).
var mcpCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove stale unravel mcp registry entries",
	Long: `Walk the per-host registry directory and remove entries whose owning
process is no longer alive, plus (without --force) entries whose parent
process is dead AND last activity is older than 10 minutes.

The calling process's own record is always preserved. Note: clean only
removes the JSON record — if the target process is still running its
parent is gone but the kernel hasn't reaped it yet, clean does not
signal it. Use the OS process tooling (Stop-Process / kill) for that.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		dir, err := lifecycle.DefaultDir()
		if err != nil {
			return fmt.Errorf("registry dir: %w", err)
		}
		force, _ := cmd.Flags().GetBool("force")
		results, err := lifecycle.Clean(dir, force)
		if err != nil {
			return fmt.Errorf("clean: %w", err)
		}
		removed := 0
		for _, r := range results {
			if r.Err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warn: pid=%d remove failed: %v\n", r.Info.PID, r.Err)
				continue
			}
			if r.Removed {
				removed++
				fmt.Fprintf(cmd.OutOrStdout(), "removed pid=%d reason=%s project=%s\n",
					r.Info.PID, r.Reason, r.Info.ProjectDir)
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%d entries removed, %d kept\n", removed, len(results)-removed)
		return nil
	},
}

func init() {
	mcpListCmd.Flags().Bool("json", false, "Emit JSON array instead of tabular output")
	mcpCleanCmd.Flags().Bool("force", false, "Remove dead-self/dead-parent entries regardless of last-activity age")
	mcpCmd.AddCommand(mcpListCmd, mcpCleanCmd)
}

// lifecycleProcessAlive is a thin alias for lifecycle.ProcessAlive,
// kept as a function so the call sites in this file stay symmetric
// with the rest of the codebase.
func lifecycleProcessAlive(pid int) bool { return lifecycle.ProcessAlive(pid) }

func aliveString(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// short renders a duration with one significant unit, dropping the
// fractional tail for the table view (e.g. 12h instead of 12h13m4.2s).
func short(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}
