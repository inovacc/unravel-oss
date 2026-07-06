/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	out "github.com/inovacc/unravel-oss/cmd/output"

	"github.com/spf13/cobra"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Browse and compare debug sessions",
	Long: `Browse debug sessions created by the --debug flag.

Debug sessions contain timestamped artifacts from dissect runs,
including step metadata, timing, inputs/outputs, and AI prompts.

Subcommands:
  list    - List all debug sessions
  show    - Show session details and step breakdown
  diff    - Compare two sessions side by side`,
}

var debugListCmd = &cobra.Command{
	Use:   "list [directory]",
	Short: "List all debug sessions",
	Long:  "List all debug sessions found under ./debug/ (or a custom directory).",
	Args:  cobra.MaximumNArgs(1),
	Run:   runDebugList,
}

var debugShowCmd = &cobra.Command{
	Use:   "show <session>",
	Short: "Show session details and step breakdown",
	Long: `Show detailed information about a debug session.

The argument can be:
  - A session directory name (e.g., 2026-02-24_14-30-00)
  - A full path to the session directory
  - "latest" to show the most recent session`,
	Args: cobra.ExactArgs(1),
	Run:  runDebugShow,
}

var debugDiffCmd = &cobra.Command{
	Use:   "diff <session1> <session2>",
	Short: "Compare two debug sessions",
	Long: `Compare two debug sessions side by side.

Shows differences in file types, analyses performed, step durations,
and error counts between two sessions.`,
	Args: cobra.ExactArgs(2),
	Run:  runDebugDiff,
}

func init() {
	rootCmd.AddCommand(debugCmd)
	debugCmd.AddCommand(debugListCmd)
	debugCmd.AddCommand(debugShowCmd)
	debugCmd.AddCommand(debugDiffCmd)
	debugShowCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
	debugDiffCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}

func runDebugList(_ *cobra.Command, args []string) {
	dir := "debug"
	if len(args) == 1 {
		dir = args[0]
	}

	sessions, err := listSessions(dir)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if len(sessions) == 0 {
		fmt.Println("No debug sessions found.")
		fmt.Println("Run dissect with --debug to create one:")
		fmt.Println("  unravel dissect ./file --debug")
		return
	}

	out.PrintDebugList(sessions)
}

func runDebugShow(_ *cobra.Command, args []string) {
	session, err := resolveSession(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	detail, err := loadSession(session)
	if err != nil {
		fmt.Printf("Error loading session: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(detail)
		return
	}

	out.PrintDebugShow(detail)
}

func runDebugDiff(_ *cobra.Command, args []string) {
	s1, err := resolveSession(args[0])
	if err != nil {
		fmt.Printf("Error resolving session 1: %v\n", err)
		os.Exit(1)
	}

	s2, err := resolveSession(args[1])
	if err != nil {
		fmt.Printf("Error resolving session 2: %v\n", err)
		os.Exit(1)
	}

	d1, err := loadSession(s1)
	if err != nil {
		fmt.Printf("Error loading session 1: %v\n", err)
		os.Exit(1)
	}

	d2, err := loadSession(s2)
	if err != nil {
		fmt.Printf("Error loading session 2: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"session1": d1, "session2": d2})
		return
	}

	out.PrintDebugDiff(d1, d2)
}

func listSessions(baseDir string) ([]out.SessionSummary, error) {
	entries, err := os.ReadDir(baseDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", baseDir, err)
	}

	var sessions []out.SessionSummary
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		sessionPath := filepath.Join(baseDir, entry.Name())
		summary := out.SessionSummary{
			Name: entry.Name(),
			Path: sessionPath,
		}

		// Try to read session.json for metadata
		sessionJSON := filepath.Join(sessionPath, "session.json")
		if data, err := os.ReadFile(sessionJSON); err == nil {
			var meta map[string]any
			if json.Unmarshal(data, &meta) == nil {
				if ts, ok := meta["timestamp"].(string); ok {
					summary.Timestamp = ts
				}
				if ft, ok := meta["file_type"].(string); ok {
					summary.FileType = ft
				}
				if inp, ok := meta["input"].(string); ok {
					summary.Input = inp
				}
				if cnt, ok := meta["analyses_count"].(float64); ok {
					summary.Steps = int(cnt)
				}
				if cnt, ok := meta["errors_count"].(float64); ok {
					summary.Errors = int(cnt)
				}
				if dur, ok := meta["duration_ms"].(float64); ok {
					summary.Duration = int64(dur)
				}
			}
		}

		sessions = append(sessions, summary)
	}

	// Sort by name descending (newest first)
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].Name > sessions[j].Name
	})

	return sessions, nil
}

func resolveSession(arg string) (string, error) {
	// Full path
	if filepath.IsAbs(arg) {
		if _, err := os.Stat(arg); err != nil {
			return "", fmt.Errorf("session not found: %s", arg)
		}
		return arg, nil
	}

	// "latest" keyword
	if strings.EqualFold(arg, "latest") {
		sessions, err := listSessions("debug")
		if err != nil {
			return "", err
		}
		if len(sessions) == 0 {
			return "", fmt.Errorf("no debug sessions found")
		}
		return sessions[0].Path, nil
	}

	// Session name under debug/
	candidate := filepath.Join("debug", arg)
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}

	// Try as-is (relative path)
	if _, err := os.Stat(arg); err == nil {
		return arg, nil
	}

	return "", fmt.Errorf("session not found: %s", arg)
}

func loadSession(dir string) (*out.SessionDetail, error) {
	detail := &out.SessionDetail{
		Name: filepath.Base(dir),
		Path: dir,
	}

	// Load session.json
	sessionJSON := filepath.Join(dir, "session.json")
	if data, err := os.ReadFile(sessionJSON); err == nil {
		var meta map[string]any
		if json.Unmarshal(data, &meta) == nil {
			detail.Session = meta
		}
	}

	// Find step directories (each has metadata.json)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read session dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			detail.Files = append(detail.Files, entry.Name())
			continue
		}

		metaPath := filepath.Join(dir, entry.Name(), "metadata.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}

		var step out.StepMetadata
		if json.Unmarshal(data, &step) == nil {
			detail.Steps = append(detail.Steps, step)
		}
	}

	return detail, nil
}
