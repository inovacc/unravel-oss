package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/capture/webview2"
	"github.com/inovacc/unravel-oss/pkg/config"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/insights"

	"github.com/spf13/cobra"
)

// insightsSessionID is one random id per process lifetime, attached to
// every captured event so the rollup pass can group by session. Also
// exported via env UNRAVEL_INSIGHTS_SESSION so child MCP-tool calls
// and Task-spawned subagents can attach to the same session bucket.
var insightsSessionID = func() string {
	if v := os.Getenv("UNRAVEL_INSIGHTS_SESSION"); v != "" {
		return v
	}
	id := insights.SessionID()
	_ = os.Setenv("UNRAVEL_INSIGHTS_SESSION", id)
	return id
}()

const banner = `
██╗   ██╗███╗   ██╗██████╗  █████╗ ██╗   ██╗███████╗██╗
██║   ██║████╗  ██║██╔══██╗██╔══██╗██║   ██║██╔════╝██║
██║   ██║██╔██╗ ██║██████╔╝███████║██║   ██║█████╗  ██║
██║   ██║██║╚██╗██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║
╚██████╔╝██║ ╚████║██║  ██║██║  ██║ ╚████╔╝ ███████╗███████╗
 ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝
`

var Version = "dev"

var (
	verbose    bool
	output     string
	jsonFormat bool
	debugMode  bool
	toolsDir   string
)

var rootCmd = &cobra.Command{
	Use:     "unravel",
	Version: Version,
	Short:   "AI App Security Analyzer",
	Long: banner + `
Unravel is a unified security analysis toolkit for desktop applications
built on Electron and Tauri frameworks.

Commands:
  analyze   - Full security analysis with manifest-based detection
  asar      - Extract and search ASAR archives
  chromium  - Extract Chromium profile data
  dpapi     - Decrypt Windows DPAPI protected data
  leveldb   - Parse LevelDB databases
  cache     - Parse HTTP cache
  ipc       - Fuzz IPC channels
  license   - Test license validation
  tpm       - Extract TPM keys
  extension - Browser extension forensics
  cert      - Binary certificate extraction and analysis
  garble    - Go binary obfuscation analysis (garble detection)
  android   - Android APK analysis, decompilation, and reverse engineering
  deb       - Debian package analysis and extraction
  rpm       - RPM package analysis and extraction
  detect    - Detect file types and show applicable commands
  transpile - Transpile source code to Go (C++, Java, Python, TypeScript)
  dissect   - Auto-detect and run all applicable analyses

Examples:
  unravel analyze ./MyApp -o ./report
  unravel asar extract ./app.asar -o ./extracted
  unravel chromium extract %APPDATA%/MyApp -o ./data
  unravel extension scan --browser chrome --json
  unravel extension analyze <extension_id>
  unravel garble detect ./binary.exe
  unravel garble scan ./directory -v
`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if toolsDir != "" {
			absDir, err := filepath.Abs(toolsDir)
			if err == nil {
				_ = os.Setenv("PATH", absDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			}
		}

		// First-run bootstrap: drop the annotated config template at the
		// resolved config path when none exists yet, so a fresh install has
		// an editable config.yaml instead of nothing. No-op when the file is
		// already present. Non-fatal: a scaffold failure must not block the
		// command — log and continue (the user can still run `unravel db setup`).
		if created, resolved, err := config.Scaffold(""); err != nil {
			slog.Default().Warn("config.scaffold.failed", "err", err.Error())
		} else if created {
			slog.Default().Info("config.scaffold.created", "path", resolved)
		}

		// CR-01: run the D-05 self-heal unconditionally and early for
		// EVERY unravel invocation (not only webview2-attach), so any
		// later run repairs a leaked unravel-tagged HKCU\Environment
		// value left by a hard-killed prior capture. No-op on non-Windows
		// and when no stale value is present. Non-fatal: a self-heal
		// failure must not block unrelated commands — log and continue.
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		if err := webview2.SelfHeal(ctx, slog.Default()); err != nil {
			slog.Default().Warn("webview2.selfheal.early_failed", "err", err.Error())
		}
		// Insights capture: record every CLI invocation as one event.
		// Silent no-op when UNRAVEL_INSIGHTS=off. Skip self-recursion
		// (insights subcommand records via its own path).
		if !strings.HasPrefix(cmd.CommandPath(), "unravel insights") {
			_ = insights.Record(insights.Event{
				Type:      insights.EventCommandInvoked,
				SessionID: insightsSessionID,
				Payload: map[string]any{
					"cmd":  cmd.CommandPath(),
					"args": args,
				},
			})
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print(banner)
		fmt.Printf("  AI App Security Analyzer v%s\n\n", Version)
		fmt.Println("Use 'unravel --help' for available commands")
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "output directory")
	rootCmd.PersistentFlags().BoolVar(&debugMode, "debug", false, "dump all intermediate artifacts to a timestamped debug/ directory")
	rootCmd.PersistentFlags().StringVar(&toolsDir, "tools-dir", "", "directory with RE tools to prepend to PATH")

	// Phase 4 (Wave 5) — WinUI 3 + UWP framework analysis surface.
	rootCmd.AddCommand(winuiCmd)
	rootCmd.AddCommand(uwpCmd)
}

// debugRecorder returns a debug recorder based on the --debug flag.
func debugRecorder(logger *slog.Logger) (*debug.Recorder, error) {
	if !debugMode {
		return debug.NopRecorder(), nil
	}

	return debug.New(".", logger)
}
