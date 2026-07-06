/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/inject"
	"github.com/inovacc/unravel-oss/pkg/inject/builtins"
	_ "github.com/inovacc/unravel-oss/pkg/inject/registry" // blank-import: fire scanner init() registrations
)

// init46-03: wire the asar repatcher into the inject library so Method=ASAR
// dispatches to a real implementation. Plan 46-01 shipped asar.Repatch /
// asar.RepatchWithPreloadInject; 46-02 shipped the dispatcher hook seam;
// 46-03 (here) closes the wiring loop.
func init() {
	inject.RegisterASARRepatcher(func(_ context.Context, asarPath string, script []byte, scriptName string) (string, error) {
		if scriptName == "" {
			scriptName = "preload.js"
		}
		out := siblingInjectedASAR(asarPath)
		if err := asar.RepatchWithPreloadInject(asarPath, out, scriptName, script); err != nil {
			return "", err
		}
		return out, nil
	})
}

func siblingInjectedASAR(src string) string {
	dir := filepath.Dir(src)
	base := filepath.Base(src)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if ext == "" {
		ext = ".asar"
	}
	return filepath.Join(dir, stem+".injected"+ext)
}

var injectScanCmd = &cobra.Command{
	Use:   "scan <app>",
	Short: "Enumerate injection seams in an Electron / Tauri / WebView2 app",
	Args:  cobra.ExactArgs(1),
	RunE:  runInjectScan,
}

// injectActiveCmd implements `unravel inject <app>` per 999.1-CONTEXT D-16.
// Defensive analysis only — every code path requires explicit consent (env
// var UNRAVEL_INJECT_CONFIRM=1, --yes flag, or interactive [y/N] prompt
// with a 5s cool-down). Non-tty stdin without env/flag is refused.
var injectActiveCmd = &cobra.Command{
	Use:   "inject <app>",
	Short: "Inject a script into a running Electron / WebView2 app (defensive analysis only)",
	Long: `Active injection via CDP attach or ASAR repatch.

Refuses to run unless one of the following is true:
  - UNRAVEL_INJECT_CONFIRM=1 is set in the environment
  - --yes is passed on the command line
  - stdin is a TTY and the user types 'y' after the 5-second cool-down

Every successful injection writes one line to the audit log
(Windows: %LOCALAPPDATA%\Unravel\inject-log.jsonl; POSIX: ~/unravel/inject-log.jsonl;
override via UNRAVEL_INJECT_LOG). There is no flag to disable this.`,
	Args: cobra.ExactArgs(1),
	RunE: runInjectActive,
}

var injectCmd = &cobra.Command{
	Use:   "inject",
	Short: "Code-injection analysis (scan + active injection — both defensive only)",
}

func init() {
	appCmd.AddCommand(injectCmd)
	injectCmd.AddCommand(injectScanCmd)
	injectCmd.AddCommand(injectActiveCmd)

	injectScanCmd.Flags().StringP("output", "o", "", "Output dir (default ./out/inject-<basename>)")
	injectScanCmd.Flags().String("platform", "auto", "Target platform: auto | macos | linux | windows")

	injectActiveCmd.Flags().String("script", "", "Path to user-supplied JS script (mutually exclusive with --builtin)")
	injectActiveCmd.Flags().String("builtin", "", "Name of built-in script (devtools | ipc-logger | network)")
	injectActiveCmd.Flags().String("world", "isolated", "Execution world: main | isolated")
	injectActiveCmd.Flags().String("method", "auto", "Injection method: cdp | asar | auto")
	injectActiveCmd.Flags().Bool("persistent", false, "CDP only: addScriptToEvaluateOnNewDocument vs Runtime.evaluate")
	injectActiveCmd.Flags().Int("cdp-port", 0, "CDP only: remote-debugging-port the target was launched with")
	injectActiveCmd.Flags().String("asar-path", "", "ASAR only: explicit path to app.asar (default: <app>/resources/app.asar)")
	injectActiveCmd.Flags().Bool("in-place", false, "ASAR only: overwrite app.asar in place (requires second confirmation)")
	injectActiveCmd.Flags().Bool("yes", false, "Skip interactive confirm (still requires you to mean it)")
}

func runInjectScan(cmd *cobra.Command, args []string) error {
	appDir := args[0]
	out, _ := cmd.Flags().GetString("output")
	if out == "" {
		out = filepath.Join("out", "inject-"+filepath.Base(appDir))
	}
	platform, _ := cmd.Flags().GetString("platform")
	if platform == "" {
		platform = "auto"
	}
	resolved := inject.ResolvePlatform(appDir, platform)

	result, err := inject.ScanWithPlatform(cmd.Context(), appDir, resolved)
	if err != nil {
		return fmt.Errorf("inject scan: %w", err)
	}
	if err := inject.WriteSeamsJSON(out, result); err != nil {
		return fmt.Errorf("write seams: %w", err)
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", filepath.Join(out, "security", "injection_seams.json"))
	return nil
}

// errInjectConsentRequired is the user-facing refusal text. Distinct from
// inject.ErrConsentRequired (library sentinel) so the CLI can speak in
// terms of how to grant consent on the command line.
var errInjectConsentRequired = errors.New("consent required: set UNRAVEL_INJECT_CONFIRM=1, pass --yes, or run interactively from a TTY")

func runInjectActive(cmd *cobra.Command, args []string) error {
	target := args[0]

	scriptPath, _ := cmd.Flags().GetString("script")
	builtinName, _ := cmd.Flags().GetString("builtin")
	world, _ := cmd.Flags().GetString("world")
	method, _ := cmd.Flags().GetString("method")
	persistent, _ := cmd.Flags().GetBool("persistent")
	cdpPort, _ := cmd.Flags().GetInt("cdp-port")
	asarPath, _ := cmd.Flags().GetString("asar-path")
	inPlace, _ := cmd.Flags().GetBool("in-place")
	yes, _ := cmd.Flags().GetBool("yes")

	if scriptPath == "" && builtinName == "" {
		return errors.New("one of --script or --builtin is required")
	}
	if scriptPath != "" && builtinName != "" {
		return errors.New("--script and --builtin are mutually exclusive")
	}

	script, scriptName, err := loadInjectScript(scriptPath, builtinName)
	if err != nil {
		return err
	}

	resolvedMethod := resolveInjectMethod(method, target, asarPath)
	if resolvedMethod == "" {
		return fmt.Errorf("could not auto-detect injection method for %s — pass --method cdp or --method asar", target)
	}

	if resolvedMethod == inject.MethodASAR && asarPath == "" {
		asarPath = guessASARPath(target)
	}

	hash := sha256Hex(script)

	// Consent gate. Order: env var → --yes flag → interactive [y/N].
	if os.Getenv("UNRAVEL_INJECT_CONFIRM") != "1" && !yes {
		if !stdinIsTTY(cmd.InOrStdin()) {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), refusalBanner(target, resolvedMethod, scriptName, hash))
			return errInjectConsentRequired
		}
		if !promptInteractive(cmd, target, resolvedMethod, scriptName, hash, persistent) {
			return errInjectConsentRequired
		}
	}

	// ASAR --in-place is destructive; require a second affirmative.
	if resolvedMethod == inject.MethodASAR && inPlace {
		if os.Getenv("UNRAVEL_INJECT_CONFIRM") != "1" && !yes {
			if !stdinIsTTY(cmd.InOrStdin()) {
				return errors.New("--in-place refused on non-tty without UNRAVEL_INJECT_CONFIRM=1 or --yes")
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: --in-place will overwrite", asarPath)
			if !promptYesNo(cmd, "type 'overwrite' to confirm in-place ASAR rewrite", "overwrite") {
				return errInjectConsentRequired
			}
		}
	}

	opts := inject.InjectOpts{
		Method:     resolvedMethod,
		Script:     script,
		ScriptName: scriptName,
		World:      world,
		Persistent: persistent,
		CDPPort:    cdpPort,
		ASARPath:   asarPath,
		Confirmed:  true,
	}

	res, err := inject.Inject(cmd.Context(), target, opts)
	if err != nil {
		return fmt.Errorf("inject: %w", err)
	}

	out := map[string]any{
		"target":      res.TargetPath,
		"method":      string(res.Method),
		"script_hash": "sha256:" + res.ScriptHash,
		"script_name": scriptName,
		"started_at":  res.StartedAt.Format(time.RFC3339Nano),
		"finished_at": res.FinishedAt.Format(time.RFC3339Nano),
		"persistent":  res.Persistent,
		"output_path": res.OutputPath,
		"audit_log":   inject.LogPath(),
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func loadInjectScript(scriptPath, builtinName string) (script []byte, name string, err error) {
	if scriptPath != "" {
		b, rerr := os.ReadFile(scriptPath)
		if rerr != nil {
			return nil, "", fmt.Errorf("read script: %w", rerr)
		}
		return b, filepath.Base(scriptPath), nil
	}
	b, gerr := builtins.Get(builtinName)
	if gerr != nil {
		return nil, "", fmt.Errorf("builtin %q: %w (available: %s)", builtinName, gerr, strings.Join(builtins.List(), ", "))
	}
	return b, builtinName + ".js", nil
}

func resolveInjectMethod(method, target, asarPath string) inject.InjectMethod {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "cdp":
		return inject.MethodCDP
	case "asar":
		return inject.MethodASAR
	case "", "auto":
		// Auto: if asarPath supplied or a sibling app.asar exists, prefer ASAR.
		if asarPath != "" {
			return inject.MethodASAR
		}
		if _, err := os.Stat(guessASARPath(target)); err == nil {
			return inject.MethodASAR
		}
		// Fall back to CDP — it's the non-destructive option.
		return inject.MethodCDP
	}
	return ""
}

func guessASARPath(target string) string {
	// Common Electron layout: <app>/resources/app.asar.
	candidate := filepath.Join(target, "resources", "app.asar")
	return candidate
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func stdinIsTTY(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func refusalBanner(target string, method inject.InjectMethod, scriptName, hash string) string {
	var sb strings.Builder
	sb.WriteString("REFUSED: active injection requires explicit consent.\n")
	sb.WriteString(fmt.Sprintf("  target:      %s\n", target))
	sb.WriteString(fmt.Sprintf("  method:      %s\n", method))
	sb.WriteString(fmt.Sprintf("  script:      %s (sha256:%s)\n", scriptName, hash))
	sb.WriteString("\nTo grant consent, choose one:\n")
	sb.WriteString("  - export UNRAVEL_INJECT_CONFIRM=1\n")
	sb.WriteString("  - re-run with --yes\n")
	sb.WriteString("  - run interactively from a TTY and answer 'y' at the prompt\n")
	return sb.String()
}

// injectCoolDown is the interactive-prompt cool-down. var (not const) so
// tests can stub it down to zero.
var injectCoolDown = 5 * time.Second

func promptInteractive(cmd *cobra.Command, target string, method inject.InjectMethod, scriptName, hash string, persistent bool) bool {
	w := cmd.ErrOrStderr()
	_, _ = fmt.Fprintln(w, "================ unravel inject — confirm ================")
	_, _ = fmt.Fprintf(w, "target:      %s\n", target)
	_, _ = fmt.Fprintf(w, "method:      %s\n", method)
	_, _ = fmt.Fprintf(w, "persistent:  %v\n", persistent)
	_, _ = fmt.Fprintf(w, "script:      %s\n", scriptName)
	_, _ = fmt.Fprintf(w, "sha256:      %s\n", hash)
	_, _ = fmt.Fprintf(w, "audit log:   %s\n", inject.LogPath())
	_, _ = fmt.Fprintln(w, "==========================================================")
	if injectCoolDown > 0 {
		_, _ = fmt.Fprintf(w, "(cool-down: %s before prompt)\n", injectCoolDown)
		time.Sleep(injectCoolDown)
	}
	return promptYesNo(cmd, "proceed? [y/N]", "y")
}

func promptYesNo(cmd *cobra.Command, prompt, expect string) bool {
	w := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(w, "%s: ", prompt)
	var answer string
	if _, err := fmt.Fscanln(cmd.InOrStdin(), &answer); err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(answer), expect)
}
