/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// execCommand is the function used to create exec.Cmd instances.
// It is a package-level variable to allow injection in tests.
var execCommand = exec.CommandContext

// Runner manages Frida script execution on a target device.
type Runner struct {
	Host        string    // frida-server host:port (default "127.0.0.1:27042")
	DeviceID    string    // specific device ID (for adb devices)
	PackageName string    // target app package name
	Verbose     bool      // enable verbose logging
	Output      io.Writer // where to write script output (default os.Stdout)
}

// RunResult holds the output from executing a single Frida script.
type RunResult struct {
	ScriptName string        `json:"script_name"`
	Output     []string      `json:"output"` // captured console.log lines
	Errors     []string      `json:"errors"` // any errors during execution
	Duration   time.Duration `json:"duration"`
	Started    time.Time     `json:"started"`
}

// SessionResult holds the combined output from running multiple scripts.
type SessionResult struct {
	PackageName string        `json:"package_name"`
	Device      string        `json:"device"`
	Scripts     []RunResult   `json:"scripts"`
	Duration    time.Duration `json:"duration"`
}

// RunnerOption configures a Runner.
type RunnerOption func(*Runner)

// WithHost sets the frida-server host:port.
func WithHost(host string) RunnerOption {
	return func(r *Runner) {
		r.Host = host
	}
}

// WithDevice sets the target device ID for direct USB mode.
func WithDevice(deviceID string) RunnerOption {
	return func(r *Runner) {
		r.DeviceID = deviceID
	}
}

// WithVerbose enables verbose output.
func WithVerbose(v bool) RunnerOption {
	return func(r *Runner) {
		r.Verbose = v
	}
}

// WithOutput sets the writer for script output.
func WithOutput(w io.Writer) RunnerOption {
	return func(r *Runner) {
		r.Output = w
	}
}

// NewRunner creates a runner with default settings.
func NewRunner(packageName string, opts ...RunnerOption) *Runner {
	r := &Runner{
		Host:        "127.0.0.1:27042",
		PackageName: packageName,
		Output:      os.Stdout,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// CheckDevice verifies frida-server is reachable.
// Uses frida-ps -H host or frida-ps -D device.
func (r *Runner) CheckDevice(ctx context.Context) error {
	args := r.deviceArgs()
	cmd := execCommand(ctx, "frida-ps", args...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		if isNotFound(err) {
			return fmt.Errorf("frida-ps not found in PATH: install Frida tools (pip install frida-tools)")
		}

		return fmt.Errorf("frida-ps failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

// RunScript executes a single Frida script against the target app.
// Uses: frida -H host -n packageName -l script.js --no-pause
func (r *Runner) RunScript(ctx context.Context, script GeneratedScript, timeout time.Duration) (*RunResult, error) {
	return r.runFrida(ctx, script, timeout, false)
}

// Spawn starts the target app with Frida instrumentation.
// Uses: frida -H host -f packageName -l script.js --no-pause
func (r *Runner) Spawn(ctx context.Context, script GeneratedScript, timeout time.Duration) (*RunResult, error) {
	return r.runFrida(ctx, script, timeout, true)
}

// RunAll executes all scripts sequentially, collecting results.
func (r *Runner) RunAll(ctx context.Context, scripts []GeneratedScript, perScriptTimeout time.Duration) (*SessionResult, error) {
	started := time.Now()

	device := r.Host
	if r.DeviceID != "" {
		device = r.DeviceID
	}

	session := &SessionResult{
		PackageName: r.PackageName,
		Device:      device,
		Scripts:     make([]RunResult, 0, len(scripts)),
	}

	for _, s := range scripts {
		result, err := r.RunScript(ctx, s, perScriptTimeout)
		if err != nil {
			session.Scripts = append(session.Scripts, RunResult{
				ScriptName: s.Name,
				Errors:     []string{err.Error()},
				Started:    time.Now(),
			})

			continue
		}

		session.Scripts = append(session.Scripts, *result)
	}

	session.Duration = time.Since(started)

	return session, nil
}

func (r *Runner) runFrida(ctx context.Context, script GeneratedScript, timeout time.Duration, spawn bool) (*RunResult, error) {
	// Write script to temp file.
	// Use filepath.Base to strip any directory components from script.Name,
	// then remove residual path separators so an attacker-controlled Name
	// (e.g. "../../home/user/.bashrc") cannot escape the temp directory.
	safeName := filepath.Base(script.Name)
	safeName = strings.NewReplacer("/", "_", "\\", "_").Replace(safeName)
	tmpDir := os.TempDir()
	scriptPath := filepath.Join(tmpDir, fmt.Sprintf("frida_%s_%d.js", safeName, time.Now().UnixNano()))

	if err := os.WriteFile(scriptPath, []byte(script.Content), 0644); err != nil {
		return nil, fmt.Errorf("write temp script: %w", err)
	}
	defer func() { _ = os.Remove(scriptPath) }()

	// Build frida command args
	args := r.deviceArgs()

	if spawn {
		args = append(args, "-f", r.PackageName)
	} else {
		args = append(args, "-n", r.PackageName)
	}

	args = append(args, "-l", scriptPath, "--no-pause")

	// Apply timeout via context
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	started := time.Now()
	cmd := execCommand(ctx, "frida", args...)

	result := &RunResult{
		ScriptName: script.Name,
		Started:    started,
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("frida not found in PATH: install Frida tools (pip install frida-tools)")
		}

		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("frida not found in PATH: install Frida tools (pip install frida-tools)")
		}

		return nil, fmt.Errorf("start frida: %w", err)
	}

	// Read stdout lines
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			result.Output = append(result.Output, line)

			if r.Verbose {
				_, _ = fmt.Fprintln(r.Output, line)
			}
		}
	}()

	// Read stderr lines
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			result.Errors = append(result.Errors, line)

			if r.Verbose {
				_, _ = fmt.Fprintf(r.Output, "[ERR] %s\n", line)
			}
		}
	}()

	err = cmd.Wait()
	result.Duration = time.Since(started)

	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return result, fmt.Errorf("script %s timed out after %s", script.Name, timeout)
	}

	// Non-zero exit is not necessarily fatal for frida; we still return the result
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	}

	return result, nil
}

func (r *Runner) deviceArgs() []string {
	if r.DeviceID != "" {
		return []string{"-D", r.DeviceID}
	}

	return []string{"-H", r.Host}
}

func isNotFound(err error) bool {
	return strings.Contains(err.Error(), exec.ErrNotFound.Error())
}
