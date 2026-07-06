/*
Copyright (c) 2026 Security Research
*/
package tools

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

const defaultTimeout = 10 * time.Minute

// RunResult holds the output of an external tool invocation.
type RunResult struct {
	Tool      string        `json:"tool"`
	Command   string        `json:"command"`
	Args      []string      `json:"args"`
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
	ExitCode  int           `json:"exit_code"`
	Duration  time.Duration `json:"duration"`
	OutputDir string        `json:"output_dir,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// RunOptions configures tool execution.
type RunOptions struct {
	Timeout   time.Duration
	WorkDir   string
	OutputDir string
	Env       []string
}

// Run executes a registered tool with default options.
// Returns a RunResult even on non-zero exit. Returns an error only for
// infrastructure failures (tool not found, context issues).
func (r *Registry) Run(ctx context.Context, name string, args ...string) (*RunResult, error) {
	return r.RunWithOptions(ctx, name, nil, args...)
}

// RunWithOptions executes a registered tool with custom options.
func (r *Registry) RunWithOptions(ctx context.Context, name string, opts *RunOptions, args ...string) (*RunResult, error) {
	r.mu.RLock()
	t, ok := r.tools[name]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}

	if !t.Available {
		return nil, fmt.Errorf("tool not available: %s (%s)", name, t.Error)
	}

	timeout := defaultTimeout
	if opts != nil && opts.Timeout > 0 {
		timeout = opts.Timeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, t.Path, args...)

	if opts != nil {
		if opts.WorkDir != "" {
			cmd.Dir = opts.WorkDir
		}

		if len(opts.Env) > 0 {
			cmd.Env = opts.Env
		}
	}

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	result := &RunResult{
		Tool:     name,
		Command:  t.Path,
		Args:     args,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: duration,
	}

	if opts != nil && opts.OutputDir != "" {
		result.OutputDir = opts.OutputDir
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			result.Error = fmt.Sprintf("exit code %d", result.ExitCode)

			return result, nil
		}

		result.Error = err.Error()

		return result, err
	}

	return result, nil
}
