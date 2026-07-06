/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
)

// locateILSpy resolves the ilspycmd binary on PATH.
//
// On miss, returns a wrapped error containing the install command (D-03).
func locateILSpy() (string, error) {
	bin, err := exec.LookPath("ilspycmd")
	if err != nil {
		return "", fmt.Errorf("ilspycmd not found: install with `dotnet tool install -g ilspycmd`: %w", err)
	}

	return bin, nil
}

// detectVersion runs `ilspycmd --version` and returns the trimmed first line.
// On any error returns "unknown" (D-02 — capture verbatim, accept any output).
//
// Wrapped in defer/recover per D-20 because we will eventually parse output.
func detectVersion(ctx context.Context, bin string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "unknown"
		}
	}()

	if bin == "" {
		return "unknown"
	}

	cmd := exec.CommandContext(ctx, bin, "--version")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Some versions print to stderr; fall back to that.
		if v := firstNonEmptyLine(stderr.String()); v != "" {
			return v
		}

		return "unknown"
	}

	if v := firstNonEmptyLine(stdout.String()); v != "" {
		return v
	}

	if v := firstNonEmptyLine(stderr.String()); v != "" {
		return v
	}

	return "unknown"
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}

	return ""
}

// runILSpyCmd shells out to ilspycmd in project mode, writing per-type .cs
// files under outDir. Mirrors the pkg/disasm/external.go template.
//
// Behavior:
//   - bin == "" → loud install-hint error (D-03)
//   - non-zero exit → fmt.Errorf("ilspycmd %s: %w (stderr: %s)", asm, err, stderr)
//   - ctx cancellation → exec.CommandContext kills process; error wraps
//     context.DeadlineExceeded (D-08 timeout)
func runILSpyCmd(ctx context.Context, bin, asm, outDir string) error {
	if bin == "" {
		return errors.New("ilspycmd not found: install with `dotnet tool install -g ilspycmd`")
	}

	// Absolutize the (untrusted, in-bundle) assembly path so it can never be
	// parsed as a flag by ilspycmd (argument injection, CWE-88).
	if abs, absErr := filepath.Abs(asm); absErr == nil {
		asm = abs
	}

	args := []string{"-p", "-o", outDir, asm}
	cmd := exec.CommandContext(ctx, bin, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard

	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("ilspycmd %s: %w (stderr: %s)", asm, ctxErr, strings.TrimSpace(stderr.String()))
		}

		return fmt.Errorf("ilspycmd %s: %w (stderr: %s)", asm, err, strings.TrimSpace(stderr.String()))
	}

	return nil
}
