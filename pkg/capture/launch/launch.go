/*
Copyright (c) 2026 Security Research
*/

// Package launch builds *exec.Cmd values for known frameworks with a debug
// port injected and a per-run isolated user-data-dir (T-08-06 mitigation).
// All callers MUST use *exec.Cmd.Start themselves — this package only assembles
// the command, never executes (testability).
package launch

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
)

var (
	// ErrPathTraversal is returned when the binary path resolves to a directory
	// or contains traversal segments after Clean (T-08-01).
	ErrPathTraversal = errors.New("launch: path-traversal rejected")

	// ErrSymlink is returned when the binary path is a symlink (D-19).
	ErrSymlink = errors.New("launch: symlink target rejected")

	// ErrUnsupported is returned when the requested framework cannot be
	// auto-launched (e.g. Tauri on non-Windows hosts).
	ErrUnsupported = errors.New("launch: framework not supported by --target; use --cdp instead")
)

// Framework names the supported auto-launch targets.
type Framework string

const (
	FrameworkElectron Framework = "electron"
	FrameworkTauri    Framework = "tauri"
	FrameworkWebView2 Framework = "webview2"
)

// Builder constructs an *exec.Cmd for a specific framework given the target
// binary path, the CDP debug port, and a per-run user-data-dir.
type Builder func(path string, port int, userDataDir string) (*exec.Cmd, error)

var registry = map[Framework]Builder{
	FrameworkElectron: LaunchElectron,
	FrameworkTauri:    LaunchTauri,
	FrameworkWebView2: LaunchWebView2,
}

// Build dispatches to the registered builder for fw.
func Build(fw Framework, path string, port int, userDataDir string) (*exec.Cmd, error) {
	b, ok := registry[fw]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, fw)
	}
	return b(path, port, userDataDir)
}

// validatePath cleans/abs-resolves p and rejects traversal segments,
// directories, and symlinks (T-08-01, D-19).
func validatePath(p string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("resolve abs: %w", err)
	}
	// Reject traversal segments in the original input.
	if slices.Contains(filepath.SplitList(filepath.ToSlash(p)), "..") {
		return "", ErrPathTraversal
	}
	if containsTraversal(p) {
		return "", ErrPathTraversal
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("lstat: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", ErrSymlink
	}
	if info.IsDir() {
		return "", fmt.Errorf("%w: %s is a directory", ErrPathTraversal, abs)
	}
	return abs, nil
}

// containsTraversal returns true if p contains a ".." segment after splitting
// on either Unix or Windows path separators.
func containsTraversal(p string) bool {
	s := filepath.ToSlash(p)
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && s[j] != '/' {
			j++
		}
		if s[i:j] == ".." {
			return true
		}
		i = j + 1
	}
	return false
}

func itoa(n int) string { return strconv.Itoa(n) }
