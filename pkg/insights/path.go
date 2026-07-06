/*
Copyright (c) 2026 Security Research
*/

// Package insights captures unravel-usage friction metrics and rolls
// them up into actionable improvement suggestions for unravel's own
// commands, agents, MCP tools, and prompts. Local-only — no telemetry
// leaves the machine.
//
// Storage root per platform:
//
//	Windows : %LOCALAPPDATA%\Unravel\insights\improving\
//	Linux   : $XDG_DATA_HOME/unravel/insights/improving (or ~/.local/share/...)
//	macOS   : ~/Library/Application Support/Unravel/insights/improving
package insights

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// SubdirRoot is the trailing path under the platform data dir.
const SubdirRoot = "insights/improving"

// Subdirs created on first use under the root.
const (
	SubdirEvents      = "events"
	SubdirGoals       = "goals"
	SubdirRollups     = "rollups"
	SubdirSuggestions = "suggestions"
)

// Root returns the absolute storage root path for this platform.
// Creates parent directories as needed; safe to call repeatedly.
// Override with UNRAVEL_INSIGHTS_ROOT for tests.
func Root() (string, error) {
	if override := os.Getenv("UNRAVEL_INSIGHTS_ROOT"); override != "" {
		return ensureDir(override)
	}
	base, err := platformBase()
	if err != nil {
		return "", err
	}
	return ensureDir(filepath.Join(base, SubdirRoot))
}

// SubPath returns the absolute path of a known subdir under Root, ensuring it exists.
func SubPath(sub string) (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return ensureDir(filepath.Join(root, sub))
}

func platformBase() (string, error) {
	switch runtime.GOOS {
	case "windows":
		// %LOCALAPPDATA% expands to e.g. C:\Users\<u>\AppData\Local
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, "Unravel"), nil
		}
		// Fallback: derive from USERPROFILE
		if v := os.Getenv("USERPROFILE"); v != "" {
			return filepath.Join(v, "AppData", "Local", "Unravel"), nil
		}
		return "", fmt.Errorf("insights: unable to resolve LOCALAPPDATA or USERPROFILE on windows")
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("insights: resolve home: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", "Unravel"), nil
	default: // linux, freebsd, etc.
		if v := os.Getenv("XDG_DATA_HOME"); v != "" {
			return filepath.Join(v, "unravel"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("insights: resolve home: %w", err)
		}
		return filepath.Join(home, ".local", "share", "unravel"), nil
	}
}

func ensureDir(p string) (string, error) {
	if err := os.MkdirAll(p, 0o755); err != nil {
		return "", fmt.Errorf("insights: mkdir %s: %w", p, err)
	}
	return p, nil
}
