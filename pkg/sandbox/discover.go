/*
Copyright (c) 2026 Security Research
*/
package sandbox

import (
	"os/exec"
	"runtime"
)

// commonNodePaths lists well-known Node.js install locations per OS.
var commonNodePaths = map[string][]string{
	"windows": {
		`C:\Program Files\nodejs\node.exe`,
		`C:\Program Files (x86)\nodejs\node.exe`,
	},
	"linux": {
		"/usr/bin/node",
		"/usr/local/bin/node",
		"/snap/bin/node",
	},
	"darwin": {
		"/usr/local/bin/node",
		"/opt/homebrew/bin/node",
	},
}

// commonNPMPaths lists well-known npm install locations per OS.
var commonNPMPaths = map[string][]string{
	"windows": {
		`C:\Program Files\nodejs\npm.cmd`,
		`C:\Program Files (x86)\nodejs\npm.cmd`,
	},
	"linux": {
		"/usr/bin/npm",
		"/usr/local/bin/npm",
	},
	"darwin": {
		"/usr/local/bin/npm",
		"/opt/homebrew/bin/npm",
	},
}

// FindNode discovers the Node.js binary on the system.
// It first checks PATH, then falls back to common install locations.
func FindNode() string {
	return findBinary("node", commonNodePaths)
}

// FindNPM discovers the npm binary on the system.
// It first checks PATH, then falls back to common install locations.
func FindNPM() string {
	name := "npm"
	if runtime.GOOS == "windows" {
		name = "npm.cmd"
	}

	return findBinary(name, commonNPMPaths)
}

// findBinary searches PATH first, then checks common install locations.
func findBinary(name string, fallback map[string][]string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}

	for _, p := range fallback[runtime.GOOS] {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}

	return ""
}
