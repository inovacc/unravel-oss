/*
Copyright (c) 2026 Security Research
*/

package aihost

import "os"

// Host is the minimum surface a plugin host implementation must expose
// so cmd/plugin_install.go can drive install/uninstall uniformly.
//
// Concrete hosts: pkg/aihost/claude (and future: gemini, codex, ...).
type Host interface {
	// Name returns the short host identifier ("claude", "gemini", ...).
	Name() string

	// InstallTarget returns the absolute filesystem path where the
	// rendered plugin tree should be written (under user $HOME).
	InstallTarget() (string, error)

	// TreeWriter provides Walk (rendered assets) + ManifestFiles
	// (host-specific manifests). Defined in write_tree.go.
	TreeWriter
}

// Installer is an optional capability for hosts that know how to wire
// themselves into their CLI's marketplace / settings layer. The cmd
// dispatcher checks for this with a type assertion so hosts can ship
// without install plumbing in early stages.
type Installer interface {
	// Install writes plugin files to target and patches any host-side
	// state (marketplace.json, settings.json, etc.). Returns file count
	// written.
	Install(target string) (int, error)
	// Uninstall removes plugin files at target and undoes patches.
	Uninstall(target string) error
}

// Status is an optional capability for hosts that report install
// health checks suitable for a `plugin status` CLI subcommand.
type Status interface {
	PrintStatus(w *os.File) error
}

// DoctorCheck is one host-side health check result.
type DoctorCheck struct {
	Name    string `json:"name"`
	Verdict string `json:"verdict"` // PASS | WARN | FAIL
	Detail  string `json:"detail,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// DoctorReport is the structured output of a host's self-diagnosis.
type DoctorReport struct {
	Host    string        `json:"host"`
	Target  string        `json:"target"`
	Checks  []DoctorCheck `json:"checks"`
	Verdict string        `json:"verdict"` // OK | DEGRADED | FAILED
}

// Doctor is an optional capability that returns host-side health
// findings (marketplace registration, settings flips, CLI presence).
// MCP-side checks live in pkg/mcp/tools/plugin_doctor.go and call
// Doctor() once per registered host.
type Doctor interface {
	Doctor() DoctorReport
}
