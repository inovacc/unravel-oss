/*
Copyright (c) 2026 Security Research
*/

package codex

import (
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/aihost"
)

// Doctor runs codex-side health checks. Lightweight version — codex
// CLI integration is not yet wired so this only validates install-target
// existence + manifest presence. Marketplace + plugin-enable checks
// will land when codex CLI surfaces stabilise.
func (h Host) Doctor() aihost.DoctorReport {
	target, _ := h.InstallTarget()
	r := aihost.DoctorReport{Host: h.Name(), Target: target}

	add := func(name, verdict, detail, fix string) {
		r.Checks = append(r.Checks, aihost.DoctorCheck{
			Name: name, Verdict: verdict, Detail: detail, Fix: fix,
		})
	}

	if _, err := os.Stat(target); err == nil {
		add("install_target", "PASS", target, "")
	} else {
		add("install_target", "FAIL", "missing "+target,
			"run `unravel plugin install --host codex`")
	}
	pluginJSON := filepath.Join(target, ".codex-plugin", "plugin.json")
	if _, err := os.Stat(pluginJSON); err == nil {
		add("plugin_manifest", "PASS", pluginJSON, "")
	} else {
		add("plugin_manifest", "FAIL", "missing "+pluginJSON,
			"reinstall via `unravel plugin install --host codex`")
	}
	mcpJSON := filepath.Join(target, ".mcp.json")
	if _, err := os.Stat(mcpJSON); err == nil {
		add("mcp_manifest", "PASS", mcpJSON, "")
	} else {
		add("mcp_manifest", "FAIL", "missing "+mcpJSON,
			"reinstall via `unravel plugin install --host codex`")
	}
	add("marketplace_register", "WARN",
		"codex CLI auto-registration not wired",
		"manually add to ~/.agents/plugins/marketplace.json")

	r.Verdict = verdict(r.Checks)
	return r
}

func verdict(checks []aihost.DoctorCheck) string {
	hasFail := false
	hasWarn := false
	for _, c := range checks {
		switch c.Verdict {
		case "FAIL":
			hasFail = true
		case "WARN":
			hasWarn = true
		}
	}
	switch {
	case hasFail:
		return "FAILED"
	case hasWarn:
		return "DEGRADED"
	default:
		return "OK"
	}
}
