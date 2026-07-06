/*
Copyright (c) 2026 Security Research
*/

package claude

import (
	"fmt"
	"os/exec"

	"github.com/inovacc/unravel-oss/pkg/aihost"
)

// Doctor runs claude-side health checks: marketplace registration,
// settings.json `enabledPlugins` flip, .mcp.json spec-form presence,
// and `claude` CLI availability. The MCP tool wrapper in pkg/mcp/tools
// calls this once per registered host.
func Doctor() aihost.DoctorReport {
	target, _ := Host{}.InstallTarget()
	r := aihost.DoctorReport{Host: "claude", Target: target}

	add := func(name, verdict, detail, fix string) {
		r.Checks = append(r.Checks, aihost.DoctorCheck{
			Name: name, Verdict: verdict, Detail: detail, Fix: fix,
		})
	}

	if pathExists(target) {
		add("install_target", "PASS", target, "")
	} else {
		add("install_target", "FAIL", "missing "+target,
			"run `unravel plugin install --host claude`")
	}
	if MarketplaceHasEntry() {
		add("marketplace_entry", "PASS", "marketplace.json declares unravel", "")
	} else {
		add("marketplace_entry", "FAIL", "marketplace.json missing unravel entry",
			"run `unravel plugin install --host claude`")
	}
	if SettingsHasEnabled() {
		add("settings_enabled", "PASS",
			"settings.json enabledPlugins[unravel@unravel]=true", "")
	} else {
		add("settings_enabled", "FAIL",
			"settings.json missing enabledPlugins[unravel@unravel]",
			`add "unravel@unravel": true to enabledPlugins in ~/.claude/settings.json`)
	}
	if cmd, ok := McpServersHasUnravel(); ok {
		add("mcp_registered", "PASS", "mcp command="+cmd, "")
	} else {
		add("mcp_registered", "FAIL", "no unravel MCP server registered",
			"check plugin .mcp.json was written during install")
	}
	if _, err := exec.LookPath("claude"); err != nil {
		add("claude_cli", "WARN", "claude CLI not on PATH",
			"required for `claude plugin marketplace add` during install")
	} else {
		add("claude_cli", "PASS", "claude CLI on PATH", "")
	}

	r.Verdict = computeVerdict(r.Checks)
	return r
}

// Doctor satisfies aihost.Doctor on Host.
func (Host) Doctor() aihost.DoctorReport { return Doctor() }

func computeVerdict(checks []aihost.DoctorCheck) string {
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

// silence
var _ = fmt.Stringer(nil)
