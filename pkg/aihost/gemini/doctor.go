/*
Copyright (c) 2026 Security Research
*/

package gemini

import (
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/aihost"
)

// Doctor runs gemini-side health checks. Validates install-target +
// gemini-extension.json + GEMINI.md presence. `gemini extensions
// install` auto-registration will be added when the CLI subcommand
// surface stabilises.
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
			"run `unravel plugin install --host gemini`")
	}
	ext := filepath.Join(target, "gemini-extension.json")
	if _, err := os.Stat(ext); err == nil {
		add("extension_manifest", "PASS", ext, "")
	} else {
		add("extension_manifest", "FAIL", "missing "+ext,
			"reinstall via `unravel plugin install --host gemini`")
	}
	ctx := filepath.Join(target, "GEMINI.md")
	if _, err := os.Stat(ctx); err == nil {
		add("context_file", "PASS", ctx, "")
	} else {
		add("context_file", "WARN", "missing "+ctx,
			"reinstall to restore GEMINI.md")
	}
	add("cli_register", "WARN",
		"gemini extensions install auto-registration not wired",
		"manually run `gemini extensions install "+target+"` or symlink")

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
