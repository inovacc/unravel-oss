/*
Copyright (c) 2026 Security Research
*/

package claude

import (
	"encoding/json"
	"fmt"
)

// Claude Code lifecycle hooks for the unravel plugin.
//
// Hooks convert governance that is currently prose the LLM is trusted to
// obey (resume-after-compact, auto-heal, quota fences) into code the
// harness enforces. They are NOT aihost assets (Kind covers only
// command/agent/skill) — they ship as a manifest file, hooks/hooks.json,
// via GeneratedFiles(). That path is both WRITTEN on install and PRESERVED
// across reinstall, because the install stale-sweep only touches
// commands/agents/skills (install.go:71) — same treatment as .mcp.json.
//
// Every hook is a DIRECT invocation of the unravel binary (`unravel hook
// <name>`), never a bundled shell script. Claude Code pipes the event JSON
// to the command's stdin; the handler reads it and dials the supervisor for
// authoritative state. This satisfies the single-binary + cross-platform
// constraints and keeps the handlers Go-testable. Until a handler is built,
// `unravel hook <name>` drains stdin and exits 0 (cmd/hook.go), so shipping
// this manifest is always safe.

// hookInvocation is one hook entry — a direct unravel-binary command.
type hookInvocation struct {
	Type    string `json:"type"`    // always "command"
	Command string `json:"command"` // "unravel hook <name>"
}

// hookGroup binds an optional tool matcher to a list of invocations.
// Lifecycle events (SessionStart/Stop/PreCompact) omit Matcher; tool
// events (PreToolUse/PostToolUse) set it.
type hookGroup struct {
	Matcher string           `json:"matcher,omitempty"`
	Hooks   []hookInvocation `json:"hooks"`
}

// hookCommand builds the direct-binary command string for a hook. McpCommand
// (the unravel binary name) is interpolated — never hard-coded — so a renamed
// binary or the codex/gemini hosts that reuse it stay consistent.
func hookCommand(name string) string { return McpCommand + " hook " + name }

func cmdGroup(name string) hookGroup {
	return hookGroup{Hooks: []hookInvocation{{Type: "command", Command: hookCommand(name)}}}
}

// matchGroup builds a hook group scoped to a specific tool-name matcher.
func matchGroup(matcher, name string) hookGroup {
	return hookGroup{Matcher: matcher, Hooks: []hookInvocation{{Type: "command", Command: hookCommand(name)}}}
}

// HooksSpec enumerates the hooks unravel ships. Deliberately small and
// high-value: only INFREQUENT lifecycle events whose no-op cost is
// negligible. Enforcement hooks on hot tool paths (PreToolUse on
// Bash/Read/Grep, PostToolUse on every KB tool) are added once their
// handlers exist — shipping them as no-ops now would spawn a subprocess
// per tool call for nothing.
func HooksSpec() map[string][]hookGroup {
	return map[string][]hookGroup{
		// Session/subagent start (and post-compact resume): reconstruct
		// enrich-run state and inject the next concrete command. Wraps the
		// existing unravel-resume agent logic in code so it fires
		// automatically instead of being human-triggered.
		"SessionStart": {cmdGroup("resume")},
		// Session end: run kb_ops_doctor + sweep stale in_progress enrich
		// rows to interrupted. Wraps unravel-self-healer / /unravel:doctor.
		"Stop": {cmdGroup("heal")},
		// Fires after unravel_app_dissect completes: captures the dissect
		// result into the KB automatically instead of requiring a manual
		// follow-up kb_capture call. PostToolUse matches against the
		// MCP-qualified tool name Claude Code actually sees
		// (mcp__<server>__<tool>), not the bare tool name — the unravel MCP
		// server registers as "unravel", so the qualified name is
		// mcp__unravel__unravel_app_dissect.
		"PostToolUse": {matchGroup("mcp__unravel__unravel_app_dissect", "kb-capture")},
	}
}

// HooksJSON returns the bytes for hooks/hooks.json (pretty-printed, trailing
// newline).
func HooksJSON() ([]byte, error) {
	doc := map[string]any{"hooks": HooksSpec()}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal hooks.json: %w", err)
	}

	return append(b, '\n'), nil
}

// HookNames returns the hook handler names referenced by the manifest — the
// set cmd/hook.go must register (as no-op-safe handlers at minimum).
func HookNames() []string {
	seen := map[string]struct{}{}
	var names []string

	for _, groups := range HooksSpec() {
		for _, g := range groups {
			for _, h := range g.Hooks {
				// command is "<bin> hook <name>"; take the last field.
				fields := splitFields(h.Command)
				if len(fields) == 0 {
					continue
				}

				name := fields[len(fields)-1]
				if _, ok := seen[name]; ok {
					continue
				}

				seen[name] = struct{}{}
				names = append(names, name)
			}
		}
	}

	return names
}

func splitFields(s string) []string {
	var out []string

	field := ""
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if field != "" {
				out = append(out, field)
				field = ""
			}

			continue
		}

		field += string(r)
	}

	if field != "" {
		out = append(out, field)
	}

	return out
}
