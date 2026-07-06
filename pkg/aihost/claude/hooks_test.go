/*
Copyright (c) 2026 Security Research
*/

package claude

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// TestHooksJSON_DirectBinaryNoScripts pins the two load-bearing invariants of
// the hooks manifest: (1) every hook is a direct `unravel hook <name>` binary
// invocation — never a shell/script wrapper (.sh/.bat/.ps1/.cmd/bash), which
// keeps hooks cross-platform + Go-testable; (2) the manifest wires the
// intended lifecycle events to the intended handlers.
func TestHooksJSON_DirectBinaryNoScripts(t *testing.T) {
	raw, err := HooksJSON()
	if err != nil {
		t.Fatalf("HooksJSON: %v", err)
	}

	var doc struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("hooks.json is not valid JSON: %v\n%s", err, raw)
	}

	want := map[string]string{
		"SessionStart": McpCommand + " hook resume",
		"Stop":         McpCommand + " hook heal",
		"PostToolUse":  McpCommand + " hook kb-capture",
	}

	for event, cmd := range want {
		groups, ok := doc.Hooks[event]
		if !ok || len(groups) == 0 || len(groups[0].Hooks) == 0 {
			t.Errorf("hooks.json missing %s wiring:\n%s", event, raw)
			continue
		}

		got := groups[0].Hooks[0]
		if got.Type != "command" {
			t.Errorf("%s hook type = %q, want \"command\"", event, got.Type)
		}
		if got.Command != cmd {
			t.Errorf("%s command = %q, want %q", event, got.Command, cmd)
		}
	}

	// No script wrappers anywhere in the manifest.
	lower := strings.ToLower(string(raw))
	for _, bad := range []string{".sh", ".bat", ".ps1", ".cmd", "bash ", "sh -c", "powershell"} {
		if strings.Contains(lower, bad) {
			t.Errorf("hooks.json references a script wrapper %q (must be direct binary):\n%s", bad, raw)
		}
	}
}

// TestGeneratedFiles_IncludesHooks ensures hooks.json ships via GeneratedFiles
// (so install writes it AND the stale-sweep preserves it, like .mcp.json).
func TestGeneratedFiles_IncludesHooks(t *testing.T) {
	files, err := GeneratedFiles()
	if err != nil {
		t.Fatalf("GeneratedFiles: %v", err)
	}
	if _, ok := files["hooks/hooks.json"]; !ok {
		got := make([]string, 0, len(files))
		for k := range files {
			got = append(got, k)
		}
		sort.Strings(got)
		t.Errorf("GeneratedFiles missing hooks/hooks.json; has %v", got)
	}
}

// TestHookNames matches the manifest handlers to what cmd/hook.go must register.
func TestHookNames(t *testing.T) {
	got := HookNames()
	sort.Strings(got)
	want := []string{"heal", "kb-capture", "resume"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("HookNames() = %v, want %v", got, want)
	}
}
