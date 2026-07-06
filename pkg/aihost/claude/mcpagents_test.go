/*
Copyright (c) 2026 Security Research
*/

package claude

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteMcpScopedAgents_HasInlineMcpServer(t *testing.T) {
	home := t.TempDir()

	paths, err := WriteMcpScopedAgents(home)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("no agents written")
	}

	data, _ := os.ReadFile(filepath.Join(home, ".claude", "agents", "unravel-enricher-mcp.md"))
	s := string(data)

	if !strings.Contains(s, "mcpServers:") || !strings.Contains(s, "unravel") {
		t.Fatal("enricher agent must declare an inline mcpServers unravel entry")
	}
}

func TestWriteMcpScopedAgents_WritesAll(t *testing.T) {
	home := t.TempDir()

	paths, err := WriteMcpScopedAgents(home)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	if len(paths) != len(mcpScopedAgents) {
		t.Fatalf("expected %d agents written, got %d", len(mcpScopedAgents), len(paths))
	}

	for _, a := range mcpScopedAgents {
		p := filepath.Join(home, ".claude", "agents", a.Name+".md")
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}
}

func TestRemoveMcpScopedAgents(t *testing.T) {
	home := t.TempDir()

	if _, err := WriteMcpScopedAgents(home); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := RemoveMcpScopedAgents(home); err != nil {
		t.Fatalf("remove: %v", err)
	}

	for _, a := range mcpScopedAgents {
		p := filepath.Join(home, ".claude", "agents", a.Name+".md")
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, err=%v", p, err)
		}
	}

	// Removing again must be a no-op, not an error.
	if err := RemoveMcpScopedAgents(home); err != nil {
		t.Fatalf("second remove should be a no-op: %v", err)
	}
}
